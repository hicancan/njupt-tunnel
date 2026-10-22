package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

var ErrAuthentication = errors.New("gateway rejected tunnel authentication")

// Config describes one immutable gateway connection. Reconnection creates a
// new Tunnel and network stack; packets never cross connection generations.
type Config struct {
	Gateway  string
	TLS      *tls.Config
	Username string
	Token    string
	BindIP   string
	MTU      uint32
	DNS      netip.Addr // DNS from the authenticated controller policy.
}

// Info is the network the gateway assigns to one connection. PrefixLen comes
// from the gateway's netmask attribute; the DNS server does not, because the
// handshake advertises a loopback address there.
type Info struct {
	Address   netip.Addr
	PrefixLen int
	DNS       netip.Addr
}

// Open performs only the verified TLS and tunnel authentication handshake.
// TLS I/O starts in Run; Open also allocates the connection's network stack.
func Open(ctx context.Context, cfg Config) (*Tunnel, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if cfg.TLS == nil {
		return nil, errors.New("tunnel needs a TLS policy")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}}
	if cfg.BindIP != "" {
		ip := net.ParseIP(cfg.BindIP)
		if ip == nil {
			return nil, errors.New("invalid gateway source address")
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Gateway)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	conn := tls.Client(raw, cfg.TLS)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("gateway TLS: %w", err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	info, err := authenticate(conn, cfg.Username, cfg.Token)
	if err != nil {
		conn.Close()
		return nil, err
	}
	info.DNS = cfg.DNS
	if !info.DNS.Is4() || !info.DNS.IsGlobalUnicast() {
		conn.Close()
		return nil, errors.New("authenticated controller policy did not supply an IPv4 DNS server")
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	network, err := newNetwork(info, cfg.MTU)
	if err != nil {
		conn.Close()
		return nil, err
	}
	stop()
	if err := ctx.Err(); err != nil {
		conn.Close()
		network.Close()
		return nil, err
	}
	return &Tunnel{conn: conn, network: network, info: info}, nil
}

func authenticate(conn net.Conn, username, token string) (Info, error) {
	if len(username) == 0 || len(username) > 255 || len(token) == 0 || len(token) > 255 {
		return Info{}, errors.New("tunnel username and token must contain 1..255 bytes")
	}
	frame := make([]byte, txHeaderSize, txHeaderSize+7+len(username)+len(token))
	frame = append(frame, 1, 0, byte(len(username)))
	frame = append(frame, username...)
	frame = append(frame, 2, 0, byte(len(token)))
	frame = append(frame, token...)
	frame = append(frame, attrEnd)
	encodeHeader(frame, typeAuth, len(frame))
	if err := writeAll(conn, frame); err != nil {
		return Info{}, fmt.Errorf("write tunnel authentication: %w", err)
	}
	var hdr [txHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Info{}, fmt.Errorf("read tunnel authentication: %w", err)
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if hdr[0] != 1 || hdr[1] != typeAuthReply || length < txHeaderSize {
		return Info{}, errors.New("invalid tunnel authentication frame")
	}
	body := make([]byte, length-txHeaderSize)
	if _, err := io.ReadFull(conn, body); err != nil {
		return Info{}, fmt.Errorf("read tunnel attributes: %w", err)
	}
	return parseInfo(body)
}

func parseInfo(body []byte) (Info, error) {
	var info Info
	for len(body) > 0 {
		if body[0] == attrEnd {
			body = body[1:]
			if len(body) != 0 {
				return Info{}, errors.New("trailing tunnel attributes")
			}
			break
		}
		if len(body) < 3 || int(body[2]) > len(body)-3 {
			return Info{}, errors.New("truncated tunnel attribute")
		}
		tag, n := binary.LittleEndian.Uint16(body), int(body[2])
		value := body[3 : 3+n]
		body = body[3+n:]
		switch tag {
		case attrAddress:
			if len(value) != 4 {
				return Info{}, errors.New("invalid virtual IPv4 attribute")
			}
			info.Address = netip.AddrFrom4([4]byte(value))
		case attrNetmask:
			ones, bits := net.IPMask(value).Size()
			if len(value) != 4 || bits != 32 {
				return Info{}, errors.New("invalid virtual IPv4 netmask attribute")
			}
			info.PrefixLen = ones
		}
	}
	if !info.Address.Is4() || !info.Address.IsGlobalUnicast() {
		return Info{}, ErrAuthentication
	}
	if info.PrefixLen < 8 || info.PrefixLen > 32 {
		return Info{}, errors.New("gateway did not assign a usable IPv4 netmask")
	}
	return info, nil
}
