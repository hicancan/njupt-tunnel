package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	Socks5Version        = 5
	CmdConnect           = 1
	CmdUdpAssociate      = 3
	AtypIPv4             = 1
	AtypDomain           = 3
	AtypIPv6             = 4
	RepSuccess           = 0
	RepServerFailure     = 1
	RepCommandNotSupport = 7
	RepAddressNotSupport = 8
)

type SOCKS5Server struct {
	ListenAddr string
	Dialer     Dialer
	lifecycle  serverLifecycle
}

func NewSOCKS5Server(listenAddr string, backend Dialer) *SOCKS5Server {
	return &SOCKS5Server{ListenAddr: listenAddr, Dialer: backend}
}

func (s *SOCKS5Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	return s.Serve(ctx, listener)
}

// Serve takes ownership of listener and all connections accepted from it.
func (s *SOCKS5Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, finish, err := s.lifecycle.begin(ctx, listener)
	if err != nil {
		return err
	}
	defer finish()
	tracked := trackedListener{Listener: listener, ctx: ctx, lifecycle: &s.lifecycle}
	for {
		conn, err := tracked.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept SOCKS5: %w", err)
		}
		go func() { defer conn.Close(); s.handleConnection(conn.(*trackedConn).ctx, conn) }()
	}
}

func (s *SOCKS5Server) Close() error { return s.lifecycle.close() }

func (s *SOCKS5Server) handleConnection(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	reader := bufio.NewReaderSize(conn, 512)
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:2]); err != nil || header[0] != Socks5Version {
		return
	}
	var methods [255]byte
	if _, err := io.ReadFull(reader, methods[:header[1]]); err != nil {
		return
	}
	method := byte(255)
	for _, candidate := range methods[:header[1]] {
		if candidate == 0 {
			method = 0
			break
		}
	}
	if _, err := conn.Write([]byte{Socks5Version, method}); err != nil || method == 255 {
		return
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return
	}
	if header[0] != Socks5Version || header[2] != 0 {
		_ = writeSOCKSReply(conn, RepServerFailure, nil)
		return
	}
	if header[1] != CmdConnect && header[1] != CmdUdpAssociate {
		_ = writeSOCKSReply(conn, RepCommandNotSupport, nil)
		return
	}
	target, err := readSOCKSAddress(reader, header[3])
	if err != nil {
		_ = writeSOCKSReply(conn, RepAddressNotSupport, nil)
		return
	}
	if s.Dialer == nil {
		_ = writeSOCKSReply(conn, RepServerFailure, nil)
		return
	}
	if header[1] == CmdUdpAssociate {
		s.handleUDPAssociate(ctx, conn, reader, target)
		return
	}
	if target.port == 0 {
		_ = writeSOCKSReply(conn, RepAddressNotSupport, nil)
		return
	}
	upstream, err := dialTCP(ctx, s.Dialer, target)
	if err != nil {
		_ = writeSOCKSReply(conn, RepServerFailure, nil)
		return
	}
	if err := writeSOCKSReply(conn, RepSuccess, nil); err != nil {
		_ = upstream.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	relayTCP(ctx, conn, reader, upstream)
}

func readSOCKSAddress(reader io.Reader, atyp byte) (endpoint, error) {
	var buffer [255]byte
	var target endpoint
	switch atyp {
	case AtypIPv4, AtypIPv6:
		size := net.IPv4len
		if atyp == AtypIPv6 {
			size = net.IPv6len
		}
		if _, err := io.ReadFull(reader, buffer[:size]); err != nil {
			return target, err
		}
		target.host = net.IP(buffer[:size]).String()
	case AtypDomain:
		if _, err := io.ReadFull(reader, buffer[:1]); err != nil {
			return target, err
		}
		size := int(buffer[0])
		if _, err := io.ReadFull(reader, buffer[:size]); err != nil {
			return target, err
		}
		target.host = strings.ToLower(strings.TrimSuffix(string(buffer[:size]), "."))
		if !validHost(target.host) {
			return target, errors.New("invalid SOCKS5 hostname")
		}
	default:
		return target, errors.New("unsupported SOCKS5 address type")
	}
	if _, err := io.ReadFull(reader, buffer[:2]); err != nil {
		return target, err
	}
	target.port = binary.BigEndian.Uint16(buffer[:2])
	return target, nil
}

func writeSOCKSReply(writer io.Writer, code byte, bound *net.UDPAddr) error {
	var reply [22]byte
	reply[0], reply[1], reply[3] = Socks5Version, code, AtypIPv4
	size := 10
	if bound != nil {
		if v4 := bound.IP.To4(); v4 != nil {
			copy(reply[4:8], v4)
		} else {
			reply[3], size = AtypIPv6, 22
			copy(reply[4:20], bound.IP.To16())
		}
		binary.BigEndian.PutUint16(reply[size-2:size], uint16(bound.Port))
	}
	_, err := writer.Write(reply[:size])
	return err
}
