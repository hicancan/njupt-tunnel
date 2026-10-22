package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

func (s *SOCKS5Server) handleUDPAssociate(ctx context.Context, control net.Conn, reader *bufio.Reader, requested endpoint) {
	peer, ok := control.RemoteAddr().(*net.TCPAddr)
	local, localOK := control.LocalAddr().(*net.TCPAddr)
	if !ok || !localOK {
		_ = writeSOCKSReply(control, RepServerFailure, nil)
		return
	}
	expectedIP, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return
	}
	expectedIP = expectedIP.Unmap()
	requestedIP := net.ParseIP(requested.host)
	if requestedIP == nil || !requestedIP.IsUnspecified() && !requestedIP.Equal(peer.IP) {
		_ = writeSOCKSReply(control, RepAddressNotSupport, nil)
		return
	}
	network := "udp4"
	if local.IP.To4() == nil {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		_ = writeSOCKSReply(control, RepServerFailure, nil)
		return
	}
	defer socket.Close()
	packet, cancel, err := openUDPAssociation(ctx, s.Dialer, handshakeTimeout)
	if err != nil {
		_ = writeSOCKSReply(control, RepServerFailure, nil)
		return
	}
	defer cancel()
	defer packet.Close()
	if err := writeSOCKSReply(control, RepSuccess, socket.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})

	var mu sync.Mutex
	var client netip.AddrPort
	if requested.port != 0 {
		client = netip.AddrPortFrom(expectedIP, requested.port)
	}
	stop := context.AfterFunc(ctx, func() { _ = control.Close(); _ = socket.Close(); _ = packet.Close() })
	defer stop()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer control.Close()
		buffer := make([]byte, 65535)
		var destination udpDestination
		for {
			n, source, err := socket.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
			if source.Addr() != expectedIP {
				continue
			}
			mu.Lock()
			accepted := !client.IsValid() || client == source
			mu.Unlock()
			if !accepted {
				continue
			}
			target, payload, ok := destination.decode(buffer[:n])
			if !ok {
				continue
			}
			mu.Lock()
			if !client.IsValid() {
				client = source
			}
			mu.Unlock()
			if _, err := packet.WriteTo(payload, target); errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer control.Close()
		buffer := make([]byte, 65535+22)
		for {
			n, source, err := packet.ReadFrom(buffer[22:])
			if err != nil {
				return
			}
			header, ok := encodeUDPHeader(buffer[:22], source)
			if !ok {
				continue
			}
			mu.Lock()
			destination := client
			mu.Unlock()
			if !destination.IsValid() {
				continue
			}
			if _, err := socket.WriteToUDPAddrPort(buffer[22-header:22+n], destination); err != nil {
				return
			}
		}
	}()
	_, _ = io.Copy(io.Discard, reader)
	_ = socket.Close()
	_ = packet.Close()
	workers.Wait()
}

// Setup has a finite budget; the returned packet socket keeps its context for
// the entire association. A deadline context canceled on return would also
// destroy an otherwise successful socket.
func openUDPAssociation(ctx context.Context, backend Dialer, budget time.Duration) (net.PacketConn, context.CancelFunc, error) {
	association, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(budget, cancel)
	packet, err := backend.ListenPacket(association)
	if !timer.Stop() {
		err = context.DeadlineExceeded
	} else if err == nil {
		err = association.Err()
	}
	if err == nil && packet == nil {
		err = errors.New("tunnel backend returned no UDP socket")
	}
	if err != nil {
		cancel()
		if packet != nil {
			_ = packet.Close()
		}
		return nil, nil, err
	}
	return packet, cancel, nil
}

// Decode only unfragmented SOCKS5 datagrams. Names remain unresolved until they
// reach the tunnel backend; malformed packets never claim the association's source.
type udpDestination struct {
	ip     net.UDPAddr
	domain DomainAddr
}

func (d *udpDestination) decode(packet []byte) (net.Addr, []byte, bool) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, nil, false
	}
	var address net.Addr
	var end int
	switch packet[3] {
	case AtypIPv4:
		end = 10
		if len(packet) < end {
			return nil, nil, false
		}
		d.ip.IP, d.ip.Port = net.IP(packet[4:8]), int(binary.BigEndian.Uint16(packet[8:10]))
		address = &d.ip
	case AtypIPv6:
		end = 22
		if len(packet) < end {
			return nil, nil, false
		}
		d.ip.IP, d.ip.Port = net.IP(packet[4:20]), int(binary.BigEndian.Uint16(packet[20:22]))
		address = &d.ip
	case AtypDomain:
		if len(packet) < 5 {
			return nil, nil, false
		}
		end = 7 + int(packet[4])
		if len(packet) < end {
			return nil, nil, false
		}
		host := string(packet[5 : end-2])
		if !validHost(host) {
			return nil, nil, false
		}
		d.domain.Host, d.domain.Port = host, int(binary.BigEndian.Uint16(packet[end-2:end]))
		address = &d.domain
	default:
		return nil, nil, false
	}
	port := binary.BigEndian.Uint16(packet[end-2 : end])
	if port == 0 {
		return nil, nil, false
	}
	return address, packet[end:], true
}

// Place the header immediately before the payload at buffer[22:].
func encodeUDPHeader(buffer []byte, source net.Addr) (int, bool) {
	address, ok := source.(*net.UDPAddr)
	if !ok || address.Port < 1 || address.Port > 65535 {
		return 0, false
	}
	size, atyp := 22, byte(AtypIPv6)
	ip := address.IP.To16()
	if v4 := address.IP.To4(); v4 != nil {
		size, atyp, ip = 10, AtypIPv4, v4
	}
	if ip == nil {
		return 0, false
	}
	header := buffer[22-size : 22]
	clear(header)
	header[3] = atyp
	copy(header[4:], ip)
	binary.BigEndian.PutUint16(header[size-2:], uint16(address.Port))
	return size, true
}
