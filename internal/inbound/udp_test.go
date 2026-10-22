package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type testDatagram struct {
	data    []byte
	address net.Addr
}

type packetBackend struct {
	sent     chan testDatagram
	received chan testDatagram
	closed   chan struct{}
	once     sync.Once
}

func newPacketBackend() *packetBackend {
	return &packetBackend{sent: make(chan testDatagram, 8), received: make(chan testDatagram, 8), closed: make(chan struct{})}
}
func (p *packetBackend) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case packet := <-p.received:
		return copy(buffer, packet.data), packet.address, nil
	}
}
func (p *packetBackend) WriteTo(buffer []byte, address net.Addr) (int, error) {
	if udp, ok := address.(*net.UDPAddr); ok {
		address = &net.UDPAddr{IP: append(net.IP(nil), udp.IP...), Port: udp.Port}
	}
	if domain, ok := address.(*DomainAddr); ok {
		address = *domain
	}
	packet := testDatagram{append([]byte(nil), buffer...), address}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	case p.sent <- packet:
		return len(buffer), nil
	}
}
func (p *packetBackend) Close() error                     { p.once.Do(func() { close(p.closed) }); return nil }
func (p *packetBackend) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4zero} }
func (p *packetBackend) SetDeadline(time.Time) error      { return nil }
func (p *packetBackend) SetReadDeadline(time.Time) error  { return nil }
func (p *packetBackend) SetWriteDeadline(time.Time) error { return nil }

func startAssociation(t *testing.T, requested *net.UDPAddr) (net.Conn, *net.UDPAddr, *packetBackend) {
	t.Helper()
	packet := newPacketBackend()
	backend := testBackend{packet: func(context.Context) (net.PacketConn, error) { return packet, nil }}
	listener, _, _, _ := startProxy(t, "socks5", backend)
	control, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	testDeadline(t, control)
	socksGreeting(t, control, 0)
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if requested != nil {
		copy(request[4:8], requested.IP.To4())
		binary.BigEndian.PutUint16(request[8:10], uint16(requested.Port))
	}
	if _, err := control.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("UDP associate reply=%x err=%v", reply, err)
	}
	relay := &net.UDPAddr{IP: append(net.IP(nil), reply[4:8]...), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	return control, relay, packet
}

func testUDPSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return conn
}

func udpDatagram(host string, port uint16, payload string) []byte {
	packet := []byte{0, 0, 0, AtypDomain, byte(len(host))}
	packet = append(packet, host...)
	packet = binary.BigEndian.AppendUint16(packet, port)
	return append(packet, payload...)
}

func awaitDatagram(t *testing.T, packet *packetBackend) testDatagram {
	t.Helper()
	select {
	case result := <-packet.sent:
		return result
	case <-time.After(time.Second):
		t.Fatal("UDP packet not forwarded")
		return testDatagram{}
	}
}

func TestUDPDomainForwardingSourceLockAndControlLifetime(t *testing.T) {
	for _, explicitPort := range []bool{false, true} {
		t.Run(map[bool]string{false: "learn first valid source", true: "requested source port"}[explicitPort], func(t *testing.T) {
			owner := testUDPSocket(t)
			stranger := testUDPSocket(t)
			var requested *net.UDPAddr
			if explicitPort {
				requested = owner.LocalAddr().(*net.UDPAddr)
			}
			control, relay, packet := startAssociation(t, requested)
			// A malformed packet must not claim an association whose source port is unknown.
			malformed := udpDatagram("dns.example.test", 53, "fragment")
			malformed[2] = 1
			if _, err := stranger.WriteToUDP(malformed, relay); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.WriteToUDP(udpDatagram("dns.example.test", 53, "query"), relay); err != nil {
				t.Fatal(err)
			}
			sent := awaitDatagram(t, packet)
			domain, ok := sent.address.(DomainAddr)
			if !ok || domain.Host != "dns.example.test" || domain.Port != 53 || string(sent.data) != "query" {
				t.Fatalf("lost unresolved domain: %+v", sent)
			}
			if _, err := stranger.WriteToUDP(udpDatagram("dns.example.test", 53, "hijack"), relay); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.WriteToUDP(udpDatagram("dns.example.test", 53, "next"), relay); err != nil {
				t.Fatal(err)
			}
			if sent := awaitDatagram(t, packet); string(sent.data) != "next" {
				t.Fatalf("source switch accepted: %q", sent.data)
			}
			packet.received <- testDatagram{[]byte("answer"), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 53), Port: 53}}
			var buffer [128]byte
			n, _, err := owner.ReadFromUDP(buffer[:])
			if err != nil {
				t.Fatal(err)
			}
			var destination udpDestination
			address, payload, ok := destination.decode(buffer[:n])
			if !ok || address.String() != "10.0.0.53:53" || string(payload) != "answer" {
				t.Fatalf("reply %x", buffer[:n])
			}
			_ = stranger.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := stranger.ReadFromUDP(buffer[:]); err == nil {
				t.Fatal("response leaked to wrong source")
			}
			control.Close()
			select {
			case <-packet.closed:
			case <-time.After(time.Second):
				t.Fatal("TCP close did not close UDP backend")
			}
		})
	}
}

func TestUDPRejectsRequestedForeignClientAddress(t *testing.T) {
	backend := testBackend{packet: func(context.Context) (net.PacketConn, error) {
		t.Error("foreign client created UDP association")
		return nil, errors.New("unused")
	}}
	listener, _, _, _ := startProxy(t, "socks5", backend)
	control, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	testDeadline(t, control)
	socksGreeting(t, control, 0)
	request := []byte{5, 3, 0, 1, 192, 0, 2, 1, 0, 53}
	if code := socksCommand(t, control, request); code != RepAddressNotSupport {
		t.Fatalf("foreign requested address accepted: %x", code)
	}
}

func TestUDPBackendFailureClosesControlConnection(t *testing.T) {
	control, _, packet := startAssociation(t, nil)
	packet.Close()
	var one [1]byte
	if _, err := control.Read(one[:]); err == nil {
		t.Fatal("dead UDP backend left TCP control open")
	}
}

func TestUDPAssociationSetupIsBoundedWhileBackendOffline(t *testing.T) {
	backend := testBackend{packet: func(ctx context.Context) (net.PacketConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	started := time.Now()
	packet, cancel, err := openUDPAssociation(context.Background(), backend, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || packet != nil || cancel != nil {
		t.Fatalf("offline association: packet=%v cancel=%v err=%v", packet, cancel != nil, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("offline setup exceeded its budget")
	}
}

func TestUDPAssociationSuccessfulSetupRetainsContextUntilClosed(t *testing.T) {
	var association context.Context
	packet := newPacketBackend()
	var stop func() bool
	backend := testBackend{packet: func(ctx context.Context) (net.PacketConn, error) {
		association = ctx
		stop = context.AfterFunc(ctx, func() { _ = packet.Close() })
		return packet, nil
	}}
	opened, cancel, err := openUDPAssociation(context.Background(), backend, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	defer cancel()
	defer stop()
	select {
	case <-association.Done():
		t.Fatal("successful setup canceled its packet context")
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := opened.WriteTo([]byte("still open"), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 53), Port: 53}); err != nil {
		t.Fatal("setup timer closed an established association", err)
	}
	cancel()
	select {
	case <-packet.closed:
	case <-time.After(time.Second):
		t.Fatal("association close did not cancel its packet context")
	}
}

func TestUDPAssociationSetupClosesPartialSocketOnFailure(t *testing.T) {
	packet := newPacketBackend()
	backend := testBackend{packet: func(ctx context.Context) (net.PacketConn, error) {
		<-ctx.Done()
		return packet, nil
	}}
	opened, _, err := openUDPAssociation(context.Background(), backend, 10*time.Millisecond)
	if opened != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late setup accepted: %v", err)
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("late packet socket leaked")
	}
}

func TestUDPAddressParsingAndFraming(t *testing.T) {
	for _, address := range []*net.UDPAddr{
		{IP: net.IPv4(10, 0, 0, 53), Port: 53},
		{IP: net.ParseIP("2001:db8::1"), Port: 5353},
	} {
		buffer := make([]byte, 22+4)
		copy(buffer[22:], "data")
		header, ok := encodeUDPHeader(buffer[:22], address)
		if !ok {
			t.Fatal("valid source rejected")
		}
		var destination udpDestination
		target, payload, ok := destination.decode(buffer[22-header:])
		if !ok || target.String() != address.String() || string(payload) != "data" {
			t.Fatalf("round trip=%v %q %v", target, payload, ok)
		}
	}
	for _, packet := range [][]byte{
		nil, {0}, {0, 0, 0, 1}, {0, 0, 0, 3}, {0, 0, 0, 3, 255},
		{0, 0, 1, 1, 10, 0, 0, 1, 0, 53},
		{0, 1, 0, 1, 10, 0, 0, 1, 0, 53},
		{0, 0, 0, 1, 10, 0, 0, 1, 0, 0},
		{0, 0, 0, 4, 0}, {0, 0, 0, 99},
		udpDatagram("invalid/name", 53, ""),
	} {
		var destination udpDestination
		if _, _, ok := destination.decode(packet); ok {
			t.Fatalf("malformed packet accepted: %x", packet)
		}
	}
}

func FuzzUDPDatagram(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 10, 0, 0, 53, 0, 53, 1, 2, 3})
	f.Add(udpDatagram("dns.example.test", 53, "query"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		var destination udpDestination
		address, payload, ok := destination.decode(packet)
		if ok && (address == nil || len(payload) > len(packet)) {
			t.Fatal("invalid decoding")
		}
	})
}

func BenchmarkUDPDecodeIPv4(b *testing.B) {
	packet := []byte{0, 0, 0, 1, 10, 0, 0, 53, 0, 53, 1, 2, 3}
	var destination udpDestination
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, ok := destination.decode(packet); !ok {
			b.Fatal("decode")
		}
	}
}
func BenchmarkUDPEncodeHeader(b *testing.B) {
	buffer := make([]byte, 22)
	address := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 53), Port: 53}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := encodeUDPHeader(buffer, address); !ok {
			b.Fatal("encode")
		}
	}
}
