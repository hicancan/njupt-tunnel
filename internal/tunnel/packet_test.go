package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type packetDomain string

func (a packetDomain) Network() string { return "udp" }
func (a packetDomain) String() string  { return string(a) }

type pendingPacketWrite struct {
	conn   net.PacketConn
	dns    *gonet.UDPConn
	query  []byte
	source net.Addr
	done   <-chan error
}

// Read the actual DNS query from the peer stack but withhold its response.
// No mock resolver or wall-clock guess is needed to know WriteTo is resolving.
func startPendingPacketWrite(t *testing.T, ctx context.Context) pendingPacketWrite {
	t.Helper()
	client, server := testNetworks(t)
	dns, err := gonet.DialUDP(server.stack, &tcpip.FullAddress{NIC: nicID, Port: 53}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dns.Close() })
	conn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	done := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("payload"), packetDomain("blocked.example.test:12345"))
		done <- err
	}()
	dns.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 4096)
	n, source, err := dns.ReadFrom(buffer)
	if err != nil {
		t.Fatal("WriteTo did not begin DNS exchange", err)
	}
	return pendingPacketWrite{conn: conn, dns: dns, query: buffer[:n], source: source, done: done}
}

func awaitPacketWrite(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("WriteTo remained blocked in DNS")
		return nil
	}
}

func TestPacketWriteDNSHonorsCloseCancellationAndMovedDeadline(t *testing.T) {
	for _, action := range []string{"Close", "Cancel", "SetDeadline", "SetWriteDeadline"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pending := startPendingPacketWrite(t, ctx)
			switch action {
			case "Close":
				pending.conn.Close()
			case "Cancel":
				cancel()
			case "SetDeadline":
				if err := pending.conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
			case "SetWriteDeadline":
				if err := pending.conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			err := awaitPacketWrite(t, pending.done)
			switch action {
			case "Close":
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Close error=%v", err)
				}
			case "Cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel error=%v", err)
				}
			default:
				timeout, ok := err.(net.Error)
				if !ok || !timeout.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline error=%v", err)
				}
			}
		})
	}
}

func TestPacketWriteDNSCanExtendAndClearDeadline(t *testing.T) {
	for _, clearDeadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "extend", true: "clear"}[clearDeadline], func(t *testing.T) {
			pending := startPendingPacketWrite(t, context.Background())
			if err := pending.conn.SetWriteDeadline(time.Now().Add(60 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			if clearDeadline {
				deadline = time.Time{}
			}
			if err := pending.conn.SetWriteDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-pending.done:
				t.Fatalf("deadline change aborted DNS: %v", err)
			case <-time.After(120 * time.Millisecond):
			}
			var query dnsmessage.Message
			if err := query.Unpack(pending.query); err != nil {
				t.Fatal(err)
			}
			reply := dnsAnswer(query, 30)
			wire, err := reply.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pending.dns.WriteTo(wire, pending.source); err != nil {
				t.Fatal(err)
			}
			if err := awaitPacketWrite(t, pending.done); err != nil {
				t.Fatalf("updated deadline lost DNS result: %v", err)
			}
		})
	}
}

func TestPacketContextCancellationClosesPendingRead(t *testing.T) {
	client, _ := testNetworks(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 32)); done <- err }()
	cancel()
	if err := awaitPacketWrite(t, done); err == nil {
		t.Fatal("canceled packet read succeeded")
	}
}

func TestPacketExpiredDeadlineRejectsIPAndClearingRestoresWrites(t *testing.T) {
	client, _ := testNetworks(t)
	conn, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:12345"))
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("payload"), target); err == nil {
		t.Fatal("expired IP write succeeded")
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("payload"), target); err != nil {
		t.Fatal("cleared deadline still rejected IP", err)
	}
}

func BenchmarkPacketWriteIP(b *testing.B) {
	client, server := testNetworks(b)
	remote, err := gonet.DialUDP(server.stack, &tcpip.FullAddress{NIC: nicID, Port: 12345}, nil, ipv4.ProtocolNumber)
	if err != nil {
		b.Fatal(err)
	}
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buffer [32]byte
		for {
			if _, _, err := remote.ReadFrom(buffer[:]); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() { remote.Close(); <-done })
	conn, err := client.ListenPacket(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("payload")
	target := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:12345"))
	for _, tc := range []struct {
		name string
		conn net.PacketConn
	}{
		{"underlying", conn.(*packetConn).UDPConn}, {"wrapper", conn},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := tc.conn.WriteTo(payload, target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
