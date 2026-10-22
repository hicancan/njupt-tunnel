package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func testNetworks(tb testing.TB) (*network, *network) {
	tb.Helper()
	dns := netip.MustParseAddr("10.77.0.2")
	a, err := newNetwork(Info{Address: netip.MustParseAddr("10.77.0.1"), DNS: dns}, 1400)
	if err != nil {
		tb.Fatal(err)
	}
	b, err := newNetwork(Info{Address: dns, DNS: dns}, 1400)
	if err != nil {
		a.Close()
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	for _, pair := range [][2]*network{{a, b}, {b, a}} {
		workers.Add(1)
		go func(src, dst *network) {
			defer workers.Done()
			for {
				packet := src.link.ReadContext(ctx)
				if packet == nil {
					return
				}
				inbound := packet.CloneToInbound()
				packet.DecRef()
				dst.link.InjectInbound(ipv4.ProtocolNumber, inbound)
				inbound.DecRef()
			}
		}(pair[0], pair[1])
	}
	tb.Cleanup(func() { cancel(); a.Close(); b.Close(); workers.Wait() })
	return a, b
}

func listenTestTCP(tb testing.TB, n *network, port uint16) *gonet.TCPListener {
	tb.Helper()
	listener, err := gonet.ListenTCP(n.stack, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 77, 0, 2}), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { listener.Close() })
	return listener
}

func TestTCPBulkTransferAndHalfClose(t *testing.T) {
	client, server := testNetworks(t)
	listener := listenTestTCP(t, server, 20001)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 65536)
	checksum := sha256.Sum256(payload)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(data, payload) {
			err = errors.New("large transfer corrupted")
		}
		if err == nil {
			sum := sha256.Sum256(data)
			_, err = conn.Write(sum[:])
		}
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "10.77.0.2:20001")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeAll(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(reply, checksum[:]) {
		t.Fatalf("half-close response: %v (%d bytes)", err, len(reply))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCloseAbortsPendingDialAndRejectsSockets(t *testing.T) {
	n, err := newNetwork(Info{Address: netip.MustParseAddr("10.77.0.1"), DNS: netip.MustParseAddr("10.77.0.2")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := n.DialContext(context.Background(), "tcp", "10.77.0.2:20002")
		if err == nil && conn != nil {
			conn.Close()
		}
		if err != nil && conn != nil {
			t.Error("failed dial returned a non-nil connection")
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet := n.link.ReadContext(ctx)
	if packet == nil {
		t.Fatal("dial did not emit a SYN")
	}
	packet.DecRef()
	n.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending dial succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("network close blocked on active dial")
	}
	if _, err := n.ListenPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed network accepted UDP socket: %v", err)
	}
	if _, err := n.DialContext(context.Background(), "tcp", "10.77.0.2:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed network accepted TCP socket: %v", err)
	}
}

func TestUDPRoundTripAndNetworkShutdown(t *testing.T) {
	client, server := testNetworks(t)
	remote, err := gonet.DialUDP(server.stack, &tcpip.FullAddress{NIC: nicID, Port: 20003}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	conn, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	remote.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("a complete datagram")
	dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.77.0.2:20003"))
	if _, err = conn.WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	count, from, err := remote.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:count], payload) {
		t.Fatalf("UDP receive: %v", err)
	}
	if _, err = remote.WriteTo(buf[:count], from); err != nil {
		t.Fatal(err)
	}
	count, from, err = conn.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:count], payload) || from.String() != dst.String() {
		t.Fatalf("UDP return: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(buf); done <- err }()
	client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("UDP read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("UDP read survived network teardown")
	}
}

func BenchmarkTCPThroughput(b *testing.B) {
	client, server := testNetworks(b)
	listener := listenTestTCP(b, server, 20004)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 65536)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		for i := 0; i < b.N; i++ {
			if _, err = io.ReadFull(conn, buf); err != nil {
				done <- err
				return
			}
			if _, err = conn.Write([]byte{1}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	conn, err := client.DialContext(context.Background(), "tcp", "10.77.0.2:20004")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	var ack [1]byte
	for i := 0; i < b.N; i++ {
		if err = writeAll(conn, payload); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(conn, ack[:]); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
}
