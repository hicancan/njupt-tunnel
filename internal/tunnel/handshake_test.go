package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handshakeAttributes mirrors the attribute set a real gateway returns, so the
// parser is exercised against the tags it actually meets. Only 0x0b and 0x0c
// are consumed; 0x24 carries a loopback address and is never the tunnel DNS.
func handshakeAttributes() []byte {
	body := []byte{
		0x0b, 0, 4, 10, 77, 0, 1, // virtual IPv4 10.77.0.1
		0x0c, 0, 4, 0xff, 0xff, 0, 0, // netmask 255.255.0.0
		0x23, 0, 4, 1, 1, 1, 1, // tunnel peer
		0x2b, 0, 1, 0, // single-byte flag of unknown meaning
		0x24, 0, 9, // DNS attribute: loopback, deliberately ignored
	}
	body = append(body, []byte("127.0.0.1")...)
	return append(body, 0xff)
}

func authReply(body []byte) []byte {
	frame := make([]byte, 12+len(body))
	frame[0], frame[1] = 1, 2
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	frame[8] = 1
	copy(frame[12:], body)
	return frame
}

func TestAuthenticationExactWireAndPartialIO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	server.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		request := make([]byte, 12+7+len("alice01")+len("secret-token"))
		if _, err := io.ReadFull(server, request); err != nil {
			done <- err
			return
		}
		want := []byte{1, 1, 0, 38, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 7}
		want = append(want, []byte("alice01")...)
		want = append(want, 2, 0, 12)
		want = append(want, []byte("secret-token")...)
		want = append(want, 0xff)
		if !bytes.Equal(request, want) {
			done <- errors.New("authentication wire format changed")
			return
		}
		for _, b := range authReply(handshakeAttributes()) {
			if _, err := server.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	info, err := authenticate(client, "alice01", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if info.Address != netip.MustParseAddr("10.77.0.1") || info.DNS.IsValid() {
		t.Fatal("incorrect assigned network")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRejectsMalformedHandshakeAndInvalidCredentials(t *testing.T) {
	valid := authReply(handshakeAttributes())
	badVersion := append([]byte(nil), valid...)
	badVersion[0] = 2
	badKind := append([]byte(nil), valid...)
	badKind[1] = 4
	badSize := append([]byte(nil), valid...)
	badSize[2], badSize[3] = 0, 8
	for _, reply := range [][]byte{badVersion, badKind, badSize, authReply([]byte{0x0b, 0, 4, 10}), authReply([]byte{0xff})} {
		client, server := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		server.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			var hdr [12]byte
			if _, err := io.ReadFull(server, hdr[:]); err != nil {
				return
			}
			body := make([]byte, int(binary.BigEndian.Uint16(hdr[2:4]))-12)
			if _, err := io.ReadFull(server, body); err != nil {
				return
			}
			server.Write(reply)
		}()
		if _, err := authenticate(client, "alice01", "secret-token"); err == nil {
			t.Error("malformed handshake accepted")
		}
		client.Close()
		<-done
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	for _, credentials := range [][2]string{{"", "token"}, {"alice01", ""}, {"alice01", strings.Repeat("x", 256)}, {strings.Repeat("x", 256), "token"}} {
		if _, err := authenticate(client, credentials[0], credentials[1]); err == nil {
			t.Fatal("invalid credential lengths accepted")
		}
	}
}

func TestParseInfoRequiresVIPButAllowsControllerDNS(t *testing.T) {
	for _, body := range [][]byte{
		nil,
		{0xff},
		{0x0b},
		{0x0b, 0, 5, 10, 77, 0, 1},
		{0x0b, 0, 3, 10, 77, 0},
		{0xff, 1},
		{0x0b, 0, 4, 10, 77, 0, 1, 0xff}, // no netmask attribute
		{0x0b, 0, 4, 10, 77, 0, 1, 0x0c, 0, 4, 0xff, 0, 0xff, 0, 0xff}, // non-contiguous mask
		{0x0b, 0, 4, 10, 77, 0, 1, 0x0c, 0, 4, 0, 0, 0, 0, 0xff},       // /0 is not usable
	} {
		if _, err := parseInfo(body); err == nil {
			t.Fatalf("invalid network attributes accepted: % x", body)
		}
	}
	info, err := parseInfo(handshakeAttributes())
	if err != nil || info.Address != netip.MustParseAddr("10.77.0.1") || info.PrefixLen != 16 || info.DNS.IsValid() {
		t.Fatalf("tunnel assignment must take the gateway netmask and leave DNS to controller policy: %+v %v", info, err)
	}
}

func TestTunnelRunStopsBothWorkers(t *testing.T) {
	for _, mode := range []string{"context cancellation", "peer EOF", "malformed frame"} {
		t.Run(mode, func(t *testing.T) {
			n, err := newNetwork(Info{Address: netip.MustParseAddr("10.77.0.1"), DNS: netip.MustParseAddr("10.77.0.2")}, 1400)
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			tun := &Tunnel{conn: client, network: n}
			defer tun.Close()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tun.Run(ctx) }()
			switch mode {
			case "context cancellation":
				cancel()
			case "peer EOF":
				server.Close()
			case "malformed frame":
				server.Write([]byte{2, 4, 0, 8, 0, 0, 0, 0})
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("failed tunnel exited without an error")
				}
				if mode == "context cancellation" && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation cause: %v", err)
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("tunnel left an I/O worker blocked")
			}
			if _, err := tun.ListenPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
				t.Fatal("tunnel teardown left network live")
			}
		})
	}
}

type shortWriter struct {
	bytes.Buffer
	size int
}

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > w.size {
		b = b[:w.size]
	}
	return w.Buffer.Write(b)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{size: 3}
	payload := []byte("a frame split across writes")
	if err := writeAll(writer, payload); err != nil || !bytes.Equal(writer.Bytes(), payload) {
		t.Fatal("short writes lost data")
	}
	if err := writeAll(zeroWriter{}, payload); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("zero-progress writer spun")
	}
}

// testGateway replaces only the TLS byte transport with net.Pipe. Packet
// framing and both TCP/IP stacks remain the same as the production data path.
func testGateway(tb testing.TB) (*Tunnel, *network) {
	tb.Helper()
	dns := netip.MustParseAddr("10.77.0.2")
	client, err := newNetwork(Info{Address: netip.MustParseAddr("10.77.0.1"), DNS: dns}, 1400)
	if err != nil {
		tb.Fatal(err)
	}
	server, err := newNetwork(Info{Address: dns, DNS: dns}, 1400)
	if err != nil {
		client.Close()
		tb.Fatal(err)
	}
	wire, peer := net.Pipe()
	tun := &Tunnel{conn: wire, network: client}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); tun.Run(ctx) }()
	go func() {
		defer workers.Done()
		defer peer.Close()
		for {
			var header [12]byte
			if _, err := io.ReadFull(peer, header[:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(header[2:4]))
			if header[0] != 1 || size < 12 {
				tb.Error("invalid outbound tunnel frame")
				return
			}
			body := make([]byte, size-12)
			if _, err := io.ReadFull(peer, body); err != nil {
				return
			}
			if header[1] == 3 {
				continue
			}
			if header[1] != 4 {
				tb.Error("invalid outbound tunnel frame kind")
				return
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(body)})
			server.link.InjectInbound(ipv4.ProtocolNumber, packet)
			packet.DecRef()
		}
	}()
	go func() {
		defer workers.Done()
		for {
			packet := server.link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			packet.DecRef()
			frame := make([]byte, 8+view.Size())
			frame[0], frame[1] = 1, 4
			binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
			copy(frame[8:], view.AsSlice())
			view.Release()
			if err := writeAll(peer, frame); err != nil {
				return
			}
		}
	}()
	tb.Cleanup(func() { cancel(); tun.Close(); peer.Close(); server.Close(); workers.Wait() })
	return tun, server
}

func TestFramedTCPDataPath(t *testing.T) {
	tun, server := testGateway(t)
	listener := listenTestTCP(t, server, 20100)
	payload := bytes.Repeat([]byte("framed payload"), 50000)
	sum := sha256.Sum256(payload)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		body, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(body, payload) {
			err = errors.New("framed transfer corrupted")
		}
		if err == nil {
			_, err = conn.Write(sum[:])
		}
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tun.DialContext(ctx, "tcp", "10.77.0.2:20100")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeAll(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(reply, sum[:]) {
		t.Fatalf("tunnel data/half-close failed: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkFramedTCPThroughput(b *testing.B) {
	tun, server := testGateway(b)
	listener := listenTestTCP(b, server, 20101)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 65536)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		body := make([]byte, len(payload))
		for i := 0; i < b.N; i++ {
			if _, err = io.ReadFull(conn, body); err != nil {
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
	conn, err := tun.DialContext(context.Background(), "tcp", "10.77.0.2:20101")
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

func BenchmarkEncodePacket(b *testing.B) {
	payload := make([]byte, 1400)
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
	defer packet.DecRef()
	destination := make([]byte, 1412)
	b.SetBytes(1400)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if size := encodePacket(destination, packet); size != 1412 {
			b.Fatal("incorrect tunnel frame size")
		}
	}
}
