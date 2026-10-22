package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Dialer carries both proxy protocols over the same authenticated network.
// PacketConn.WriteTo accepts UDPAddr and DomainAddr; domains are resolved by
// the backend, using the same DNS policy as DialContext.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
}

// DomainAddr preserves the destination hostname until it reaches the backend.
type DomainAddr struct {
	Host string
	Port int
}

func (a DomainAddr) Network() string { return "udp" }
func (a DomainAddr) String() string  { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

const handshakeTimeout = 10 * time.Second

func dialTCP(ctx context.Context, backend Dialer, destination endpoint) (net.Conn, error) {
	if backend == nil {
		return nil, errors.New("tunnel backend is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := backend.DialContext(ctx, "tcp", destination.authority())
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			err = errors.New("backend returned no connection")
		}
		return nil, fmt.Errorf("dial tunnel destination: %w", err)
	}
	return conn, nil
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

type relayBuffer struct {
	data [32 << 10]byte
	readerOnly
	writerOnly
}

var relayBuffers = sync.Pool{New: func() any { return new(relayBuffer) }}

func copyStream(dst io.Writer, src io.Reader) error {
	buffer := relayBuffers.Get().(*relayBuffer)
	buffer.Reader, buffer.Writer = src, dst
	// The backend is a userspace connection: socket splice cannot cross it.
	// Bypass optional Copy methods so both directions reuse bounded buffers.
	_, err := io.CopyBuffer(&buffer.writerOnly, &buffer.readerOnly, buffer.data[:])
	buffer.Reader, buffer.Writer = nil, nil
	relayBuffers.Put(buffer)
	return err
}

func closeWrite(conn net.Conn) {
	if tracked, ok := conn.(*trackedConn); ok {
		conn = tracked.Conn
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}

// EOF closes only the opposite write direction. An error or cancellation closes
// both sockets. Established tunnels have no arbitrary inactivity deadline.
func relayTCP(ctx context.Context, client net.Conn, reader io.Reader, upstream net.Conn) {
	closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{})
	copyDirection := func(dst net.Conn, src io.Reader) {
		if err := copyStream(dst, src); err != nil {
			closeBoth()
		} else {
			closeWrite(dst)
		}
	}
	go func() {
		defer close(done)
		if buffered, ok := reader.(*bufio.Reader); ok {
			// Hijack's reader wraps net/http's connection reader, which cancels
			// the request on EOF. Drain read-ahead, then use the socket directly
			// so a TCP FIN remains a half-close instead of canceling the tunnel.
			if _, err := io.CopyN(upstream, buffered, int64(buffered.Buffered())); err != nil {
				closeBoth()
				return
			}
			reader = client
		}
		copyDirection(upstream, reader)
	}()
	copyDirection(client, upstream)
	<-done
}
