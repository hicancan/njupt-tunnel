package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	heartbeatInterval = 12 * time.Second
	frameReadTimeout  = 10 * time.Second
	writeTimeout      = 10 * time.Second
	batchSize         = 64 * 1024
)

// Tunnel has exactly one TLS reader and one TLS writer. Heartbeats share the
// writer, and packet bursts are encoded into one reusable bounded batch.
type Tunnel struct {
	conn      net.Conn
	network   *network
	info      Info
	closeOnce sync.Once
}

func (t *Tunnel) Info() Info { return t.info }
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.network.DialContext(ctx, network, address)
}
func (t *Tunnel) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return t.network.ListenPacket(ctx)
}

func (t *Tunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.conn.Close()
		t.network.Close()
	})
	return err
}

// Run returns after both I/O workers have stopped and all sockets are aborted.
// A caller may then publish a new generation with a different virtual IP.
func (t *Tunnel) Run(ctx context.Context) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = t.Close() })
	defer stop()
	done := make(chan error, 2)
	go func() { done <- t.readLoop() }()
	go func() { done <- t.writeLoop(ctx) }()
	err := <-done
	cancel()
	_ = t.Close()
	<-done
	if parent.Err() != nil {
		return parent.Err()
	}
	return err
}

func (t *Tunnel) readLoop() error {
	reader := bufio.NewReaderSize(t.conn, 64*1024)
	var hdr [rxHeaderSize]byte
	for {
		// Keepalives are one-way on this gateway. A healthy idle connection
		// need not send any frames; bound partial frames, not idle time.
		first, err := reader.ReadByte()
		if err != nil {
			return err
		}
		hdr[0] = first
		bounded := reader.Buffered() < rxHeaderSize-1
		if bounded {
			_ = t.conn.SetReadDeadline(time.Now().Add(frameReadTimeout))
		}
		if _, err := io.ReadFull(reader, hdr[1:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(hdr[2:4]))
		if hdr[0] != 1 || size < rxHeaderSize {
			return errors.New("invalid gateway frame header")
		}
		view := buffer.NewViewSize(size - rxHeaderSize)
		if !bounded && reader.Buffered() < view.Size() {
			bounded = true
			_ = t.conn.SetReadDeadline(time.Now().Add(frameReadTimeout))
		}
		if _, err := io.ReadFull(reader, view.AsSlice()); err != nil {
			view.Release()
			return err
		}
		if bounded {
			_ = t.conn.SetReadDeadline(time.Time{})
		}
		if hdr[1] == typeIPv4 {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(view)})
			t.network.link.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
		} else {
			// The gateway sends no control frames of its own: measured across a
			// full connection lifetime, including the moment it hangs up.
			view.Release()
		}
	}
}

func (t *Tunnel) writeLoop(ctx context.Context) error {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	batch := make([]byte, batchSize)
	var heartbeat [txHeaderSize]byte
	encodeHeader(heartbeat[:], typeHeartbeat, len(heartbeat))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := writeAll(t.conn, heartbeat[:]); err != nil {
				return err
			}
		case <-t.network.notify:
			used := 0
			for count := 0; count < 32; count++ {
				pkt := t.network.link.Read()
				if pkt == nil {
					break
				}
				size := txHeaderSize + pkt.Size()
				if size > maxFrameSize {
					pkt.DecRef()
					return errors.New("outbound IP packet exceeds the tunnel frame limit")
				}
				if used+size > len(batch) {
					_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
					if err := writeAll(t.conn, batch[:used]); err != nil {
						pkt.DecRef()
						return err
					}
					used = 0
				}
				used += encodePacket(batch[used:], pkt)
				pkt.DecRef()
			}
			if used > 0 {
				_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err := writeAll(t.conn, batch[:used]); err != nil {
					return err
				}
			}
			if t.network.link.NumQueued() > 0 {
				t.network.WriteNotify()
			}
		}
	}
}

func encodePacket(dst []byte, pkt *stack.PacketBuffer) int {
	size := txHeaderSize + pkt.Size()
	encodeHeader(dst, typeIPv4, size)
	views, offset := pkt.AsViewList()
	pos := txHeaderSize
	for view := views.Front(); view != nil; view = view.Next() {
		data := view.AsSlice()
		if offset >= len(data) {
			offset -= len(data)
			continue
		}
		pos += copy(dst[pos:], data[offset:])
		offset = 0
	}
	return size
}
