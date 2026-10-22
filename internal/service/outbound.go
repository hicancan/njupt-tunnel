package service

import (
	"context"
	"net"
	"sync"

	"github.com/hicancan/njupt-tunnel/internal/tunnel"
)

// outbound is the only mutable pointer to the live tunnel. Inbounds dial
// through it; a dial made while offline waits on a broadcast channel with its
// own context, and data is never queued for replay.
type outbound struct {
	mu       sync.RWMutex
	current  *tunnel.Tunnel
	changed  chan struct{}
	closed   bool
	replaced []func()
}

func newOutbound() *outbound { return &outbound{changed: make(chan struct{})} }

// onReplace registers work to run after the live tunnel is swapped. Inbounds
// use it to drop connections they pooled against the tunnel that just died.
func (o *outbound) onReplace(drop func()) {
	o.mu.Lock()
	o.replaced = append(o.replaced, drop)
	o.mu.Unlock()
}

func (o *outbound) publish(t *tunnel.Tunnel) {
	o.mu.Lock()
	o.current = t
	close(o.changed)
	o.changed = make(chan struct{})
	replaced := o.replaced
	o.mu.Unlock()
	// Anything pooled against the previous tunnel is now a dead socket, and
	// handing one to a caller looks like a failed request rather than a
	// reconnect. Drop them before the next dial can pick one up.
	for _, drop := range replaced {
		drop()
	}
}

func (o *outbound) close() {
	o.mu.Lock()
	o.closed = true
	close(o.changed)
	o.mu.Unlock()
}

func (o *outbound) get(ctx context.Context) (*tunnel.Tunnel, error) {
	for {
		o.mu.RLock()
		t, changed, closed := o.current, o.changed, o.closed
		o.mu.RUnlock()
		if closed {
			return nil, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if t != nil {
			return t, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (o *outbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t, err := o.get(ctx)
	if err != nil {
		return nil, err
	}
	return t.DialContext(ctx, network, address)
}

func (o *outbound) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	t, err := o.get(ctx)
	if err != nil {
		return nil, err
	}
	return t.ListenPacket(ctx)
}
