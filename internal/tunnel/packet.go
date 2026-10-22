package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// packetConn adds tunnel-side domain resolution at the socket boundary; the proxy
// adapter never resolves a target on the host network.
type packetConn struct {
	*gonet.UDPConn
	network     *network
	ctx         context.Context
	cancel      context.CancelCauseFunc
	stop        func() bool
	mu          sync.Mutex
	writeCtx    context.Context
	writeCancel context.CancelFunc
}

func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := context.Cause(c.ctx); err != nil {
		return 0, err
	}
	if addr == nil {
		return 0, errors.New("missing UDP destination")
	}
	// The common IP path never needs a DNS context, goroutine, or address copy.
	if target, ok := addr.(*net.UDPAddr); ok {
		if target == nil || target.Port < 1 || target.Port > 65535 || target.IP.To4() == nil {
			return 0, errors.New("invalid IPv4 UDP destination")
		}
		return c.UDPConn.WriteTo(b, target)
	}
	host, port, err := splitDestination(addr.String())
	if err != nil {
		return 0, err
	}
	for {
		c.mu.Lock()
		ctx := c.writeCtx
		c.mu.Unlock()
		ip, err := c.network.dns.resolve(ctx, host)
		if err == nil {
			return c.UDPConn.WriteTo(b, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
		}
		if cause := context.Cause(c.ctx); cause != nil {
			return 0, cause
		}
		c.mu.Lock()
		current := c.writeCtx == ctx
		c.mu.Unlock()
		if !current {
			// A moved or cleared deadline cancels the old wait, not the DNS
			// exchange shared with other callers. Rejoin with the new deadline.
			continue
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: os.ErrDeadlineExceeded}
		}
		return 0, err
	}
}

func (c *packetConn) Close() error {
	c.cancel(net.ErrClosed)
	c.stop()
	return c.UDPConn.Close()
}

func (c *packetConn) SetDeadline(deadline time.Time) error {
	return c.setWriteDeadline(deadline, true)
}

func (c *packetConn) SetWriteDeadline(deadline time.Time) error {
	return c.setWriteDeadline(deadline, false)
}

func (c *packetConn) setWriteDeadline(deadline time.Time, both bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return net.ErrClosed
	}
	var err error
	if both {
		err = c.UDPConn.SetDeadline(deadline)
	} else {
		err = c.UDPConn.SetWriteDeadline(deadline)
	}
	if err != nil {
		return err
	}
	previous := c.writeCancel
	if deadline.IsZero() {
		c.writeCtx, c.writeCancel = context.WithCancel(c.ctx)
	} else {
		c.writeCtx, c.writeCancel = context.WithDeadline(c.ctx, deadline)
	}
	if previous != nil {
		previous()
	}
	return nil
}
