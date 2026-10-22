package inbound

import (
	"context"
	"errors"
	"net"
	"sync"
)

const maxConnections = 1024

// The listener owns every accepted connection, including hijacked HTTP tunnels.
// Closing it cancels pending dials and closes established streams and UDP relays.
type serverLifecycle struct {
	mu       sync.Mutex
	listener net.Listener
	active   map[*trackedConn]struct{}
	closed   bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func (s *serverLifecycle) begin(ctx context.Context, listener net.Listener) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed || s.listener != nil {
		s.mu.Unlock()
		_ = listener.Close()
		return nil, nil, errors.New("proxy server has already been started or closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.listener, s.cancel = listener, cancel
	s.active = make(map[*trackedConn]struct{})
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.close() })
	return ctx, func() { stop(); _ = s.close(); s.wg.Wait() }, nil
}

func (s *serverLifecycle) track(ctx context.Context, conn net.Conn) (*trackedConn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.active) == maxConnections {
		_ = conn.Close()
		return nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedConn{Conn: conn, ctx: ctx, cancel: cancel, lifecycle: s}
	s.active[tracked] = struct{}{}
	s.wg.Add(1)
	return tracked, true
}

func (s *serverLifecycle) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener, cancel := s.listener, s.cancel
	connections := make([]*trackedConn, 0, len(s.active))
	for conn := range s.active {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if listener != nil {
		err = listener.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type trackedConn struct {
	net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	lifecycle *serverLifecycle
	once      sync.Once
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.Conn.Close()
		c.lifecycle.mu.Lock()
		delete(c.lifecycle.active, c)
		c.lifecycle.mu.Unlock()
		c.lifecycle.wg.Done()
	})
	return err
}

type trackedListener struct {
	net.Listener
	ctx       context.Context
	lifecycle *serverLifecycle
}

func (l trackedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if tracked, ok := l.lifecycle.track(l.ctx, conn); ok {
			return tracked, nil
		}
	}
}
