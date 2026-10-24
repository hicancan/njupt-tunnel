package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/hicancan/sdp-tunnel/internal/captcha"
	"github.com/hicancan/sdp-tunnel/internal/config"
	"github.com/hicancan/sdp-tunnel/internal/gateway"
	"github.com/hicancan/sdp-tunnel/internal/inbound"
	"github.com/hicancan/sdp-tunnel/internal/tunnel"
)

func Run(ctx context.Context, path string, check bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cachePath := filepath.Join(filepath.Dir(path), ".session.json")
	session, err := loadSession(cachePath)
	if err != nil {
		return fmt.Errorf("read session cache (preserved): %w", err)
	}
	var reader *captcha.Recognizer
	if cfg.Captcha.Model != "" {
		if reader, err = captcha.Load(cfg.Captcha.Model); err != nil {
			return err
		}
		width, height := reader.Size()
		log.Printf("Captcha model loaded: %dx%d", width, height)
	}
	policy, err := gateway.TLSPolicy(cfg.Gateway.Host, cfg.Gateway.CAFile)
	if err != nil {
		return err
	}
	conn := connector{cfg: cfg, policy: policy, path: cachePath, session: session, persisted: session, reader: reader, check: check}
	if session != nil && cfg.Auth.Username != "" && session.Username != cfg.Auth.Username {
		conn.session = nil
	}
	connect := conn.connect
	if check {
		t, err := connect(ctx)
		if err != nil {
			return err
		}
		defer t.Close()
		log.Printf("Cached authentication and tunnel handshake passed (IPv4 %s, DNS %s). Application access needs a separate check.", t.Info().Address, t.Info().DNS)
		return nil
	}
	listeners, err := bindInbounds(cfg.Inbounds)
	if err != nil {
		return err
	}
	defer closeInbounds(listeners)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Shutdown still has to hand the address lease back, so the release runs on
	// a context that outlives the cancellation that triggered it.
	defer func() {
		release, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer done()
		conn.release(release)
	}()
	out := newOutbound()
	defer out.close()
	var workers sync.WaitGroup
	errorsCh := make(chan error, len(listeners)+1)
	var servers []interface{ Close() error }
	defer func() {
		cancel()
		for _, s := range servers {
			_ = s.Close()
		}
		workers.Wait()
	}()
	for _, bound := range listeners {
		var serve func(context.Context, net.Listener) error
		if bound.config.Type == "socks5" {
			s := inbound.NewSOCKS5Server(bound.listener.Addr().String(), out)
			servers = append(servers, s)
			serve = s.Serve
		} else {
			s := inbound.NewHTTPServer(bound.listener.Addr().String(), out)
			out.onReplace(s.DropIdleConnections)
			servers = append(servers, s)
			serve = s.Serve
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := serve(ctx, bound.listener); err != nil {
				errorsCh <- err
			}
		}()
		log.Printf("%s listening on %s", bound.config.Tag, bound.listener.Addr())
	}
	workers.Add(1)
	go func() { defer workers.Done(); errorsCh <- supervise(ctx, out, connect) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsCh:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

var healthySessionThreshold = 30 * time.Second

func supervise(ctx context.Context, out *outbound, connect func(context.Context) (*tunnel.Tunnel, error)) error {
	backoff := 500 * time.Millisecond
	for {
		started := time.Now()
		t, err := connect(ctx)
		if err == nil {
			log.Printf("Tunnel ready: IPv4 %s, DNS %s", t.Info().Address, t.Info().DNS)
			out.publish(t)
			err = t.Run(ctx)
			out.publish(nil)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var fatal fatalError
		if errors.As(err, &fatal) {
			return err
		}
		if time.Since(started) > healthySessionThreshold {
			backoff = 500 * time.Millisecond
			log.Printf("Tunnel closed after %s: %v; reconnecting immediately", time.Since(started).Round(time.Second), err)
			continue
		}
		log.Printf("Gateway unavailable: %v; retry in %s", err, backoff)
		if err := wait(ctx, backoff); err != nil {
			return err
		}
		backoff = min(backoff*2, 8*time.Second)
	}
}

type boundInbound struct {
	config   config.InboundConfig
	listener net.Listener
}

func bindInbounds(inbounds []config.InboundConfig) ([]boundInbound, error) {
	var bound []boundInbound
	for _, inbound := range inbounds {
		listener, err := net.Listen("tcp", net.JoinHostPort(inbound.Listen, strconv.Itoa(inbound.Port)))
		if err != nil {
			closeInbounds(bound)
			return nil, fmt.Errorf("listen %s: %w", inbound.Tag, err)
		}
		bound = append(bound, boundInbound{inbound, listener})
	}
	return bound, nil
}
func closeInbounds(bound []boundInbound) {
	for _, b := range bound {
		_ = b.listener.Close()
	}
}
