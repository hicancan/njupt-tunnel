package service

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hicancan/sdp-tunnel/internal/config"
	"github.com/hicancan/sdp-tunnel/internal/gateway"
	"github.com/hicancan/sdp-tunnel/internal/tunnel"
)

type validatorFunc func(context.Context, *gateway.Session) (*gateway.Session, error)

func (f validatorFunc) ValidateSession(ctx context.Context, s *gateway.Session) (*gateway.Session, error) {
	return f(ctx, s)
}

func TestSessionValidationPreservesCacheOnFailure(t *testing.T) {
	session := &gateway.Session{Username: "alice", Token: "token", UserID: "id", Cookie: "SID=session", CreatedAt: time.Now()}
	path := filepath.Join(t.TempDir(), ".session.json")
	if err := session.Save(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, cause := range []error{gateway.ErrSessionInvalid, errors.New("network outage"), context.DeadlineExceeded} {
		got, err := validateSession(context.Background(), validatorFunc(func(context.Context, *gateway.Session) (*gateway.Session, error) { return nil, cause }), session)
		if got != nil {
			t.Fatal("rejected session reused")
		}
		if errors.Is(cause, gateway.ErrSessionInvalid) {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, cause) {
			t.Fatalf("error lost: %v", err)
		}
		after, readErr := os.ReadFile(path)
		if readErr != nil || string(before) != string(after) {
			t.Fatal("validation changed persisted credentials")
		}
	}
}

func TestBackendOfflineDialsCancelAndClose(t *testing.T) {
	out := newOutbound()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	conn, err := out.DialContext(ctx, "tcp", "10.0.0.1:80")
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("offline dial: %v, %v", conn, err)
	}
	done := make(chan error, 1)
	go func() { _, err := out.ListenPacket(context.Background()); done <- err }()
	out.close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("offline association leaked")
	}
}

func TestSupervisorStopsOnPermanentRejection(t *testing.T) {
	out := newOutbound()
	defer out.close()
	calls := 0
	err := supervise(context.Background(), out, func(context.Context) (*tunnel.Tunnel, error) {
		calls++
		return nil, fatalError{gateway.ErrLoginRejected}
	})
	if calls != 1 || err == nil {
		t.Fatalf("permanent rejection retried %d times: %v", calls, err)
	}
}

func TestSupervisorBackoffCancels(t *testing.T) {
	out := newOutbound()
	defer out.close()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := supervise(ctx, out, func(context.Context) (*tunnel.Tunnel, error) { calls++; cancel(); return nil, errors.New("offline") })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor: %d %v", calls, err)
	}
}

func TestSupervisorImmediateReconnectOnHealthySession(t *testing.T) {
	origThreshold := healthySessionThreshold
	healthySessionThreshold = 20 * time.Millisecond
	defer func() { healthySessionThreshold = origThreshold }()

	out := newOutbound()
	defer out.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	calls := 0
	var firstDone time.Time
	var secondStart time.Time

	err := supervise(ctx, out, func(ctx context.Context) (*tunnel.Tunnel, error) {
		calls++
		if calls == 1 {
			// Simulate a healthy session that runs longer than healthySessionThreshold
			time.Sleep(30 * time.Millisecond)
			firstDone = time.Now()
			return nil, errors.New("healthy tunnel closed with EOF")
		}
		secondStart = time.Now()
		cancel()
		return nil, errors.New("supervisor done")
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	gap := secondStart.Sub(firstDone)
	// Gap should be near-zero (< 100ms), NOT the default 500ms backoff
	if gap > 150*time.Millisecond {
		t.Fatalf("expected immediate reconnect without 500ms backoff, took %v", gap)
	}
}

func TestBindInboundsRollsBackOnFailure(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, err = bindInbounds([]config.InboundConfig{{Type: "socks5", Listen: "127.0.0.1", Port: port}, {Type: "http", Listen: "127.0.0.1", Port: occupied.Addr().(*net.TCPAddr).Port}})
	if err == nil {
		t.Fatal("occupied port accepted")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal("listener leaked", err)
	}
	listener.Close()
}
