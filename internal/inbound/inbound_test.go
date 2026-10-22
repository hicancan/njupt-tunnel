package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testBackend struct {
	dial   func(context.Context, string, string) (net.Conn, error)
	packet func(context.Context) (net.PacketConn, error)
}

func (b testBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if b.dial == nil {
		return nil, errors.New("dial unavailable")
	}
	return b.dial(ctx, network, address)
}
func (b testBackend) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if b.packet == nil {
		return nil, errors.New("UDP unavailable")
	}
	return b.packet(ctx)
}

func testDeadline(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

func runSOCKSConnection(t *testing.T, backend Dialer) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		NewSOCKS5Server("127.0.0.1:0", backend).handleConnection(context.Background(), server)
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS handler did not exit")
		}
	})
	testDeadline(t, client)
	return client
}

func socksGreeting(t *testing.T, conn net.Conn, methods ...byte) byte {
	t.Helper()
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatal(err)
	}
	if response[0] != 5 {
		t.Fatalf("greeting: %x", response)
	}
	return response[1]
}

func domainCommand(host string, port uint16) []byte {
	command := append([]byte{5, CmdConnect, 0, AtypDomain, byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(command, port)
}

func socksCommand(t *testing.T, conn net.Conn, command []byte) byte {
	t.Helper()
	go func() { _, _ = conn.Write(command) }()
	var response [10]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatal(err)
	}
	return response[1]
}

func TestSOCKSNegotiationAndValidation(t *testing.T) {
	for _, tc := range []struct {
		methods []byte
		want    byte
	}{
		{[]byte{0}, 0}, {[]byte{2, 0}, 0}, {[]byte{2}, 255}, {nil, 255},
	} {
		conn := runSOCKSConnection(t, nil)
		if got := socksGreeting(t, conn, tc.methods...); got != tc.want {
			t.Fatalf("methods %x: %x", tc.methods, got)
		}
	}
	for _, tc := range []struct {
		name    string
		request []byte
		want    byte
	}{
		{"version", []byte{4, 1, 0, 1}, RepServerFailure},
		{"reserved", []byte{5, 1, 1, 1}, RepServerFailure},
		{"BIND", []byte{5, 2, 0, 1}, RepCommandNotSupport},
		{"address type", []byte{5, 1, 0, 9}, RepAddressNotSupport},
		{"empty domain", domainCommand("", 80), RepAddressNotSupport},
		{"invalid domain", domainCommand("x/y", 80), RepAddressNotSupport},
		{"zero port", domainCommand("intranet.test", 0), RepAddressNotSupport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := runSOCKSConnection(t, testBackend{})
			socksGreeting(t, conn, 0)
			if got := socksCommand(t, conn, tc.request); got != tc.want {
				t.Fatalf("reply=%x want=%x", got, tc.want)
			}
		})
	}
}

func startProxy(t *testing.T, kind string, backend Dialer) (net.Listener, context.CancelFunc, func() error, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var serve func(context.Context, net.Listener) error
	var closeServer func() error
	if kind == "http" {
		server := NewHTTPServer(listener.Addr().String(), backend)
		serve, closeServer = server.Serve, server.Close
	} else {
		server := NewSOCKS5Server(listener.Addr().String(), backend)
		serve, closeServer = server.Serve, server.Close
	}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = closeServer()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy Serve did not exit")
		}
	})
	return listener, cancel, closeServer, done
}

func TestTunnelsPreserveBufferedPayloadAndHalfClose(t *testing.T) {
	for _, kind := range []string{"socks5", "http"} {
		t.Run(kind, func(t *testing.T) {
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			originDone := make(chan error, 1)
			go func() {
				conn, err := origin.Accept()
				if err != nil {
					originDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload, err := io.ReadAll(conn)
				if err == nil && string(payload) != "buffered payload" {
					err = fmt.Errorf("payload=%q", payload)
				}
				if err == nil {
					_, err = conn.Write([]byte("reply after client FIN"))
				}
				if err == nil {
					err = conn.(*net.TCPConn).CloseWrite()
				}
				originDone <- err
			}()
			backend := testBackend{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "intranet.test:8443" {
					return nil, fmt.Errorf("target=%s %s", network, address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, origin.Addr().String())
			}}
			listener, _, _, _ := startProxy(t, kind, backend)
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			testDeadline(t, client)
			reader := bufio.NewReader(client)
			if kind == "socks5" {
				socksGreeting(t, client, 0)
				command := append(domainCommand("intranet.test", 8443), []byte("buffered payload")...)
				if _, err := client.Write(command); err != nil {
					t.Fatal(err)
				}
				var reply [10]byte
				if _, err := io.ReadFull(reader, reply[:]); err != nil || reply[1] != 0 {
					t.Fatalf("SOCKS reply=%x err=%v", reply, err)
				}
			} else {
				if _, err := io.WriteString(client, "CONNECT intranet.test:8443 HTTP/1.1\r\nHost: intranet.test:8443\r\n\r\nbuffered payload"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
				if err != nil || response.StatusCode != 200 {
					t.Fatalf("CONNECT response=%v err=%v", response, err)
				}
			}
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(reader)
			if err != nil || string(response) != "reply after client FIN" {
				t.Fatalf("response=%q err=%v", response, err)
			}
			if err := <-originDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPForwardStreamsAndReusesConnections(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != "payload" || r.URL.RequestURI() != "/submit?q=x%2Fy" || r.Header.Get("X-App") != "kept" {
			t.Errorf("request body=%q URL=%s headers=%v", body, r.URL.RequestURI(), r.Header)
		}
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("proxy headers reached origin")
		}
		w.Header().Set("Connection", "X-Private")
		w.Header().Set("X-Private", "remove")
		w.Header().Set("X-App", "kept")
		w.Header().Set("Trailer", "X-End")
		_, _ = io.WriteString(w, "streamed reply")
		w.Header().Set("X-End", "trailer")
	}))
	defer origin.Close()
	var dials atomic.Int32
	backend := testBackend{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	server := NewHTTPServer("127.0.0.1:8080", backend)
	defer server.Close()
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest("POST", origin.URL+"/submit?q=x%2Fy", strings.NewReader("payload"))
		request.Header.Set("Proxy-Authorization", "secret")
		request.Header.Set("Connection", "X-Hop")
		request.Header.Set("X-Hop", "remove")
		request.Header.Set("X-App", "kept")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		response := recorder.Result()
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "streamed reply" || response.Header.Get("X-Private") != "" || response.Trailer.Get("X-End") != "trailer" {
			t.Fatalf("response=%d %q header=%v trailer=%v err=%v", response.StatusCode, body, response.Header, response.Trailer, err)
		}
	}
	if calls.Load() != 2 || dials.Load() != 1 {
		t.Fatalf("calls=%d upstream dials=%d", calls.Load(), dials.Load())
	}
}

func TestHTTPEventStreamArrivesBeforeOriginFinishes(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer origin.Close()
	defer finish()
	backend := testBackend{dial: (&net.Dialer{}).DialContext}
	listener, _, _, _ := startProxy(t, "http", backend)
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var first [13]byte
	if _, err := io.ReadFull(response.Body, first[:]); err != nil || string(first[:]) != "data: first\n\n" {
		t.Fatalf("first event=%q err=%v", first, err)
	}
	finish()
}

func TestHTTPRejectsAmbiguousAndSelfTargets(t *testing.T) {
	backend := testBackend{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("invalid request reached backend")
		return nil, errors.New("unused")
	}}
	server := NewHTTPServer("127.0.0.1:8080", backend)
	defer server.Close()
	for _, tc := range []struct{ method, url, host string }{
		{"GET", "http://intranet.test/a", "other.test"},
		{"GET", "http://127.0.0.1:8080/a", "127.0.0.1:8080"},
		{"GET", "ftp://intranet.test/a", "intranet.test"},
		{"CONNECT", "intranet.test:443", "other.test:443"},
		{"CONNECT", "127.0.0.1:8080", "127.0.0.1:8080"},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(tc.method, tc.url, nil)
		request.Host = tc.host
		server.ServeHTTP(recorder, request)
		if recorder.Code != 400 {
			t.Fatalf("%s %s Host:%s returned %d", tc.method, tc.url, tc.host, recorder.Code)
		}
	}
}

func TestUpstreamFailureCannotReportSuccessOrExposeSecrets(t *testing.T) {
	for _, backend := range []Dialer{nil, testBackend{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("https://gateway/?token=do-not-expose")
	}}, testBackend{dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}} {
		conn := runSOCKSConnection(t, backend)
		socksGreeting(t, conn, 0)
		if code := socksCommand(t, conn, domainCommand("intranet.test", 443)); code != RepServerFailure {
			t.Fatalf("SOCKS reply=%x", code)
		}
		server := NewHTTPServer("127.0.0.1:8080", backend)
		for _, method := range []string{"GET", "CONNECT"} {
			target := "http://intranet.test/"
			if method == "CONNECT" {
				target = "intranet.test:443"
			}
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
			if recorder.Code != 502 || strings.Contains(recorder.Body.String(), "do-not-expose") {
				t.Fatalf("unsafe reply %d %q", recorder.Code, recorder.Body.String())
			}
		}
		server.Close()
	}
	server, client := net.Pipe()
	defer server.Close()
	backend := testBackend{dial: func(context.Context, string, string) (net.Conn, error) { return client, errors.New("failed") }}
	if _, err := dialTCP(context.Background(), backend, endpoint{"intranet.test", 443}); err == nil {
		t.Fatal("partial dial accepted")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("partial connection leaked")
	}
}

func TestProxyShutdownCancelsPendingDialsAndEstablishedStreams(t *testing.T) {
	for _, kind := range []string{"http", "socks5"} {
		for _, phase := range []string{"handshake", "dial", "stream"} {
			for _, action := range []string{"cancel", "close"} {
				t.Run(kind+"/"+phase+"/"+action, func(t *testing.T) {
					entered := make(chan struct{})
					closed := make(chan struct{})
					backend := testBackend{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						close(entered)
						if phase == "dial" {
							<-ctx.Done()
							close(closed)
							return nil, ctx.Err()
						}
						server, client := net.Pipe()
						go func() { defer close(closed); defer server.Close(); _, _ = io.Copy(io.Discard, server) }()
						return client, nil
					}}
					listener, cancel, closeServer, _ := startProxy(t, kind, backend)
					client, err := net.Dial("tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					testDeadline(t, client)
					if phase == "handshake" {
						if kind == "http" {
							_, err = io.WriteString(client, "GET / HTTP/1.1\r\n")
						} else {
							_, err = client.Write([]byte{5})
						}
					} else if kind == "http" {
						_, err = io.WriteString(client, "CONNECT intranet.test:443 HTTP/1.1\r\nHost: intranet.test:443\r\n\r\n")
					} else {
						socksGreeting(t, client, 0)
						_, err = client.Write(domainCommand("intranet.test", 443))
					}
					if err != nil {
						t.Fatal(err)
					}
					if phase != "handshake" {
						select {
						case <-entered:
						case <-time.After(time.Second):
							t.Fatal("dial did not start")
						}
						if phase == "stream" {
							if kind == "http" {
								response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "CONNECT"})
								if err != nil || response.StatusCode != 200 {
									t.Fatalf("CONNECT response=%v err=%v", response, err)
								}
							} else {
								var reply [10]byte
								if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0 {
									t.Fatalf("SOCKS reply=%x err=%v", reply, err)
								}
							}
						}
					}
					if action == "cancel" {
						cancel()
					} else if err := closeServer(); err != nil {
						t.Fatal(err)
					}
					if phase != "handshake" {
						select {
						case <-closed:
						case <-time.After(time.Second):
							t.Fatal("backend not canceled/closed")
						}
					}
					if _, err := io.Copy(io.Discard, client); err != nil {
						if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
							t.Fatalf("client left open: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestConnectionLimitDoesNotLoseExistingConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle serverLifecycle
	ctx, finish, err := lifecycle.begin(context.Background(), listener)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	clients := make([]net.Conn, 0, maxConnections)
	defer func() {
		for _, conn := range clients {
			conn.Close()
		}
	}()
	for i := 0; i < maxConnections; i++ {
		server, client := net.Pipe()
		clients = append(clients, client)
		if _, ok := lifecycle.track(ctx, server); !ok {
			t.Fatalf("rejected connection %d", i)
		}
	}
	overflow, peer := net.Pipe()
	defer peer.Close()
	if _, ok := lifecycle.track(ctx, overflow); ok {
		t.Fatal("connection limit not enforced")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection left open")
	}
	lifecycle.mu.Lock()
	var first *trackedConn
	for conn := range lifecycle.active {
		first = conn
		break
	}
	lifecycle.mu.Unlock()
	first.Close()
	server, client := net.Pipe()
	defer client.Close()
	if _, ok := lifecycle.track(ctx, server); !ok {
		t.Fatal("closed connection did not release capacity")
	}
}

func TestEndpointValidation(t *testing.T) {
	for _, tc := range []struct {
		authority string
		port      uint16
		want      string
	}{
		{"Intranet.Test.:8443", 0, "intranet.test:8443"},
		{"[::1]:443", 0, "[::1]:443"},
		{"10.0.0.9", 80, "10.0.0.9:80"},
	} {
		endpoint, err := parseEndpoint(tc.authority, tc.port)
		if err != nil || endpoint.authority() != tc.want {
			t.Fatalf("%q -> %v %v", tc.authority, endpoint, err)
		}
	}
	for _, authority := range []string{"", "host:", "host:0", "host:65536", "user@host:80", "host/path", "x/y:80", "host:443?x", "host\x00:80", "bad_host:80", "[::1%25zone]:80"} {
		if endpoint, err := parseEndpoint(authority, 0); err == nil {
			t.Fatalf("accepted %q: %+v", authority, endpoint)
		}
	}
}

func BenchmarkRelayCopy(b *testing.B) {
	payload := strings.Repeat("x", 64<<10)
	for _, tc := range []struct {
		name string
		copy func(io.Writer, io.Reader) error
	}{
		{"allocated", func(dst io.Writer, src io.Reader) error {
			_, err := io.Copy(writerOnly{dst}, readerOnly{src})
			return err
		}},
		{"pooled", copyStream},
	} {
		b.Run(tc.name, func(b *testing.B) {
			reader := strings.NewReader(payload)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reader.Reset(payload)
				if err := tc.copy(io.Discard, reader); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestHTTPDropsConnectionsPooledOnADeadTunnel(t *testing.T) {
	var dials int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	backend := testBackend{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials++
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}}
	s := NewHTTPServer("127.0.0.1:0", backend)
	defer s.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, listener) }()

	request := func() {
		req, err := http.NewRequest(http.MethodGet, "http://upstream.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.URL.Host, req.Host = "upstream.test", "upstream.test"
		proxied := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + listener.Addr().String())
		}}}
		resp, err := proxied.Do(req)
		if err != nil {
			t.Fatalf("proxied request: %v", err)
		}
		_ = resp.Body.Close()
	}

	request()
	request()
	if dials != 1 {
		t.Fatalf("the second request should reuse the pooled connection, dials = %d", dials)
	}
	// A new tunnel generation invalidates everything pooled on the old one.
	s.DropIdleConnections()
	request()
	if dials != 2 {
		t.Fatalf("dropping idle connections must force a fresh dial, dials = %d", dials)
	}
}
