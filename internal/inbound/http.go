package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPServer struct {
	ListenAddr string
	Dialer     Dialer
	server     *http.Server
	transport  *http.Transport
	lifecycle  serverLifecycle
}

func NewHTTPServer(listenAddr string, backend Dialer) *HTTPServer {
	s := &HTTPServer{ListenAddr: listenAddr, Dialer: backend}
	s.transport = &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			target, err := parseEndpoint(address, 0)
			if err != nil {
				return nil, err
			}
			return dialTCP(ctx, s.Dialer, target)
		},
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		MaxIdleConns:       128, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 64,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    handshakeTimeout,
		ResponseHeaderTimeout:  60 * time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
	s.server = &http.Server{
		Addr: listenAddr, Handler: s,
		ReadHeaderTimeout: handshakeTimeout, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if tracked, ok := conn.(*trackedConn); ok {
				return tracked.ctx
			}
			return ctx
		},
	}
	return s
}

func (s *HTTPServer) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP proxy: %w", err)
	}
	return s.Serve(ctx, listener)
}

func (s *HTTPServer) Serve(ctx context.Context, listener net.Listener) error {
	ctx, finish, err := s.lifecycle.begin(ctx, listener)
	if err != nil {
		return err
	}
	defer finish()
	defer s.transport.CloseIdleConnections()
	err = s.server.Serve(trackedListener{Listener: listener, ctx: ctx, lifecycle: &s.lifecycle})
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("serve HTTP proxy: %w", err)
}

// DropIdleConnections discards pooled upstream connections. They live on the
// tunnel, so they die with it.
func (s *HTTPServer) DropIdleConnections() { s.transport.CloseIdleConnections() }

func (s *HTTPServer) Close() error {
	err := s.lifecycle.close()
	serverErr := s.server.Close()
	s.transport.CloseIdleConnections()
	if err != nil {
		return err
	}
	if errors.Is(serverErr, net.ErrClosed) || errors.Is(serverErr, http.ErrServerClosed) {
		return nil
	}
	return serverErr
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		s.serveConnect(w, request)
		return
	}
	protocol := request.URL.Scheme
	if protocol == "" {
		protocol = "http"
	}
	if protocol != "http" && protocol != "https" || request.URL.Opaque != "" || request.URL.User != nil {
		http.Error(w, "unsupported proxy request URL", http.StatusBadRequest)
		return
	}
	port := uint16(80)
	if protocol == "https" {
		port = 443
	}
	target, err := parseEndpoint(request.Host, port)
	if err != nil {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	if request.URL.Host != "" {
		urlTarget, err := parseEndpoint(request.URL.Host, port)
		if err != nil || target != urlTarget {
			http.Error(w, "request URL and Host disagree", http.StatusBadRequest)
			return
		}
	}
	if s.isSelfTarget(target) {
		http.Error(w, "HTTP proxy requires a remote target", http.StatusBadRequest)
		return
	}
	if request.Header.Get("Upgrade") != "" {
		http.Error(w, "use CONNECT for protocol upgrades", http.StatusNotImplemented)
		return
	}
	outbound := request.Clone(request.Context())
	outbound.URL.Scheme, outbound.URL.Host = protocol, target.authority()
	outbound.RequestURI, outbound.Close = "", false
	stripHopHeaders(outbound.Header)
	response, err := s.transport.RoundTrip(outbound)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer response.Body.Close()
	stripHopHeaders(response.Header)
	for name, values := range response.Header {
		w.Header()[name] = values
	}
	for name := range response.Trailer {
		w.Header().Add("Trailer", name)
	}
	w.WriteHeader(response.StatusCode)
	var output io.Writer = w
	if response.ContentLength == -1 || strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		output = flushWriter{w}
	}
	if err := copyStream(output, response.Body); err != nil {
		// Abort instead of advertising a truncated response as a complete body.
		panic(http.ErrAbortHandler)
	}
	for name, values := range response.Trailer {
		w.Header()[http.TrailerPrefix+name] = values
	}
}

type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

func (s *HTTPServer) isSelfTarget(target endpoint) bool {
	self, err := parseEndpoint(s.ListenAddr, 0)
	if err != nil || self.port != target.port {
		return false
	}
	if self.host == target.host {
		return true
	}
	ip := net.ParseIP(target.host)
	return ip != nil && ip.IsLoopback() && (self.host == "0.0.0.0" || self.host == "::" || self.host == "localhost" || net.ParseIP(self.host) != nil && net.ParseIP(self.host).IsLoopback())
}

func (s *HTTPServer) serveConnect(w http.ResponseWriter, request *http.Request) {
	target, err := parseEndpoint(request.Host, 0)
	if err != nil || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		http.Error(w, "CONNECT requires host:port and no request body", http.StatusBadRequest)
		return
	}
	if request.URL.Host != "" {
		urlTarget, err := parseEndpoint(request.URL.Host, 0)
		if err != nil || target != urlTarget {
			http.Error(w, "CONNECT URL and Host disagree", http.StatusBadRequest)
			return
		}
	}
	if s.isSelfTarget(target) {
		http.Error(w, "CONNECT cannot target this proxy", http.StatusBadRequest)
		return
	}
	upstream, err := dialTCP(request.Context(), s.Dialer, target)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP server cannot establish a tunnel", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_ = client.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relayTCP(request.Context(), client, buffered.Reader, upstream)
}

func stripHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func writeUpstreamError(w http.ResponseWriter, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, "tunnel destination timed out", http.StatusGatewayTimeout)
	} else {
		http.Error(w, "tunnel destination unavailable", http.StatusBadGateway)
	}
}
