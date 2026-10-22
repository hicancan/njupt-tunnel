package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

const maxDNSCache = 1024

type dnsEntry struct {
	ip      netip.Addr
	expires time.Time
}

// resolver is IPv4-only because the gateway assigns no IPv6 address. Each
// exchange uses a connected socket (source and destination validated by the
// stack), validates the DNS question, and retries truncated replies over TCP.
type resolver struct {
	network *network
	server  netip.Addr
	mu      sync.RWMutex
	cache   map[string]dnsEntry
	flight  singleflight.Group
	queries chan struct{}
}

func newResolver(n *network, server netip.Addr) *resolver {
	return &resolver{network: n, server: server, cache: make(map[string]dnsEntry), queries: make(chan struct{}, 64)}
}

func (r *resolver) cached(host string) (netip.Addr, bool) {
	r.mu.RLock()
	entry, ok := r.cache[host]
	r.mu.RUnlock()
	return entry.ip, ok && time.Now().Before(entry.expires)
}

func (r *resolver) resolve(ctx context.Context, host string) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !ip.Is4() {
			return netip.Addr{}, errors.New("the gateway assigns IPv4 only")
		}
		return ip, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return netip.Addr{}, errors.New("invalid DNS name")
	}
	if ip, ok := r.cached(host); ok {
		return ip, nil
	}
	result := r.flight.DoChan(host, func() (any, error) {
		if ip, ok := r.cached(host); ok {
			return ip, nil
		}
		queryCtx, cancel := context.WithTimeout(r.network.ctx, 5*time.Second)
		defer cancel()
		select {
		case r.queries <- struct{}{}:
			defer func() { <-r.queries }()
		case <-queryCtx.Done():
			return netip.Addr{}, queryCtx.Err()
		}
		ip, expires, err := r.lookup(queryCtx, host, 0)
		if err == nil && time.Now().Before(expires) {
			r.mu.Lock()
			if len(r.cache) >= maxDNSCache {
				for key := range r.cache {
					delete(r.cache, key)
					break
				}
			}
			r.cache[host] = dnsEntry{ip, expires}
			r.mu.Unlock()
		}
		return ip, err
	})
	select {
	case <-ctx.Done():
		return netip.Addr{}, ctx.Err()
	case <-r.network.ctx.Done():
		return netip.Addr{}, net.ErrClosed
	case result := <-result:
		if result.Err != nil {
			return netip.Addr{}, result.Err
		}
		return result.Val.(netip.Addr), nil
	}
}

func (r *resolver) lookup(ctx context.Context, host string, depth int) (netip.Addr, time.Time, error) {
	if depth >= 8 {
		return netip.Addr{}, time.Time{}, errors.New("DNS CNAME chain exceeds 8 names")
	}
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	data, err := r.exchange(ctx, wire, false)
	if err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	var msg dnsmessage.Message
	var parser dnsmessage.Parser
	hdr, err := parser.Start(data)
	if err != nil {
		return netip.Addr{}, time.Time{}, fmt.Errorf("decode DNS header: %w", err)
	}
	question, err := parser.Question()
	if err != nil || !hdr.Response || hdr.ID != query.ID || question.Type != dnsmessage.TypeA || question.Class != dnsmessage.ClassINET || !strings.EqualFold(question.Name.String(), name.String()) {
		return netip.Addr{}, time.Time{}, errors.New("DNS response does not match the query")
	}
	if hdr.Truncated {
		data, err = r.exchange(ctx, wire, true)
		if err != nil {
			return netip.Addr{}, time.Time{}, err
		}
	}
	if err = msg.Unpack(data); err != nil {
		return netip.Addr{}, time.Time{}, fmt.Errorf("decode DNS response: %w", err)
	}
	if !msg.Response || msg.ID != query.ID || msg.Truncated || len(msg.Questions) != 1 || msg.Questions[0].Type != dnsmessage.TypeA || msg.Questions[0].Class != dnsmessage.ClassINET || !strings.EqualFold(msg.Questions[0].Name.String(), name.String()) {
		return netip.Addr{}, time.Time{}, errors.New("DNS response does not match the query")
	}
	if msg.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, time.Time{}, &net.DNSError{Err: msg.RCode.String(), Name: host, IsNotFound: msg.RCode == dnsmessage.RCodeNameError}
	}
	current := name.String()
	received := time.Now()
	expires := received.Add(time.Hour)
	for step := 0; step <= len(msg.Answers); step++ {
		for _, answer := range msg.Answers {
			if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), current) {
				continue
			}
			if a, ok := answer.Body.(*dnsmessage.AResource); ok {
				return netip.AddrFrom4(a.A), earlier(expires, received.Add(time.Duration(answer.Header.TTL)*time.Second)), nil
			}
		}
		next := ""
		for _, answer := range msg.Answers {
			if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok && answer.Header.Class == dnsmessage.ClassINET && strings.EqualFold(answer.Header.Name.String(), current) {
				next = cname.CNAME.String()
				expires = earlier(expires, received.Add(time.Duration(answer.Header.TTL)*time.Second))
				break
			}
		}
		if next == "" {
			break
		}
		current = next
	}
	if !strings.EqualFold(current, name.String()) {
		ip, chainExpires, err := r.lookup(ctx, strings.TrimSuffix(current, "."), depth+1)
		return ip, earlier(expires, chainExpires), err
	}
	return netip.Addr{}, time.Time{}, &net.DNSError{Err: "no IPv4 answer", Name: host, IsNotFound: true}
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *resolver) exchange(ctx context.Context, query []byte, tcp bool) ([]byte, error) {
	var conn net.Conn
	var err error
	if tcp {
		conn, err = r.network.dialIP(ctx, r.server, 53)
	} else {
		r.network.mu.RLock()
		if r.network.closed {
			r.network.mu.RUnlock()
			return nil, net.ErrClosed
		}
		conn, err = gonet.DialUDP(r.network.stack, &tcpip.FullAddress{NIC: nicID}, &tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(r.server.As4()), Port: 53}, ipv4.ProtocolNumber)
		r.network.mu.RUnlock()
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if tcp {
		frame := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if err = writeAll(conn, frame); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		response := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		_, err = io.ReadFull(conn, response)
		return response, err
	}
	if err = writeAll(conn, query); err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	count, err := conn.Read(response)
	return response[:count], err
}
