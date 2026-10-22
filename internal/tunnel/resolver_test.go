package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type dnsFixture struct {
	udp atomic.Int32
	tcp atomic.Int32
}

func serveTestDNS(t *testing.T, n *network, answer func(dnsmessage.Message, bool) dnsmessage.Message, udpTransform ...func([]byte) []byte) *dnsFixture {
	t.Helper()
	counts := new(dnsFixture)
	udp, err := gonet.DialUDP(n.stack, &tcpip.FullAddress{NIC: nicID, Port: 53}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcp := listenTestTCP(t, n, 53)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buf := make([]byte, 4096)
		for {
			count, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err = query.Unpack(buf[:count]); err != nil {
				t.Error(err)
				return
			}
			counts.udp.Add(1)
			response := answer(query, false)
			wire, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			for _, transform := range udpTransform {
				wire = transform(wire)
			}
			if _, err = udp.WriteTo(wire, from); err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			var size [2]byte
			if _, err = io.ReadFull(conn, size[:]); err != nil {
				conn.Close()
				t.Error(err)
				return
			}
			wire := make([]byte, int(binary.BigEndian.Uint16(size[:])))
			if _, err = io.ReadFull(conn, wire); err != nil {
				conn.Close()
				t.Error(err)
				return
			}
			var query dnsmessage.Message
			if err = query.Unpack(wire); err != nil {
				conn.Close()
				t.Error(err)
				return
			}
			counts.tcp.Add(1)
			response := answer(query, true)
			wire, err = response.Pack()
			if err != nil {
				conn.Close()
				t.Error(err)
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
			if err = writeAll(conn, append(size[:], wire...)); err != nil {
				conn.Close()
				t.Error(err)
				return
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { udp.Close(); tcp.Close(); workers.Wait() })
	return counts
}

func dnsAnswer(query dnsmessage.Message, ttl uint32) dnsmessage.Message {
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: ttl},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 9}},
		}},
	}
}

func TestDNSRoundTripCacheTTLAndZeroTTL(t *testing.T) {
	client, server := testNetworks(t)
	counts := serveTestDNS(t, server, func(query dnsmessage.Message, _ bool) dnsmessage.Message {
		ttl := uint32(60)
		if query.Questions[0].Name.String() == "uncached.example.test." {
			ttl = 0
		}
		return dnsAnswer(query, ttl)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, host := range []string{"Intranet.EXAMPLE.test.", "intranet.example.test"} {
		ip, err := client.dns.resolve(ctx, host)
		if err != nil || ip != netip.MustParseAddr("10.0.0.9") {
			t.Fatalf("DNS lookup: %v", err)
		}
	}
	if counts.udp.Load() != 1 {
		t.Fatal("case-normalized DNS cache missed")
	}
	client.dns.mu.Lock()
	entry := client.dns.cache["intranet.example.test"]
	remaining := time.Until(entry.expires)
	entry.expires = time.Now().Add(-time.Second)
	client.dns.cache["intranet.example.test"] = entry
	client.dns.mu.Unlock()
	if remaining <= 0 || remaining > time.Minute {
		t.Fatal("DNS cache ignored response TTL")
	}
	if _, err := client.dns.resolve(ctx, "intranet.example.test"); err != nil {
		t.Fatal(err)
	}
	if counts.udp.Load() != 2 {
		t.Fatal("expired cache entry reused")
	}
	for i := 0; i < 2; i++ {
		if _, err := client.dns.resolve(ctx, "uncached.example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if counts.udp.Load() != 4 {
		t.Fatal("zero-TTL DNS response was cached")
	}
}

func TestDNSTruncationUsesTCPWithSameQuestion(t *testing.T) {
	client, server := testNetworks(t)
	counts := serveTestDNS(t, server, func(query dnsmessage.Message, tcp bool) dnsmessage.Message {
		reply := dnsAnswer(query, 30)
		if !tcp {
			reply.Truncated = true
			reply.Answers = nil
		}
		return reply
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := client.dns.resolve(ctx, "private.example.test")
	if err != nil || ip != netip.MustParseAddr("10.0.0.9") {
		t.Fatalf("DNS TCP fallback: %v", err)
	}
	if counts.udp.Load() != 1 || counts.tcp.Load() != 1 {
		t.Fatal("truncated DNS did not fall back once to TCP")
	}
}

func TestDNSRejectsMismatchedAndNegativeReplies(t *testing.T) {
	for _, mode := range []string{"ID", "question", "response bit", "NXDOMAIN"} {
		t.Run(mode, func(t *testing.T) {
			client, server := testNetworks(t)
			serveTestDNS(t, server, func(query dnsmessage.Message, _ bool) dnsmessage.Message {
				reply := dnsAnswer(query, 60)
				switch mode {
				case "ID":
					reply.ID ^= 1
				case "question":
					reply.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("other.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
				case "response bit":
					reply.Response = false
				case "NXDOMAIN":
					reply.RCode = dnsmessage.RCodeNameError
					reply.Answers = nil
				}
				return reply
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := client.dns.resolve(ctx, "private.example.test"); err == nil {
				t.Fatal("mismatched or negative DNS response accepted")
			} else if mode == "NXDOMAIN" {
				var dnsError *net.DNSError
				if !errors.As(err, &dnsError) || !dnsError.IsNotFound {
					t.Fatal("NXDOMAIN lost not-found classification")
				}
			}
		})
	}
}

func TestDNSCNAMEUsesMinimumTTLAndRejectsUnrelatedAnswer(t *testing.T) {
	client, server := testNetworks(t)
	serveTestDNS(t, server, func(query dnsmessage.Message, _ bool) dnsmessage.Message {
		reply := dnsAnswer(query, 3600)
		name := dnsmessage.MustNewName("backend.example.test.")
		reply.Answers[0].Header.Name = name
		reply.Answers = append(reply.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 7},
			Body:   &dnsmessage.CNAMEResource{CNAME: name},
		})
		// An unrelated A answer must never be selected merely because it is first.
		reply.Answers = append([]dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("attacker.invalid."), Class: dnsmessage.ClassINET, TTL: 3600},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}},
		}}, reply.Answers...)
		return reply
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := client.dns.resolve(ctx, "alias.example.test")
	if err != nil || ip != netip.MustParseAddr("10.0.0.9") {
		t.Fatalf("CNAME selected wrong address: %v", err)
	}
	client.dns.mu.RLock()
	entry := client.dns.cache["alias.example.test"]
	client.dns.mu.RUnlock()
	if remaining := time.Until(entry.expires); remaining <= 0 || remaining > 7*time.Second {
		t.Fatal("CNAME cache exceeded shortest TTL")
	}
}

func TestDNSCallerCancellationAndNetworkTeardown(t *testing.T) {
	client, _ := testNetworks(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.dns.resolve(ctx, "private.example.test"); !errors.Is(err, context.Canceled) {
		t.Fatal("DNS ignored caller cancellation")
	}
	client.Close()
	if _, err := client.dns.resolve(context.Background(), "private.example.test"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed network accepted DNS query: %v", err)
	}
}

func TestDNSTruncatedResourceTailStillFallsBackToTCP(t *testing.T) {
	client, server := testNetworks(t)
	counts := serveTestDNS(t, server, func(query dnsmessage.Message, tcp bool) dnsmessage.Message {
		reply := dnsAnswer(query, 30)
		reply.Truncated = !tcp
		return reply
	}, func(wire []byte) []byte {
		// The TC reply retains its answer count but loses the end of the A RR.
		// Complete-message unpacking must fail; the header/question suffice to
		// authenticate the truncation indication before retrying over TCP.
		wire = wire[:len(wire)-1]
		var incomplete dnsmessage.Message
		if incomplete.Unpack(wire) == nil {
			t.Error("fixture did not truncate a DNS resource")
		}
		return wire
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := client.dns.resolve(ctx, "truncated.example.test")
	if err != nil || ip != netip.MustParseAddr("10.0.0.9") {
		t.Fatalf("truncated RR tail prevented TCP fallback: %v", err)
	}
	if counts.udp.Load() != 1 || counts.tcp.Load() != 1 {
		t.Fatal("truncated resource did not cause one TCP retry")
	}
}

func TestDNSCNAMEExpiresDuringDownstreamLookup(t *testing.T) {
	client, server := testNetworks(t)
	serveTestDNS(t, server, func(query dnsmessage.Message, _ bool) dnsmessage.Message {
		if query.Questions[0].Name.String() == "slow-backend.example.test." {
			time.Sleep(1100 * time.Millisecond)
			return dnsAnswer(query, 60)
		}
		return dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("slow-backend.example.test.")},
			}},
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := client.dns.resolve(ctx, "short-alias.example.test")
	if err != nil || ip != netip.MustParseAddr("10.0.0.9") {
		t.Fatalf("delayed CNAME lookup: %v", err)
	}
	if _, ok := client.dns.cached("short-alias.example.test"); ok {
		t.Fatal("CNAME TTL restarted after its downstream lookup")
	}
}
