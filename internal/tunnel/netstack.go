package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

// network owns the lifetime of every socket on one authenticated virtual IP.
// The gate excludes new sockets before teardown aborts existing endpoints.
type network struct {
	stack     *stack.Stack
	link      *channel.Endpoint
	notify    chan struct{}
	dns       *resolver
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
}

func newNetwork(info Info, mtu uint32) (*network, error) {
	if mtu < 576 || mtu > 9000 {
		return nil, errors.New("tunnel MTU must be between 576 and 9000")
	}
	n := &network{
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocolCUBIC, udp.NewProtocol, icmp.NewProtocol4},
		}),
		link:   channel.New(256, mtu, ""),
		notify: make(chan struct{}, 1),
	}
	n.link.AddNotify(n)
	n.ctx, n.cancel = context.WithCancel(context.Background())
	if err := n.stack.CreateNIC(nicID, n.link); err != nil {
		n.Close()
		return nil, fmt.Errorf("create tunnel NIC: %s", err)
	}
	// The prefix is the gateway's own netmask attribute, not an assumed /32.
	assigned := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4(info.Address.As4()),
		PrefixLen: info.PrefixLen,
	}
	if err := n.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: assigned}, stack.AddressProperties{}); err != nil {
		n.Close()
		return nil, fmt.Errorf("assign virtual IPv4: %s", err)
	}
	n.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	n.dns = newResolver(n, info.DNS)
	return n, nil
}

func (n *network) WriteNotify() {
	select {
	case n.notify <- struct{}{}:
	default:
	}
}

func (n *network) Close() {
	n.closeOnce.Do(func() {
		n.cancel()
		n.mu.Lock()
		n.closed = true
		n.mu.Unlock()
		n.link.Close()
		n.stack.Destroy()
	})
}

func (n *network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("unsupported network %q: the gateway assigns IPv4 only", network)
	}
	ip, port, err := n.destination(ctx, address)
	if err != nil {
		return nil, err
	}
	return n.dialIP(ctx, ip, port)
}

func (n *network) dialIP(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	defer cancel()
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed || n.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	conn, err := gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(ip.As4()), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (n *network) destination(ctx context.Context, address string) (netip.Addr, uint16, error) {
	host, port, err := splitDestination(address)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	ip, err := n.dns.resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return ip, port, nil
}

func splitDestination(address string) (string, uint16, error) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("invalid destination port")
	}
	return host, uint16(port), nil
}

func (n *network) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed {
		return nil, net.ErrClosed
	}
	conn, err := gonet.DialUDP(n.stack, &tcpip.FullAddress{NIC: nicID}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	writeCtx, writeCancel := context.WithCancel(ctx)
	packet := &packetConn{UDPConn: conn, network: n, ctx: ctx, cancel: cancel, writeCtx: writeCtx, writeCancel: writeCancel}
	packet.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return packet, nil
}
