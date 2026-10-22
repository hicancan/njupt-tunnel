package service

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/netip"
	"strconv"

	"github.com/hicancan/njupt-tunnel/internal/captcha"
	"github.com/hicancan/njupt-tunnel/internal/config"
	"github.com/hicancan/njupt-tunnel/internal/gateway"
	"github.com/hicancan/njupt-tunnel/internal/tunnel"
)

// gateway holds the credential across reconnects. Only the reconnect
// supervisor calls it, one connect at a time, so its fields need no lock.
type connector struct {
	cfg       *config.Config
	policy    *tls.Config
	path      string
	session   *gateway.Session // the credential last accepted by the controller
	persisted *gateway.Session // the credential last written to disk
	dns       netip.Addr       // campus resolver, from the authenticated policy
	leased    netip.Addr       // address registered with the controller
	reader    *captcha.Recognizer
	check     bool
	refused   bool // a tunnel-auth refusal already forced one re-acquire
}

func (c *connector) connect(ctx context.Context) (*tunnel.Tunnel, error) {
	source := c.cfg.Gateway.BindIP
	client, err := c.controller(source)
	if err != nil {
		return nil, fatalError{err}
	}
	defer client.Close()

	// A credential that already worked needs no controller round trip at all.
	if c.session == nil || !c.dns.IsValid() {
		if err := c.acquire(ctx, client); err != nil {
			return nil, err
		}
	}
	t, err := tunnel.Open(ctx, c.tunnelConfig(source))
	if errors.Is(err, tunnel.ErrAuthentication) {
		// The controller accepted this credential but the tunnel refused it.
		// Forget it once and let the next attempt re-acquire; a second refusal
		// means the account itself cannot open a tunnel.
		if c.refused {
			return nil, fatalError{err}
		}
		c.refused, c.session, c.dns = true, nil, netip.Addr{}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	c.refused = false
	c.bind(ctx, client, t.Info().Address)
	return t, nil
}

// acquire climbs from the cheapest credential to the most expensive: validate
// what is cached, renew it without a captcha, and only then log in.
func (c *connector) acquire(ctx context.Context, client *gateway.Client) error {
	session, err := validateSession(ctx, client, c.session)
	if err != nil {
		return err
	}
	if session == nil && c.session != nil && c.cfg.Protocol.RenewSalt != "" {
		if session, err = renew(ctx, client, c.session); err != nil {
			log.Printf("Session renewal declined, falling back to login: %v", err)
		}
	}
	if session == nil {
		if c.check {
			return fatalError{errors.New("no valid cached authentication; run without -check to log in")}
		}
		if session, err = logIn(ctx, client, c.cfg.Auth, c.reader); err != nil {
			return err
		}
	}
	if !client.GatewayDNS().IsValid() {
		return fatalError{errors.New("authenticated controller policy has no IPv4 DNS for this gateway")}
	}
	if err := c.persist(session); err != nil {
		return err
	}
	c.session, c.dns = session, client.GatewayDNS()
	return nil
}

// release returns the address lease so the controller does not keep it
// reserved for a connection that has ended.
func (c *connector) release(ctx context.Context) {
	if c.check || c.session == nil || !c.leased.IsValid() {
		return
	}
	client, err := c.controller(c.cfg.Gateway.BindIP)
	if err != nil {
		return
	}
	defer client.Close()
	if err := client.ReleaseVirtualIP(ctx, c.session, c.leased.String()); err != nil {
		log.Printf("Could not release address %s: %v", c.leased, err)
		return
	}
	c.leased = netip.Addr{}
}

func (c *connector) controller(source string) (*gateway.Client, error) {
	return gateway.NewClient(c.cfg.Gateway.Host, c.cfg.Gateway.Port, source, c.policy, gateway.Protocol{
		APIBase:       c.cfg.Protocol.APIBase,
		UserAgent:     c.cfg.Protocol.UserAgent,
		SessionCookie: c.cfg.Protocol.SessionCookie,
		RenewSalt:     c.cfg.Protocol.RenewSalt,
	})
}

func (c *connector) tunnelConfig(source string) tunnel.Config {
	return tunnel.Config{
		Gateway:  net.JoinHostPort(c.cfg.Gateway.Host, strconv.Itoa(c.cfg.Gateway.Port)),
		TLS:      c.policy,
		Username: c.session.Username,
		Token:    c.session.Token,
		BindIP:   source,
		MTU:      c.cfg.Gateway.MTU,
		DNS:      c.dns,
	}
}

// bind records the assigned address with the controller. The gateway hands out
// the address and the controller tracks the lease; a failure here leaves the
// tunnel usable, so it is reported and not fatal.
func (c *connector) bind(ctx context.Context, client *gateway.Client, address netip.Addr) {
	if err := client.BindVirtualIP(ctx, c.session, address.String()); err != nil {
		log.Printf("Could not register address %s: %v", address, err)
		return
	}
	c.leased = address
}

func (c *connector) persist(session *gateway.Session) error {
	if c.check || (c.persisted != nil && *c.persisted == *session) {
		return nil
	}
	if err := session.Save(c.path); err != nil {
		return fatalError{err}
	}
	c.persisted = session
	return nil
}
