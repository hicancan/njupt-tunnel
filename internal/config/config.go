package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type GatewayConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// BindIP pins the local source address. Leave it empty on a single-homed
	// host: the operating system then picks the route, which is what every
	// other program on the machine does. Set it only to force one uplink.
	BindIP string `json:"bind_ip,omitempty"`
	CAFile string `json:"ca_file,omitempty"`
	MTU    uint32 `json:"mtu"`
}

// ProtocolConfig is the deployment profile of the controller API. It has no
// defaults: every gateway names its own paths, client identity and cookie.
type ProtocolConfig struct {
	APIBase       string `json:"api_base"`
	UserAgent     string `json:"user_agent"`
	SessionCookie string `json:"session_cookie"`
	RenewSalt     string `json:"renew_salt,omitempty"`
}

// CaptchaConfig points at a trained model file. Leave it empty on a host that
// only ever resumes a cached session: logging in needs a model.
type CaptchaConfig struct {
	Model string `json:"model,omitempty"`
}

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type InboundConfig struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Listen string `json:"listen"`
	Port   int    `json:"port"`
}

type Config struct {
	Gateway  GatewayConfig   `json:"gateway"`
	Protocol ProtocolConfig  `json:"protocol"`
	Captcha  CaptchaConfig   `json:"captcha,omitempty"`
	Auth     AuthConfig      `json:"auth"`
	Inbounds []InboundConfig `json:"inbounds"`
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(data) > 64<<10 {
		return nil, errors.New("configuration exceeds 64 KiB")
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing config JSON")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Paths in the file are relative to the file, not to the working directory.
	for _, p := range []*string{&cfg.Gateway.CAFile, &cfg.Captcha.Model} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	return &cfg, nil
}

// Validate checks all settings before authentication or opening any listener.
// Credentials may both be omitted when an existing session is used.
func (c *Config) Validate() error {
	c.Gateway.Host = strings.TrimSpace(c.Gateway.Host)
	if strings.HasPrefix(c.Gateway.Host, "[") && strings.HasSuffix(c.Gateway.Host, "]") {
		c.Gateway.Host = c.Gateway.Host[1 : len(c.Gateway.Host)-1]
	}
	for _, ch := range c.Gateway.Host {
		if ch <= 0x20 || ch == 0x7f {
			return errors.New("gateway.host contains a control character")
		}
	}
	if c.Gateway.Host == "" || strings.ContainsAny(c.Gateway.Host, " /\\?#@\t\r\n") || (strings.Contains(c.Gateway.Host, ":") && net.ParseIP(c.Gateway.Host) == nil) {
		return errors.New("gateway.host must be a hostname or IP address without a scheme or port")
	}
	if c.Gateway.Port == 0 {
		c.Gateway.Port = 8443
	}
	if !validPort(c.Gateway.Port) {
		return errors.New("gateway port must be between 1 and 65535")
	}
	if c.Gateway.MTU == 0 {
		c.Gateway.MTU = 1400
	}
	if c.Gateway.MTU < 576 || c.Gateway.MTU > 9000 {
		return errors.New("gateway.mtu must be between 576 and 9000")
	}
	if c.Gateway.BindIP != "" {
		ip := net.ParseIP(c.Gateway.BindIP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("gateway.bind_ip must be empty or a local IP address")
		}
	}
	if err := c.Protocol.validate(); err != nil {
		return err
	}
	if (strings.TrimSpace(c.Auth.Username) == "") != (c.Auth.Password == "") {
		return errors.New("auth.username and auth.password must both be supplied or both be empty")
	}
	if len(c.Inbounds) == 0 {
		return errors.New("at least one inbound is required")
	}
	tags, addresses := make(map[string]bool), make(map[string]bool)
	for i := range c.Inbounds {
		inbound := &c.Inbounds[i]
		if inbound.Type != "socks5" && inbound.Type != "http" {
			return fmt.Errorf("inbound %d has unsupported type %q", i, inbound.Type)
		}
		if inbound.Listen == "" {
			inbound.Listen = "127.0.0.1"
		}
		if strings.HasPrefix(inbound.Listen, "[") && strings.HasSuffix(inbound.Listen, "]") {
			inbound.Listen = inbound.Listen[1 : len(inbound.Listen)-1]
		}
		if strings.EqualFold(inbound.Listen, "localhost") {
			inbound.Listen = "127.0.0.1"
		}
		ip := net.ParseIP(inbound.Listen)
		if ip == nil {
			return fmt.Errorf("inbound %d listen must be an IP address or localhost", i)
		}
		inbound.Listen = ip.String()
		if !validPort(inbound.Port) {
			return fmt.Errorf("inbound %d port must be between 1 and 65535", i)
		}
		if inbound.Tag == "" {
			inbound.Tag = fmt.Sprintf("%s-%d", inbound.Type, i+1)
		}
		if tags[inbound.Tag] {
			return fmt.Errorf("duplicate inbound tag %q", inbound.Tag)
		}
		tags[inbound.Tag] = true
		address := net.JoinHostPort(strings.ToLower(inbound.Listen), strconv.Itoa(inbound.Port))
		if addresses[address] {
			return fmt.Errorf("duplicate inbound address %s", address)
		}
		addresses[address] = true
	}
	return nil
}

func (p *ProtocolConfig) validate() error {
	p.APIBase = strings.TrimSuffix(strings.TrimSpace(p.APIBase), "/")
	if !strings.HasPrefix(p.APIBase, "/") || strings.ContainsAny(p.APIBase, "?#%\\ \t\r\n") {
		return errors.New("protocol.api_base must be an absolute URL path such as /api/client")
	}
	if p.UserAgent == "" || strings.ContainsAny(p.UserAgent, "\r\n") {
		return errors.New("protocol.user_agent must be a single non-empty line")
	}
	if (&http.Cookie{Name: p.SessionCookie, Value: "x"}).Valid() != nil {
		return errors.New("protocol.session_cookie must be a valid cookie name")
	}
	return nil
}

func validPort(port int) bool { return port > 0 && port <= 65535 }
