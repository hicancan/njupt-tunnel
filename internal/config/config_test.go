package config

import (
	"os"
	"path/filepath"
	"testing"
)

func validConfig() *Config {
	return &Config{
		Gateway:  GatewayConfig{Host: "gateway.invalid", BindIP: "127.0.0.1"},
		Protocol: ProtocolConfig{APIBase: "/gw/api/", UserAgent: "TestClient", SessionCookie: "SID"},
		Inbounds: []InboundConfig{{Type: "socks5", Port: 1080}},
	}
}

func TestValidateRejectsUnsupportedOrAmbiguousConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"gateway scheme", func(c *Config) { c.Gateway.Host = "https://gateway.invalid" }},
		{"gateway port", func(c *Config) { c.Gateway.Port = -1 }},
		{"MTU", func(c *Config) { c.Gateway.MTU = 65536 }},
		{"bind IP", func(c *Config) { c.Gateway.BindIP = "typo" }},
		{"wildcard bind", func(c *Config) { c.Gateway.BindIP = "0.0.0.0" }},
		{"multicast bind", func(c *Config) { c.Gateway.BindIP = "224.0.0.1" }},
		{"missing API base", func(c *Config) { c.Protocol.APIBase = "" }},
		{"relative API base", func(c *Config) { c.Protocol.APIBase = "gw/api" }},
		{"API base query", func(c *Config) { c.Protocol.APIBase = "/gw/api?x=1" }},
		{"missing user agent", func(c *Config) { c.Protocol.UserAgent = "" }},
		{"multiline user agent", func(c *Config) { c.Protocol.UserAgent = "a\r\nX-Injected: 1" }},
		{"invalid cookie name", func(c *Config) { c.Protocol.SessionCookie = "S ID" }},
		{"partial auth", func(c *Config) { c.Auth.Username = "alice" }},
		{"no inbounds", func(c *Config) { c.Inbounds = nil }},
		{"unknown inbound", func(c *Config) { c.Inbounds[0].Type = "socks4" }},
		{"bad listener", func(c *Config) { c.Inbounds[0].Listen = "http://localhost" }},
		{"bad inbound port", func(c *Config) { c.Inbounds[0].Port = 65536 }},
		{"duplicate address", func(c *Config) { c.Inbounds = append(c.Inbounds, c.Inbounds[0]) }},
		{"duplicate tag", func(c *Config) {
			c.Inbounds[0].Tag = "same"
			c.Inbounds = append(c.Inbounds, InboundConfig{Type: "http", Tag: "same", Port: 8080})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.edit(c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestValidateDefaultsAndIPv6(t *testing.T) {
	c := validConfig()
	c.Gateway.Host = "[::1]"
	c.Inbounds[0].Listen = "[::1]"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Gateway.Host != "::1" || c.Inbounds[0].Listen != "::1" || c.Gateway.Port != 8443 || c.Gateway.MTU != 1400 || c.Protocol.APIBase != "/gw/api" || c.Inbounds[0].Tag == "" {
		t.Fatalf("defaults not normalized: %+v", c)
	}
}

func TestLoadResolvesCAFileRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{"gateway":{"host":"gateway.invalid","bind_ip":"127.0.0.1","ca_file":"certs/root.pem"},"protocol":{"api_base":"/gw/api","user_agent":"TestClient","session_cookie":"SID"},"inbounds":[{"type":"socks5","port":1080}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Gateway.CAFile != filepath.Join(dir, "certs", "root.pem") {
		t.Fatalf("CA path = %s", c.Gateway.CAFile)
	}
}
