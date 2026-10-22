package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// TLSPolicy verifies the gateway certificate against the system trust store.
// An optional PEM file adds trusted CAs without replacing the system roots.
// The caller builds this once and hands the same policy to the control plane
// and to every tunnel, so neither has to know how the other is configured.
func TLSPolicy(serverName, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: strings.Trim(serverName, "[]"),
		MinVersion: tls.VersionTLS12,
	}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read gateway CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate roots: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("gateway CA file contains no PEM certificates")
	}
	cfg.RootCAs = roots
	return cfg, nil
}
