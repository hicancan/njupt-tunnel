package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigSecureDefaults(t *testing.T) {
	config, err := TLSPolicy("gateway.invalid", "")
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS12 || config.RootCAs != nil || config.ServerName != "gateway.invalid" {
		t.Fatal("unexpected TLS policy")
	}
	config, err = TLSPolicy("[::1]", "")
	if err != nil || config.ServerName != "::1" {
		t.Fatal("IPv6 certificate name retained brackets")
	}
}

func TestConfigAddsPEMCertificateAndRejectsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.pem")
	if _, err := TLSPolicy("gateway.invalid", path); err == nil {
		t.Fatal("missing CA file accepted")
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLSPolicy("gateway.invalid", path); err == nil {
		t.Fatal("invalid PEM accepted")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"gateway.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := TLSPolicy("gateway.invalid", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: "gateway.invalid"}); err != nil {
		t.Fatalf("additional PEM CA not trusted: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: "outside.invalid"}); err == nil {
		t.Fatal("custom CA bypassed hostname validation")
	}
}
