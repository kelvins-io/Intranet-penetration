package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreateCAAndIssue(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.CertPEM) != string(ca2.CertPEM) {
		t.Fatal("CA not persisted")
	}

	certPEM, keyPEM, serial, notAfter, err := ca.IssueAgentCert("agent-1", "ten-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || notAfter.Before(time.Now()) {
		t.Fatalf("bad serial/expiry: %s %v", serial, notAfter)
	}

	certFile := filepath.Join(dir, "agent.crt")
	keyFile := filepath.Join(dir, "agent.key")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cli, err := ClientMTLSConfig(caFile, certFile, keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cli.Certificates) != 1 {
		t.Fatal("expected client cert")
	}

	srv := ServerMTLSConfig(nil, ca, "require")
	if srv.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("auth mode %v", srv.ClientAuth)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem decode")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if PeerAgentID(tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}) != "agent-1" {
		t.Fatal("peer cn mismatch")
	}
}
