package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrCreateCA loads CA from dir or creates a new one.
func LoadOrCreateCA(dir string) (*CA, error) {
	if dir == "" {
		dir = "data"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return parseCA(certPEM, keyPEM)
	}
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, ca.KeyPEM, 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Intranet-penetration"}, CommonName: "IP Tunnel CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid ca key pem")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// IssueAgentCert issues a client certificate for agentID (CN=agentID).
func (ca *CA) IssueAgentCert(agentID, tenantID string, ttl time.Duration) (certPEM, keyPEM []byte, serial string, notAfter time.Time, err error) {
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	serialBig, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	notAfter = time.Now().Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: serialBig,
		Subject: pkix.Name{
			Organization:       []string{"Intranet-penetration"},
			OrganizationalUnit: []string{tenantID},
			CommonName:         agentID,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	serial = serialBig.Text(16)
	return certPEM, keyPEM, serial, notAfter, nil
}

// ServerMTLSConfig builds a TLS config that optionally/require verifies agent client certs.
// mode: off | optional | require
func ServerMTLSConfig(base *tls.Config, ca *CA, mode string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if base != nil {
		cfg = base.Clone()
	}
	if ca == nil || mode == "" || mode == "off" {
		return cfg
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	cfg.ClientCAs = pool
	switch mode {
	case "require":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "optional":
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		cfg.ClientAuth = tls.NoClientCert
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"ip-tunnel"}
	}
	return cfg
}

// ClientMTLSConfig loads agent client cert for dialing.
func ClientMTLSConfig(caFile, certFile, keyFile string, insecureSkipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify,
		NextProtos:         []string{"ip-tunnel"},
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("failed to parse ca cert")
		}
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// PeerAgentID extracts CN from the first peer certificate.
func PeerAgentID(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}
