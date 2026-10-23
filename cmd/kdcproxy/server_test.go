package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/certinel/fswatcher"
)

// writeCertificate writes a self-signed certificate and key for "kdcproxy" to
// dir and returns their paths and a pool trusting the certificate
func writeCertificate(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kdcproxy"},
		DNSNames:              []string{"kdcproxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}

	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return certPath, keyPath, pool
}

func TestNewServer(t *testing.T) {
	certPath, keyPath, pool := writeCertificate(t, t.TempDir())
	sentinel, err := fswatcher.New(certPath, keyPath)
	if err != nil {
		t.Fatalf("fswatcher.New() error = %v", err)
	}

	tests := []struct {
		name    string
		certs   certificateSource
		wantTLS bool
	}{
		{"plain_http", nil, false},
		{"tls", sentinel, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newServer(":8443", http.NotFoundHandler(), tt.certs)

			if srv.Addr != ":8443" {
				t.Errorf("Addr = %q, want %q", srv.Addr, ":8443")
			}
			if !tt.wantTLS {
				if srv.TLSConfig != nil {
					t.Errorf("TLSConfig = %v, want nil", srv.TLSConfig)
				}
				return
			}
			if srv.TLSConfig == nil {
				t.Fatalf("TLSConfig = nil, want a TLS configuration")
			}

			// complete a handshake against the server's TLS configuration
			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()

			errs := make(chan error, 1)
			go func() { errs <- tls.Server(serverConn, srv.TLSConfig).Handshake() }()

			if err := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: "kdcproxy"}).Handshake(); err != nil {
				t.Errorf("client handshake error = %v", err)
			}
			if err := <-errs; err != nil {
				t.Errorf("server handshake error = %v", err)
			}
		})
	}
}
