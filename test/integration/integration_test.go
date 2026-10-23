//go:build integration

// Package integration runs MIT krb5 clients against the KKDCP server and a
// Samba AD DC, using the environment in compose.yaml.
package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// runDir holds the TLS material for a run. It is inside the repository
	// rather than t.TempDir() because snap-packaged Docker cannot bind mount
	// from /tmp.
	runDir = ".run"

	password    = "Passw0rd-1!"
	newPassword = "N3w-Passw0rd-2!"
)

// compose runs docker compose against compose.yaml and returns its combined
// output. Output is always captured, as snap-packaged Docker can fail
// silently when it is not.
func compose(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "--file", "compose.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()

	return string(out), err
}

// client runs a shell script in the client container against the proxy for
// transport, with env set in its environment
func client(transport, script string, env ...string) (string, error) {
	args := []string{"exec", "-T",
		"--env", "KRB5_CONFIG=/etc/krb5/krb5-" + transport + ".conf",
		"--env", "KRB5CCNAME=FILE:/tmp/krb5cc_" + transport,
	}
	for _, e := range env {
		args = append(args, "--env", e)
	}

	return compose(append(args, "client", "sh", "-c", script)...)
}

// createUser adds a user to the domain
func createUser(t *testing.T, name string, mustChange bool) {
	t.Helper()

	args := []string{"exec", "-T", "dc", "samba-tool", "user", "create", name, password}
	if mustChange {
		args = append(args, "--must-change-at-next-login")
	}
	if out, err := compose(args...); err != nil {
		t.Fatalf("creating user %s: %v\n%s", name, err, out)
	}
}

// writeTLS generates a throwaway CA and a server certificate for both proxies
func writeTLS(t *testing.T) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kdcproxy integration test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	// sign with the parsed CA, which has the generated subject key ID, so the
	// server certificate gets an authority key ID that strict verifiers require
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	server := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kdcproxy"},
		DNSNames:     []string{"kdcproxy-udp", "kdcproxy-tcp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating server certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding server key: %v", err)
	}

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", runDir, err)
	}
	// readable by the proxy, which runs as a different user in its container
	for name, block := range map[string]*pem.Block{
		"ca.pem":     {Type: "CERTIFICATE", Bytes: caDER},
		"server.crt": {Type: "CERTIFICATE", Bytes: serverDER},
		"server.key": {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(runDir, name), pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
}

// setUp builds and starts the environment, and tears it down when the test ends
func setUp(t *testing.T) {
	t.Helper()

	writeTLS(t)
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	if out, err := compose("build"); err != nil {
		t.Fatalf("building images: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := compose("logs", "--no-color")
			t.Logf("compose logs:\n%s", logs)
		}
		if out, err := compose("down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("tearing down: %v\n%s", err, out)
		}
	})

	if out, err := compose("up", "--detach", "--wait"); err != nil {
		t.Fatalf("starting environment: %v\n%s", err, out)
	}
}

// kerberosRequests returns kdc_proxy_kerberos_requests_total by protocol for
// a proxy, fetched from the DC container, which has Python
func kerberosRequests(t *testing.T, proxy string) map[string]float64 {
	t.Helper()

	script := `import ssl, urllib.request
ctx = ssl.create_default_context(cafile="/run/kdcproxy/ca.pem")
print(urllib.request.urlopen("https://` + proxy + `:8443/metrics", context=ctx).read().decode())`
	out, err := compose("exec", "-T", "dc", "python3", "-c", script)
	if err != nil {
		t.Fatalf("fetching metrics from %s: %v\n%s", proxy, err, out)
	}

	requests := map[string]float64{}
	for _, line := range strings.Split(out, "\n") {
		var proto string
		var n float64
		if _, err := fmt.Sscanf(line, `kdc_proxy_kerberos_requests_total{proto=%q} %g`, &proto, &n); err == nil {
			requests[proto] = n
		}
	}

	return requests
}

// kinit gets a TGT for user with pass
const kinit = `printf '%s\n' "$PASS" | kinit "$KUSER"`

func TestIntegration(t *testing.T) {
	setUp(t)

	tests := []struct {
		clause string
		name   string
		user   string
		// mustChange creates the user with an expired password
		mustChange bool
		script     string
		env        []string
		wantErr    bool
		want       []string
		notWant    []string
	}{
		{
			clause: "4.1",
			name:   "kinit",
			user:   "kinit",
			script: kinit + ` && klist`,
			env:    []string{"PASS=" + password},
			want:   []string{"krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"},
		},
		{
			clause: "4.1",
			name:   "kvno",
			user:   "kvno",
			script: kinit + ` && kvno host/dc1.example.test@EXAMPLE.TEST`,
			env:    []string{"PASS=" + password},
			want:   []string{"host/dc1.example.test@EXAMPLE.TEST: kvno ="},
		},
		{
			clause:  "3.2.5.2-1",
			name:    "wrong_password",
			user:    "wrongpw",
			script:  kinit,
			env:     []string{"PASS=" + newPassword},
			wantErr: true,
			want:    []string{"Password incorrect"},
			notWant: []string{"Cannot contact any KDC"},
		},
		{
			clause: "4.2",
			name:   "kpasswd",
			user:   "kpasswd",
			script: `printf '%s\n%s\n%s\n' "$PASS" "$NEWPASS" "$NEWPASS" | kpasswd "$KUSER" && PASS="$NEWPASS" && ` + kinit + ` && klist`,
			env:    []string{"PASS=" + password, "NEWPASS=" + newPassword},
			want:   []string{"Password changed", "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"},
		},
		{
			clause:     "4.2",
			name:       "expired_password",
			user:       "expired",
			mustChange: true,
			script:     `printf '%s\n%s\n%s\n' "$PASS" "$NEWPASS" "$NEWPASS" | kinit "$KUSER" && klist`,
			env:        []string{"PASS=" + password, "NEWPASS=" + newPassword},
			want:       []string{"Password expired", "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"},
		},
	}
	for _, tt := range tests {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(tt.clause+"/"+tt.name+"/"+transport, func(t *testing.T) {
				user := fmt.Sprintf("%s-%s", tt.user, transport)
				createUser(t, user, tt.mustChange)

				out, err := client(transport, tt.script, append(tt.env, "KUSER="+user)...)
				if (err != nil) != tt.wantErr {
					t.Fatalf("error = %v, wantErr %v\n%s", err, tt.wantErr, out)
				}
				for _, w := range tt.want {
					if !strings.Contains(out, w) {
						t.Errorf("output does not contain %q:\n%s", w, out)
					}
				}
				for _, w := range tt.notWant {
					if strings.Contains(out, w) {
						t.Errorf("output contains %q:\n%s", w, out)
					}
				}
			})
		}
	}

	// the scenarios pass either way, so check each proxy really used the
	// transport it was set up for
	t.Run("3.2.5.1-5/transport_used", func(t *testing.T) {
		if got := kerberosRequests(t, "kdcproxy-udp"); got["udp"] == 0 {
			t.Errorf("kdcproxy-udp requests = %v, want some over udp", got)
		}
		if got := kerberosRequests(t, "kdcproxy-tcp"); got["udp"] != 0 || got["tcp"] == 0 {
			t.Errorf("kdcproxy-tcp requests = %v, want only tcp", got)
		}
	})
}
