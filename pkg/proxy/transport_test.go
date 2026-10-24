package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/prometheus/client_golang/prometheus"
)

func TestUDPTransport(t *testing.T) {
	msg := fixtureKerbMessage(t, "asreq1")[4:]
	reply := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")

	tests := []struct {
		name      string
		kdc       fakeKDC
		want      []byte
		wantErr   error
		wantResps float64
	}{
		{name: "reply", kdc: fakeKDC{reply: reply}, want: reply, wantResps: 1},
		{name: "response_too_big", kdc: fakeKDC{reply: krbError(t, errorcode.KRB_ERR_RESPONSE_TOO_BIG, "")}, wantErr: errResponseTooBig, wantResps: 1},
		{name: "no_reply", kdc: fakeKDC{}, wantErr: errAny},
		{name: "dial_error", kdc: fakeKDC{dialErr: errors.New("refused")}, wantErr: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &fakeDialer{kdcs: map[string]fakeKDC{"udp/kdc1:88": tt.kdc}}
			m := newMetrics(prometheus.NewRegistry())

			got, err := udpTransport{dialer: d, metrics: m}.exchange(context.Background(), "kdc1:88", msg)

			checkExchange(t, got, err, tt.want, tt.wantErr)
			if tt.kdc.dialErr == nil {
				if len(d.sent) != 1 || !bytes.Equal(d.sent[0].data, msg) {
					t.Errorf("sent %v, want the message without its length prefix", d.sent)
				}
			}
			if got := counterValue(t, m.kerbReqs.WithLabelValues(protoUdp)); got != 1 {
				t.Errorf("udp requests = %v, want 1", got)
			}
			if got := counterValue(t, m.kerbResp.WithLabelValues(protoUdp)); got != tt.wantResps {
				t.Errorf("udp responses = %v, want %v", got, tt.wantResps)
			}
		})
	}
}

func TestTCPTransport(t *testing.T) {
	msg := fixtureKerbMessage(t, "asreq1")[4:]
	reply := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")

	tests := []struct {
		name      string
		kdc       fakeKDC
		want      []byte
		wantErr   error
		wantResps float64
	}{
		{name: "reply", kdc: fakeKDC{reply: reply}, want: reply, wantResps: 1},
		{name: "empty_reply", kdc: fakeKDC{reply: []byte{}}, want: []byte{}, wantResps: 1},
		{name: "truncated_prefix", kdc: fakeKDC{raw: []byte{0, 0}}, wantErr: errAny},
		{name: "truncated_reply", kdc: fakeKDC{raw: append(MarshalKerbLength(len(reply)), reply[:len(reply)-1]...)}, wantErr: errAny},
		{name: "dial_error", kdc: fakeKDC{dialErr: errors.New("refused")}, wantErr: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &fakeDialer{kdcs: map[string]fakeKDC{"tcp/kdc1:88": tt.kdc}}
			m := newMetrics(prometheus.NewRegistry())

			got, err := tcpTransport{dialer: d, metrics: m}.exchange(context.Background(), "kdc1:88", msg)

			checkExchange(t, got, err, tt.want, tt.wantErr)
			if tt.kdc.dialErr == nil {
				if want := append(MarshalKerbLength(len(msg)), msg...); len(d.sent) != 1 || !bytes.Equal(d.sent[0].data, want) {
					t.Errorf("sent %v, want the message with its length prefix", d.sent)
				}
			}
			if got := counterValue(t, m.kerbReqs.WithLabelValues(protoTcp)); got != 1 {
				t.Errorf("tcp requests = %v, want 1", got)
			}
			if got := counterValue(t, m.kerbResp.WithLabelValues(protoTcp)); got != tt.wantResps {
				t.Errorf("tcp responses = %v, want %v", got, tt.wantResps)
			}
		})
	}
}

// errAny is a wantErr for any non-nil error
var errAny = errors.New("any error")

// checkExchange checks the reply and error from an exchange
func checkExchange(t *testing.T, got []byte, err error, want []byte, wantErr error) {
	t.Helper()

	switch {
	case wantErr == nil && err != nil:
		t.Fatalf("exchange() error = %v, want nil", err)
	case wantErr == errAny && err == nil:
		t.Fatalf("exchange() error = nil, want an error")
	case wantErr != nil && wantErr != errAny && !errors.Is(err, wantErr):
		t.Fatalf("exchange() error = %v, want %v", err, wantErr)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("exchange() = %x, want %x", got, want)
	}
}

// prefixOnlyConn is a TCP connection that sends only a length prefix and
// records any attempt to read past it
type prefixOnlyConn struct {
	net.Conn
	prefix   []byte
	bodyRead bool
}

func (c *prefixOnlyConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	c.bodyRead = true

	return 0, io.EOF
}

func (c *prefixOnlyConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *prefixOnlyConn) Close() error                { return nil }
func (c *prefixOnlyConn) SetDeadline(time.Time) error { return nil }

// connDialer returns conn for every dial
type connDialer struct {
	conn net.Conn
}

func (d connDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

// TestTCPTransportReplyLength checks an oversized TCP reply is refused before
// its body is read or allocated
func TestTCPTransportReplyLength(t *testing.T) {
	tests := []struct {
		clause       string
		name         string
		length       int
		wantBodyRead bool
	}{
		{"5.1-1", "at_max", maxLength, true},
		{"5.1-1", "over_max", maxLength + 1, false},
		{"5.1-1", "high_bit", 1 << 31, false},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			conn := &prefixOnlyConn{prefix: MarshalKerbLength(tt.length)}
			tr := tcpTransport{dialer: connDialer{conn: conn}, metrics: newMetrics(prometheus.NewRegistry())}

			if _, err := tr.exchange(context.Background(), "kdc1:88", []byte("request")); err == nil {
				t.Errorf("exchange() error = nil, want error")
			}
			if conn.bodyRead != tt.wantBodyRead {
				t.Errorf("body read = %v, want %v", conn.bodyRead, tt.wantBodyRead)
			}
		})
	}
}
