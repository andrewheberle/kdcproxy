package proxy

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/time/rate"
)

func TestUnmarshalKerbLength(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    int
		wantErr bool
	}{
		{"nil slice", nil, 0, true},
		{"too short 1/4", []byte{0}, 0, true},
		{"too short 2/4", []byte{0, 0}, 0, true},
		{"too short 3/4", []byte{0, 0, 0}, 0, true},
		{"length == 0", []byte{0, 0, 0, 0}, 0, false},
		{"length == 1", []byte{0, 0, 0, 1}, 1, false},
		{"length == 257", []byte{0, 0, 1, 1}, 257, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalKerbLength(tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalKerbLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("UnmarshalKerbLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalKerbLength(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []byte
	}{
		{"zero length", 0, []byte{0, 0, 0, 0}},
		{"length == 1", 1, []byte{0, 0, 0, 1}},
		{"length == 257", 257, []byte{0, 0, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MarshalKerbLength(tt.n)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalKerbLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitKdcProxy_WithConfig(t *testing.T) {
	_, err := InitKdcProxy(WithConfig("missing.conf"))
	if err == nil {
		t.Errorf("expected error attempting to load missing config file, got nil")
	}
}

const testRealm = "FREEIPA.LOCAL"

// fixture returns a proxy message captured by latchset/kdcproxy
func fixture(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", "latchset", name+".der"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	return b
}

// fixtureKerbMessage returns the Kerberos message inside a fixture
func fixtureKerbMessage(t *testing.T, name string) []byte {
	t.Helper()

	var m KdcProxyMsg
	if _, err := asn1.Unmarshal(fixture(t, name), &m); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}

	return m.KerbMessage
}

// proxyMessage encodes a client proxy message; an empty targetDomain is omitted
func proxyMessage(t *testing.T, kerbMessage []byte, targetDomain string) []byte {
	t.Helper()

	b, err := asn1.Marshal(KdcProxyMsg{KerbMessage: kerbMessage, TargetDomain: targetDomain})
	if err != nil {
		t.Fatalf("encoding proxy message: %v", err)
	}

	return b
}

// serverProxyMessage encodes a proxy message carrying only kerb-message, as
// MS-KKDCP 3.2.5.2 requires of server replies
func serverProxyMessage(t *testing.T, kerbMessage []byte) []byte {
	t.Helper()

	b, err := asn1.Marshal(struct {
		KerbMessage []byte `asn1:"tag:0,explicit"`
	}{kerbMessage})
	if err != nil {
		t.Fatalf("encoding proxy message: %v", err)
	}

	return b
}

// krbError returns a KDC_ERR_PREAUTH_REQUIRED KRB-ERROR, the usual first reply to an AS-REQ
func krbError(t *testing.T) []byte {
	t.Helper()

	e := messages.NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+testRealm), testRealm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("encoding KRB-ERROR: %v", err)
	}

	return b
}

// withLengthPrefix adds the RFC 4120 7.2.2 length prefix
func withLengthPrefix(b []byte) []byte {
	return append(MarshalKerbLength(len(b)), b...)
}

// counterValue returns the current value of a Prometheus counter
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()

	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("reading counter: %v", err)
	}

	return m.GetCounter().GetValue()
}

func newTestProxy(t *testing.T, locator kdcLocator, dialer dialer) *KerberosProxy {
	t.Helper()

	k, err := InitKdcProxy()
	if err != nil {
		t.Fatalf("InitKdcProxy() error = %v", err)
	}
	k.locator = locator
	k.dialer = dialer

	return k
}

// These tests characterise the current behaviour of the handler, including
// where it deviates from MS-KKDCP. See docs/spec-conformance.md for the
// clauses and the issues that will change these expectations.

// TestHandlerRejects covers requests that are refused before reaching a KDC
func TestHandlerRejects(t *testing.T) {
	asReq := fixtureKerbMessage(t, "asreq1")

	tests := []struct {
		clause          string
		name            string
		method          string
		body            []byte
		contentLength   int64
		setup           func(*KerberosProxy)
		wantStatus      int
		wantContentType string
	}{
		{
			clause:          "2.1-1",
			name:            "get_not_allowed",
			method:          http.MethodGet,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
		},
		{
			clause:          "2.1-4",
			name:            "content_length_required",
			body:            fixture(t, "asreq1"),
			contentLength:   -1,
			wantStatus:      http.StatusLengthRequired,
			wantContentType: "text/plain; charset=utf-8",
		},
		{
			clause:          "2.1-4",
			name:            "body_too_large",
			body:            fixture(t, "asreq1"),
			contentLength:   maxLength + 1,
			wantStatus:      http.StatusRequestEntityTooLarge,
			wantContentType: "text/plain; charset=utf-8",
		},
		{
			clause:          "3.2.5.1-2",
			name:            "missing_target_domain",
			body:            proxyMessage(t, asReq, ""),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "text/plain; charset=utf-8",
		},
		{
			clause:          "5.1-2",
			name:            "rate_limited",
			body:            proxyMessage(t, asReq, testRealm),
			setup:           func(k *KerberosProxy) { k.limiter = rate.NewLimiter(0, 0) },
			wantStatus:      http.StatusTooManyRequests,
			wantContentType: "text/plain; charset=utf-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			locator := &fakeLocator{}
			dialer := &fakeDialer{}
			k := newTestProxy(t, locator, dialer)
			if tt.setup != nil {
				tt.setup(k)
			}

			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			r := httptest.NewRequest(method, "/KdcProxy", bytes.NewReader(tt.body))
			if tt.contentLength != 0 {
				r.ContentLength = tt.contentLength
			}
			w := httptest.NewRecorder()

			k.Handler(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if got := w.Header().Get("Content-Type"); got != tt.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantContentType)
			}
			if len(locator.calls) != 0 || len(dialer.dials) != 0 {
				t.Errorf("KDC contacted: locate calls %v, dials %v", locator.calls, dialer.dials)
			}
		})
	}
}

// TestHandlerDrops covers malformed messages, where MS-KKDCP 3.2.5.1-1 says
// to drop the connection rather than respond
func TestHandlerDrops(t *testing.T) {
	asReq := fixtureKerbMessage(t, "asreq1")

	tests := []struct {
		clause string
		name   string
		body   []byte
	}{
		{"2.1-4", "not_der", []byte("not a proxy message")},
		{"2.1-4", "trailing_data", append(fixture(t, "asreq1"), 0x00)},
		{"2.2.2-1", "empty", proxyMessage(t, []byte{}, testRealm)},
		{"2.2.2-1", "three_octets", proxyMessage(t, []byte{0, 0, 0}, testRealm)},
		{"2.2.2-1", "length_prefix_too_short", proxyMessage(t, append(MarshalKerbLength(len(asReq)-5), asReq[4:]...), testRealm)},
		{"2.2.2-1", "length_prefix_too_long", proxyMessage(t, append(MarshalKerbLength(len(asReq)-3), asReq[4:]...), testRealm)},
		{"2.2.2-1", "length_prefix_only", proxyMessage(t, MarshalKerbLength(0), testRealm)},
		{"3.2.5.1-1", "not_kerberos", proxyMessage(t, withLengthPrefix([]byte("not kerberos")), testRealm)},
		{"3.2.5.1-1", "kpasswd_req_not_recognised", fixture(t, "kpasswdreq")},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			locator := &fakeLocator{}
			dialer := &fakeDialer{}
			k := newTestProxy(t, locator, dialer)
			r := httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(tt.body))
			w := httptest.NewRecorder()
			dropped := counterValue(t, httpDropped.WithLabelValues(reasonMalformedKerberosMessage))

			defer func() {
				if got := recover(); got != http.ErrAbortHandler {
					t.Errorf("Handler() panic = %v, want %v", got, http.ErrAbortHandler)
				}
				if w.Body.Len() != 0 {
					t.Errorf("body = %q, want nothing written", w.Body.Bytes())
				}
				if got := counterValue(t, httpDropped.WithLabelValues(reasonMalformedKerberosMessage)) - dropped; got != 1 {
					t.Errorf("dropped connections counter increased by %v, want 1", got)
				}
				if len(locator.calls) != 0 || len(dialer.dials) != 0 {
					t.Errorf("KDC contacted: locate calls %v, dials %v", locator.calls, dialer.dials)
				}
			}()
			k.Handler(w, r)
		})
	}
}

// TestHandlerForwards covers requests that are forwarded to a KDC
func TestHandlerForwards(t *testing.T) {
	asReq := fixtureKerbMessage(t, "asreq1")
	tgsReq := fixtureKerbMessage(t, "tgsreq")
	reply := krbError(t)

	udpThenTCP := []locateCall{{realm: testRealm}, {realm: testRealm, tcp: true}}
	oneKDC := func(reply []byte) *fakeDialer {
		return &fakeDialer{kdcs: map[string]fakeKDC{
			"udp/kdc1:88": {reply: reply},
			"tcp/kdc1:88": {reply: reply},
		}}
	}

	tests := []struct {
		clause     string
		name       string
		body       []byte
		locator    *fakeLocator
		dialer     *fakeDialer
		setup      func(*KerberosProxy)
		wantStatus int
		wantReply  []byte
		wantLocate []locateCall
		wantSent   []sent
	}{
		{
			clause:     "4.1",
			name:       "as_req",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: udpThenTCP,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "tcp", addr: "kdc1:88", data: asReq},
			},
		},
		{
			clause:     "4.1",
			name:       "tgs_req",
			body:       fixture(t, "tgsreq"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: udpThenTCP,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: tgsReq[4:]},
				{network: "tcp", addr: "kdc1:88", data: tgsReq},
			},
		},
		{
			clause:     "2.2.2-2",
			name:       "routed_by_target_domain",
			body:       proxyMessage(t, asReq, "OTHER.REALM"),
			locator:    &fakeLocator{tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			setup:      func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 },
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: []locateCall{{realm: "OTHER.REALM", tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
		{
			clause:     "2.2.2-3",
			name:       "target_domain_located_as_sent",
			body:       proxyMessage(t, asReq, "freeipa.local"),
			locator:    &fakeLocator{tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			setup:      func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 },
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: []locateCall{{realm: "freeipa.local", tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
		{
			clause:     "3.2.5.1-5",
			name:       "udp_reply_times_out_then_tcp",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: reply},
				"tcp/kdc2:88": {reply: []byte("from tcp")},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix([]byte("from tcp")),
			wantLocate: udpThenTCP,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "tcp", addr: "kdc2:88", data: asReq},
			},
		},
		{
			clause:     "3.2.5.1-5",
			name:       "over_udp_preference_limit_tcp_only",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			setup:      func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = len(asReq) - 5 },
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: []locateCall{{realm: testRealm, tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
		{
			clause:  "3.2.5.1-5",
			name:    "next_kdc_after_dial_failure",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{tcp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"tcp/kdc1:88": {dialErr: errors.New("connection refused")},
				"tcp/kdc2:88": {reply: reply},
			}},
			setup:      func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 },
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: []locateCall{{realm: testRealm, tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc2:88", data: asReq}},
		},
		{
			clause:     "3.2.5.1-5",
			name:       "no_kdcs",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{err: errors.New("no KDC SRV records")},
			dialer:     &fakeDialer{},
			wantStatus: http.StatusServiceUnavailable,
			wantLocate: udpThenTCP,
		},
		{
			clause:     "3.2.5.2-1",
			name:       "tcp_reply_not_validated",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{tcp: []string{"kdc1:88"}},
			dialer:     oneKDC([]byte("not kerberos")),
			setup:      func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 },
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix([]byte("not kerberos")),
			wantLocate: []locateCall{{realm: testRealm, tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			k := newTestProxy(t, tt.locator, tt.dialer)
			if tt.setup != nil {
				tt.setup(k)
			}

			r := httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(tt.body))
			w := httptest.NewRecorder()

			k.Handler(w, r)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tt.wantStatus, w.Body.Bytes())
			}
			if tt.wantReply != nil {
				// 3.2.5.2-1, 2.2.2-4: the reply carries only kerb-message
				if got, want := w.Body.Bytes(), serverProxyMessage(t, tt.wantReply); !bytes.Equal(got, want) {
					t.Errorf("body = %x, want %x", got, want)
				}
				// 3.2.5.2-2
				if got := w.Header().Get("Content-Type"); got != "application/kerberos" {
					t.Errorf("Content-Type = %q, want %q", got, "application/kerberos")
				}
			}
			if !reflect.DeepEqual(tt.locator.calls, tt.wantLocate) {
				t.Errorf("locate calls = %+v, want %+v", tt.locator.calls, tt.wantLocate)
			}
			if !slices.EqualFunc(tt.dialer.sent, tt.wantSent, func(a, b sent) bool {
				return a.network == b.network && a.addr == b.addr && bytes.Equal(a.data, b.data)
			}) {
				t.Errorf("sent = %+v, want %+v", tt.dialer.sent, tt.wantSent)
			}
		})
	}
}

func TestKrb5Locator(t *testing.T) {
	cfg, err := krb5config.NewFromString(`[libdefaults]
 dns_lookup_kdc = false
 dns_lookup_realm = false

[realms]
 FREEIPA.LOCAL = {
  kdc = kdc1.freeipa.local:88
  kdc = kdc2.freeipa.local:88
  kpasswd_server = kpasswd.freeipa.local:464
 }
`)
	if err != nil {
		t.Fatalf("parsing krb5.conf: %v", err)
	}
	l := &krb5Locator{config: cfg}

	tests := []struct {
		clause  string
		name    string
		realm   string
		kpasswd bool
		want    []string
		wantErr bool
	}{
		{"3.2.5.1-3", "kdcs_from_krb5conf", testRealm, false, []string{"kdc1.freeipa.local:88", "kdc2.freeipa.local:88"}, false},
		{"3.2.5.1-3", "kpasswd_from_krb5conf", testRealm, true, []string{"kpasswd.freeipa.local:464"}, false},
		{"3.2.5.1-3", "unknown_realm", "OTHER.REALM", false, nil, true},
		{"2.2.2-3", "kdcs_realm_case_insensitive", "freeipa.local", false, []string{"kdc1.freeipa.local:88", "kdc2.freeipa.local:88"}, false},
		{"2.2.2-3", "kpasswd_realm_case_insensitive", "FreeIPA.Local", true, []string{"kpasswd.freeipa.local:464"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			got, err := l.locate(t.Context(), tt.realm, true, tt.kpasswd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("locate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// krb5.conf servers are shuffled, so compare as a set
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("locate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestKdcProxyMsgEncoding checks KdcProxyMsg against proxy messages from real
// KKDCP clients, so the struct cannot drift from the wire format unnoticed
func TestKdcProxyMsgEncoding(t *testing.T) {
	tests := []struct {
		clause  string
		name    string
		fixture string
	}{
		{"2.2.2-2", "as_req", "asreq1"},
		{"2.2.2-2", "as_req_preauth", "asreq2"},
		{"2.2.2-2", "tgs_req", "tgsreq"},
		{"2.2.2-2", "kpasswd_req", "kpasswdreq"},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			b := fixture(t, tt.fixture)

			var m KdcProxyMsg
			if _, err := asn1.Unmarshal(b, &m); err != nil {
				t.Fatalf("asn1.Unmarshal() error = %v", err)
			}
			if m.TargetDomain != testRealm {
				t.Errorf("TargetDomain = %q, want %q", m.TargetDomain, testRealm)
			}

			got, err := asn1.Marshal(m)
			if err != nil {
				t.Fatalf("asn1.Marshal() error = %v", err)
			}
			if !bytes.Equal(got, b) {
				t.Errorf("asn1.Marshal() = %x, want %x", got, b)
			}
		})
	}
}
