package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
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

// TestNewKdcProxySharesMetrics checks proxies registered with the same registry
// share its metrics rather than failing to register them again
func TestNewKdcProxySharesMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()

	first, err := newKdcProxy(reg)
	if err != nil {
		t.Fatalf("first newKdcProxy() error = %v", err)
	}
	second, err := newKdcProxy(reg)
	if err != nil {
		t.Fatalf("second newKdcProxy() error = %v", err)
	}

	if first.metrics.httpResp != second.metrics.httpResp {
		t.Errorf("proxies have separate responses counters, want them shared")
	}
	if first.metrics.kerbReqs != second.metrics.kerbReqs {
		t.Errorf("proxies have separate Kerberos requests counters, want them shared")
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

// krbError returns a KRB-ERROR with the given error code
func krbError(t *testing.T, code int32, etext string) []byte {
	t.Helper()

	e := messages.NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+testRealm), testRealm, code, etext)
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("encoding KRB-ERROR: %v", err)
	}

	return b
}

// kdcRepFields returns the fields of an AS-REP or TGS-REP with dummy encrypted parts
func kdcRepFields(msgType int) messages.KDCRepFields {
	encrypted := types.EncryptedData{EType: 18, Cipher: []byte{0}}

	return messages.KDCRepFields{
		PVNO:    5,
		MsgType: msgType,
		CRealm:  testRealm,
		CName:   types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "admin"),
		Ticket: messages.Ticket{
			TktVNO:  5,
			Realm:   testRealm,
			SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+testRealm),
			EncPart: encrypted,
		},
		EncPart: encrypted,
	}
}

// asRep returns an AS-REP
func asRep(t *testing.T) []byte {
	t.Helper()

	r := messages.ASRep{KDCRepFields: kdcRepFields(msgtype.KRB_AS_REP)}
	b, err := r.Marshal()
	if err != nil {
		t.Fatalf("encoding AS-REP: %v", err)
	}
	if err := r.Unmarshal(b); err != nil {
		t.Fatalf("decoding AS-REP: %v", err)
	}

	return b
}

// tgsRep returns a TGS-REP
func tgsRep(t *testing.T) []byte {
	t.Helper()

	r := messages.TGSRep{KDCRepFields: kdcRepFields(msgtype.KRB_TGS_REP)}
	b, err := r.Marshal()
	if err != nil {
		t.Fatalf("encoding TGS-REP: %v", err)
	}
	if err := r.Unmarshal(b); err != nil {
		t.Fatalf("decoding TGS-REP: %v", err)
	}

	return b
}

// apRep returns an AP-REP, which a KDC never sends on its own
func apRep(t *testing.T) []byte {
	t.Helper()

	r := messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: types.EncryptedData{EType: 18, Cipher: []byte{0}}}
	b, err := asn1.Marshal(r)
	if err != nil {
		t.Fatalf("encoding AP-REP: %v", err)
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.APREP)
	if err := r.Unmarshal(b); err != nil {
		t.Fatalf("decoding AP-REP: %v", err)
	}

	return b
}

// kpasswdMessage frames a password change request or reply:
// message length (2) | version (2) | AP-REQ/AP-REP length (2) | ap | rest
func kpasswdMessage(version uint16, ap, rest []byte) []byte {
	b := make([]byte, 6, 6+len(ap)+len(rest))
	binary.BigEndian.PutUint16(b[0:2], uint16(6+len(ap)+len(rest)))
	binary.BigEndian.PutUint16(b[2:4], version)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(ap)))

	return append(append(b, ap...), rest...)
}

// kpasswdParts returns the AP-REQ and KRB-PRIV of the latchset password change request
func kpasswdParts(t *testing.T) (apReq, krbPriv []byte) {
	t.Helper()

	msg := fixtureKerbMessage(t, "kpasswdreq")[4:]
	l := int(binary.BigEndian.Uint16(msg[4:6]))

	return msg[6 : 6+l], msg[6+l:]
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

	k, err := newKdcProxy(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("newKdcProxy() error = %v", err)
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
	apReq, krbPriv := kpasswdParts(t)

	badMessageLength := kpasswdMessage(0x0001, apReq, krbPriv)
	binary.BigEndian.PutUint16(badMessageLength[0:2], uint16(len(badMessageLength)+1))
	apReqPastEnd := kpasswdMessage(0x0001, apReq, krbPriv)
	binary.BigEndian.PutUint16(apReqPastEnd[4:6], uint16(len(apReqPastEnd)))

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
		{"3.2.5.1-1", "bare_ap_req", proxyMessage(t, withLengthPrefix(apReq), testRealm)},
		{"3.2.5.1-1", "kpasswd_too_short", proxyMessage(t, withLengthPrefix([]byte{0, 5, 0, 1, 0}), testRealm)},
		{"3.2.5.1-1", "kpasswd_bad_message_length", proxyMessage(t, withLengthPrefix(badMessageLength), testRealm)},
		{"3.2.5.1-1", "kpasswd_bad_version", proxyMessage(t, withLengthPrefix(kpasswdMessage(0x0002, apReq, krbPriv)), testRealm)},
		{"3.2.5.1-1", "kpasswd_ap_req_length_past_end", proxyMessage(t, withLengthPrefix(apReqPastEnd), testRealm)},
		{"3.2.5.1-1", "kpasswd_ap_req_invalid", proxyMessage(t, withLengthPrefix(kpasswdMessage(0x0001, []byte("not an AP-REQ"), krbPriv)), testRealm)},
		{"3.2.5.1-1", "kpasswd_krb_priv_invalid", proxyMessage(t, withLengthPrefix(kpasswdMessage(0x0001, apReq, []byte("not a KRB-PRIV"))), testRealm)},
		{"3.2.5.1-1", "kpasswd_krb_priv_missing", proxyMessage(t, withLengthPrefix(kpasswdMessage(0x0001, apReq, nil)), testRealm)},
	}
	for _, tt := range tests {
		t.Run(tt.clause+"/"+tt.name, func(t *testing.T) {
			locator := &fakeLocator{}
			dialer := &fakeDialer{}
			k := newTestProxy(t, locator, dialer)
			r := httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(tt.body))
			w := httptest.NewRecorder()

			defer func() {
				if got := recover(); got != http.ErrAbortHandler {
					t.Errorf("Handler() panic = %v, want %v", got, http.ErrAbortHandler)
				}
				if w.Body.Len() != 0 {
					t.Errorf("body = %q, want nothing written", w.Body.Bytes())
				}
				if got := counterValue(t, k.metrics.httpDropped.WithLabelValues(reasonMalformedKerberosMessage)); got != 1 {
					t.Errorf("dropped connections = %v, want 1", got)
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
	reply := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
	fromKDC2 := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "kdc2")
	unknown := krbError(t, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "")
	tooBig := krbError(t, errorcode.KRB_ERR_RESPONSE_TOO_BIG, "")
	garbage := []byte("not kerberos")

	kpasswdReq := fixtureKerbMessage(t, "kpasswdreq")
	apReq, krbPriv := kpasswdParts(t)
	setPasswordReq := withLengthPrefix(kpasswdMessage(0xff80, apReq, krbPriv))
	changed := kpasswdMessage(0x0001, apRep(t), krbPriv)
	kpasswdErr := kpasswdMessage(0x0001, nil, reply)
	badLength := kpasswdMessage(0x0001, apRep(t), krbPriv)
	binary.BigEndian.PutUint16(badLength[0:2], uint16(len(badLength)-1))
	kpasswdUDP := []locateCall{{realm: testRealm, kpasswd: true}}
	kpasswdServers := func(replies ...[]byte) *fakeDialer {
		d := &fakeDialer{kdcs: map[string]fakeKDC{}}
		for i, r := range replies {
			d.kdcs[fmt.Sprintf("udp/kpasswd%d:464", i+1)] = fakeKDC{reply: r}
		}
		return d
	}

	udpOnly := []locateCall{{realm: testRealm}}
	udpThenTCP := []locateCall{{realm: testRealm}, {realm: testRealm, tcp: true}}
	tcpOnly := []locateCall{{realm: testRealm, tcp: true}}
	forceTCP := func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 }
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
			dialer:     oneKDC(asRep(t)),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(asRep(t)),
			wantLocate: udpOnly,
			wantSent:   []sent{{network: "udp", addr: "kdc1:88", data: asReq[4:]}},
		},
		{
			clause:     "4.1",
			name:       "tgs_req",
			body:       fixture(t, "tgsreq"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(tgsRep(t)),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(tgsRep(t)),
			wantLocate: udpOnly,
			wantSent:   []sent{{network: "udp", addr: "kdc1:88", data: tgsReq[4:]}},
		},
		{
			clause:     "2.2.2-2",
			name:       "routed_by_target_domain",
			body:       proxyMessage(t, asReq, "OTHER.REALM"),
			locator:    &fakeLocator{tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			setup:      forceTCP,
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
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: []locateCall{{realm: "freeipa.local", tcp: true}},
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
		{
			clause:  "3.2.5.1-5",
			name:    "udp_timeout_then_tcp",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {},
				"tcp/kdc2:88": {reply: fromKDC2},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
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
			wantLocate: tcpOnly,
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
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: tcpOnly,
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
			name:       "krb_error_relayed_over_udp",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: udpOnly,
			wantSent:   []sent{{network: "udp", addr: "kdc1:88", data: asReq[4:]}},
		},
		{
			clause:     "3.2.5.2-1",
			name:       "krb_error_relayed_over_tcp",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(reply),
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: tcpOnly,
			wantSent:   []sent{{network: "tcp", addr: "kdc1:88", data: asReq}},
		},
		{
			clause:  "3.2.5.2-1",
			name:    "krb_error_not_retried",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{udp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: unknown},
				"udp/kdc2:88": {reply: fromKDC2},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(unknown),
			wantLocate: udpOnly,
			wantSent:   []sent{{network: "udp", addr: "kdc1:88", data: asReq[4:]}},
		},
		{
			clause:  "3.2.5.2-1",
			name:    "response_too_big_moves_to_tcp",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{udp: []string{"kdc1:88", "kdc2:88"}, tcp: []string{"kdc3:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: tooBig},
				"udp/kdc2:88": {reply: tooBig},
				"tcp/kdc3:88": {reply: reply},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: udpThenTCP,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "tcp", addr: "kdc3:88", data: asReq},
			},
		},
		{
			clause:  "5.1-1",
			name:    "udp_invalid_reply_next_kdc",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{udp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: garbage},
				"udp/kdc2:88": {reply: fromKDC2},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: udpOnly,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "udp", addr: "kdc2:88", data: asReq[4:]},
			},
		},
		{
			clause:  "5.1-1",
			name:    "tcp_invalid_reply_next_kdc",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{tcp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"tcp/kdc1:88": {reply: garbage},
				"tcp/kdc2:88": {reply: fromKDC2},
			}},
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: tcpOnly,
			wantSent: []sent{
				{network: "tcp", addr: "kdc1:88", data: asReq},
				{network: "tcp", addr: "kdc2:88", data: asReq},
			},
		},
		{
			clause:  "5.1-1",
			name:    "ap_rep_not_relayed",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{tcp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"tcp/kdc1:88": {reply: apRep(t)},
				"tcp/kdc2:88": {reply: fromKDC2},
			}},
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: tcpOnly,
			wantSent: []sent{
				{network: "tcp", addr: "kdc1:88", data: asReq},
				{network: "tcp", addr: "kdc2:88", data: asReq},
			},
		},
		{
			clause:  "5.1-1",
			name:    "tcp_length_prefix_over_max",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{tcp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"tcp/kdc1:88": {raw: append(MarshalKerbLength(maxLength+1), make([]byte, maxLength+1)...)},
				"tcp/kdc2:88": {reply: fromKDC2},
			}},
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: tcpOnly,
			wantSent: []sent{
				{network: "tcp", addr: "kdc1:88", data: asReq},
				{network: "tcp", addr: "kdc2:88", data: asReq},
			},
		},
		{
			clause:  "5.1-1",
			name:    "tcp_length_prefix_high_bit",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{tcp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"tcp/kdc1:88": {raw: append(MarshalKerbLength(1<<31|len(reply)), reply...)},
				"tcp/kdc2:88": {reply: fromKDC2},
			}},
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: tcpOnly,
			wantSent: []sent{
				{network: "tcp", addr: "kdc1:88", data: asReq},
				{network: "tcp", addr: "kdc2:88", data: asReq},
			},
		},
		{
			clause:     "4.2",
			name:       "change_password",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464"}},
			dialer:     kpasswdServers(changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent:   []sent{{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]}},
		},
		{
			clause:     "4.2",
			name:       "set_password",
			body:       proxyMessage(t, setPasswordReq, testRealm),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464"}},
			dialer:     kpasswdServers(changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent:   []sent{{network: "udp", addr: "kpasswd1:464", data: setPasswordReq[4:]}},
		},
		{
			clause:     "4.2",
			name:       "change_password_over_tcp",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{tcp: []string{"kpasswd1:464"}},
			dialer:     &fakeDialer{kdcs: map[string]fakeKDC{"tcp/kpasswd1:464": {reply: changed}}},
			setup:      forceTCP,
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: []locateCall{{realm: testRealm, tcp: true, kpasswd: true}},
			wantSent:   []sent{{network: "tcp", addr: "kpasswd1:464", data: kpasswdReq}},
		},
		{
			clause:     "4.2",
			name:       "framed_krb_error_relayed",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464"}},
			dialer:     kpasswdServers(kpasswdErr),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(kpasswdErr),
			wantLocate: kpasswdUDP,
			wantSent:   []sent{{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]}},
		},
		{
			clause:     "4.2",
			name:       "bare_krb_error_relayed",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464"}},
			dialer:     kpasswdServers(reply),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(reply),
			wantLocate: kpasswdUDP,
			wantSent:   []sent{{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]}},
		},
		{
			clause:     "4.2",
			name:       "no_kpasswd_server",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{err: errors.New("no kpasswd SRV records")},
			dialer:     &fakeDialer{},
			wantStatus: http.StatusServiceUnavailable,
			wantLocate: []locateCall{{realm: testRealm, kpasswd: true}, {realm: testRealm, tcp: true, kpasswd: true}},
		},
		{
			clause:     "5.1-1",
			name:       "kpasswd_reply_bad_version",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464", "kpasswd2:464"}},
			dialer:     kpasswdServers(kpasswdMessage(0xff80, apRep(t), krbPriv), changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent: []sent{
				{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]},
				{network: "udp", addr: "kpasswd2:464", data: kpasswdReq[4:]},
			},
		},
		{
			clause:     "5.1-1",
			name:       "kpasswd_reply_bad_message_length",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464", "kpasswd2:464"}},
			dialer:     kpasswdServers(badLength, changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent: []sent{
				{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]},
				{network: "udp", addr: "kpasswd2:464", data: kpasswdReq[4:]},
			},
		},
		{
			clause:     "5.1-1",
			name:       "kpasswd_reply_ap_rep_truncated",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464", "kpasswd2:464"}},
			dialer:     kpasswdServers(kpasswdMessage(0x0001, apRep(t)[:10], krbPriv), changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent: []sent{
				{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]},
				{network: "udp", addr: "kpasswd2:464", data: kpasswdReq[4:]},
			},
		},
		{
			clause:     "5.1-1",
			name:       "kpasswd_reply_short",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464", "kpasswd2:464"}},
			dialer:     kpasswdServers([]byte{0, 5, 0, 1, 0}, changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent: []sent{
				{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]},
				{network: "udp", addr: "kpasswd2:464", data: kpasswdReq[4:]},
			},
		},
		{
			clause:     "5.1-1",
			name:       "kdc_reply_to_kpasswd_req_not_relayed",
			body:       fixture(t, "kpasswdreq"),
			locator:    &fakeLocator{udp: []string{"kpasswd1:464", "kpasswd2:464"}},
			dialer:     kpasswdServers(asRep(t), changed),
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(changed),
			wantLocate: kpasswdUDP,
			wantSent: []sent{
				{network: "udp", addr: "kpasswd1:464", data: kpasswdReq[4:]},
				{network: "udp", addr: "kpasswd2:464", data: kpasswdReq[4:]},
			},
		},
		{
			clause:  "5.1-1",
			name:    "kpasswd_reply_to_as_req_not_relayed",
			body:    fixture(t, "asreq1"),
			locator: &fakeLocator{udp: []string{"kdc1:88", "kdc2:88"}},
			dialer: &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: changed},
				"udp/kdc2:88": {reply: fromKDC2},
			}},
			wantStatus: http.StatusOK,
			wantReply:  withLengthPrefix(fromKDC2),
			wantLocate: udpOnly,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "udp", addr: "kdc2:88", data: asReq[4:]},
			},
		},
		{
			clause:     "5.1-1",
			name:       "no_valid_reply",
			body:       fixture(t, "asreq1"),
			locator:    &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}},
			dialer:     oneKDC(garbage),
			wantStatus: http.StatusServiceUnavailable,
			wantLocate: udpThenTCP,
			wantSent: []sent{
				{network: "udp", addr: "kdc1:88", data: asReq[4:]},
				{network: "tcp", addr: "kdc1:88", data: asReq},
			},
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

// prefixOnlyConn is a TCP connection that sends only a length prefix and
// records any attempt to read past it
type prefixOnlyConn struct {
	fakeUDPConn
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

func (c *prefixOnlyConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// TestGetResponseLengthLimit checks an oversized TCP reply is refused before
// its body is read or allocated
func TestGetResponseLengthLimit(t *testing.T) {
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

			k := newTestProxy(t, &fakeLocator{}, &fakeDialer{})
			if _, err := k.getresponse(conn, validReply); err == nil {
				t.Errorf("getresponse() error = nil, want error")
			}
			if conn.bodyRead != tt.wantBodyRead {
				t.Errorf("body read = %v, want %v", conn.bodyRead, tt.wantBodyRead)
			}
		})
	}
}

// TestKerberosRequestsMetric checks requests to KDCs are counted by protocol
func TestKerberosRequestsMetric(t *testing.T) {
	reply := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")

	tests := []struct {
		name    string
		setup   func(*KerberosProxy)
		wantUDP float64
		wantTCP float64
	}{
		{"udp", nil, 1, 0},
		{"tcp", func(k *KerberosProxy) { k.krb5Config.LibDefaults.UDPPreferenceLimit = 1 }, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newTestProxy(t, &fakeLocator{udp: []string{"kdc1:88"}, tcp: []string{"kdc1:88"}}, &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: reply},
				"tcp/kdc1:88": {reply: reply},
			}})
			if tt.setup != nil {
				tt.setup(k)
			}
			k.Handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(fixture(t, "asreq1"))))

			if got := counterValue(t, k.metrics.kerbReqs.WithLabelValues(protoUdp)); got != tt.wantUDP {
				t.Errorf("udp requests = %v, want %v", got, tt.wantUDP)
			}
			if got := counterValue(t, k.metrics.kerbReqs.WithLabelValues(protoTcp)); got != tt.wantTCP {
				t.Errorf("tcp requests = %v, want %v", got, tt.wantTCP)
			}
		})
	}
}

// TestHTTPResponsesMetric checks each response is counted once under its
// status, and a dropped connection is counted as dropped rather than as a response
func TestHTTPResponsesMetric(t *testing.T) {
	reply := krbError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")

	tests := []struct {
		name          string
		method        string
		body          []byte
		contentLength int64
		setup         func(*KerberosProxy)
		locator       *fakeLocator
		wantCode      string
		wantDropped   bool
	}{
		{name: "ok", locator: &fakeLocator{udp: []string{"kdc1:88"}}, wantCode: http.StatusText(http.StatusOK)},
		{name: "method_not_allowed", method: http.MethodGet, wantCode: http.StatusText(http.StatusMethodNotAllowed)},
		{name: "length_required", contentLength: -1, wantCode: http.StatusText(http.StatusLengthRequired)},
		{name: "request_entity_too_large", contentLength: maxLength + 1, wantCode: http.StatusText(http.StatusRequestEntityTooLarge)},
		{name: "too_many_requests", setup: func(k *KerberosProxy) { k.limiter = rate.NewLimiter(0, 0) }, wantCode: http.StatusText(http.StatusTooManyRequests)},
		{name: "bad_request", body: proxyMessage(t, fixtureKerbMessage(t, "asreq1"), ""), wantCode: http.StatusText(http.StatusBadRequest)},
		{name: "service_unavailable", wantCode: http.StatusText(http.StatusServiceUnavailable)},
		{name: "dropped", body: []byte("not a proxy message"), wantDropped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locator := tt.locator
			if locator == nil {
				locator = &fakeLocator{}
			}
			k := newTestProxy(t, locator, &fakeDialer{kdcs: map[string]fakeKDC{
				"udp/kdc1:88": {reply: reply},
			}})
			if tt.setup != nil {
				tt.setup(k)
			}
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			body := tt.body
			if body == nil {
				body = fixture(t, "asreq1")
			}
			r := httptest.NewRequest(method, "/KdcProxy", bytes.NewReader(body))
			if tt.contentLength != 0 {
				r.ContentLength = tt.contentLength
			}

			func() {
				defer func() {
					if got := recover(); got != nil && (!tt.wantDropped || got != http.ErrAbortHandler) {
						panic(got)
					}
				}()
				k.Handler(httptest.NewRecorder(), r)
			}()

			wantTotal, wantDropped := 1.0, 0.0
			if tt.wantDropped {
				wantTotal, wantDropped = 0, 1
			}
			if got := responsesTotal(t, k.metrics.httpResp); got != wantTotal {
				t.Errorf("responses = %v in total, want %v", got, wantTotal)
			}
			if !tt.wantDropped {
				if got := counterValue(t, k.metrics.httpResp.WithLabelValues(tt.wantCode)); got != 1 {
					t.Errorf("responses with code %q = %v, want 1", tt.wantCode, got)
				}
			}
			if got := counterValue(t, k.metrics.httpDropped.WithLabelValues(reasonMalformedKerberosMessage)); got != wantDropped {
				t.Errorf("dropped connections = %v, want %v", got, wantDropped)
			}
		})
	}
}

// responsesTotal returns the sum of the responses counter across all codes
func responsesTotal(t *testing.T, httpResp *prometheus.CounterVec) float64 {
	t.Helper()

	ch := make(chan prometheus.Metric)
	go func() {
		httpResp.Collect(ch)
		close(ch)
	}()

	var total float64
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("reading counter: %v", err)
		}
		total += d.GetCounter().GetValue()
	}

	return total
}
