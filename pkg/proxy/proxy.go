package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	"golang.org/x/time/rate"
)

const (
	maxLength = 128 * 1024
	timeout   = 2 * time.Second
	protoUdp  = "udp"
	protoTcp  = "tcp"
)

// DefaultRateLimit is the default number of requests per second to allow
const DefaultRateLimit = 10

// KdcProxyMsg represents a KDC_PROXY_MESSAGE as per https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5778aff5-b182-4b97-a970-29c7f911eef2
type KdcProxyMsg struct {
	KerbMessage   []byte `asn1:"tag:0,explicit"`
	TargetDomain  string `asn1:"tag:1,optional,generalstring"`
	DcLocatorHint int    `asn1:"tag:2,optional"`
}

// KerberosProxy is a KDC Proxy
type KerberosProxy struct {
	config string

	krb5Config *krb5config.Config
	limiter    *rate.Limiter
}

// InitKdcProxy creates a KerberosProxy using the defaults of looking up KDC's via DNS
// with the abilty to override these defaults by providing ...[ProxyOption]
func InitKdcProxy(opts ...ProxyOption) (*KerberosProxy, error) {
	// set defaults
	cfg := krb5config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	kp := &KerberosProxy{
		krb5Config: cfg,
		limiter:    rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultRateLimit),
	}

	// apply options
	for _, o := range opts {
		o(kp)
	}

	// load config if set
	if kp.config != "" {
		// load config from file
		cfg, err := krb5config.Load(kp.config)
		if err != nil {
			return nil, err
		}

		kp.krb5Config = cfg
	}

	return kp, nil
}

// Deprecated: Use InitKdcProxy(WithConfig(config)) instead
func InitKdcProxyWithConfig(config string) (*KerberosProxy, error) {
	return InitKdcProxy(WithConfig(config))
}

// Deprecated: Use InitKdcProxy(WithLimit(limit)) instead
func InitKdcProxyWithLimit(limit int) (*KerberosProxy, error) {
	return InitKdcProxy(WithLimit(limit))
}

// Deprecated: Use InitKdcProxy(WithConfig(config), WithLimit(limit)) instead
func InitKdcProxyWithConfigAndLimit(config string, limit int) (*KerberosProxy, error) {
	return InitKdcProxy(WithConfig(config), WithLimit(limit))
}

// Handler implements a KDC Proxy endpoint over HTTP
func (k *KerberosProxy) Handler(w http.ResponseWriter, r *http.Request) {
	// metrics
	httpReqs.Inc()
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		httpRespTimeHistogram.Observe(duration.Seconds())
	}()

	// ensure content type is always "application/kerberos"
	w.Header().Set("Content-Type", "application/kerberos")

	// we only handle POST's
	if r.Method != http.MethodPost {
		httpResp.WithLabelValues(http.StatusText(http.StatusMethodNotAllowed)).Inc()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check content length is valid
	length := r.ContentLength
	if length == -1 {
		httpResp.WithLabelValues(http.StatusText(http.StatusLengthRequired)).Inc()
		http.Error(w, "Content length required", http.StatusLengthRequired)
		return
	}

	if length > maxLength {
		httpResp.WithLabelValues(http.StatusText(http.StatusRequestEntityTooLarge)).Inc()
		http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	// read data from request body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		httpResp.WithLabelValues(http.StatusText(http.StatusInternalServerError)).Inc()
		http.Error(w, "Error reading from stream", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// check rate limit to avoid DDoS of KDC
	if !k.limiter.Allow() {
		httpResp.WithLabelValues(http.StatusText(http.StatusTooManyRequests)).Inc()
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// decode the message
	msg, err := k.decode(data)
	if err != nil {
		httpResp.WithLabelValues(http.StatusText(http.StatusBadRequest)).Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// fail if no realm is specified
	if msg.TargetDomain == "" {
		httpResp.WithLabelValues(http.StatusText(http.StatusBadRequest)).Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// forward to kdc(s)
	resp, err := k.forward(msg)
	if err != nil {
		httpResp.WithLabelValues(http.StatusText(http.StatusServiceUnavailable)).Inc()
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// encode response
	reply, err := k.encode(resp)
	if err != nil {
		httpResp.WithLabelValues(http.StatusText(http.StatusInternalServerError)).Inc()
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}

	// metrics
	httpResp.WithLabelValues(http.StatusText(http.StatusOK))

	// send back to client
	w.Write(reply)
}

func (k *KerberosProxy) forward(msg *KdcProxyMsg) ([]byte, error) {
	// time forward process for metrics
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		kerbRespTimeHistogram.Observe(duration.Seconds())
	}()

	// use both udp and tcp
	protocols := []string{protoUdp, protoTcp}
	// if message is too large only use TCP
	if len(msg.KerbMessage)-4 > k.krb5Config.LibDefaults.UDPPreferenceLimit {
		protocols = []string{protoTcp}
	}

	// try protocol options
	for _, proto := range protocols {
		// get kdcs
		c, kdcs, err := k.krb5Config.GetKDCs(msg.TargetDomain, proto == protoTcp)
		if err != nil || c < 1 {
			continue
		}

		// try each kdc
		for _, kdc := range kdcs {
			// metrics
			kerbReqs.WithLabelValues("proto").Inc()

			// connect to kdc
			conn, err := net.Dial(proto, kdc)
			if err != nil {
				continue
			}
			conn.SetDeadline(time.Now().Add(timeout))

			req := msg.KerbMessage
			// for udp trim off length
			if proto == protoUdp {
				req = msg.KerbMessage[4:]
			}

			// send message
			n, err := conn.Write(req)
			if err != nil {
				conn.Close()
				continue
			}

			// check that all the data was sent
			if n != len(req) {
				conn.Close()
				continue
			}

			// get Kerberos response
			resp, err := getresponse(conn)
			if err != nil {
				// for an error try next kdc
				continue
			}

			return resp, nil
		}
	}

	return nil, fmt.Errorf("no kdcs found for realm %s", msg.TargetDomain)
}

func (k *KerberosProxy) decode(data []byte) (*KdcProxyMsg, error) {
	var m KdcProxyMsg

	// unamrshal KDC-PROXY-MESSAGE
	rest, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	// make sure no trailing data exists
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in request")
	}

	// is it a AS_REQ
	asReq := messages.ASReq{}
	if err := asReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: asReq.ReqBody.Realm,
		}, nil
	}

	// TGS_REQ
	tgsReq := messages.TGSReq{}
	if err := tgsReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: tgsReq.ReqBody.Realm,
		}, nil
	}

	// AP_REQ
	apReq := messages.APReq{}
	if err := apReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: apReq.Ticket.Realm,
		}, nil
	}

	return nil, fmt.Errorf("message was not valid")
}

func getresponse(conn net.Conn) ([]byte, error) {
	// close connection once done
	defer conn.Close()

	// handle udp and tcp responses differently
	if conn.LocalAddr().Network() == protoUdp {
		// for udp just read response
		msg, err := io.ReadAll(conn)
		if err != nil {
			return nil, err
		}

		// metrics
		kerbResp.WithLabelValues("udp").Inc()

		// validate response
		if !validReply(msg) {
			return nil, fmt.Errorf("reply message was not valid")
		}

		// return message with length added
		return append(MarshalKerbLength(len(msg)), msg...), nil
	}

	// read initial 4 bytes to get length of response
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	// work out length of message
	length, err := UnmarshalKerbLength(buf[:])
	if err != nil {
		return nil, err
	}

	// read rest of message
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}

	// metrics
	kerbResp.WithLabelValues("tcp").Inc()

	// return response (including length)
	return append(buf, msg...), nil
}

// Encodes the provided bytes as a KDC-PROXY-MESSAGE
func (k *KerberosProxy) encode(data []byte) (r []byte, err error) {
	msg := KdcProxyMsg{KerbMessage: data}
	enc, err := asn1.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func validReply(msg []byte) bool {
	// AS_REP
	asRep := messages.ASRep{}
	if err := asRep.Unmarshal(msg); err == nil {
		return true
	}

	// TGS_REP
	tgsRep := messages.TGSRep{}
	if err := tgsRep.Unmarshal(msg); err == nil {
		return true
	}

	// AP_REP
	apRep := messages.APRep{}
	if err := apRep.Unmarshal(msg); err == nil {
		return true
	}

	return false
}

// UnmarshalKerbLength returns the length of a kerberos message based on the leading 4-bytes
func UnmarshalKerbLength(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("invalid length")
	}
	n := binary.BigEndian.Uint32(b)

	return int(n), nil
}

// MarshalKerbLength encodes the length of a kerberos message as bytes
func MarshalKerbLength(n int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n))

	return b
}
