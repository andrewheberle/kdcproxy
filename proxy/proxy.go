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
)

const (
	maxLength = 128 * 1024
	timeout   = 2 * time.Second
	protoUdp  = "udp"
	protoTcp  = "tcp"
)

// KdcProxyMsg represents a KDC_PROXY_MESSAGE as per https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5778aff5-b182-4b97-a970-29c7f911eef2
type KdcProxyMsg struct {
	KerbMessage   []byte `asn1:"tag:0,explicit"`
	TargetDomain  string `asn1:"tag:1,optional,generalstring"`
	DcLocatorHint int    `asn1:"tag:2,optional"`
}

// KerberosProxy is a KDC Proxy
type KerberosProxy struct {
	krb5Config *krb5config.Config
}

// InitKdcProxy creates a KerberosProxy using the defaults of looking up KDC's via DNS
func InitKdcProxy() (*KerberosProxy, error) {
	return initproxy("")
}

// InitKdcProxyWithConfig creates a KerberosProxy based on the configured "krb5.conf" file
func InitKdcProxyWithConfig(config string) (*KerberosProxy, error) {
	return initproxy(config)
}

func initproxy(config string) (*KerberosProxy, error) {
	// with no config rely on DNS to find KDC
	if config == "" {
		cfg := krb5config.New()
		cfg.LibDefaults.DNSLookupKDC = true

		return &KerberosProxy{cfg}, nil
	}

	// load config from file
	cfg, err := krb5config.Load(config)
	if err != nil {
		return nil, err
	}

	return &KerberosProxy{cfg}, nil
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
		httpRespMethodNotAllowed.Inc()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check content length is valid
	length := r.ContentLength
	if length == -1 {
		httpRespLengthRequired.Inc()
		http.Error(w, "Content length required", http.StatusLengthRequired)
		return
	}

	if length > maxLength {
		httpRespRequestEntityTooLarge.Inc()
		http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	// read data from request body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		httpRespInternalServerError.Inc()
		http.Error(w, "Error reading from stream", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// decode the message
	msg, err := k.decode(data)
	if err != nil {
		httpRespBadRequest.Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// fail if no realm is specified
	if msg.TargetDomain == "" {
		httpRespBadRequest.Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// forward to kdc(s)
	resp, err := k.forward(msg)
	if err != nil {
		httpRespServiceUnavailable.Inc()
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// encode response
	reply, err := k.encode(resp)
	if err != nil {
		httpRespInternalServerError.Inc()
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}

	// metrics
	httpRespOK.Inc()

	// send back to client
	w.Write(reply)
}

func (k *KerberosProxy) forward(msg *KdcProxyMsg) ([]byte, error) {
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
			if proto == protoTcp {
				kerbReqTcp.Inc()
			} else {
				kerbReqUdp.Inc()
			}

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

			// handle udp and tcp responses differently
			if proto == protoUdp {
				// for udp just read response
				msg, err := io.ReadAll(conn)
				if err != nil {
					conn.Close()
					continue
				}
				conn.Close()

				// metrics
				kerbResUdp.Inc()

				// return message with length added
				return append(uint32ToBytes(uint32(len(msg))), msg...), nil
			} else {
				// read initial 4 bytes to get length of response
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil {
					conn.Close()
					continue
				}

				// work out length of message
				length, err := bytesToUint32(buf[:])
				if err != nil {
					conn.Close()
					continue
				}

				// read rest of message
				msg := make([]byte, int(length))
				if _, err := io.ReadFull(conn, msg); err != nil {
					conn.Close()
					continue
				}
				conn.Close()

				// metrics
				kerbResTcp.Inc()

				// return response (including length)
				return append(buf, msg...), nil
			}
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

	// AS_REQ
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

// Encodes the provide bytes as a KDC-PROXY-MESSAGE
func (k *KerberosProxy) encode(data []byte) (r []byte, err error) {
	msg := KdcProxyMsg{KerbMessage: data}
	enc, err := asn1.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// Returns the length of a kerberos message based on the leading 4-bytes
func bytesToUint32(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("invalid length")
	}
	n := binary.BigEndian.Uint32(b)

	return n, nil
}

// Encodes the length of a kerberos message as bytes
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)

	return b
}
