package kdcproxy

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
	"github.com/rs/zerolog"
)

const (
	maxLength = 128 * 1024
	timeout   = 5 * time.Second
)

type KdcProxyMsg struct {
	KerbMessage   []byte `asn1:"tag:0,explicit"`
	TargetDomain  string `asn1:"tag:1,optional,generalstring"`
	DcLocatorHint int    `asn1:"tag:2,optional"`
}

type KerberosProxy struct {
	krb5Config *krb5config.Config
	logger     zerolog.Logger
	protocols  []string
}

func InitKdcProxy(logger zerolog.Logger, tcpOnly bool) *KerberosProxy {
	cfg := krb5config.New()
	cfg.LibDefaults.DNSLookupKDC = true

	logger.Debug().Interface("cfg", cfg).Send()

	if tcpOnly {
		return &KerberosProxy{cfg, logger, []string{"tcp"}}
	}

	return &KerberosProxy{cfg, logger, []string{"udp", "tcp"}}
}

func (k *KerberosProxy) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	length := r.ContentLength
	if length == -1 {
		http.Error(w, "Content length required", http.StatusLengthRequired)
		return
	}

	if length > maxLength {
		http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	// read data from request body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		k.logger.Error().Err(err).Msg("error reading from stream")
		http.Error(w, "Error reading from stream", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// decode the message
	msg, err := k.decode(data)
	if err != nil {
		k.logger.Error().Err(err).Msg("cannot unmarshal")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// fail if no realm is specified
	if msg.TargetDomain == "" {
		k.logger.Error().Msg("target-domain must not be empty")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// forward to kdc(s)
	resp, err := k.forward(msg)
	if err != nil {
		k.logger.Error().Err(err).Msg("cannot forward to kdc")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// encode response
	reply, err := k.encode(resp)
	if err != nil {
		k.logger.Error().Err(err).Msg("unable to encode krb5 message")
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}

	// send back to client
	w.Header().Set("Content-Type", "application/kerberos")
	w.Write(reply)
}

func (k *KerberosProxy) forward(msg *KdcProxyMsg) ([]byte, error) {
	// do tcp only at the moment first
	for _, proto := range k.protocols {
		logger := k.logger.With().Str("realm", msg.TargetDomain).Str("proto", proto).Logger()
		c, kdcs, err := k.krb5Config.GetKDCs(msg.TargetDomain, proto == "tcp")
		if err != nil || c < 1 {
			logger.Warn().Err(err).Msg("cannot get kdc")
			continue
		}

		// try each kdc
		for _, kdc := range kdcs {
			// add kdc to logger chain
			logger := logger.With().Str("kdc", kdc).Logger()

			// connect to kdc
			conn, err := net.Dial(proto, kdc)
			if err != nil {
				logger.Warn().Err(err).Msg("error connecting, trying next if available")
				continue
			}
			conn.SetDeadline(time.Now().Add(timeout))

			// for udp trim off length
			req := msg.KerbMessage
			if proto == "udp" {
				req = msg.KerbMessage[4:]
			}

			// send message
			if _, err := conn.Write(req); err != nil {
				logger.Warn().Err(err).Msg("cannot write packet data, trying next if available")
				conn.Close()
				continue
			}

			// handle udp and tcp responses differently
			if proto == "udp" {
				// for udp just read response
				msg, err := io.ReadAll(conn)
				if err != nil {
					k.logger.Warn().Err(err).Msg("error reading response from kdc, trying next if available")
					conn.Close()
					continue
				}
				conn.Close()

				logger.Debug().Msg("got response")

				// return message with length added
				return append(uint32ToBytes(uint32(len(msg))), msg...), nil
			} else {
				// read inital 4 bytes to get length of response
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil {
					logger.Warn().Err(err).Msg("error reading message length from kdc, trying next if available")
					conn.Close()
					continue
				}

				// work out length of message
				length, err := bytesToUint32(buf[:])
				if err != nil {
					logger.Warn().Err(err).Msg("error parsing length from kdc, trying next if available")
					conn.Close()
					continue
				}

				// read rest of message
				msg := make([]byte, int(length))
				logger.Debug().Uint32("length", length).Msg("reading kerberos response")
				if _, err := io.ReadFull(conn, msg); err != nil {
					logger.Warn().Err(err).Msg("error reading response from kdc, trying next if available")
					conn.Close()
					continue
				}
				conn.Close()

				logger.Debug().Msg("got response")

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

	// make sure no tailing data exists
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in request")
	}

	// AS_REQ
	asReq := messages.ASReq{}
	if err := asReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		k.logger.Debug().Interface("message", asReq).Msg("KRB_AS_REQ")
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: asReq.ReqBody.Realm,
		}, nil
	}

	// TGS_REQ
	tgsReq := messages.TGSReq{}
	if err := tgsReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		k.logger.Debug().Interface("message", tgsReq).Msg("KRB_TGS_REQ")
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: tgsReq.ReqBody.Realm,
		}, nil
	}

	// AP_REQ
	apReq := messages.APReq{}
	if err := apReq.Unmarshal(m.KerbMessage[4:]); err == nil {
		k.logger.Debug().Interface("message", apReq).Msg("KRB_AP_REQ")
		return &KdcProxyMsg{
			KerbMessage:  m.KerbMessage,
			TargetDomain: apReq.Ticket.Realm,
		}, nil
	}

	return nil, fmt.Errorf("message was not valid")
}

func (k *KerberosProxy) encode(data []byte) (r []byte, err error) {
	msg := KdcProxyMsg{KerbMessage: data}
	k.logger.Debug().Interface("msg", msg).Msg("KDC_PROXY_MESSAGE reply")
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
