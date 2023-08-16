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
}

func InitKdcProxy(logger zerolog.Logger) *KerberosProxy {
	cfg := krb5config.New()
	cfg.LibDefaults.DNSLookupKDC = true

	logger.Debug().Interface("cfg", cfg).Send()

	return &KerberosProxy{cfg, logger}
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
	reply, err := encode(resp)
	if err != nil {
		k.logger.Error().Err(err).Msg("unable to encode krb5 message")
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}

	// send back to client
	w.Header().Set("Content-Type", "application/kerberos")
	w.Write(reply)
}

func (k *KerberosProxy) forward(msg *KdcProxyMsg) ([]byte, error) {
	// do tcp only
	c, kdcs, err := k.krb5Config.GetKDCs(msg.TargetDomain, true)
	if err != nil || c < 1 {
		return nil, fmt.Errorf("cannot get kdc for realm %s due to %s", msg.TargetDomain, err)
	}

	for i := range kdcs {
		conn, err := net.Dial("tcp", kdcs[i])
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error connecting, trying next if available")
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		// send message
		if _, err := conn.Write(msg.KerbMessage); err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("cannot write packet data, trying next if available")
			conn.Close()
			continue
		}

		// read response
		buf := make([]byte, 1048576)
		n, err := io.ReadAtLeast(conn, buf, 4)
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error reading message length from kdc, trying next if available")
			conn.Close()
			continue
		}

		// work out length of message
		length, err := klen(buf)
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error parsing length from kdc, trying next if available")
			conn.Close()
			continue
		}

		k.logger.Debug().Uint32("length", length).Msg("kerberos response")

		// have we got whole message
		if n-4 == int(length) {
			k.logger.Debug().Msg("got whole response initially")
			conn.Close()
			return buf, nil
		}

		// read rest of message
		rlen := int(length) - (n - 4)
		rest := make([]byte, rlen)
		k.logger.Debug().Int("remainder", rlen).Msg("more data to come")
		if _, err := io.ReadAtLeast(conn, rest, rlen); err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error reading remainder of message from kdc, trying next if available")
			conn.Close()
			continue
		}
		conn.Close()

		k.logger.Debug().Msg("got response")

		// add remainder to buffer
		buf = append(buf, rest...)

		// return message (minus length)
		return buf, nil
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

func encode(krb5data []byte) (r []byte, err error) {
	m := KdcProxyMsg{KerbMessage: krb5data}
	enc, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// Returns the length of a kerberos message based on the leading 4-bytes
func klen(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("invalid length")
	}
	n := binary.BigEndian.Uint32(data)

	return n, nil
}
