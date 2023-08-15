package kdcproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/rs/zerolog"
)

const (
	maxLength = 128 * 1024
	timeout   = 5 * time.Second
)

type KdcProxyMsg struct {
	Message []byte `asn1:"tag:0,explicit"`
	Realm   string `asn1:"tag:1,optional,generalstring"`
	Flags   int    `asn1:"tag:2,optional"`
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
	msg, err := decode(data)
	if err != nil {
		k.logger.Error().Err(err).Msg("cannot unmarshal")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// fail if no realm is specified
	if msg.Realm == "" {
		k.logger.Error().Msg("realm must not be empty")
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

func (k *KerberosProxy) forward(msg *KdcProxyMsg) (resp []byte, err error) {
	// do tcp only
	c, kdcs, err := k.krb5Config.GetKDCs(msg.Realm, true)
	if err != nil || c < 1 {
		return nil, fmt.Errorf("cannot get kdc for realm %s due to %s", msg.Realm, err)
	}

	for i := range kdcs {
		conn, err := net.Dial("tcp", kdcs[i])
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error connecting, trying next if available")
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write(msg.Message)
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("cannot write packet data, trying next if available")
			conn.Close()
			continue
		}

		// todo check header
		resp, err = io.ReadAll(conn)
		if err != nil {
			k.logger.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error reading from kdc, trying next if available")
			conn.Close()
			continue
		}
		conn.Close()

		return resp, nil
	}

	return nil, fmt.Errorf("no kdcs found for realm %s", msg.Realm)
}

func decode(data []byte) (msg *KdcProxyMsg, err error) {
	var m KdcProxyMsg
	rest, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in request")
	}

	return &m, nil
}

func encode(krb5data []byte) (r []byte, err error) {
	m := KdcProxyMsg{Message: krb5data}
	enc, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	return enc, nil
}
