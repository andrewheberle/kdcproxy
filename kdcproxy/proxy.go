package kdcproxy

import (
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	krb5config "github.com/bolkedebruin/gokrb5/v8/config"
	"github.com/rs/zerolog/log"
)

const (
	maxLength = 128 * 1024
	timeout   = 5 * time.Second
)

type KdcProxyMsg struct {
	Message []byte `asn1:"tag:0,explicit"`
	Realm   string `asn1:"tag:1,optional"`
	Flags   int    `asn1:"tag:2,optional"`
}

type KerberosProxy struct {
	krb5Config *krb5config.Config
}

func InitKdcProxy(realm string) KerberosProxy {
	config := krb5config.New()
	config.LibDefaults.DNSLookupKDC = true
	config.LibDefaults.DefaultRealm = realm
	return KerberosProxy{config}
}

func (k KerberosProxy) Handler(w http.ResponseWriter, r *http.Request) {
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

	data := make([]byte, length)
	_, err := io.ReadFull(r.Body, data)
	if err != nil {
		log.Error().Err(err).Msg("Error reading from stream")
		http.Error(w, "Error reading from stream", http.StatusInternalServerError)
		return
	}

	msg, err := decode(data)
	if err != nil {
		log.Error().Err(err).Msg("Cannot unmarshal")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	krb5resp, err := k.forward(msg.Realm, msg.Message)
	if err != nil {
		log.Error().Err(err).Msg("cannot forward to kdc")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	reply, err := encode(krb5resp)
	if err != nil {
		log.Error().Err(err).Msg("unable to encode krb5 message")
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/kerberos")
	w.Write(reply)
}

func (k *KerberosProxy) forward(realm string, data []byte) (resp []byte, err error) {
	if realm == "" {
		realm = k.krb5Config.LibDefaults.DefaultRealm
	}

	// load udp first as is the default for kerberos
	c, kdcs, err := k.krb5Config.GetKDCs(realm, false)
	if err != nil || c < 1 {
		return nil, fmt.Errorf("cannot get kdc for realm %s due to %s", realm, err)
	}

	for i := range kdcs {
		conn, err := net.Dial("tcp", kdcs[i])
		if err != nil {
			log.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error connecting, trying next if available")
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write(data)
		if err != nil {
			log.Warn().Err(err).Str("kdc", kdcs[i]).Msg("cannot write packet data, trying next if available")
			conn.Close()
			continue
		}

		// todo check header
		resp, err = io.ReadAll(conn)
		if err != nil {
			log.Warn().Err(err).Str("kdc", kdcs[i]).Msg("error reading from kdc, trying next if available")
			conn.Close()
			continue
		}
		conn.Close()

		return resp, nil
	}

	return nil, fmt.Errorf("no kdcs found for realm %s", realm)
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
		log.Error().Err(err).Msg("cannot marshal")
		return nil, err
	}
	return enc, nil
}

func getkdcs(realm string) {

}
