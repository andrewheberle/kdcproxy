package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

// certificateSource provides the certificate to serve over TLS
type certificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// newServer returns the HTTP server for handler, serving TLS with the
// certificate from certs when it is not nil
func newServer(addr string, handler http.Handler, certs certificateSource) *http.Server {
	srv := &http.Server{
		Addr:         addr,
		ReadTimeout:  time.Second * 30,
		WriteTimeout: time.Second * 30,
		Handler:      handler,
	}

	if certs != nil {
		// GetCertificate rather than a fixed certificate, so a rotated certificate is picked up
		srv.TLSConfig = &tls.Config{GetCertificate: certs.GetCertificate}
	}

	return srv
}
