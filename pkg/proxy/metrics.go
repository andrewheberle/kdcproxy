package proxy

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// reasonMalformedKerberosMessage is the httpDropped reason for a malformed
// proxy message or Kerberos message (MS-KKDCP 3.2.5.1-1)
const reasonMalformedKerberosMessage = "malformed_kerberos_message"

// metrics are the Prometheus metrics for a KerberosProxy
type metrics struct {
	// HTTP service
	httpReqs              prometheus.Counter
	httpResp              *prometheus.CounterVec
	httpDropped           *prometheus.CounterVec
	httpRespTimeHistogram prometheus.Histogram

	// Kerberos side
	kerbReqs              *prometheus.CounterVec
	kerbResp              *prometheus.CounterVec
	kerbRespTimeHistogram prometheus.Histogram
}

// newMetrics creates the metrics and registers them with reg
func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		httpReqs: register(reg, prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kdc_proxy_http_requests_total",
			Help: "The total number of HTTP requests handled",
		})),
		httpResp: register(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_proxy_http_responses_total",
			Help: "The total number of HTTP responses returned",
		}, []string{"code"})),
		httpDropped: register(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_proxy_http_dropped_connections_total",
			Help: "The total number of HTTP connections dropped without a response",
		}, []string{"reason"})),
		httpRespTimeHistogram: register(reg, prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "kdc_proxy_http_request_duration_seconds",
				Help:    "Histogram of response time for the KDC Proxy in seconds",
				Buckets: prometheus.DefBuckets,
			},
		)),
		kerbReqs: register(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_proxy_kerberos_requests_total",
			Help: "The total number Kerberos requests sent",
		}, []string{"proto"})),
		kerbResp: register(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_proxy_kerberos_responses_total",
			Help: "The total number Kerberos responses received",
		}, []string{"proto"})),
		kerbRespTimeHistogram: register(reg, prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "kdc_proxy_kerberos_forward_duration_seconds",
				Help:    "Histogram of Kerberos forwarding time for the KDC Proxy in seconds",
				Buckets: prometheus.DefBuckets,
			},
		)),
	}

	// export the series before the first drop
	m.httpDropped.WithLabelValues(reasonMalformedKerberosMessage)

	return m
}

// register registers c with reg. If an identical collector is already
// registered, such as by an earlier KerberosProxy, that collector is returned
// instead so the proxies share it. Any other registration error is a
// programming error, so it panics as prometheus.MustRegister does.
func register[T prometheus.Collector](reg prometheus.Registerer, c T) T {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(T); ok {
				return existing
			}
		}
		panic(err)
	}

	return c
}

// Prometheus metrics handler
func (k *KerberosProxy) Metrics() http.Handler {
	return promhttp.Handler()
}
