package proxy

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics for HTTP service
var (
	httpReqs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_requests_total",
		Help: "The total number of HTTP requests handled",
	})
	httpRespOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_200",
		Help: "The total number of 200 OK HTTP responses",
	})
	httpRespBadRequest = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_400",
		Help: "The total number of 400 Bad Request HTTP responses",
	})
	httpRespMethodNotAllowed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_405",
		Help: "The total number of 405 Not Allowed HTTP responses",
	})
	httpRespLengthRequired = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_411",
		Help: "The total number of 411 Length Required HTTP responses",
	})
	httpRespRequestEntityTooLarge = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_413",
		Help: "The total number of 413 Request Entity Too Large HTTP responses",
	})
	httpRespInternalServerError = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_500",
		Help: "The total number of 500 Internal Server Error HTTP responses",
	})
	httpRespServiceUnavailable = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_503",
		Help: "The total number of 503 Service Unavailable HTTP responses",
	})
	httpRespTimeHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kdc_proxy_http_request_duration_seconds",
			Help:    "Histogram of response time for the KDC Proxy in seconds",
			Buckets: prometheus.DefBuckets,
		})
)

// Metrics for Kerberos side
var (
	kerbReqTcp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_request_tcp",
		Help: "The total number Kerberos requests sent via TCP",
	})
	kerbResTcp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_response_tcp",
		Help: "The total number Kerberos responses via TCP",
	})
	kerbReqUdp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_request_udp",
		Help: "The total number Kerberos requests sent via UDP",
	})
	kerbResUdp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_response_udp",
		Help: "The total number Kerberos responses via UDP",
	})
)

// Prometheus metrics handler
func (k *KerberosProxy) Metrics() http.Handler {
	return promhttp.Handler()
}
