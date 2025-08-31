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
	httpResp = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kdc_proxy_http_responses_total",
		Help: "The total number of HTTP responses returned",
	}, []string{"code"})
	httpRespTimeHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kdc_proxy_http_request_duration_seconds",
			Help:    "Histogram of response time for the KDC Proxy in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// Metrics for Kerberos side
var (
	kerbReqs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_requests_total",
		Help: "The total number Kerberos requests sent",
	}, []string{"proto"})
	kerbResp = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kdc_proxy_kerberos_responses_total",
		Help: "The total number Kerberos responses received",
	}, []string{"proto"})
	kerbRespTimeHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kdc_proxy_kerberos_forward_duration_seconds",
			Help:    "Histogram of Kerberos forwarding time for the KDC Proxy in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// Prometheus metrics handler
func (k *KerberosProxy) Metrics() http.Handler {
	return promhttp.Handler()
}
