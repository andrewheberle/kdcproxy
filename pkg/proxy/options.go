package proxy

import "golang.org/x/time/rate"

// ProxyOption allows changing the behaviour of the KerberosProxy
type ProxyOption func(*KerberosProxy)

// WithConfig loads the specified krb5.conf file
func WithConfig(config string) ProxyOption {
	return func(kp *KerberosProxy) {
		kp.config = config
	}
}

// WithLimit sets a rate limit of requests per second to forward
func WithLimit(limit int) ProxyOption {
	return func(kp *KerberosProxy) {
		kp.limiter = rate.NewLimiter(rate.Limit(limit), limit)
	}
}
