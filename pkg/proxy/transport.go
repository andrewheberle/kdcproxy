package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// transport exchanges a Kerberos message with a KDC over one network,
// handling that network's framing. Messages and replies are bare, without
// the 4-octet length prefix.
type transport interface {
	// network is the network dialled, which also labels the metrics
	network() string
	// exchange sends msg to the KDC at addr and returns its reply, without
	// validating it
	exchange(ctx context.Context, addr string, msg []byte) ([]byte, error)
}

// udpTransport sends a Kerberos message as a single datagram, with no length
// prefix (RFC 4120 7.2.1)
type udpTransport struct {
	dialer  dialer
	metrics *metrics
}

func (udpTransport) network() string { return protoUdp }

// exchange returns errResponseTooBig if the KDC replies with
// KRB_ERR_RESPONSE_TOO_BIG, so the request can be retried over TCP
func (t udpTransport) exchange(ctx context.Context, addr string, msg []byte) ([]byte, error) {
	// metrics
	t.metrics.kerbReqs.WithLabelValues(protoUdp).Inc()

	conn, err := dial(ctx, t.dialer, protoUdp, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := send(conn, msg); err != nil {
		return nil, err
	}

	// the reply is a single datagram, so there is no EOF to wait for
	buf := make([]byte, maxUDPReply)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	reply := buf[:n]

	// metrics
	t.metrics.kerbResp.WithLabelValues(protoUdp).Inc()

	if responseTooBig(reply) {
		return nil, errResponseTooBig
	}

	return reply, nil
}

// tcpTransport sends a Kerberos message preceded by its 4-octet length, and
// reads the reply the same way (RFC 4120 7.2.2)
type tcpTransport struct {
	dialer  dialer
	metrics *metrics
}

func (tcpTransport) network() string { return protoTcp }

// exchange refuses a reply longer than maxLength before reading its body
func (t tcpTransport) exchange(ctx context.Context, addr string, msg []byte) ([]byte, error) {
	// metrics
	t.metrics.kerbReqs.WithLabelValues(protoTcp).Inc()

	conn, err := dial(ctx, t.dialer, protoTcp, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := send(conn, append(MarshalKerbLength(len(msg)), msg...)); err != nil {
		return nil, err
	}

	// read initial 4 bytes to get length of reply
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		return nil, err
	}

	// work out length of reply
	length, err := UnmarshalKerbLength(prefix)
	if err != nil {
		return nil, err
	}

	// limit the length, which also rejects the reserved high bit (RFC 4120 7.2.2)
	if length < 0 || length > maxLength {
		return nil, fmt.Errorf("reply length %d exceeds maximum %d", length, maxLength)
	}

	// read rest of reply
	reply := make([]byte, length)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}

	// metrics
	t.metrics.kerbResp.WithLabelValues(protoTcp).Inc()

	return reply, nil
}

// dial connects to the KDC at addr, with a deadline for the whole exchange
func dial(ctx context.Context, d dialer, network, addr string) (net.Conn, error) {
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	return conn, nil
}

// send writes b to conn in a single write, failing if any of it was not sent
func send(conn net.Conn, b []byte) error {
	n, err := conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("sent %d of %d bytes", n, len(b))
	}

	return nil
}
