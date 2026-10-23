package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type locateCall struct {
	realm   string
	tcp     bool
	kpasswd bool
}

// fakeLocator returns fixed KDC addresses per transport and records each lookup
type fakeLocator struct {
	udp []string
	tcp []string
	err error

	mu    sync.Mutex
	calls []locateCall
}

func (l *fakeLocator) locate(_ context.Context, realm string, tcp, kpasswd bool) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls = append(l.calls, locateCall{realm: realm, tcp: tcp, kpasswd: kpasswd})
	if l.err != nil {
		return nil, l.err
	}
	if tcp {
		return l.tcp, nil
	}

	return l.udp, nil
}

// fakeKDC is how a KDC behaves at one network/address
type fakeKDC struct {
	reply   []byte
	dialErr error
}

type sent struct {
	network string
	addr    string
	data    []byte
}

// fakeDialer connects to in-memory KDCs keyed by "network/addr" and records what is sent to them
type fakeDialer struct {
	kdcs map[string]fakeKDC

	mu    sync.Mutex
	dials []string
	sent  []sent
}

func (d *fakeDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	key := network + "/" + addr

	d.mu.Lock()
	d.dials = append(d.dials, key)
	d.mu.Unlock()

	kdc, ok := d.kdcs[key]
	if !ok {
		return nil, fmt.Errorf("no fake kdc at %s", key)
	}
	if kdc.dialErr != nil {
		return nil, kdc.dialErr
	}

	record := func(b []byte) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.sent = append(d.sent, sent{network: network, addr: addr, data: append([]byte(nil), b...)})
	}

	if network == protoUdp {
		return &fakeUDPConn{reply: kdc.reply, record: record}, nil
	}

	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()

		// a single write from the proxy arrives in a single read
		buf := make([]byte, maxLength)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		record(buf[:n])

		_, _ = server.Write(append(MarshalKerbLength(len(kdc.reply)), kdc.reply...))
	}()

	return client, nil
}

// fakeUDPConn answers one datagram with one reply datagram. Like a real UDP
// socket with a deadline, a read after the reply is consumed fails with a
// timeout rather than io.EOF.
type fakeUDPConn struct {
	reply  []byte
	record func([]byte)

	mu        sync.Mutex
	written   bool
	delivered bool
}

func (c *fakeUDPConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.record(b)
	c.written = true

	return len(b), nil
}

func (c *fakeUDPConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.written || c.delivered {
		return 0, os.ErrDeadlineExceeded
	}
	c.delivered = true

	return copy(b, c.reply), nil
}

func (c *fakeUDPConn) Close() error                     { return nil }
func (c *fakeUDPConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakeUDPConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *fakeUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeUDPConn) SetWriteDeadline(time.Time) error { return nil }
