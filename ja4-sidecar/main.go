// The ja4-sidecar terminates TLS for the demo stack. Before handing the
// connection to crypto/tls it peeks the raw ClientHello bytes, computes the
// JA4 fingerprint, then replays the consumed bytes into the real TLS stack
// so the handshake proceeds normally. Every proxied request carries the
// fingerprint upstream in X-JA4-Raw.
//
// Anti-spoofing note: this process is the only component that sees the raw
// handshake, so it unconditionally strips any client-supplied X-JA4-Raw /
// X-Detection-JA4 / X-Forwarded-For before setting its own values. The
// Envoy WASM filter downstream strips and re-signs again — two independent
// enforcement points on the same trust boundary.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/humblelad/protocol-abuse-detection/ja4-sidecar/ja4"
)

type ctxKeyJA4 struct{}

func main() {
	listenAddr := envOr("LISTEN_ADDR", ":8443")
	upstream := envOr("UPSTREAM_ADDR", "envoy:10000")

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("generating self-signed cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	inner, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	ln := newPeekListener(inner, tlsCfg)

	srv := &http.Server{
		Handler:           newProxy(upstream),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if jc, ok := c.(*ja4Conn); ok {
				return context.WithValue(ctx, ctxKeyJA4{}, jc.fingerprint)
			}
			return ctx
		},
	}

	log.Printf("ja4-sidecar listening on %s, proxying to %s", listenAddr, upstream)
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
}

// newProxy builds the reverse proxy that forwards decrypted requests to
// Envoy with the trusted fingerprint header attached.
func newProxy(upstream string) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "http", Host: upstream}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host

			// Strip everything a client could try to smuggle through.
			pr.Out.Header.Del("X-JA4-Raw")
			pr.Out.Header.Del("X-Detection-JA4")
			pr.Out.Header.Del("X-Forwarded-For")

			if fp, ok := pr.In.Context().Value(ctxKeyJA4{}).(string); ok && fp != "" {
				pr.Out.Header.Set("X-JA4-Raw", fp)
			}
			pr.SetXForwarded()
		},
	}
}

// peekListener accepts TCP connections, peeks the ClientHello off each one
// in its own goroutine (so a slow client never blocks other accepts), and
// hands http.Server a TLS connection annotated with the JA4 fingerprint.
type peekListener struct {
	inner  net.Listener
	tlsCfg *tls.Config
	conns  chan net.Conn
	errs   chan error
}

// ja4Conn is a served TLS connection tagged with the fingerprint computed
// from its ClientHello.
type ja4Conn struct {
	*tls.Conn
	fingerprint string
}

// replayConn replays the peeked handshake bytes before reading from the
// wire, so crypto/tls sees an untouched byte stream.
type replayConn struct {
	net.Conn
	pre *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.pre != nil && c.pre.Len() > 0 {
		return c.pre.Read(p)
	}
	c.pre = nil
	return c.Conn.Read(p)
}

func newPeekListener(inner net.Listener, tlsCfg *tls.Config) *peekListener {
	l := &peekListener{
		inner:  inner,
		tlsCfg: tlsCfg,
		conns:  make(chan net.Conn),
		errs:   make(chan error, 1),
	}
	go l.acceptLoop()
	return l
}

func (l *peekListener) acceptLoop() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			l.errs <- err
			return
		}
		go l.prepare(raw)
	}
}

func (l *peekListener) prepare(raw net.Conn) {
	raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, consumed, err := ja4.ReadClientHello(raw)
	raw.SetReadDeadline(time.Time{})

	fp := ""
	if err != nil {
		// Not fatal: the request proceeds without a fingerprint and the
		// scoring service treats the absence itself as a signal.
		log.Printf("ja4 peek failed from %s: %v", raw.RemoteAddr(), err)
	} else {
		fp = hello.JA4()
		log.Printf("ja4=%s sni=%q remote=%s", fp, hello.SNI, raw.RemoteAddr())
	}

	rc := &replayConn{Conn: raw, pre: bytes.NewReader(consumed)}
	l.conns <- &ja4Conn{Conn: tls.Server(rc, l.tlsCfg), fingerprint: fp}
}

func (l *peekListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	}
}

func (l *peekListener) Close() error   { return l.inner.Close() }
func (l *peekListener) Addr() net.Addr { return l.inner.Addr() }

// selfSignedCert generates an in-memory ECDSA P-256 certificate at startup.
// Demo-only: a real deployment terminates with a managed certificate.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ja4-sidecar"},
		DNSNames:     []string{"localhost", "ja4-sidecar"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
