package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
)

// NewRecoveryClient creates the separate recovery endpoint client. Before bounds
// supplies authenticated time, only the public GetRecoveryTime RPC is allowed.
// Provisional TLS verifies the pinned chain at a date within its validity overlap;
// that date grants neither authenticated time nor permission to send action proofs.
// Every connection use, including keepalive, verifies the entire authenticated
// interval once available. There is no device certificate, cookie jar, proxy or
// redirect, and the caller closes idle connections after recovery execution.
func NewRecoveryClient(origin string, caPEM []byte, bounds func() (time.Time, time.Time, error)) (recoveryv1connect.RecoveryServiceClient, func(), error) {
	if err := checkOrigin(origin); err != nil {
		return nil, nil, err
	}
	if bounds == nil {
		return nil, nil, errors.New("missing authenticated recovery time bounds")
	}
	if len(caPEM) == 0 || len(caPEM) > 65536 {
		return nil, nil, errors.New("invalid pinned recovery transport trust")
	}
	roots := x509.NewCertPool()
	var pinned []*x509.Certificate
	for len(caPEM) != 0 {
		block, rest := pem.Decode(caPEM)
		if block == nil {
			break
		}
		caPEM = rest
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		roots.AddCert(certificate)
		pinned = append(pinned, certificate)
	}
	if len(pinned) == 0 {
		return nil, nil, errors.New("invalid pinned recovery transport trust")
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, nil, err
	}
	guard := &recoveryTransport{
		roots: roots, pinned: pinned, host: parsed.Host, hostname: parsed.Hostname(), bounds: bounds,
	}
	transport := newHTTPTransport(&tls.Config{
		RootCAs: roots, ServerName: guard.hostname,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		// The default verifier uses the RTC. The replacement below preserves
		// chain, hostname, EKU and constraint checks with an explicit date.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			lower, upper, authenticated, err := guard.timeBounds()
			if err != nil {
				return err
			}
			return guard.verifyConnection(state, lower, upper, authenticated)
		},
	})
	guard.transport = transport
	httpClient := newHTTPClient(transport)
	httpClient.Transport = guard
	client := recoveryv1connect.NewRecoveryServiceClient(httpClient, origin, connect.WithReadMaxBytes(1<<20))
	return client, transport.CloseIdleConnections, nil
}

type recoveryTransport struct {
	transport     *http.Transport
	roots         *x509.CertPool
	pinned        []*x509.Certificate
	host          string
	hostname      string
	bounds        func() (time.Time, time.Time, error)
	authenticated atomic.Bool
}

func (t *recoveryTransport) timeBounds() (time.Time, time.Time, bool, error) {
	lower, upper, err := t.bounds()
	if err != nil {
		if t.authenticated.Load() {
			return time.Time{}, time.Time{}, false, fmt.Errorf("authenticated recovery time unavailable: %w", err)
		}
		return time.Time{}, time.Time{}, false, nil
	}
	// Never downgrade a client back to provisional verification.
	t.authenticated.Store(true)
	if lower.IsZero() || upper.IsZero() || upper.Before(lower) {
		return time.Time{}, time.Time{}, false, errors.New("invalid authenticated recovery time bounds")
	}
	return lower, upper, true, nil
}

func (t *recoveryTransport) requestBounds(request *http.Request) (time.Time, time.Time, bool, error) {
	if request.URL.Scheme != "https" || request.URL.Host != t.host || (request.Host != "" && request.Host != t.host) {
		return time.Time{}, time.Time{}, false, errors.New("recovery request escaped its pinned origin")
	}
	for header := range request.Header {
		if strings.EqualFold(header, "Authorization") || strings.EqualFold(header, "Proxy-Authorization") || strings.EqualFold(header, "Cookie") {
			return time.Time{}, time.Time{}, false, errors.New("recovery transport does not accept identity headers")
		}
	}
	lower, upper, authenticated, err := t.timeBounds()
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	if !authenticated && request.URL.Path != recoveryv1connect.RecoveryServiceGetRecoveryTimeProcedure {
		return time.Time{}, time.Time{}, false, errors.New("authenticated recovery time is required for action RPCs")
	}
	return lower, upper, authenticated, nil
}

func (t *recoveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, _, _, err := t.requestBounds(request); err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(request.Context())
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		lower, upper, authenticated, err := t.requestBounds(request)
		if err == nil {
			connection, ok := info.Conn.(*tls.Conn)
			if !ok {
				err = errors.New("recovery connection is not TLS")
			} else {
				err = t.verifyConnection(connection.ConnectionState(), lower, upper, authenticated)
			}
		}
		if err != nil {
			cancel(err)
			// GotConn precedes HTTP/1 and HTTP/2 request writes. Cancellation
			// alone can race with a write, so close the connection as well.
			_ = info.Conn.Close()
		}
	}}
	response, err := t.transport.RoundTrip(request.Clone(httptrace.WithClientTrace(ctx, trace)))
	if err != nil {
		cause := context.Cause(ctx)
		cancel(nil)
		if cause != nil {
			return nil, cause
		}
		return nil, err
	}
	response.Body = &recoveryResponseBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type recoveryResponseBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b *recoveryResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel(nil)
	return err
}

func (t *recoveryTransport) verifyConnection(state tls.ConnectionState, lower, upper time.Time, authenticated bool) error {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return errors.New("recovery endpoint requires a TLS 1.3 server certificate")
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	options := x509.VerifyOptions{
		Roots: t.roots, Intermediates: intermediates, DNSName: t.hostname,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if authenticated {
		options.CurrentTime = lower
		chains, err := leaf.Verify(options)
		if err != nil {
			return fmt.Errorf("recovery TLS certificate at authenticated lower bound: %w", err)
		}
		for _, chain := range chains {
			valid := true
			for _, certificate := range chain {
				if upper.After(certificate.NotAfter) {
					valid = false
					break
				}
			}
			// All non-time constraints were checked at lower. Requiring the
			// same chain to cover upper authenticates the entire interval.
			if valid {
				return nil
			}
		}
		return errors.New("recovery TLS certificate chain expires before authenticated upper bound")
	}
	// If any valid path has a nonempty validity overlap, its earliest date
	// is the NotBefore of one of its certificates. Try those dates rather
	// than consulting the RTC or disabling any X.509 validity constraint.
	last := errors.New("no certificate validity overlap")
	for _, certificates := range [][]*x509.Certificate{state.PeerCertificates, t.pinned} {
		for _, certificate := range certificates {
			candidate := certificate.NotBefore
			if candidate.IsZero() {
				// A zero VerifyOptions.CurrentTime would consult the RTC.
				candidate = candidate.Add(time.Nanosecond)
			}
			if candidate.Before(leaf.NotBefore) || candidate.After(leaf.NotAfter) {
				continue
			}
			options.CurrentTime = candidate
			if _, err := leaf.Verify(options); err == nil {
				return nil
			} else {
				last = err
			}
		}
	}
	return fmt.Errorf("recovery provisional TLS certificate: %w", last)
}
