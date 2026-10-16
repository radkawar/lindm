// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"
)

const httpGETAttempts = 5

type retryCounterKey struct{}
type retryAttemptKey struct{}

// WithRetryCounter attributes additional HTTP attempts to one source refresh.
// Child contexts retain the concurrency-safe counter. A nil counter leaves ctx
// unchanged; callers must install a new counter for each attempted refresh.
func WithRetryCounter(ctx context.Context, counter *atomic.Int64) context.Context {
	if counter == nil {
		return ctx
	}
	return context.WithValue(ctx, retryCounterKey{}, counter)
}

// RetryCounter returns the current source refresh's counter, or nil for an
// acquisition without network-refresh accounting, such as an offline import.
func RetryCounter(ctx context.Context) *atomic.Int64 {
	counter, _ := ctx.Value(retryCounterKey{}).(*atomic.Int64)
	return counter
}

// countHTTPRetry is called by do only after acquiring any shared network permit,
// immediately before initiating the retried request, not while queued or asleep.
func countHTTPRetry(ctx context.Context) {
	if retry, _ := ctx.Value(retryAttemptKey{}).(bool); retry {
		if counter := RetryCounter(ctx); counter != nil {
			counter.Add(1)
		}
	}
}

// Production uses real time. Tests can advance the same clock used by the
// process-wide Red Hat gate without sleeping or changing retry limits.
type httpRetryPolicy struct {
	now  func() time.Time
	wait func(context.Context, time.Duration) error
}

var defaultHTTPRetryPolicy = httpRetryPolicy{now: time.Now, wait: waitRedHatHTTP}

// getHTTP owns the only retry budget. do remains a single redirect-chain attempt,
// and authentication/decoding/parsing remain outside this acquisition boundary.
// prepare resets private staging storage before each attempt; storage errors are
// terminal. consume may retry only errors originating in response-body reads.
func (c *Client) getHTTP(request *http.Request, client *http.Client, archive bool, prepare func() error, consume func(*http.Response) error) error {
	ctx := request.Context()
	if client.Timeout > 0 {
		// Unlike net/http's per-Do timer, this includes every backoff, shared
		// cooldown, permit wait and body read across all five attempts.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.Timeout)
		defer cancel()
	}
	policy := c.httpRetry
	if policy == nil {
		policy = &defaultHTTPRetryPolicy
	}
	label := ""
	fetchLabel := "fetch"
	if archive {
		label = "archive "
		fetchLabel = "fetch archive"
	}
	for attempt := range httpGETAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if prepare != nil {
			if err := prepare(); err != nil {
				return err
			}
		}
		attemptCtx := ctx
		if attempt != 0 {
			attemptCtx = context.WithValue(ctx, retryAttemptKey{}, true)
		}
		response, err := c.do(client, request.WithContext(attemptCtx))
		retry := false
		var retryAfter string
		rateLimited := false
		if err != nil {
			retry = transientHTTPError(err)
			err = fmt.Errorf("feed: %s: %w", fetchLabel, err)
		} else {
			switch {
			case response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0:
				err = fmt.Errorf("feed: %sresponse lacks verified TLS", label)
			case response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity":
				err = fmt.Errorf("feed: unsupported %sHTTP content encoding", label)
			case response.StatusCode != http.StatusOK:
				err = fmt.Errorf("feed: %sHTTP status %d", label, response.StatusCode)
				rateLimited = response.StatusCode == http.StatusTooManyRequests
				retry = rateLimited || response.StatusCode >= 500 && response.StatusCode <= 599
				retryAfter = response.Header.Get("Retry-After")
			default:
				response.Body = httpRetryBody{response.Body}
				err = consume(response)
				var readError *httpBodyReadError
				retry = errors.As(err, &readError) && transientHTTPError(readError.err)
			}
			// Never hold a body/network permit during retry waits. Close failures
			// are terminal, including alongside an otherwise transient read error.
			if closeErr := response.Body.Close(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
		}
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err == nil || !retry || attempt+1 == httpGETAttempts {
			return err
		}
		// Four waits: 1, 2, 4 and 8 seconds. Retry-After can only lengthen
		// them; the shared Red Hat gate independently retains any longer pause.
		until := policy.now().Add(time.Second << attempt)
		if rateLimited {
			limitedUntil, indefinite := redHatRetryAfter(retryAfter, policy.now())
			if indefinite {
				<-ctx.Done()
				return errors.Join(err, ctx.Err())
			}
			if limitedUntil.After(until) {
				until = limitedUntil
			}
		}
		for delay := until.Sub(policy.now()); delay > 0; delay = until.Sub(policy.now()) {
			if waitErr := policy.wait(ctx, delay); waitErr != nil {
				return errors.Join(err, waitErr)
			}
		}
	}
	panic("unreachable HTTP retry loop")
}

// Distinguish body read failures from file writes, watchdog callbacks and other
// local failures even when those errors happen to implement net.Error.
type httpBodyReadError struct{ err error }

func (e *httpBodyReadError) Error() string { return e.err.Error() }
func (e *httpBodyReadError) Unwrap() error { return e.err }

type httpRetryBody struct{ io.ReadCloser }

func (b httpRetryBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		err = &httpBodyReadError{err}
	}
	return n, err
}

func transientHTTPError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, ErrRefreshStalled) || errors.Is(err, ErrRefreshCeiling) {
		return false
	}
	var certificate *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &certificate) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalidCertificate) {
		return false
	}
	// net's own DNS/socket timeouts can match context.DeadlineExceeded even
	// while the acquisition context is live. The caller checks that context
	// separately; do not mistake a resolver's UDP timeout for its exhaustion.
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return !dns.IsNotFound && (dns.Timeout() || dns.Temporary())
	}
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}
