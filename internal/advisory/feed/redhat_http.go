// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	advisoryFeedUserAgent = "lindm advisory feed"
	redHatHTTPConcurrency = 4
	// An absent, malformed, or already elapsed Retry-After must not turn a 429
	// into immediate repeated requests. This fallback never retries a request.
	redHatRetryAfterFallback = time.Minute
)

var sharedRedHatHTTPPolicy = newRedHatHTTPPolicy()

// redHatHTTPPolicy belongs to the process, not a feed or refresh context. In
// particular, canceling the refresh that received a 429 cannot clear its pause.
// The clock and wait functions let tests isolate policy state without sleeping
// through publisher cooldowns or replacing the process-wide instance.
type redHatHTTPPolicy struct {
	slots         chan struct{}
	mu            sync.Mutex
	cooldownUntil time.Time
	indefinite    bool
	now           func() time.Time
	wait          func(context.Context, time.Duration) error
}

func newRedHatHTTPPolicy() *redHatHTTPPolicy {
	return &redHatHTTPPolicy{
		slots: make(chan struct{}, redHatHTTPConcurrency),
		now:   time.Now,
		wait:  waitRedHatHTTP,
	}
}

func waitRedHatHTTP(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *redHatHTTPPolicy) waitCooldown(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		indefinite := p.indefinite
		delay := p.cooldownUntil.Sub(p.now())
		p.mu.Unlock()
		if indefinite {
			<-ctx.Done()
			return ctx.Err()
		}
		if delay <= 0 {
			return nil
		}
		if err := p.wait(ctx, delay); err != nil {
			return err
		}
		// A different request may have extended the shared pause while waiting.
	}
}

func (p *redHatHTTPPolicy) acquire(ctx context.Context) error {
	for {
		if err := p.waitCooldown(ctx); err != nil {
			return err
		}
		select {
		case p.slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			p.release()
			return err
		}
		p.mu.Lock()
		cooling := p.indefinite || p.now().Before(p.cooldownUntil)
		p.mu.Unlock()
		if !cooling {
			return nil
		}
		// A 429 received while this request queued for a slot takes precedence.
		p.release()
	}
}

func (p *redHatHTTPPolicy) release() {
	<-p.slots
}

func (p *redHatHTTPPolicy) rateLimited(retryAfter string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, indefinite := redHatRetryAfter(retryAfter, p.now())
	p.indefinite = p.indefinite || indefinite
	if until.After(p.cooldownUntil) {
		p.cooldownUntil = until
	}
}

func redHatRetryAfter(value string, now time.Time) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value != "" && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > uint64((1<<63-1)/int64(time.Second)) {
			// A valid positive delay that cannot fit a timer must never become
			// the short malformed-header fallback. Quarantine this process's
			// Red Hat requests indefinitely; every wait remains cancellable.
			return time.Time{}, true
		}
		if seconds > 0 {
			return now.Add(time.Duration(seconds) * time.Second), false
		}
	}
	if until, err := http.ParseTime(value); err == nil && until.After(now) {
		return until, false
	}
	return now.Add(redHatRetryAfterFallback), false
}

func isRedHatHTTP(u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Hostname(), "security.access.redhat.com")
}

// do preserves the client's redirect and TLS policy. One permit covers the
// complete redirect chain from its first Red Hat request through final body
// closure, including bodies handed to streaming archive consumers. Non-Red-Hat
// requests do not wait unless their redirect chain actually enters Red Hat.
func (c *Client) do(client *http.Client, request *http.Request) (*http.Response, error) {
	policy := c.redHatHTTP
	if policy == nil {
		policy = sharedRedHatHTTPPolicy
	}
	held := false
	redHat := isRedHatHTTP(request.URL)
	var cancel context.CancelFunc
	if redHat && client.Timeout > 0 {
		// net/http starts this timeout in Do; include the preceding gate wait
		// without changing archive clients' caller-owned transfer deadlines.
		var ctx context.Context
		ctx, cancel = context.WithTimeout(request.Context(), client.Timeout)
		defer func() {
			if cancel != nil {
				cancel()
			}
		}()
		request = request.WithContext(ctx)
	}
	if redHat {
		if err := policy.acquire(request.Context()); err != nil {
			return nil, err
		}
		held = true
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("User-Agent", advisoryFeedUserAgent)

	// The state is per redirect chain, whereas the gate and cooldown are shared
	// by ordinary/archive clients and every Client instance in the process.
	copyClient := *client
	checkRedirect := client.CheckRedirect
	copyClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if checkRedirect != nil {
			if err := checkRedirect(next, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		next.Header.Set("User-Agent", advisoryFeedUserAgent)
		nextRedHat := isRedHatHTTP(next.URL)
		if nextRedHat {
			if held {
				if err := policy.waitCooldown(next.Context()); err != nil {
					return err
				}
			} else {
				if err := policy.acquire(next.Context()); err != nil {
					return err
				}
				held = true
			}
		}
		redHat = nextRedHat
		return nil
	}
	response, err := copyClient.Do(request)
	if err != nil {
		if held {
			policy.release()
		}
		return response, err
	}
	if redHat && response.StatusCode == http.StatusTooManyRequests {
		policy.rateLimited(response.Header.Get("Retry-After"))
	}
	if held {
		response.Body = &redHatHTTPBody{ReadCloser: response.Body, policy: policy, cancel: cancel}
		cancel = nil // The response body now owns the deadline cancellation.
	}
	return response, nil
}

type redHatHTTPBody struct {
	io.ReadCloser
	policy *redHatHTTPPolicy
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (b *redHatHTTPBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		b.policy.release()
		if b.cancel != nil {
			b.cancel()
		}
	})
	return b.err
}
