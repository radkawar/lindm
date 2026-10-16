// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type redHatHTTPTestTransport func(*http.Request) (*http.Response, error)

func (f redHatHTTPTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func redHatHTTPTestResponse(request *http.Request, status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("vendor bytes")),
		Request:    request,
	}
}

func redHatHTTPTestRequest(t *testing.T, ctx context.Context, location string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func redHatHTTPTestDo(t *testing.T, client *Client, transport *http.Client, request *http.Request) *http.Response {
	t.Helper()
	response, err := client.do(transport, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	return response
}

type redHatHTTPTestResult struct {
	response *http.Response
	err      error
}

func redHatHTTPTestStart(t *testing.T, client *Client, transport *http.Client, request *http.Request, cancel context.CancelFunc) (*redHatHTTPTestResult, <-chan struct{}) {
	t.Helper()
	result := &redHatHTTPTestResult{}
	done := make(chan struct{})
	go func() {
		response, err := client.do(transport, request)
		if response != nil {
			t.Cleanup(func() { _ = response.Body.Close() })
		}
		result.response, result.err = response, err
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("HTTP request did not stop after cancellation")
		}
	})
	return result, done
}

func redHatHTTPTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP policy did not reach expected checkpoint")
	}
}

// Done is first evaluated by the permit select once all four slots are held.
// This makes queue/cancel assertions deterministic without sleeps or polling.
type redHatHTTPQueuedContext struct {
	context.Context
	queued chan struct{}
	once   sync.Once
}

func (c *redHatHTTPQueuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.queued) })
	return c.Context.Done()
}

func TestRedHatHTTPDefaultPolicySharesFourBodyHeldSlots(t *testing.T) {
	var calls atomic.Int32
	transport := redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return redHatHTTPTestResponse(request, http.StatusOK), nil
	})
	first, err := New(&http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(&http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if first.redHatHTTP != sharedRedHatHTTPPolicy || second.redHatHTTP != first.redHatHTTP {
		t.Fatal("default Client instances do not share the process-wide HTTP policy")
	}
	clients := []*Client{first, second, first, second}
	httpClients := []*http.Client{first.http, second.archive, first.archive, second.http}
	var firstBody io.ReadCloser
	for i, client := range clients {
		request := redHatHTTPTestRequest(t, context.Background(), "https://SECURITY.ACCESS.REDHAT.COM:443/advisory")
		response, err := client.do(httpClients[i], request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := io.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstBody = response.Body
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	queued := &redHatHTTPQueuedContext{Context: ctx, queued: make(chan struct{})}
	request := redHatHTTPTestRequest(t, queued, "https://security.access.redhat.com/fifth")
	result, done := redHatHTTPTestStart(t, second, second.archive, request, cancel)
	redHatHTTPTestSignal(t, queued.queued)
	select {
	case <-done:
		t.Fatal("fifth request passed four body-held slots")
	default:
	}
	if calls.Load() != 4 {
		t.Fatalf("transport calls while bodies are held: %d", calls.Load())
	}
	if err := firstBody.Close(); err != nil {
		t.Fatal(err)
	}
	redHatHTTPTestSignal(t, done)
	if result.err != nil || result.response == nil || calls.Load() != 5 {
		t.Fatalf("request did not acquire the released slot: response=%v err=%v calls=%d", result.response, result.err, calls.Load())
	}
}

func TestRedHatHTTPCanceledQueuedRequest(t *testing.T) {
	policy := newRedHatHTTPPolicy()
	client := &Client{redHatHTTP: policy}
	var calls atomic.Int32
	transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return redHatHTTPTestResponse(request, http.StatusOK), nil
	})}
	for range redHatHTTPConcurrency {
		response := redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/held"))
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	ctx, cancel := context.WithCancel(context.Background())
	queued := &redHatHTTPQueuedContext{Context: ctx, queued: make(chan struct{})}
	result, done := redHatHTTPTestStart(t, client, transport, redHatHTTPTestRequest(t, queued, "https://security.access.redhat.com/queued"), cancel)
	redHatHTTPTestSignal(t, queued.queued)
	cancel()
	redHatHTTPTestSignal(t, done)
	if !errors.Is(result.err, context.Canceled) || result.response != nil {
		t.Fatalf("queued cancellation: response=%v err=%v", result.response, result.err)
	}
	if calls.Load() != 4 || len(policy.slots) != 4 {
		t.Fatalf("canceled queue entered transport or changed held slots: calls=%d slots=%d", calls.Load(), len(policy.slots))
	}
}

type redHatHTTPTestClock struct {
	mu   sync.Mutex
	time time.Time
}

func (c *redHatHTTPTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.time
}

func (c *redHatHTTPTestClock) advance(delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.time = c.time.Add(delay)
}

func redHatHTTPTestPolicy() (*redHatHTTPPolicy, *redHatHTTPTestClock) {
	clock := &redHatHTTPTestClock{time: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	policy := newRedHatHTTPPolicy()
	policy.now = clock.now
	return policy, clock
}

func TestRedHatHTTPRetryAfterCooldown(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
		delay  time.Duration
	}{
		{"seconds", "7", 7 * time.Second},
		{"HTTP-date", "Fri, 16 Oct 2026 12:00:17 GMT", 17 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, clock := redHatHTTPTestPolicy()
			first, second := &Client{redHatHTTP: policy}, &Client{redHatHTTP: policy}
			var waits []time.Duration
			policy.wait = func(ctx context.Context, delay time.Duration) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				waits = append(waits, delay)
				clock.advance(delay)
				return nil
			}
			calls := 0
			var original *http.Response
			transport := redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				response := redHatHTTPTestResponse(request, http.StatusOK)
				if calls == 1 {
					response.StatusCode = http.StatusTooManyRequests
					response.Header.Set("Retry-After", test.header)
					original = response
				}
				return response, nil
			})
			response := redHatHTTPTestDo(t, first, &http.Client{Transport: transport}, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/limited"))
			if response != original || response.StatusCode != 429 || response.Header.Get("Retry-After") != test.header || calls != 1 || len(waits) != 0 {
				t.Fatal("429 response was replaced, retried, or delayed instead of being returned unchanged")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			response = redHatHTTPTestDo(t, second, &http.Client{Transport: transport}, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/subsequent"))
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || len(waits) != 1 || waits[0] != test.delay {
				t.Fatalf("cross-client cooldown: calls=%d waits=%v want=%v", calls, waits, test.delay)
			}
		})
	}
}

func TestRedHatHTTPInvalidRetryAfterUsesConservativeCooldown(t *testing.T) {
	for _, header := range []string{"", "not-a-delay", "1.5", "-1", "+1", "0", "Fri, 16 Oct 2026 11:59:59 GMT"} {
		t.Run(header, func(t *testing.T) {
			policy, clock := redHatHTTPTestPolicy()
			var waits []time.Duration
			policy.wait = func(_ context.Context, delay time.Duration) error {
				waits = append(waits, delay)
				clock.advance(delay)
				return nil
			}
			calls := 0
			transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				response := redHatHTTPTestResponse(request, http.StatusOK)
				if calls == 1 {
					response.StatusCode = http.StatusTooManyRequests
					if header != "" {
						response.Header.Set("Retry-After", header)
					}
				}
				return response, nil
			})}
			client := &Client{redHatHTTP: policy}
			response := redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/limited"))
			if calls != 1 || response.StatusCode != 429 {
				t.Fatal("invalid Retry-After concealed or retried the original 429")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			response = redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/next"))
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if len(waits) != 1 || waits[0] != redHatRetryAfterFallback || redHatRetryAfterFallback != time.Minute {
				t.Fatalf("invalid Retry-After %q did not enforce explicit one-minute fallback: %v", header, waits)
			}
		})
	}
}

func TestRedHatHTTPOversizedNumericRetryAfterNeverShortensCooldown(t *testing.T) {
	for _, header := range []string{"9223372037", "18446744073709551616"} {
		t.Run(header, func(t *testing.T) {
			policy, clock := redHatHTTPTestPolicy()
			calls := 0
			transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				response := redHatHTTPTestResponse(request, http.StatusOK)
				if calls == 1 {
					response.StatusCode = http.StatusTooManyRequests
					response.Header.Set("Retry-After", header)
				}
				return response, nil
			})}
			first, second := &Client{redHatHTTP: policy}, &Client{redHatHTTP: policy}
			response := redHatHTTPTestDo(t, first, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/limited"))
			if response.StatusCode != 429 || calls != 1 || !policy.indefinite {
				t.Fatal("oversized numeric delay was shortened, retried, or concealed")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			// A later short hint and elapsed fallback interval cannot clear it.
			policy.rateLimited("1")
			clock.advance(2 * redHatRetryAfterFallback)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			unexpectedResponse, err := second.do(transport, redHatHTTPTestRequest(t, ctx, "https://security.access.redhat.com/subsequent"))
			if unexpectedResponse != nil {
				defer func() { _ = unexpectedResponse.Body.Close() }()
			}
			if !errors.Is(err, context.DeadlineExceeded) || unexpectedResponse != nil || calls != 1 || len(policy.slots) != 0 {
				t.Fatalf("indefinite cooldown resumed requests or leaked a permit: calls=%d err=%v", calls, err)
			}
			response = redHatHTTPTestDo(t, second, transport, redHatHTTPTestRequest(t, context.Background(), "https://other-vendor.example/unrelated"))
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("indefinite Red Hat cooldown contaminated another vendor")
			}
		})
	}
}

func TestRedHatHTTPCanceledCooldownPersistsAcrossClients(t *testing.T) {
	policy, clock := redHatHTTPTestPolicy()
	first, second := &Client{redHatHTTP: policy}, &Client{redHatHTTP: policy}
	var calls atomic.Int32
	transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		response := redHatHTTPTestResponse(request, http.StatusOK)
		if calls.Add(1) == 1 {
			response.StatusCode = http.StatusTooManyRequests
			response.Header.Set("Retry-After", "120")
		}
		return response, nil
	})}
	refresh, cancelRefresh := context.WithCancel(context.Background())
	defer cancelRefresh()
	response := redHatHTTPTestDo(t, first, transport, redHatHTTPTestRequest(t, refresh, "https://security.access.redhat.com/limited"))
	cancelRefresh()
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	policy.wait = func(ctx context.Context, delay time.Duration) error {
		close(waiting)
		return waitRedHatHTTP(ctx, delay)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result, done := redHatHTTPTestStart(t, second, transport, redHatHTTPTestRequest(t, ctx, "https://security.access.redhat.com/paused"), cancel)
	redHatHTTPTestSignal(t, waiting)
	cancel()
	redHatHTTPTestSignal(t, done)
	if !errors.Is(result.err, context.Canceled) || result.response != nil || calls.Load() != 1 || len(policy.slots) != 0 {
		t.Fatalf("cooldown cancellation: response=%v err=%v calls=%d slots=%d", result.response, result.err, calls.Load(), len(policy.slots))
	}
	var waited time.Duration
	policy.wait = func(_ context.Context, delay time.Duration) error {
		waited += delay
		clock.advance(delay)
		return nil
	}
	response = redHatHTTPTestDo(t, first, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/later-refresh"))
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if waited != 2*time.Minute || calls.Load() != 2 {
		t.Fatalf("canceled refresh/request cleared shared cooldown: waited=%v calls=%d", waited, calls.Load())
	}
}

func TestRedHatHTTPNonRedHatIsolation(t *testing.T) {
	policy, _ := redHatHTTPTestPolicy()
	client := &Client{redHatHTTP: policy}
	transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		response := redHatHTTPTestResponse(request, http.StatusOK)
		if !isRedHatHTTP(request.URL) {
			response.StatusCode = http.StatusTooManyRequests
			response.Header.Set("Retry-After", "240")
		}
		return response, nil
	})}
	for range redHatHTTPConcurrency {
		response := redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/held"))
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	policy.rateLimited("120")
	policy.mu.Lock()
	until := policy.cooldownUntil
	policy.mu.Unlock()
	policy.wait = func(context.Context, time.Duration) error {
		return errors.New("non-Red-Hat request inherited Red Hat cooldown")
	}
	for _, location := range []string{
		"https://example.test/advisory",
		"https://security.access.redhat.com.attacker.test/advisory",
		"https://notsecurity.access.redhat.com/advisory",
		"https://redhat.com/advisory",
	} {
		response := redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), location))
		if response.StatusCode != 429 {
			t.Fatal("other vendor's response was changed")
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	policy.mu.Lock()
	defer policy.mu.Unlock()
	if !policy.cooldownUntil.Equal(until) || len(policy.slots) != 4 {
		t.Fatal("other vendors changed the shared Red Hat cooldown or slots")
	}
}

func TestRedHatHTTPRedirectLifetimeAndUserAgent(t *testing.T) {
	policy := newRedHatHTTPPolicy()
	var visits []string
	transport := redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		visits = append(visits, request.URL.String())
		if request.UserAgent() != "lindm advisory feed" {
			t.Errorf("unclear or fabricated User-Agent: %q", request.UserAgent())
		}
		response := redHatHTTPTestResponse(request, http.StatusFound)
		switch request.URL.Path {
		case "/start":
			if len(policy.slots) != 0 {
				t.Error("non-Red-Hat origin acquired a Red Hat slot")
			}
			response.Header.Set("Location", "https://security.access.redhat.com/first")
		case "/first":
			response.Header.Set("Location", "https://SECURITY.ACCESS.REDHAT.COM/second")
		case "/second":
			response.Header.Set("Location", "https://example.test/final")
		case "/final":
			response.StatusCode = http.StatusOK
		default:
			t.Fatalf("unexpected redirect target: %s", request.URL)
		}
		if request.URL.Path != "/start" && len(policy.slots) != 1 {
			t.Errorf("redirect chain did not retain exactly one permit: %d", len(policy.slots))
		}
		return response, nil
	})
	client, err := New(&http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	client.redHatHTTP = policy
	originalChecker := client.http.CheckRedirect
	client.http.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		request.Header.Set("User-Agent", "misleading/99")
		return originalChecker(request, via)
	}
	request := redHatHTTPTestRequest(t, context.Background(), "https://example.test/start")
	request.Header.Set("User-Agent", "misleading/99")
	response := redHatHTTPTestDo(t, client, client.http, request)
	if len(visits) != 4 || len(policy.slots) != 1 {
		t.Fatalf("redirect lifetime: visits=%v slots=%d", visits, len(policy.slots))
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if len(policy.slots) != 1 {
		t.Fatal("EOF released permit before body closure")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil || len(policy.slots) != 0 {
		t.Fatalf("body closure did not release exactly once: err=%v slots=%d", err, len(policy.slots))
	}
}

func TestRedHatHTTPPreservesRedirectPolicyAndReleasesOnErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		location string
		calls    int
	}{
		{"HTTPS-only", "http://security.access.redhat.com/unsafe", 1},
		{"redirect-limit", "https://security.access.redhat.com/again", 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := newRedHatHTTPPolicy()
			calls := 0
			client, err := New(&http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				response := redHatHTTPTestResponse(request, http.StatusFound)
				response.Header.Set("Location", test.location)
				return response, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			client.redHatHTTP = policy
			response, err := client.do(client.http, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/start"))
			if response != nil {
				defer func() { _ = response.Body.Close() }()
			}
			if err == nil || calls != test.calls || len(policy.slots) != 0 {
				t.Fatalf("redirect policy changed or leaked permit: err=%v calls=%d slots=%d", err, calls, len(policy.slots))
			}
		})
	}
	for _, checker := range []bool{false, true} {
		name := "transport-error"
		if checker {
			name = "checker-error"
		}
		t.Run(name, func(t *testing.T) {
			policy := newRedHatHTTPPolicy()
			client := &Client{redHatHTTP: policy}
			cause := errors.New("original HTTP failure")
			transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
				if !checker {
					return nil, cause
				}
				response := redHatHTTPTestResponse(request, http.StatusFound)
				response.Header.Set("Location", "https://security.access.redhat.com/next")
				return response, nil
			}), CheckRedirect: func(*http.Request, []*http.Request) error { return cause }}
			response, err := client.do(transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/start"))
			if response != nil {
				defer func() { _ = response.Body.Close() }()
			}
			if !errors.Is(err, cause) || len(policy.slots) != 0 {
				t.Fatalf("original failure lost or permit leaked: err=%v slots=%d", err, len(policy.slots))
			}
		})
	}
}

func TestRedHatHTTPPreservesErrUseLastResponse(t *testing.T) {
	policy := newRedHatHTTPPolicy()
	client := &Client{redHatHTTP: policy}
	calls := 0
	transport := &http.Client{Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		response := redHatHTTPTestResponse(request, http.StatusFound)
		response.Header.Set("Location", "https://security.access.redhat.com/not-followed")
		return response, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := redHatHTTPTestDo(t, client, transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/start"))
	if calls != 1 || response.StatusCode != http.StatusFound || len(policy.slots) != 1 {
		t.Fatalf("ErrUseLastResponse changed: status=%d calls=%d slots=%d", response.StatusCode, calls, len(policy.slots))
	}
	if err := response.Body.Close(); err != nil || len(policy.slots) != 0 {
		t.Fatalf("last response permit leaked: err=%v slots=%d", err, len(policy.slots))
	}
}

func TestRedHatHTTPGatePreservesClientTimeout(t *testing.T) {
	policy := newRedHatHTTPPolicy()
	client := &Client{redHatHTTP: policy}
	for range redHatHTTPConcurrency {
		if err := policy.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(policy.release)
	}
	var calls atomic.Int32
	transport := &http.Client{
		Timeout: time.Millisecond,
		Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return redHatHTTPTestResponse(request, http.StatusOK), nil
		}),
	}
	// The long caller deadline is only a guard against a broken gate; the
	// ordinary client's own timeout must stop this queued request first.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.do(transport, redHatHTTPTestRequest(t, ctx, "https://security.access.redhat.com/queued"))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if !errors.Is(err, context.DeadlineExceeded) || response != nil || ctx.Err() != nil || calls.Load() != 0 {
		t.Fatalf("queue escaped client timeout: response=%v err=%v caller=%v calls=%d", response, err, ctx.Err(), calls.Load())
	}
}

func TestRedHatHTTPCooldownOnlyExtends(t *testing.T) {
	policy, clock := redHatHTTPTestPolicy()
	policy.rateLimited("120")
	clock.advance(time.Second)
	policy.rateLimited("1")
	policy.mu.Lock()
	until := policy.cooldownUntil
	policy.mu.Unlock()
	if !until.Equal(clock.now().Add(119 * time.Second)) {
		t.Fatalf("shorter Retry-After shortened the shared cooldown: %v", until)
	}
}

type redHatHTTPFailingBody struct {
	closed int
	err    error
}

func (b *redHatHTTPFailingBody) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (b *redHatHTTPFailingBody) Close() error {
	b.closed++
	return b.err
}

func TestRedHatHTTPBodyCloseErrorReleasesExactlyOnce(t *testing.T) {
	policy := newRedHatHTTPPolicy()
	client := &Client{redHatHTTP: policy}
	cause := errors.New("original body close failure")
	body := &redHatHTTPFailingBody{err: cause}
	transport := &http.Client{
		Timeout: time.Hour,
		Transport: redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
			response := redHatHTTPTestResponse(request, http.StatusOK)
			response.Body = body
			return response, nil
		}),
	}
	response, err := client.do(transport, redHatHTTPTestRequest(t, context.Background(), "https://security.access.redhat.com/advisory"))
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); !errors.Is(err, cause) {
		t.Fatalf("body close cause lost: %v", err)
	}
	if err := response.Body.Close(); !errors.Is(err, cause) || body.closed != 1 || len(policy.slots) != 0 {
		t.Fatalf("body was not closed/released exactly once: err=%v closes=%d slots=%d", err, body.closed, len(policy.slots))
	}
	select {
	case <-response.Request.Context().Done():
	default:
		t.Fatal("body close did not cancel the queue-inclusive client timeout")
	}
}
