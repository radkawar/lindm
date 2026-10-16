// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

type httpRetryTestBody struct {
	io.Reader
	close func() error
	once  sync.Once
	err   error
}

func (b *httpRetryTestBody) Close() error {
	b.once.Do(func() {
		if b.close != nil {
			b.err = b.close()
		}
	})
	return b.err
}

type httpRetryTestResetReader struct{ raw []byte }

func (r *httpRetryTestResetReader) Read(p []byte) (int, error) {
	n := copy(p, r.raw)
	r.raw = r.raw[n:]
	return n, syscall.ECONNRESET
}

type httpRetryTestNetworkTimeout struct{}

func (httpRetryTestNetworkTimeout) Error() string   { return "i/o timeout" }
func (httpRetryTestNetworkTimeout) Timeout() bool   { return true }
func (httpRetryTestNetworkTimeout) Temporary() bool { return true }
func (httpRetryTestNetworkTimeout) Is(err error) bool {
	return err == context.DeadlineExceeded
}

func httpRetryTestResponse(request *http.Request, raw []byte, close func() error) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          &httpRetryTestBody{Reader: bytes.NewReader(raw), close: close},
		ContentLength: int64(len(raw)),
		Request:       request,
		TLS:           &tls.ConnectionState{HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{{}}}},
	}
}

func httpRetryTestResponseBody(t *testing.T, response *http.Response) *httpRetryTestBody {
	t.Helper()
	body, ok := response.Body.(*httpRetryTestBody)
	if !ok {
		t.Fatalf("unexpected response body %T", response.Body)
	}
	return body
}

func httpRetryTestClient(t *testing.T, transport redHatHTTPTestTransport) (*Client, *redHatHTTPTestClock, *[]time.Duration) {
	t.Helper()
	client, err := New(&http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	policy, clock := redHatHTTPTestPolicy()
	client.redHatHTTP = policy
	var waits []time.Duration
	wait := func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		waits = append(waits, delay)
		clock.advance(delay)
		return nil
	}
	policy.wait = wait
	client.httpRetry = &httpRetryPolicy{now: clock.now, wait: wait}
	return client, clock, &waits
}

func httpRetryTestFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "download-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestHTTPRetryEventualTransientSuccess(t *testing.T) {
	for _, test := range []struct {
		name       string
		network    error
		status     int
		retryAfter string
		location   string
		partial    bool
		wait       time.Duration
	}{
		{name: "DNS-timeout", network: &net.DNSError{Err: "timeout", Name: "security.access.redhat.com", IsTimeout: true}, wait: time.Second},
		{name: "resolver-UDP-timeout-matching-deadline", network: &net.OpError{Op: "read", Net: "udp", Err: httpRetryTestNetworkTimeout{}}, wait: time.Second},
		{name: "connection-reset", network: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, wait: time.Second},
		{name: "connection-EOF", network: io.EOF, wait: time.Second},
		{name: "HTTP-503", status: http.StatusServiceUnavailable, wait: time.Second},
		{name: "generic-HTTP-503", status: http.StatusServiceUnavailable, retryAfter: "0", location: "https://mirror.example/advisory", wait: time.Second},
		{name: "generic-HTTP-429", status: http.StatusTooManyRequests, retryAfter: "9", location: "https://mirror.example/advisory", wait: 9 * time.Second},
		{name: "HTTP-429-seconds", status: http.StatusTooManyRequests, retryAfter: "7", wait: 7 * time.Second},
		{name: "HTTP-429-date", status: http.StatusTooManyRequests, retryAfter: "Fri, 16 Oct 2026 12:00:17 GMT", wait: 17 * time.Second},
		{name: "HTTP-429-malformed", status: http.StatusTooManyRequests, retryAfter: "later", wait: time.Minute},
		{name: "HTTP-429-zero", status: http.StatusTooManyRequests, retryAfter: "0", wait: time.Minute},
		{name: "HTTP-429-past", status: http.StatusTooManyRequests, retryAfter: "Fri, 16 Oct 2026 11:59:59 GMT", wait: time.Minute},
		{name: "partial-body-reset", partial: true, wait: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls, closes := 0, 0
			payload := []byte("complete authenticated vendor bytes")
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Header.Get("User-Agent") != advisoryFeedUserAgent || request.Header.Get("Accept-Encoding") != "identity" {
					t.Error("retry lost feed request headers")
				}
				if calls == 1 && test.network != nil {
					return nil, test.network
				}
				response := httpRetryTestResponse(request, payload, func() error { closes++; return nil })
				if calls == 1 {
					if test.status != 0 {
						response.StatusCode = test.status
						response.Header.Set("Retry-After", test.retryAfter)
					}
					if test.partial {
						httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: []byte("discard partial bytes")}
					}
				}
				return response, nil
			})
			wait := client.httpRetry.wait
			client.httpRetry.wait = func(ctx context.Context, delay time.Duration) error {
				if len(client.redHatHTTP.slots) != 0 || test.network == nil && closes != 1 {
					t.Error("body or Red Hat network permit held during retry wait")
				}
				return wait(ctx, delay)
			}
			var counter atomic.Int64
			location := test.location
			if location == "" {
				location = "https://security.access.redhat.com/advisory"
			}
			raw, err := client.get(WithRetryCounter(t.Context(), &counter), location, 1024)
			if err != nil || !bytes.Equal(raw, payload) || calls != 2 || counter.Load() != 1 {
				t.Fatalf("recovery: raw=%q err=%v calls=%d retries=%d", raw, err, calls, counter.Load())
			}
			if !slices.Equal(*waits, []time.Duration{test.wait}) || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("waits=%v remaining permits=%d", *waits, len(client.redHatHTTP.slots))
			}
			wantCloses := 2
			if test.network != nil {
				wantCloses = 1
			}
			if closes != wantCloses {
				t.Fatalf("closed bodies=%d want=%d", closes, wantCloses)
			}
		})
	}
}

func TestHTTPRetryFiveAttemptBudgetAndWholeRequestDeadline(t *testing.T) {
	for _, mode := range []string{"DNS", "HTTP-500", "body-reset"} {
		t.Run(mode, func(t *testing.T) {
			calls, closes := 0, 0
			var deadline time.Time
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				current, ok := request.Context().Deadline()
				if !ok || current.After(time.Now().Add(2*time.Minute)) {
					t.Error("ordinary acquisition lost its two-minute whole-request deadline")
				}
				if calls == 1 {
					deadline = current
				} else if !current.Equal(deadline) {
					t.Error("retry restarted the whole-request deadline")
				}
				if mode == "DNS" {
					return nil, &net.DNSError{Err: "temporary", IsTemporary: true}
				}
				response := httpRetryTestResponse(request, []byte("incomplete"), func() error { closes++; return nil })
				if mode == "HTTP-500" {
					response.StatusCode = http.StatusInternalServerError
					response.Header.Set("Retry-After", "0")
				} else {
					httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: []byte("partial")}
				}
				return response, nil
			})
			var counter atomic.Int64
			location := "https://security.access.redhat.com/advisory"
			if mode == "HTTP-500" {
				location = "https://mirror.example/advisory"
			}
			raw, err := client.get(WithRetryCounter(t.Context(), &counter), location, 1024)
			if err == nil || raw != nil || calls != 5 || counter.Load() != 4 {
				t.Fatalf("budget: err=%v raw=%q calls=%d retries=%d", err, raw, calls, counter.Load())
			}
			if !slices.Equal(*waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}) {
				t.Fatalf("exponential waits=%v", *waits)
			}
			if mode != "DNS" && closes != 5 || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("cleanup: closes=%d remaining permits=%d", closes, len(client.redHatHTTP.slots))
			}
		})
	}
}

func TestHTTPRetryCanceledBackoffDoesNotCountUninitiatedAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls, closes := 0, 0
	client, _, _ := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		calls++
		response := httpRetryTestResponse(request, nil, func() error { closes++; return nil })
		response.StatusCode = http.StatusServiceUnavailable
		return response, nil
	})
	client.httpRetry.wait = func(ctx context.Context, _ time.Duration) error {
		if closes != 1 || len(client.redHatHTTP.slots) != 0 {
			t.Error("retry wait retained a response body or permit")
		}
		cancel()
		return ctx.Err()
	}
	var counter atomic.Int64
	_, err := client.get(WithRetryCounter(ctx, &counter), "https://security.access.redhat.com/advisory", 1024)
	if !errors.Is(err, context.Canceled) || calls != 1 || counter.Load() != 0 {
		t.Fatalf("canceled backoff: err=%v calls=%d retries=%d", err, calls, counter.Load())
	}
}

func TestHTTPRetryHonorsLongerSharedCooldown(t *testing.T) {
	calls := 0
	client, clock, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		calls++
		response := httpRetryTestResponse(request, []byte("vendor bytes"), nil)
		if calls == 1 {
			response.StatusCode = http.StatusTooManyRequests
			response.Header.Set("Retry-After", "7")
		}
		return response, nil
	})
	wait := client.httpRetry.wait
	client.httpRetry.wait = func(ctx context.Context, delay time.Duration) error {
		// Another feed's later 429 extends the process-wide pause while this
		// acquisition waits. Its shorter local backoff cannot clear that pause.
		client.redHatHTTP.rateLimited("30")
		return wait(ctx, delay)
	}
	started := clock.now()
	if _, err := client.get(t.Context(), "https://security.access.redhat.com/advisory", 1024); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || clock.now().Sub(started) != 30*time.Second || !slices.Equal(*waits, []time.Duration{7 * time.Second, 23 * time.Second}) {
		t.Fatalf("shared cooldown shortened: calls=%d waits=%v elapsed=%v", calls, *waits, clock.now().Sub(started))
	}
}

func TestHTTPRetryAfterOverflowKeepsIndefiniteQuarantine(t *testing.T) {
	for _, header := range []string{"9223372037", "18446744073709551616"} {
		t.Run(header, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, closes := 0, 0
			client, clock, _ := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				response := httpRetryTestResponse(request, nil, func() error { closes++; return nil })
				response.StatusCode = http.StatusTooManyRequests
				response.Header.Set("Retry-After", header)
				return response, nil
			})
			nowCalls := 0
			client.httpRetry.now = func() time.Time {
				nowCalls++
				if nowCalls == 2 {
					// Cancel exactly when Retry-After is parsed, so the
					// indefinite branch is exercised without a real wait.
					cancel()
				}
				return clock.now()
			}
			client.httpRetry.wait = func(context.Context, time.Duration) error {
				t.Error("overflow was shortened to a finite backoff")
				return context.Canceled
			}
			var counter atomic.Int64
			_, err := client.get(WithRetryCounter(ctx, &counter), "https://security.access.redhat.com/advisory", 1024)
			if !errors.Is(err, context.Canceled) || calls != 1 || closes != 1 || nowCalls != 2 || counter.Load() != 0 || !client.redHatHTTP.indefinite || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("overflow: err=%v calls=%d closes=%d retries=%d quarantine=%v permits=%d", err, calls, closes, counter.Load(), client.redHatHTTP.indefinite, len(client.redHatHTTP.slots))
			}
			// A fresh refresh cannot clear the process-owned quarantine either.
			request := redHatHTTPTestRequest(t, ctx, "https://security.access.redhat.com/next")
			response, err := client.do(client.http, request)
			if response != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if !errors.Is(err, context.Canceled) || calls != 1 {
				t.Fatalf("quarantine allowed a subsequent request: err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestHTTPRetryArchiveResetsPrivateFileDigestAndCRC(t *testing.T) {
	file := httpRetryTestFile(t)
	payload := []byte("complete archive")
	partial := bytes.Repeat([]byte("discard old partial bytes"), 8)
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	calls, closes := 0, 0
	client, _, _ := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		calls++
		if info, err := file.Stat(); err != nil || info.Size() != 0 {
			t.Errorf("private file not truncated before attempt %d: info=%v err=%v", calls, info, err)
		}
		if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
			t.Errorf("private file not rewound before attempt %d: offset=%d err=%v", calls, offset, err)
		}
		if _, ok := request.Context().Deadline(); ok {
			t.Error("archive acquired an ordinary whole-request deadline")
		}
		response := httpRetryTestResponse(request, payload, func() error { closes++; return nil })
		response.Header.Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(checksum[:]))
		if calls == 1 {
			httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: partial}
		}
		return response, nil
	})
	var counter atomic.Int64
	// Background has no deadline: archive requests must not add two minutes.
	digest, err := client.downloadArchive(WithRetryCounter(context.Background(), &counter), "https://security.access.redhat.com/archive.tar.zst", file, 1024, nil)
	wantDigest := sha256.Sum256(payload)
	if err != nil || !bytes.Equal(digest, wantDigest[:]) || calls != 2 || closes != 2 || counter.Load() != 1 {
		t.Fatalf("archive retry: digest=%x err=%v calls=%d closes=%d retries=%d", digest, err, calls, closes, counter.Load())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatalf("mixed or trailing partial archive bytes: raw=%q err=%v", raw, err)
	}
}

func TestHTTPRetryTerminalTransportAndResponseErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		network    error
		status     int
		unverified bool
		encoding   string
		body       []byte
		reset      bool
		closeError bool
	}{
		{name: "DNS-not-found", network: &net.DNSError{Err: "no such host", IsNotFound: true}},
		{name: "certificate-authority", network: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}},
		{name: "certificate-hostname", network: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "publisher.example"}},
		{name: "deadline", network: context.DeadlineExceeded},
		{name: "HTTP-404", status: http.StatusNotFound},
		{name: "HTTP-403", status: http.StatusForbidden},
		{name: "unverified-TLS-503", status: http.StatusServiceUnavailable, unverified: true},
		{name: "unsupported-encoding", encoding: "gzip"},
		{name: "unsupported-encoding-503", status: http.StatusServiceUnavailable, encoding: "gzip"},
		{name: "byte-bound-even-with-reset", body: []byte("12345"), reset: true},
		{name: "close-error", closeError: true, reset: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls, closes := 0, 0
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				if test.network != nil {
					return nil, test.network
				}
				response := httpRetryTestResponse(request, test.body, func() error {
					closes++
					if test.closeError {
						return errors.New("close failed")
					}
					return nil
				})
				if test.reset {
					httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: test.body}
				}
				if test.status != 0 {
					response.StatusCode = test.status
				}
				if test.unverified {
					response.TLS = nil
				}
				response.Header.Set("Content-Encoding", test.encoding)
				return response, nil
			})
			var counter atomic.Int64
			_, err := client.get(WithRetryCounter(t.Context(), &counter), "https://security.access.redhat.com/advisory", 4)
			if err == nil || calls != 1 || counter.Load() != 0 || len(*waits) != 0 || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("terminal failure retried or leaked: err=%v calls=%d retries=%d waits=%v permits=%d", err, calls, counter.Load(), *waits, len(client.redHatHTTP.slots))
			}
			if test.network == nil && closes != 1 {
				t.Fatalf("terminal response not closed: %d", closes)
			}
		})
	}
}

func TestHTTPRetryArchiveTerminalIntegrityBoundsAndStorage(t *testing.T) {
	for _, mode := range []string{"CRC-mismatch", "CRC-malformed", "CRC-duplicate", "known-bound", "stream-bound", "storage", "writer-network-shaped-error", "watchdog"} {
		t.Run(mode, func(t *testing.T) {
			file := httpRetryTestFile(t)
			calls, closes := 0, 0
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				response := httpRetryTestResponse(request, []byte("archive bytes"), func() error { closes++; return nil })
				switch mode {
				case "CRC-mismatch":
					response.Header.Set("X-Goog-Hash", "crc32c=AAAAAA==")
				case "CRC-malformed":
					response.Header.Set("X-Goog-Hash", "crc32c=invalid")
				case "CRC-duplicate":
					response.Header.Set("X-Goog-Hash", "crc32c=AAAAAA==,crc32c=AAAAAA==")
				case "stream-bound":
					response.ContentLength = -1
				}
				return response, nil
			})
			var counter atomic.Int64
			ctx := WithRetryCounter(t.Context(), &counter)
			bound := int64(1024)
			if strings.Contains(mode, "bound") {
				bound = 4
			}
			if mode == "storage" {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if mode == "writer-network-shaped-error" || mode == "watchdog" {
				request := redHatHTTPTestRequest(t, ctx, "https://security.access.redhat.com/archive")
				err = client.getHTTP(request, client.archive, true, nil, func(*http.Response) error {
					if mode == "watchdog" {
						return ErrRefreshStalled
					}
					return &net.OpError{Op: "write", Err: syscall.ECONNRESET}
				})
			} else {
				_, err = client.downloadArchive(ctx, "https://security.access.redhat.com/archive", file, bound, nil)
			}
			wantCalls := 1
			if mode == "storage" {
				wantCalls = 0
			}
			if err == nil || calls != wantCalls || closes != wantCalls || counter.Load() != 0 || len(*waits) != 0 || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("terminal %s: err=%v calls=%d closes=%d retries=%d waits=%v permits=%d", mode, err, calls, closes, counter.Load(), *waits, len(client.redHatHTTP.slots))
			}
		})
	}
}

func TestHTTPRetryNoRetriesForAuthenticationParsingOrValidation(t *testing.T) {
	for _, mode := range []string{"pin", "parse", "document-validation", "source-validation", "vendor-checksum", "vendor-signature"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			calls := 0
			raw := fixture(t, "redhat-rhsa-2024_6783.json")
			checksum := fixture(t, "redhat-rhsa-2024_6783.json.sha256")
			proof := fixture(t, "redhat-rhsa-2024_6783.json.asc")
			if mode == "vendor-checksum" {
				checksum = []byte(strings.Repeat("0", 64) + "  rhsa-2024_6783.json\n")
			}
			if mode == "vendor-signature" {
				proof = flippedSignature(t, proof)
			}
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				payload := []byte("not JSON")
				switch {
				case mode == "document-validation":
					payload = []byte(`{"id":"notice","schema_version":"0.0","affected":[]}`)
				case strings.HasSuffix(request.URL.Path, ".sha256"):
					payload = checksum
				case strings.HasSuffix(request.URL.Path, ".asc"):
					payload = proof
				case strings.HasPrefix(mode, "vendor-"):
					payload = raw
				}
				return httpRetryTestResponse(request, payload, nil), nil
			})
			var counter atomic.Int64
			ctx := WithRetryCounter(t.Context(), &counter)
			config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)
			config.Url = "https://security.access.redhat.com/advisory.json"
			var err error
			switch mode {
			case "pin":
				config.ExpectedSha256 = make([]byte, sha256.Size)
				_, err = client.Acquire(ctx, config, io.Discard)
			case "source-validation":
				config.Url = "not a URL"
				_, err = client.Fetch(ctx, config)
			case "parse", "document-validation":
				_, err = client.Fetch(ctx, config)
			default:
				config = source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF)
				config.Url = "https://security.access.redhat.com/rhsa-2024_6783.json"
				_, _, err = client.consumeSignedCSAF(ctx, config, func(*os.File) error {
					t.Error("unauthenticated bytes reached the consumer")
					return nil
				})
			}
			wantCalls := 1
			if mode == "source-validation" {
				wantCalls = 0
			} else if strings.HasPrefix(mode, "vendor-") {
				wantCalls = 3
			}
			if err == nil || calls != wantCalls || counter.Load() != 0 || len(*waits) != 0 {
				t.Fatalf("trust/validation failure retried: err=%v calls=%d retries=%d waits=%v", err, calls, counter.Load(), *waits)
			}
			replacementTestEmpty(t, directory, nil)
		})
	}
}

func TestHTTPRetryCancellationAndWatchdogAreTerminal(t *testing.T) {
	for _, cause := range []error{context.Canceled, ErrRefreshStalled, ErrRefreshCeiling} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			cancel(cause)
			calls := 0
			client, _, waits := httpRetryTestClient(t, func(*http.Request) (*http.Response, error) {
				calls++
				return nil, syscall.ECONNRESET
			})
			var counter atomic.Int64
			_, err := client.get(WithRetryCounter(ctx, &counter), "https://security.access.redhat.com/advisory", 1024)
			if !errors.Is(err, context.Canceled) || calls != 0 || counter.Load() != 0 || len(*waits) != 0 {
				t.Fatalf("cancelled acquisition started: err=%v calls=%d retries=%d waits=%v", err, calls, counter.Load(), *waits)
			}
		})
	}
}

func TestHTTPRetryCounterCountsOnlyAfterNetworkPermit(t *testing.T) {
	client, _, _ := httpRetryTestClient(t, func(*http.Request) (*http.Response, error) {
		t.Error("queued retry entered the transport")
		return nil, syscall.ECONNRESET
	})
	for range redHatHTTPConcurrency {
		client.redHatHTTP.slots <- struct{}{}
	}
	defer func() {
		for range redHatHTTPConcurrency {
			client.redHatHTTP.release()
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	var counter atomic.Int64
	queued := &redHatHTTPQueuedContext{Context: WithRetryCounter(ctx, &counter), queued: make(chan struct{})}
	requestCtx := context.WithValue(queued, retryAttemptKey{}, true)
	request := redHatHTTPTestRequest(t, requestCtx, "https://security.access.redhat.com/retry")
	result, done := redHatHTTPTestStart(t, client, client.archive, request, cancel)
	redHatHTTPTestSignal(t, queued.queued)
	cancel()
	redHatHTTPTestSignal(t, done)
	if !errors.Is(result.err, context.Canceled) || counter.Load() != 0 {
		t.Fatalf("uninitiated retry counted: err=%v retries=%d", result.err, counter.Load())
	}
}

func TestHTTPRetryRedirectTrustFailuresAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name, location string
		calls          int
	}{
		{"insecure", "http://security.access.redhat.com/unsafe", 1},
		{"redirect-limit", "https://security.access.redhat.com/again", 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls, closes := 0, 0
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				response := httpRetryTestResponse(request, nil, func() error { closes++; return nil })
				response.StatusCode = http.StatusFound
				response.Header.Set("Location", test.location)
				return response, nil
			})
			var counter atomic.Int64
			_, err := client.get(WithRetryCounter(t.Context(), &counter), "https://security.access.redhat.com/start", 1024)
			if err == nil || calls != test.calls || closes != calls || counter.Load() != 0 || len(*waits) != 0 || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("redirect trust failure retried or leaked: err=%v calls=%d closes=%d retries=%d waits=%v permits=%d", err, calls, closes, counter.Load(), *waits, len(client.redHatHTTP.slots))
			}
		})
	}
}

func TestHTTPRetryFailedSignedAcquisitionRemovesPartialOriginal(t *testing.T) {
	for _, mode := range []string{"exhaustion", "cancel-backoff"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checksum := fixture(t, "redhat-rhsa-2024_6783.json.sha256")
			proof := fixture(t, "redhat-rhsa-2024_6783.json.asc")
			calls, closes, payloadAttempts := 0, 0, 0
			client, _, waits := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
				calls++
				var payload []byte
				switch {
				case strings.HasSuffix(request.URL.Path, ".sha256"):
					payload = checksum
				case strings.HasSuffix(request.URL.Path, ".asc"):
					payload = proof
				}
				response := httpRetryTestResponse(request, payload, func() error { closes++; return nil })
				if strings.HasSuffix(request.URL.Path, ".json") {
					payloadAttempts++
					httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: []byte("discard failed partial original")}
				}
				return response, nil
			})
			if mode == "cancel-backoff" {
				client.httpRetry.wait = func(ctx context.Context, _ time.Duration) error {
					cancel()
					return ctx.Err()
				}
			}
			config := source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF)
			config.Url = "https://security.access.redhat.com/rhsa-2024_6783.json"
			var counter atomic.Int64
			var verified verifiedCSAF
			err := client.acquireSignedCSAF(WithRetryCounter(ctx, &counter), config, &verified)
			wantAttempts, wantRetries := 5, int64(4)
			if mode == "cancel-backoff" {
				wantAttempts, wantRetries = 1, 0
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("backoff cancellation lost: %v", err)
				}
			}
			if err == nil || verified.file != nil || payloadAttempts != wantAttempts || calls != wantAttempts+2 || closes != calls || counter.Load() != wantRetries || len(client.redHatHTTP.slots) != 0 {
				t.Fatalf("failed acquisition leaked/retried incorrectly: err=%v file=%v attempts=%d calls=%d closes=%d retries=%d permits=%d", err, verified.file, payloadAttempts, calls, closes, counter.Load(), len(client.redHatHTTP.slots))
			}
			if mode == "exhaustion" && len(*waits) != 4 {
				t.Fatalf("archive multiplied retry budgets: waits=%v", *waits)
			}
			replacementTestEmpty(t, directory, nil)
		})
	}
}

func TestHTTPRetryConcurrentSignedAcquisitionsPreserveGlobalBudgetsAndAttribution(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	ctx := replacementTestContext(t)
	raw := fixture(t, "redhat-rhsa-2024_6783.json")
	checksum := fixture(t, "redhat-rhsa-2024_6783.json.sha256")
	proof := fixture(t, "redhat-rhsa-2024_6783.json.asc")
	var active, peak atomic.Int32
	var mu sync.Mutex
	attempts := make(map[string]int)
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	transport := redHatHTTPTestTransport(func(request *http.Request) (*http.Response, error) {
		count := active.Add(1)
		for previous := peak.Load(); count > previous && !peak.CompareAndSwap(previous, count); previous = peak.Load() {
		}
		mu.Lock()
		attempts[request.URL.Path]++
		attempt := attempts[request.URL.Path]
		mu.Unlock()
		payload := raw
		switch {
		case strings.HasSuffix(request.URL.Path, ".sha256"):
			payload = checksum
		case strings.HasSuffix(request.URL.Path, ".asc"):
			payload = proof
		}
		response := httpRetryTestResponse(request, payload, func() error { active.Add(-1); return nil })
		if strings.HasSuffix(request.URL.Path, ".json") {
			if attempt == 1 {
				httpRetryTestResponseBody(t, response).Reader = &httpRetryTestResetReader{raw: []byte("untrusted partial original")}
			} else {
				httpRetryTestResponseBody(t, response).Reader = &httpRetryTestBlockedReader{ctx: request.Context(), release: release, reader: bytes.NewReader(payload)}
				started <- struct{}{}
			}
		}
		return response, nil
	})
	first, clock, _ := httpRetryTestClient(t, transport)
	second, _, _ := httpRetryTestClient(t, transport)
	// Both client instances use the real process-wide HTTP permit policy and
	// replacement file budget; only their clock/backoff is isolated.
	first.redHatHTTP = sharedRedHatHTTPPolicy
	second.redHatHTTP = sharedRedHatHTTPPolicy
	wait := func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		clock.advance(delay)
		return nil
	}
	first.httpRetry = &httpRetryPolicy{now: clock.now, wait: wait}
	second.httpRetry = first.httpRetry
	var counters [2]atomic.Int64
	results := make(chan error, 2)
	var files []*os.File
	for index, client := range []*Client{first, second} {
		batch := make([]redHatReplacement, 4)
		for i := range batch {
			config := source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF)
			config.Url = fmt.Sprintf("https://security.access.redhat.com/%d/%d/rhsa-2024_6783.json", index, i)
			batch[i] = redHatReplacement{name: config.Url, config: config, done: make(chan error, 1)}
		}
		go func() {
			results <- runRedHatReplacementBatch(WithRetryCounter(ctx, &counters[index]), batch, client.acquireSignedCSAF, func(_ context.Context, replacement *redHatReplacement) error {
				mu.Lock()
				files = append(files, replacement.verified.file)
				mu.Unlock()
				if replacement.verified.artifact.GetSignerFingerprint() != redHatFingerprint {
					return errors.New("retried original was not authenticated")
				}
				got, err := io.ReadAll(replacement.verified.file)
				if err != nil || !bytes.Equal(got, raw) {
					return errors.Join(errors.New("retried original contains partial bytes"), err)
				}
				return nil
			})
		}()
	}
	for range redHatHTTPConcurrency {
		select {
		case <-started:
		case <-ctx.Done():
			close(release)
			t.Fatal("concurrent retried originals did not overlap")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 4 || active.Load() != 4 || len(sharedRedHatHTTPPolicy.slots) != 4 || len(redHatReplacementSlots) != 4 {
		close(release)
		t.Fatalf("global budgets: files=%d active=%d HTTP permits=%d file permits=%d err=%v", len(entries), active.Load(), len(sharedRedHatHTTPPolicy.slots), len(redHatReplacementSlots), err)
	}
	close(release)
	for range 2 {
		if err := replacementTestResult(t, ctx, results); err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() != 4 || active.Load() != 0 || len(sharedRedHatHTTPPolicy.slots) != 0 || counters[0].Load() != 4 || counters[1].Load() != 4 {
		t.Fatalf("cleanup/attribution: peak=%d active=%d permits=%d retries=%d,%d", peak.Load(), active.Load(), len(sharedRedHatHTTPPolicy.slots), counters[0].Load(), counters[1].Load())
	}
	replacementTestEmpty(t, directory, files)
	// A subsequent refresh has its own zeroed counter, including through child
	// contexts; neither previous feed's counter changes.
	var next atomic.Int64
	config := source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF)
	config.Url = "https://security.access.redhat.com/0/0/rhsa-2024_6783.json"
	var verified verifiedCSAF
	child, cancel := context.WithCancel(WithRetryCounter(ctx, &next))
	defer cancel()
	if err := first.acquireSignedCSAF(child, config, &verified); err != nil {
		t.Fatal(err)
	}
	if err := verified.close(); err != nil {
		t.Fatal(err)
	}
	if next.Load() != 0 || counters[0].Load() != 4 || counters[1].Load() != 4 {
		t.Fatalf("retry counters leaked between refreshes: next=%d previous=%d,%d", next.Load(), counters[0].Load(), counters[1].Load())
	}
	replacementTestEmpty(t, directory, nil)
	if WithRetryCounter(ctx, nil) != ctx {
		t.Fatal("nil retry counter changed context")
	}
}

type httpRetryTestBlockedReader struct {
	ctx     context.Context
	release <-chan struct{}
	reader  io.Reader
}

func (r *httpRetryTestBlockedReader) Read(p []byte) (int, error) {
	select {
	case <-r.release:
		return r.reader.Read(p)
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}
