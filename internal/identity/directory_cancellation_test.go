package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/google/uuid"
)

// cancelingTransport answers directory reads only after cancelling the
// caller's context: the order a loaded host produces when a caller abandons a
// read while the answer is in flight (the server answers as the client hangs
// up, or the body is cut short). Token requests reach the fixture server.
type cancelingTransport struct {
	base   http.RoundTripper
	cancel context.CancelFunc
	body   func(context.Context) io.ReadCloser
}

func (c cancelingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/token") {
		return c.base.RoundTrip(r)
	}
	c.cancel()
	<-r.Context().Done()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: c.body(r.Context()), Request: r}, nil
}

func TestDirectoryReadRacingCancellationIsUnavailable(t *testing.T) {
	unreached := func(t *testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("directory read %s reached the server", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	// Each source is built against a TLS fixture that issues tokens, then
	// reads the directory through wrap(its transport).
	sources := map[string]func(t *testing.T, wrap func(http.RoundTripper) http.RoundTripper) (DirectorySource, string){
		"okta": func(t *testing.T, wrap func(http.RoundTripper) http.RoundTripper) (DirectorySource, string) {
			fixture := newProviderFixture(t, "okta", unreached(t))
			fixture.oauth.client.Transport = wrap(fixture.oauth.client.Transport)
			return fixture.source, "user-immutable"
		},
		"google": func(t *testing.T, wrap func(http.RoundTripper) http.RoundTripper) (DirectorySource, string) {
			fixture := newProviderFixture(t, "google", unreached(t))
			fixture.oauth.client.Transport = wrap(fixture.oauth.client.Transport)
			return fixture.source, "user-immutable"
		},
		"entra": func(t *testing.T, wrap func(http.RoundTripper) http.RoundTripper) (DirectorySource, string) {
			source, _ := entraFixture(t, unreached(t))
			source.httpClient.Transport = wrap(source.httpClient.Transport)
			return source, uuid.NewString()
		},
		"keycloak": func(t *testing.T, wrap func(http.RoundTripper) http.RoundTripper) (DirectorySource, string) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/token" {
					unreached(t)(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := fmt.Fprint(w, `{"access_token":"directory-token","token_type":"Bearer","expires_in":300}`); err != nil {
					t.Errorf("write token: %v", err)
				}
			}))
			t.Cleanup(server.Close)
			source, err := newKeycloakSource(t.Context(), server.URL+"/realms/lindm", "directory", "secret", server.URL+"/token", server.Client(), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			source.httpClient = &http.Client{Transport: wrap(server.Client().Transport)}
			return source, uuid.NewString()
		},
	}
	answers := map[string]func(context.Context) io.ReadCloser{
		// What the fixture server sent when its handler saw the client hang up.
		"complete": func(context.Context) io.ReadCloser { return http.NoBody },
		"truncated": func(ctx context.Context) io.ReadCloser {
			return io.NopCloser(io.MultiReader(strings.NewReader(`{"id":`), iotest.ErrReader(ctx.Err())))
		},
	}
	for name, build := range sources {
		for answer, body := range answers {
			t.Run(name+"/"+answer, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				source, subject := build(t, func(base http.RoundTripper) http.RoundTripper {
					return cancelingTransport{base: base, cancel: cancel, body: body}
				})
				_, err := source.Observe(ctx, subject)
				if !errors.Is(err, ErrDirectoryUnavailable) || !errors.Is(err, context.Canceled) || errors.Is(err, errDirectoryResponse) {
					t.Fatalf("abandoned read = %v, want unavailable by cancellation, not a rejected response", err)
				}
			})
		}
	}
}
