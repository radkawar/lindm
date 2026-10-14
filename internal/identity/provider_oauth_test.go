// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// These deterministic TLS contract fixtures verify signed OAuth and documented
// response handling. They are not live tenant, propagation or browser evidence.
type providerFixture struct {
	source DirectorySource
	oauth  *providerOAuth
	tokens atomic.Int32
	now    time.Time
}

func newProviderFixture(t *testing.T, provider string, api http.HandlerFunc) *providerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	fixture := &providerFixture{now: time.Unix(1800000000, 0)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth2/v1/token" || r.URL.Path == "/token" {
			fixture.tokens.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Form.Get("client_secret") != "" {
				t.Error("OAuth request leaked alternate credentials or used wrong method")
			}
			assertion := r.Form.Get("assertion")
			issuer, subject := "service@example.iam.gserviceaccount.com", "directory-admin@example.com"
			if provider == "okta" {
				issuer, subject = "directory-client", "directory-client"
				assertion = r.Form.Get("client_assertion")
				if r.Form.Get("client_id") != issuer || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || r.Form.Get("scope") != "okta.users.read okta.groups.read" {
					t.Error("incorrect Okta private_key_jwt service grant")
				}
			} else if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Error("incorrect Google service account grant")
			}
			token, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var claims jwt.Claims
			var extra struct {
				Scope string `json:"scope"`
			}
			if err := token.Claims(&key.PublicKey, &claims, &extra); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(token.Headers) != 1 || token.Headers[0].KeyID != "directory-key" || claims.Issuer != issuer || claims.Subject != subject || len(claims.Audience) != 1 || claims.Audience[0] != "https://"+r.Host+r.URL.Path || claims.IssuedAt == nil || claims.Expiry == nil || !claims.IssuedAt.Time().Equal(fixture.now) || !claims.Expiry.Time().Equal(fixture.now.Add(5*time.Minute)) {
				t.Errorf("incorrect signed OAuth claims: %+v", claims)
			}
			if provider == "okta" && claims.ID == "" {
				t.Error("Okta assertion lacks replay identifier")
			}
			if provider == "google" && extra.Scope != "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly" {
				t.Errorf("incorrect Google delegated scopes: %q", extra.Scope)
			}
			writeProviderJSON(t, w, `{"access_token":"directory-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer directory-token" {
			t.Error("directory API request lacks service token or GET method")
		}
		api(w, r)
	}))
	t.Cleanup(server.Close)
	now := func() time.Time { return fixture.now }
	if provider == "okta" {
		source, err := newOktaSource(context.Background(), server.URL, "directory-client", "directory-key", keyPEM, server.Client(), now)
		if err != nil {
			t.Fatal(err)
		}
		fixture.source, fixture.oauth = source, source.oauth
	} else {
		source, err := newGoogleSourceEndpoints(context.Background(), "service@example.iam.gserviceaccount.com", "directory-key", keyPEM, "directory-admin@example.com", []string{"group-admin", "group-auditor"}, server.Client(), now, server.URL+"/token", server.URL+"/admin/directory/v1")
		if err != nil {
			t.Fatal(err)
		}
		fixture.source, fixture.oauth = source, source.oauth
	}
	return fixture
}

func writeProviderJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := fmt.Fprint(w, body); err != nil {
		t.Errorf("write provider fixture: %v", err)
	}
}

func TestProviderHTTPAndTokenCancellation(t *testing.T) {
	for _, provider := range []string{"okta", "google"} {
		t.Run(provider, func(t *testing.T) {
			started := make(chan struct{})
			fixture := newProviderFixture(t, provider, func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := fixture.source.Observe(ctx, "user-immutable")
				result <- err
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("API request did not start")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrDirectoryUnavailable) {
					t.Fatalf("cancellation = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("observation ignored cancellation")
			}
			fixture.oauth.gate <- struct{}{}
			_, err := fixture.oauth.token(ctx, "")
			<-fixture.oauth.gate
			if !errors.Is(err, ErrDirectoryUnavailable) {
				t.Fatalf("token gate ignored cancellation: %v", err)
			}
		})
	}
}

func TestProviderRedirectAndResponseBounds(t *testing.T) {
	for _, provider := range []string{"okta", "google"} {
		for _, mode := range []string{"redirect", "oversized", "malformed"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				var leaked atomic.Int32
				sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
				defer sink.Close()
				fixture := newProviderFixture(t, provider, func(w http.ResponseWriter, r *http.Request) {
					switch mode {
					case "redirect":
						w.Header().Set("Location", sink.URL)
						w.WriteHeader(http.StatusTemporaryRedirect)
					case "oversized":
						writeProviderJSON(t, w, strings.Repeat(" ", maxDirectoryBody+1))
					case "malformed":
						writeProviderJSON(t, w, `{`)
					}
				})
				obs, err := fixture.source.Observe(context.Background(), "user-immutable")
				if err == nil || obs.Enabled || len(obs.Groups) != 0 || leaked.Load() != 0 {
					t.Fatalf("unsafe response granted authority or leaked token: %+v, %v, leaks=%d", obs, err, leaked.Load())
				}
			})
		}
	}
}

func TestProviderRetryDeadlineAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitProviderRetry(ctx, time.Hour); !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("over-deadline wait accepted: %v", err)
	}
	cancel()
	if err := waitProviderRetry(ctx, 0); !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("canceled retry accepted: %v", err)
	}
}

func TestProviderRejectedTokenRefreshIsBounded(t *testing.T) {
	for _, provider := range []string{"okta", "google"} {
		for _, recovered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovered=%t", provider, recovered), func(t *testing.T) {
				var requests atomic.Int32
				fixture := newProviderFixture(t, provider, func(w http.ResponseWriter, r *http.Request) {
					if requests.Add(1) == 1 || !recovered {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if provider == "okta" {
						writeProviderJSON(t, w, `{"id":"user-id","status":"SUSPENDED"}`)
					} else {
						writeProviderJSON(t, w, `{"id":"user-id","suspended":true,"archived":false}`)
					}
				})
				obs, err := fixture.source.Observe(context.Background(), "user-id")
				if (err == nil) != recovered || obs.Enabled || fixture.tokens.Load() != 2 || requests.Load() != 2 {
					t.Fatalf("credential rejection = %+v, %v, tokens=%d, requests=%d", obs, err, fixture.tokens.Load(), requests.Load())
				}
			})
		}
	}
}

func TestProviderRejectsMutableSubjectBeforeHTTP(t *testing.T) {
	for _, provider := range []string{"okta", "google"} {
		t.Run(provider, func(t *testing.T) {
			fixture := newProviderFixture(t, provider, func(w http.ResponseWriter, r *http.Request) {
				t.Error("invalid subject reached provider")
			})
			for _, subject := range []string{"", "name@example.com", "../users/admin", "user%2Fadmin", "user?expand=groups", " user", strings.Repeat("a", 256)} {
				obs, err := fixture.source.Observe(context.Background(), subject)
				if err == nil || obs.Enabled {
					t.Fatalf("mutable/path subject %q accepted: %+v, %v", subject, obs, err)
				}
			}
		})
	}
}
