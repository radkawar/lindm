// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	configv1 "lindm/gen/lindm/config/v1"
)

// Rewrite only the fixture issuer's transport destination, retaining signed
// production issuer/audience validation and real TLS against the fixture CA.
type providerOIDCTransport struct {
	origin *url.URL
	target *url.URL
	base   http.RoundTripper
}

func (p providerOIDCTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != p.origin.Scheme || r.URL.Host != p.origin.Host {
		return nil, fmt.Errorf("unexpected OIDC fixture destination")
	}
	copyRequest := r.Clone(r.Context())
	copyURL := *r.URL
	copyURL.Scheme, copyURL.Host = p.target.Scheme, p.target.Host
	copyRequest.URL = &copyURL
	copyRequest.Host = p.target.Host
	return p.base.RoundTrip(copyRequest)
}

func TestProviderOIDCImmutableSubjectCorrelation(t *testing.T) {
	for _, issuer := range []string{"https://tenant.okta.example", "https://tenant.okta.example/oauth2/custom", "https://accounts.google.com"} {
		t.Run(issuer, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			origin, err := url.Parse(issuer)
			if err != nil {
				t.Fatal(err)
			}
			const clientID, nonce, verifier = "browser-client", "fixture-nonce", "fixture-pkce-verifier"
			var signed atomic.Value
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case origin.Path + "/.well-known/openid-configuration":
					writeProviderJSON(t, w, fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys"))
				case origin.Path + "/keys":
					writeProviderJSON(t, w, fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","kid":"fixture","alg":"RS256","n":%q,"e":"AQAB"}]}`, base64.RawURLEncoding.EncodeToString(key.N.Bytes())))
				case origin.Path + "/token":
					if err := r.ParseForm(); err != nil {
						t.Error(err)
						return
					}
					if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != verifier || r.Form.Get("client_id") != clientID || r.Form.Get("redirect_uri") != "https://console.example/auth/callback" {
						t.Error("incorrect browser code/PKCE exchange")
					}
					raw, ok := signed.Load().(string)
					if !ok {
						t.Error("missing signed fixture identity")
						return
					}
					writeProviderJSON(t, w, fmt.Sprintf(`{"access_token":"browser-access","token_type":"Bearer","expires_in":3600,"id_token":%q}`, raw))
				default:
					t.Errorf("unexpected OIDC request: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			target, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client := server.Client()
			client.Transport = providerOIDCTransport{origin: origin, target: target, base: client.Transport}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx = oidc.ClientContext(ctx, client)
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := provider.Endpoint()
			endpoint.AuthStyle = oauth2.AuthStyleInParams
			service := &Service{
				issuer: issuer, clientID: clientID, httpClient: client, now: time.Now,
				oauth:    &oauth2.Config{ClientID: clientID, ClientSecret: "login-secret", Endpoint: endpoint, RedirectURL: "https://console.example/auth/callback"},
				verifier: provider.VerifierContext(ctx, &oidc.Config{ClientID: clientID}),
			}
			isGoogle := issuer == "https://accounts.google.com"
			subject := "00uOpaqueOktaUser"
			if isGoogle {
				subject = "123456789012345678901"
				service.google = &configv1.GoogleDirectory{HostedDomain: "example.com"}
			} else {
				service.okta = &configv1.OktaDirectory{Issuer: issuer, OrgUrl: "https://tenant.okta.example"}
			}
			for _, test := range []struct {
				name       string
				change     func(map[string]any)
				want       string
				googleOnly bool
			}{
				{name: "opaque immutable sub", want: subject},
				{name: "rename does not change identity", want: subject, change: func(c map[string]any) { c["email"] = "renamed@example.com"; c["name"] = "Renamed" }},
				{name: "recycled email changes identity", want: "different-immutable-id", change: func(c map[string]any) { c["sub"] = "different-immutable-id" }},
				{name: "email without subject denied", change: func(c map[string]any) { delete(c, "sub") }},
				{name: "wrong issuer", change: func(c map[string]any) { c["iss"] = issuer + "/other" }},
				{name: "wrong audience", change: func(c map[string]any) { c["aud"] = "another-client" }},
				{name: "wrong nonce", change: func(c map[string]any) { c["nonce"] = "another-nonce" }},
				{name: "expired", change: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
				{name: "missing hosted domain despite matching email", googleOnly: true, change: func(c map[string]any) { delete(c, "hd") }},
				{name: "wrong hosted domain", googleOnly: true, change: func(c map[string]any) { c["hd"] = "other.example" }},
				{name: "hosted domain exact case", googleOnly: true, change: func(c map[string]any) { c["hd"] = "EXAMPLE.COM" }},
				{name: "null hosted domain", googleOnly: true, change: func(c map[string]any) { c["hd"] = nil }},
			} {
				if test.googleOnly && !isGoogle {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					claims := map[string]any{
						"iss": issuer, "aud": clientID, "sub": subject, "nonce": nonce,
						"email": "same@example.com", "email_verified": true,
						"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
					}
					if isGoogle {
						claims["hd"] = "example.com"
					}
					if test.change != nil {
						test.change(claims)
					}
					signed.Store(signEntraFixture(t, key, claims))
					got, lineage, err := service.exchangeAndVerify(ctx, "fixture-code", verifier, nonceHash(nonce))
					if got != test.want || lineage != nil || (err == nil) != (test.want != "") {
						t.Fatalf("immutable subject = %q, lineage=%+v, err=%v; want %q", got, lineage, err, test.want)
					}
				})
			}
		})
	}
}
