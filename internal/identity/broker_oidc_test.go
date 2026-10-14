// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func TestBrokerOIDCRequiresSignedPersistentLineage(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var signed atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != "broker-pkce-verifier" {
			t.Error("missing code/PKCE exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		raw, ok := signed.Load().(string)
		if !ok {
			t.Error("missing signed fixture token")
			return
		}
		if _, err := fmt.Fprintf(w, `{"access_token":"access","token_type":"Bearer","expires_in":300,"id_token":%q}`, raw); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	issuer, clientID, subject, original := "https://broker.example/realms/company", "console", uuid.NewString(), uuid.NewString()
	service := &Service{issuer: issuer, clientID: clientID, httpClient: server.Client(), now: time.Now,
		broker:   &brokerSource{issuer: issuer, upstreamIssuer: "https://upstream.example/realms/company", alias: "original-saml", connector: "original-keycloak"},
		oauth:    &oauth2.Config{ClientID: clientID, ClientSecret: "secret", RedirectURL: "https://console.example/auth/callback", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}},
		verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: clientID})}
	for _, tc := range []struct {
		name              string
		change            func(map[string]any)
		wrongKey, allowed bool
	}{
		{name: "complete proof", allowed: true},
		{name: "rename does not change binding", allowed: true, change: func(c map[string]any) { c["email"] = "recycled@example.test"; c["preferred_username"] = "renamed" }},
		{name: "missing alias", change: func(c map[string]any) { delete(c, "lindm_upstream_alias") }},
		{name: "wrong alias", change: func(c map[string]any) { c["lindm_upstream_alias"] = "other" }},
		{name: "missing subject", change: func(c map[string]any) { delete(c, "lindm_upstream_subject") }},
		{name: "email is not subject", change: func(c map[string]any) { c["lindm_upstream_subject"] = "recycled@example.test" }},
		{name: "ambiguous subject", change: func(c map[string]any) { c["lindm_upstream_subject"] = []string{original, uuid.NewString()} }},
		{name: "wrong issuer", change: func(c map[string]any) { c["iss"] = "https://untrusted.example" }},
		{name: "wrong audience", change: func(c map[string]any) { c["aud"] = "other" }},
		{name: "wrong nonce", change: func(c map[string]any) { c["nonce"] = "other" }},
		{name: "expired", change: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{name: "untrusted signature", wrongKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": issuer, "aud": clientID, "sub": subject, "nonce": "broker-nonce", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "lindm_upstream_alias": "original-saml", "lindm_upstream_subject": original}
			if tc.change != nil {
				tc.change(claims)
			}
			signingKey := key
			if tc.wrongKey {
				signingKey = wrongKey
			}
			signed.Store(signEntraFixture(t, signingKey, claims))
			got, proof, err := service.exchangeAndVerify(t.Context(), "code", "broker-pkce-verifier", nonceHash("broker-nonce"))
			if tc.allowed {
				if err != nil || got != subject || proof == nil || proof.UpstreamSubject != original || proof.Connector != "original-keycloak" {
					t.Fatalf("subject=%q proof=%+v error=%v", got, proof, err)
				}
			} else if err == nil || got != "" || proof != nil {
				t.Fatalf("untrusted proof accepted subject=%q lineage=%+v error=%v", got, proof, err)
			}
		})
	}
}
