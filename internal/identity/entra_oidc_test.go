// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"lindm/internal/identity/identitydb"
)

func TestEntraOIDCClaimCorrelation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tenant, object := uuid.New(), uuid.New()
	clientID, nonce, verifier := uuid.NewString(), "fixture-nonce", "fixture-pkce-verifier"
	var signed atomic.Value
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2.0/.well-known/openid-configuration":
			writeGraphJSON(t, w, fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys"))
		case "/v2.0/keys":
			writeGraphJSON(t, w, fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","kid":"fixture","alg":"RS256","n":%q,"e":"AQAB"}]}`, base64.RawURLEncoding.EncodeToString(key.N.Bytes())))
		case "/v2.0/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != verifier || r.Form.Get("client_id") != clientID || r.Form.Get("redirect_uri") != "https://console.example/auth/callback" {
				t.Error("incorrect code/PKCE exchange")
			}
			raw, ok := signed.Load().(string)
			if !ok {
				t.Error("missing signed fixture token")
				return
			}
			writeGraphJSON(t, w, fmt.Sprintf(`{"access_token":"login-access","token_type":"Bearer","expires_in":3600,"id_token":%q}`, raw))
		default:
			t.Errorf("unexpected OIDC request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	issuer = server.URL + "/v2.0"
	ctx := oidc.ClientContext(context.Background(), server.Client())
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	service := &Service{
		issuer: issuer, entraTenant: tenant, clientID: clientID, httpClient: server.Client(), now: time.Now,
		oauth:    &oauth2.Config{ClientID: clientID, ClientSecret: "login-secret", Endpoint: endpoint, RedirectURL: "https://console.example/auth/callback"},
		verifier: provider.VerifierContext(ctx, &oidc.Config{ClientID: clientID}),
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		want   uuid.UUID
	}{
		{name: "pairwise subject binds object", want: object},
		{name: "changed pairwise subject", want: object, change: func(c map[string]any) { c["sub"] = "different-pairwise-subject" }},
		{name: "renamed email", want: object, change: func(c map[string]any) {
			c["email"] = "renamed@example.com"
			c["preferred_username"] = "renamed@example.com"
		}},
		{name: "recycled email different object", want: tenant, change: func(c map[string]any) { c["oid"] = tenant.String() }},
		{name: "missing tenant", change: func(c map[string]any) { delete(c, "tid") }},
		{name: "wrong tenant", change: func(c map[string]any) { c["tid"] = uuid.NewString() }},
		{name: "invalid tenant", change: func(c map[string]any) { c["tid"] = "common" }},
		{name: "missing object", change: func(c map[string]any) { delete(c, "oid"); c["sub"] = object.String() }},
		{name: "nil object", change: func(c map[string]any) { c["oid"] = uuid.Nil.String() }},
		{name: "invalid object", change: func(c map[string]any) { c["oid"] = "same@example.com" }},
		{name: "wrong issuer", change: func(c map[string]any) { c["iss"] = issuer + "/other" }},
		{name: "wrong audience", change: func(c map[string]any) { c["aud"] = uuid.NewString() }},
		{name: "wrong nonce", change: func(c map[string]any) { c["nonce"] = "other-nonce" }},
		{name: "expired", change: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{
				"iss": issuer, "aud": clientID, "sub": "non-UUID-pairwise-subject", "nonce": nonce,
				"tid": tenant.String(), "oid": object.String(), "email": "same@example.com",
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			}
			if test.change != nil {
				test.change(claims)
			}
			signed.Store(signEntraFixture(t, key, claims))
			got, lineage, err := service.exchangeAndVerify(ctx, "fixture-code", verifier, nonceHash(nonce))
			want := ""
			if test.want != uuid.Nil {
				want = test.want.String()
			}
			if got != want || lineage != nil || (err == nil) != (test.want != uuid.Nil) {
				t.Fatalf("principal object = %s, err = %v, want %s", got, err, test.want)
			}
		})
	}
}

func signEntraFixture(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestEntraSharedAuthorityFences(t *testing.T) {
	tenant, object, group := uuid.New(), uuid.New(), uuid.New()
	issuer, err := EntraIssuer(tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{issuer: issuer, entraTenant: tenant}
	now := time.Now()
	lineage := identitydb.PrincipalLineage{DirectoryConnector: connectorEntra, UpstreamProvider: issuer, UpstreamSubject: object.String(), UpstreamObservedAt: pgStamp(now, true)}
	row := identitydb.Principal{Issuer: issuer, Subject: object.String(), DirectoryEnabled: true}
	snapshot := service.snapshotFrom(row, lineage, []string{group.String()})
	decision := decideAccess(now, issuer, mappedPolicy(t, group.String()), snapshot)
	if decision.Kind != accessOK || decision.Role != RoleAdmin || needsRefresh(now.Add(29*time.Second), snapshot) || !needsRefresh(now.Add(30*time.Second), snapshot) {
		t.Fatalf("fresh Entra authority = %+v", decision)
	}
	if decideAccess(now.Add(60*time.Second+time.Nanosecond), issuer, mappedPolicy(t, group.String()), snapshot).Kind == accessOK {
		t.Fatal("Entra bypassed common 60-second freshness bound")
	}
	snapshot.RefreshFailed = true
	if decideAccess(now, issuer, mappedPolicy(t, group.String()), snapshot).Kind == accessOK {
		t.Fatal("refresh failure retained access")
	}
	lineage.DirectoryConnector = connectorKeycloak
	if !service.lineageConflict(lineage, issuer, object.String()) || service.snapshotFrom(row, lineage, nil).Qualified {
		t.Fatal("Entra accepted another connector's observation")
	}
	source, _ := service.tombstone("", time.Time{}, false, now)
	if source != connectorEntra {
		t.Fatalf("Entra disable source = %q", source)
	}
	if effectiveRole("", []string{group.String()}, mappedPolicy(t, uuid.NewString())) != "" {
		t.Fatal("unmapped group granted a role")
	}
	if effectiveRole(RoleOwner, nil, nil) != RoleOwner {
		t.Fatal("explicit pinned owner requires group membership")
	}
}
