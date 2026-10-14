// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestAuthenticationOptionsAdvertiseConfiguredLocalLogin(t *testing.T) {
	for _, test := range []struct {
		name                                           string
		local, policy, external, localLogin, emergency bool
	}{
		{name: "local", local: true, localLogin: true},
		{name: "external only", external: true},
		{name: "external emergency", policy: true, external: true, localLogin: true, emergency: true},
		{name: "local with policy", local: true, policy: true, localLogin: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{localPrimary: test.local}
			if test.policy {
				service.breakGlass = &configv1.BreakGlassPolicy{}
			}
			recorder := httptest.NewRecorder()
			service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://console.example.com/auth/options", nil))
			options := &authv1.AuthenticationOptions{}
			if err := protojson.Unmarshal(recorder.Body.Bytes(), options); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusOK || options.ExternalLogin != test.external || options.LocalLogin != test.localLogin || options.BreakGlass != test.emergency {
				t.Fatalf("incorrect configured login modes: status=%d external=%t local=%t emergency=%t", recorder.Code, options.ExternalLogin, options.LocalLogin, options.BreakGlass)
			}
		})
	}
}

func TestLocalAccessDoesNotUseDirectoryFreshness(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	for _, observed := range []time.Time{{}, now.Add(-24 * time.Hour), now.Add(24 * time.Hour)} {
		snapshot := directorySnapshot{Local: true, Issuer: "urn:lindm:local:test", Subject: "owner", Qualified: true, Enabled: true, AuthorizationRole: RoleOwner, ObservedAt: observed}
		if needsRefresh(now, snapshot) {
			t.Fatal("local authority requested a directory refresh")
		}
		if decision := decideAccess(now, snapshot.Issuer, nil, snapshot); decision.Kind != accessOK || decision.Role != RoleOwner {
			t.Fatalf("local access used an external observation timestamp: %v", decision)
		}
		snapshot.Enabled = false
		if decision := decideAccess(now, snapshot.Issuer, nil, snapshot); decision.Kind != accessUnauthenticated || !decision.RevokeSessions {
			t.Fatalf("disabled local account accepted: %v", decision)
		}
	}
}
