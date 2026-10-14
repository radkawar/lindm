// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"testing"
	"time"

	configv1 "lindm/gen/lindm/config/v1"
)

var authenticationModeTests = []struct {
	name                                           string
	local, policy, external, localLogin, emergency bool
}{
	{name: "local", local: true, localLogin: true},
	{name: "external only", external: true},
	{name: "external emergency", policy: true, external: true, localLogin: true, emergency: true},
	{name: "local with policy", local: true, policy: true, localLogin: true},
}

func TestAuthenticationOptionsConfiguredLocalLoginPolicy(t *testing.T) {
	for _, test := range authenticationModeTests {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{localPrimary: test.local}
			if test.policy {
				service.breakGlass = &configv1.BreakGlassPolicy{}
			}
			options := service.authenticationOptions(false)
			if options.ExternalLogin != test.external || options.LocalLogin != test.localLogin || options.BreakGlass != test.emergency || options.SetupAvailable {
				t.Fatalf("incorrect configured login modes: external=%t local=%t emergency=%t setup=%t", options.ExternalLogin, options.LocalLogin, options.BreakGlass, options.SetupAvailable)
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
