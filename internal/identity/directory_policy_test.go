// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"testing"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestDirectoryPolicyPinsAuthorityNamespace(t *testing.T) {
	definition := &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "00g12345678901234567", Role: RoleAdmin}}}
	okta := Config{Issuer: "https://login.example/oauth2/custom", Okta: &configv1.OktaDirectory{OrgUrl: "https://org.example"}, Policy: definition}
	before := testPolicy(t, okta)
	okta.Okta = &configv1.OktaDirectory{OrgUrl: "https://different-org.example"}
	if bytes.Equal(before.digest, testPolicy(t, okta).digest) {
		t.Fatal("changing the authoritative Okta org retained the old policy fence")
	}
	google := Config{Issuer: "https://accounts.google.com", Google: &configv1.GoogleDirectory{HostedDomain: "one.example", DelegatedSubject: "admin@one.example"}, Policy: definition}
	before = testPolicy(t, google)
	google.Google = &configv1.GoogleDirectory{HostedDomain: "two.example", DelegatedSubject: "admin@two.example"}
	if bytes.Equal(before.digest, testPolicy(t, google).digest) {
		t.Fatal("changing the configured Workspace namespace retained the old policy fence")
	}
	broker := Config{Issuer: "https://broker.example/realms/broker", Broker: &configv1.KeycloakBrokerUpstream{Alias: "upstream", ConnectorId: "directory", Issuer: "https://upstream.example/realms/one"}}
	before = testPolicy(t, broker)
	broker.Broker = &configv1.KeycloakBrokerUpstream{Alias: "upstream", ConnectorId: "directory", Issuer: "https://upstream.example/realms/two"}
	if bytes.Equal(before.digest, testPolicy(t, broker).digest) {
		t.Fatal("changing the original broker authority retained the old policy fence")
	}
}
