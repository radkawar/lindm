package identity

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	authv1 "lindm/gen/lindm/auth/v1"
)

func testPolicy(t *testing.T, cfg Config) *authorizationPolicy {
	t.Helper()
	rules, err := protovalidate.New(protovalidate.WithMessages(&authv1.AuthorizationPolicy{}, &authv1.DeviceScope{}))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := compilePolicy(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mappedPolicy(t *testing.T, group string) *authorizationPolicy {
	t.Helper()
	cfg := Config{Issuer: "https://idp.example/realms/lindm", Policy: &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: group, Role: RoleAdmin}}}}
	if !strings.HasPrefix(group, "/") {
		cfg.EntraTenantID = "5026e756-92d1-4328-8cc1-5f6c9b5a51a9"
	}
	return testPolicy(t, cfg)
}
