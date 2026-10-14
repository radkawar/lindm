// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"testing"

	"buf.build/go/protovalidate"

	authv1 "lindm/gen/lindm/auth/v1"
)

func TestCLIAuthorizationRedirectBoundary(t *testing.T) {
	rules, err := protovalidate.New(protovalidate.WithMessages(&authv1.CLIAuthorizationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, redirect := range []string{
		"https://127.0.0.1:34567/callback", "http://localhost:34567/callback",
		"http://[::1]:34567/callback", "http://127.0.0.2:34567/callback",
		"http://127.0.0.1:34567/callback?other=1", "http://127.0.0.1:34567/callback#fragment",
		"http://user@127.0.0.1:34567/callback", "http://127.0.0.1:0/callback",
		"http://127.0.0.1:34567/other", "http://evil.example/callback",
	} {
		if err := rules.Validate(&authv1.CLIAuthorizationRequest{RedirectUri: redirect, CodeChallenge: token, State: token}); err == nil {
			t.Errorf("accepted unsafe redirect %q", redirect)
		}
	}
	if err := rules.Validate(&authv1.CLIAuthorizationRequest{RedirectUri: "http://127.0.0.1:34567/callback", CodeChallenge: token, State: token}); err != nil {
		t.Fatal(err)
	}
}
