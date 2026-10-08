package devlab

import (
	"html"
	"net/url"
	"strings"
	"testing"
)

func TestFixtureLoginRejectsCredentialDestinationSubstitution(t *testing.T) {
	base, err := url.Parse(issuer + "/protocol/openid-connect/auth")
	if err != nil {
		t.Fatal(err)
	}
	legitimate := "https://localhost:18443/realms/lindm/login-actions/authenticate?session_code=bound-session&client_id=lindm-console"
	form := func(action string) []byte {
		return []byte(`<form id="kc-form-login" method="post" action="` + html.EscapeString(action) + `"><input type="hidden" name="credentialId" value="bound-credential"></form>`)
	}
	action, values, err := fixtureLoginForm(form(legitimate), base)
	if err != nil || action.String() != legitimate || values.Get("credentialId") != "bound-credential" {
		t.Fatalf("valid fixture login form rejected: %v", err)
	}
	for _, test := range []struct{ name, action string }{
		{"remote origin", "https://attacker.invalid/realms/lindm/login-actions/authenticate?client_id=lindm-console"},
		{"plaintext origin", strings.Replace(legitimate, "https:", "http:", 1)},
		{"console origin", strings.Replace(legitimate, "18443", "18444", 1)},
		{"embedded credentials", strings.Replace(legitimate, "https://", "https://user:password@", 1)},
		{"another client", strings.Replace(legitimate, "client_id=lindm-console", "client_id=another-client", 1)},
		{"another endpoint", strings.Replace(legitimate, "/login-actions/authenticate", "/untrusted-receiver", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := fixtureLoginForm(form(test.action), base); err == nil {
				t.Fatal("fixture credential submission accepted a substituted destination")
			}
		})
	}
	if _, _, err := fixtureLoginForm(append(form(legitimate), form(legitimate)...), base); err == nil {
		t.Fatal("ambiguous credential form accepted")
	}
	if _, _, err := fixtureLoginForm([]byte(strings.Replace(string(form(legitimate)), `method="post"`, `method="get"`, 1)), base); err == nil {
		t.Fatal("credential-bearing GET form accepted")
	}
}
