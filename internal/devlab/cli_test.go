package devlab

import "testing"

// These parser boundary tests do not substitute for the real Keycloak CLI lane.
func TestCLIApprovalCSRF(t *testing.T) {
	valid := `<form method="post" action="/auth/cli/approve"><input type="hidden" name="csrf_token" value="csrf&amp;value"><button>Approve</button></form>`
	csrf, err := cliApprovalCSRF([]byte(valid))
	if err != nil || csrf != "csrf&value" {
		t.Fatalf("approval CSRF = %q, %v; want decoded hidden value", csrf, err)
	}
	for name, body := range map[string]string{
		"absent approval": `<a href="/">Sign in</a>`,
		"foreign action":  `<form method="post" action="https://other.example/auth/cli/approve"><input type="hidden" name="csrf_token" value="secret"></form>`,
		"GET approval":    `<form method="get" action="/auth/cli/approve"><input type="hidden" name="csrf_token" value="secret"></form>`,
		"duplicate forms": valid + valid,
		"missing CSRF":    `<form method="post" action="/auth/cli/approve"></form>`,
		"nonhidden CSRF":  `<form method="post" action="/auth/cli/approve"><input name="csrf_token" value="secret"></form>`,
		"duplicate CSRF":  `<form method="post" action="/auth/cli/approve"><input type="hidden" name="csrf_token" value="one"><input type="hidden" name="csrf_token" value="two"></form>`,
		"outside CSRF":    `<input type="hidden" name="csrf_token" value="secret"><form method="post" action="/auth/cli/approve"></form>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cliApprovalCSRF([]byte(body)); err == nil {
				t.Fatal("unsafe or ambiguous approval form accepted")
			}
		})
	}
}
