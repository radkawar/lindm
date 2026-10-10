package devlab

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestEntraMFAStateCannotCrossIdentity(t *testing.T) {
	state := new(entraMFA)
	if err := state.bind(""); err == nil {
		t.Fatal("accepted empty MFA identity")
	}
	if err := state.bind("first@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := state.bind("first@example.invalid"); err != nil {
		t.Fatal("fresh login cannot reuse its owned MFA state")
	}
	if err := state.bind("second@example.invalid"); err == nil {
		t.Fatal("allowed another identity to reuse an MFA secret")
	} else if strings.Contains(err.Error(), "example.invalid") {
		t.Fatal("MFA diagnostic exposed an identity")
	}
}

func TestEntraSoftwareTOTPManualSecret(t *testing.T) {
	// RFC 6238's public SHA-1 test key, with manual-entry grouping and case.
	secret, err := entraTOTPSecret("gezd gnbv gy3t qojq\n gezd gnbv gy3t qojq")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatal("manual enrollment did not retain the expected RFC 6238 key")
	}
	for _, raw := range []string{"", "short", "INVALID-SECRET-KEY", strings.Repeat("A", 129), "GEZDGNBVGY3TQOJQ?token=private", "GEZDGNBVGY3TQOJ0"} {
		if _, err := entraTOTPSecret(raw); err == nil {
			t.Error("accepted malformed manual enrollment key")
		} else if raw != "" && strings.Contains(err.Error(), raw) {
			t.Error("invalid secret diagnostic exposed enrollment material")
		}
	}
}

func TestEntraSecurityInfoExactTrust(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		allowed  bool
	}{
		{"https://mysignins.microsoft.com/register", true},
		{"https://mysignins.microsoft.com/security-info", true},
		{"http://mysignins.microsoft.com/register", false},
		{"https://mysignins.microsoft.com:444/register", false},
		{"https://mysignins.microsoft.com.evil.invalid/register", false},
		{"https://user@mysignins.microsoft.com/register", false},
		{"https://mysignins.microsoft.com@evil.invalid/register", false},
		{"https://account.microsoft.com/register", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			endpoint, err := url.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got := entraSecurityInfoURL(endpoint); got != tc.allowed {
				t.Errorf("security-info trust = %v, want %v", got, tc.allowed)
			}
			if got := entraRequestAllowed(endpoint, "https://localhost:19444", http.MethodPost, "Document"); got != tc.allowed {
				t.Errorf("security-info navigation = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestEntraMFADiagnosticsDiscardUnrecognizedMaterial(t *testing.T) {
	got := entraMFADiagnostics([]string{"security_info_origin", "secret@example.invalid", "token=private", "get_app", "different_app_control"})
	if got != "security_info_origin,get_app,different_app_control" {
		t.Fatalf("unexpected sanitized diagnostics %q", got)
	}
	if got := entraMFADiagnostics([]string{"token=private"}); got != "unknown_page" {
		t.Fatal("unrecognized page material escaped diagnostics")
	}
	for _, tc := range []struct {
		endpoint string
		want     string
	}{
		{"https://graph.microsoft.com/v1.0/me?token=private", "graph.microsoft.com"},
		{"https://secret-user.attacker.invalid/?code=private", "unrecognized_off_origin"},
		{"https://graph.microsoft.com.attacker.invalid/", "unrecognized_off_origin"},
	} {
		endpoint, err := url.Parse(tc.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if got := entraBlockedHost(endpoint); got != tc.want {
			t.Errorf("blocked origin category = %q, want %q", got, tc.want)
		}
	}
}
