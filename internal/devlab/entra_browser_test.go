// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEntraBrowserOriginBoundaries(t *testing.T) {
	const origin = "https://localhost:19444"
	cases := []struct {
		endpoint string
		fixture  bool
		login    bool
	}{
		{"https://localhost:19444/auth/session", true, false},
		{"https://localhost:19444/auth/callback?code=private&state=private", true, false},
		{"https://localhost:19445/auth/session", false, false},
		{"https://localhost/auth/session", false, false},
		{"http://localhost:19444/auth/session", false, false},
		{"https://localhost.evil.invalid:19444/auth/session", false, false},
		{"https://localhost:19444@evil.invalid/auth/session", false, false},
		{"https://evil.invalid@localhost:19444/auth/session", false, false},
		{"https://localhost:19444/auth/session#private", false, false},
		{"https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize", false, true},
		{"https://login.microsoftonline.com/common/login", false, true},
		{"https://login.microsoftonline.com:443/common/login", false, false},
		{"https://login.microsoftonline.com.evil.invalid/common/login", false, false},
		{"https://login.microsoftonline.com@evil.invalid/common/login", false, false},
		{"https://evil.invalid@login.microsoftonline.com/common/login", false, false},
		{"https://login.microsoftonline.com/common/login#private", false, false},
		{"http://login.microsoftonline.com/common/login", false, false},
		{"https://login.live.com/common/login", false, false},
		{"https:login.microsoftonline.com/common/login", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			endpoint, err := url.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got := entraFixtureURL(endpoint, origin); got != tc.fixture {
				t.Errorf("fixture allowed = %v, want %v", got, tc.fixture)
			}
			if got := entraLoginURL(endpoint); got != tc.login {
				t.Errorf("Microsoft sign-in allowed = %v, want %v", got, tc.login)
			}
		})
	}
	if entraFixtureURL(nil, origin) || entraLoginURL(nil) {
		t.Fatal("nil endpoint was trusted")
	}
}

func TestEntraBrowserStaticAssetsCannotReceiveForms(t *testing.T) {
	const origin = "https://localhost:19444"
	cases := []struct {
		endpoint string
		method   string
		resource string
		allowed  bool
	}{
		{"https://logincdn.msauth.net/shared/login.js", http.MethodGet, "Script", true},
		{"https://aadcdn.msftauth.net/styles/login.css", http.MethodGet, "Stylesheet", true},
		{"https://static2.sharepointonline.com/files/login.js", http.MethodGet, "Script", true},
		{"https://static2.sharepointonline.com/collect", http.MethodPost, "XHR", false},
		{"https://static2.sharepointonline.com/sign-in", http.MethodGet, "Document", false},
		{"https://static2.sharepointonline.com.evil.invalid/login.js", http.MethodGet, "Script", false},
		{"https://static2.sharepointonline.com:444/login.js", http.MethodGet, "Script", false},
		{"https://user@static2.sharepointonline.com/login.js", http.MethodGet, "Script", false},
		{"http://static2.sharepointonline.com/login.js", http.MethodGet, "Script", false},
		{"https://login.live.com/login.srf", http.MethodGet, "Document", true},
		{"https://login.live.com/login.srf", http.MethodPost, "Document", true},
		{"https://login.live.com.evil.invalid/login.srf", http.MethodGet, "Document", false},
		{"https://login.live.com:444/login.srf", http.MethodGet, "Document", false},
		{"https://user@login.live.com/login.srf", http.MethodGet, "Document", false},
		{"http://login.live.com/login.srf", http.MethodGet, "Document", false},
		{"https://logincdn.msauth.net/collect", http.MethodPost, "XHR", false},
		{"https://logincdn.msauth.net/sign-in", http.MethodGet, "Document", false},
		{"https://msauth.net.evil.invalid/login.js", http.MethodGet, "Script", false},
		{"https://evilmsauth.net/login.js", http.MethodGet, "Script", false},
		{"https://logincdn.msauth.net:8443/login.js", http.MethodGet, "Script", false},
		{"https://user@logincdn.msauth.net/login.js", http.MethodGet, "Script", false},
		{"http://logincdn.msauth.net/login.js", http.MethodGet, "Script", false},
		{"https://login.microsoftonline.com/common/login", http.MethodPost, "Document", true},
		{"https://localhost:19444/auth/callback", http.MethodGet, "Document", true},
		{"https://localhost:19445/auth/callback", http.MethodGet, "Document", false},
		{"https://adfs.example.invalid/login", http.MethodPost, "Document", false},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.resource+" "+tc.endpoint, func(t *testing.T) {
			endpoint, err := url.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got := entraRequestAllowed(endpoint, origin, tc.method, tc.resource); got != tc.allowed {
				t.Errorf("allowed = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestEntraBrowserChallengeClassificationAndRedaction(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"AADSTS50076: Additional authentication required", "mfa_required (AADSTS50076)"},
		{"AADSTS50079: Enroll additional security information", "mfa_required (AADSTS50079)"},
		{"Approve sign in request", "mfa_required"},
		{"Enter code", "mfa_required"},
		{"More information required", "mfa_required"},
		{"AADSTS53003: Access blocked", "conditional_access (AADSTS53003)"},
		{"You can't get there from here", "conditional_access"},
		{"Need admin approval", "consent_required"},
		{"Permissions requested", "consent_required"},
		{"AADSTS65001: Consent needed", "consent_required (AADSTS65001)"},
		{"AADSTS50055: Expired", "password_change_required (AADSTS50055)"},
		{"Update your password", "password_change_required"},
		{"AADSTS50126: Rejected", "invalid_credentials (AADSTS50126)"},
		{"Your account or password is incorrect", "invalid_credentials"},
		{"AADSTS700016: Application missing", "identity_provider_rejected (AADSTS700016)"},
		{"Stay signed in?", ""},
		{"Enter password", ""},
		{"Sign in to your account", ""},
		{"AADSTS1234 AADSTS1234567890 AADSTS50076secret", ""},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			// Authentication diagnostics commonly contain these values. None
			// belongs in the evidence even when the upstream includes them.
			text := tc.text + "\nsecret.user@example.invalid password=not-for-logs token=private-token https://localhost/callback?code=private-code"
			got := entraChallenge(text)
			if got != tc.want {
				t.Errorf("category = %q, want %q", got, tc.want)
			}
			for _, secret := range []string{"secret.user", "not-for-logs", "private-token", "private-code", "https://"} {
				if strings.Contains(got, secret) {
					t.Error("challenge diagnostic exposed sensitive upstream text")
				}
			}
		})
	}
}

func TestEntraSessionTransportRejectsOffOriginBeforeDial(t *testing.T) {
	transport := &entraOriginTransport{origin: "https://localhost:19444"}
	// A nil underlying transport is intentional: rejection must happen before
	// any network operation, including caller-created absolute RPC requests.
	for _, endpoint := range []string{"https://evil.invalid/", "https://localhost:19445/", "http://localhost:19444/", "https://user@localhost:19444/"} {
		request, err := http.NewRequest(http.MethodPost, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(request)
		if response != nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		if err == nil {
			t.Errorf("accepted off-origin session request %q", endpoint)
		}
	}
}

// A child-created credential file must stay private even when the invoking
// user's umask is permissive. This tests process inheritance, not shell syntax.
func TestEntraBrowserChildSecretFileMode(t *testing.T) {
	runDir := t.TempDir()
	binary := filepath.Join(runDir, "browser")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf private > \"$HOME/fixture-secret\"\nwhile read -r line; do :; done <&3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LINDM_ENTRA_CHROMIUM", binary)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, cleanup, err := startEntraChromium(ctx, runDir, "public-pin", "https://localhost:19444", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		entries, err := os.ReadDir(runDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, err := os.Stat(filepath.Join(runDir, entry.Name(), "fixture-secret"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("child secret file mode %o", info.Mode().Perm())
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("child secret file was not created")
		case <-ticker.C:
		}
	}
}
