// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"lindm/internal/devlab/webauthnlab"
)

func TestLocalPassword(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	other, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == other {
		t.Fatal("password salts repeated")
	}
	var wg sync.WaitGroup
	for _, password := range []string{"correct horse battery staple", "wrong"} {
		wg.Go(func() {
			if got := verifyPassword(hash, password); got != (password == "correct horse battery staple") {
				t.Errorf("password verification = %v", got)
			}
		})
	}
	wg.Wait()
	if verifyPassword(dummyPasswordHash(), "wrong") {
		t.Fatal("dummy accepted wrong password")
	}
	for _, malformed := range []string{
		"", "$argon2id$", strings.Repeat("x", 4096),
		strings.Replace(hash, "m=65536", "m=99999", 1),
		strings.Replace(hash, "t=3", "t=0", 1),
		strings.Replace(hash, "p=1", "p=0", 1),
		strings.Replace(hash, "v=19", "v=18", 1),
		hash[:len(hash)-1], hash + "x", hash[:len(passwordHashPrefix)] + strings.Repeat("!", 66),
	} {
		if verifyPassword(malformed, "correct horse battery staple") {
			t.Fatal("accepted malformed or unbounded hash")
		}
	}
}

type localSoftwareAuthenticator struct{ *webauthnlab.Authenticator }

func localTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func localAuthenticator(t *testing.T) localSoftwareAuthenticator {
	t.Helper()
	auth, err := webauthnlab.New("console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return localSoftwareAuthenticator{auth}
}

func (a localSoftwareAuthenticator) response(t *testing.T, challenge, origin string, register, uv bool, counter uint32) ([]byte, []byte) {
	t.Helper()
	body, client, err := a.Response(challenge, origin, register, uv, counter)
	if err != nil {
		t.Fatal(err)
	}
	return body, client
}

func TestLocalWebAuthnCeremonies(t *testing.T) {
	w, err := localWebAuthn("https://console.example.com:18444")
	if err != nil {
		t.Fatal(err)
	}
	user := &localWebAuthnUser{ID: uuid.New(), Username: "owner"}
	auth := localAuthenticator(t)
	for _, tc := range []struct {
		name, origin string
		uv, valid    bool
	}{
		{"valid", "https://console.example.com:18444", true, true},
		{"wrong origin", "https://evil.example.com", true, false},
		{"missing UV", "https://console.example.com:18444", false, false},
	} {
		t.Run("registration/"+tc.name, func(t *testing.T) {
			_, session, err := w.BeginRegistration(user)
			if err != nil {
				t.Fatal(err)
			}
			body, client := auth.response(t, session.Challenge, tc.origin, true, tc.uv, 0)
			redacted, digest := redactWebAuthnSession(*session)
			if redacted.Challenge != "" || session.Challenge == "" {
				t.Fatal("challenge not redacted independently")
			}
			restored, err := restoreWebAuthnSession(redacted, digest, client)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := w.CreateCredential(user, restored, parsed)
			if (err == nil) != tc.valid {
				t.Fatalf("registration valid=%v: %v", tc.valid, err)
			}
			if tc.valid {
				user.Credentials = append(user.Credentials, *credential)
			}
		})
	}
	for _, tc := range []struct {
		name, origin string
		uv, valid    bool
	}{
		{"valid", "https://console.example.com:18444", true, true},
		{"wrong origin", "https://evil.example.com", true, false},
		{"missing UV", "https://console.example.com:18444", false, false},
	} {
		t.Run("assertion/"+tc.name, func(t *testing.T) {
			_, session, err := w.BeginLogin(user)
			if err != nil {
				t.Fatal(err)
			}
			body, client := auth.response(t, session.Challenge, tc.origin, false, tc.uv, 1)
			redacted, digest := redactWebAuthnSession(*session)
			restored, err := restoreWebAuthnSession(redacted, digest, client)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
			if err != nil {
				t.Fatal(err)
			}
			_, err = w.ValidateLogin(user, restored, parsed)
			if (err == nil) != tc.valid {
				t.Fatalf("assertion valid=%v: %v", tc.valid, err)
			}
			_, fresh, err := w.BeginLogin(user)
			if err != nil {
				t.Fatal(err)
			}
			freshRedacted, freshDigest := redactWebAuthnSession(*fresh)
			if _, err := restoreWebAuthnSession(freshRedacted, freshDigest, client); err == nil {
				t.Fatal("replayed response matched new challenge")
			}
			// Exact replay is deliberately not rejected by a stateless primitive;
			// the persistent ceremony must be atomically consumed by the caller.
			if _, err := restoreWebAuthnSession(redacted, digest, client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalWebAuthnMalformedInputs(t *testing.T) {
	for _, origin := range []string{"http://console.example.com", "https://user@console.example.com", "https://console.example.com/path", "https://console.example.com?q=1", "https://console.example.com#x", "https://"} {
		if _, err := localWebAuthn(origin); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
	w, err := localWebAuthn("https://console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := w.BeginRegistration(&localWebAuthnUser{ID: uuid.New(), Username: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	redacted, digest := redactWebAuthnSession(*session)
	for _, client := range [][]byte{nil, []byte("{"), []byte(`{"challenge":1}`), []byte(`{"challenge":"short"}`), []byte(strings.Repeat(" ", 16*1024+1))} {
		if _, err := restoreWebAuthnSession(redacted, digest, client); err == nil {
			t.Fatal("accepted malformed client data")
		}
	}
	client := localTestJSON(t, map[string]string{"challenge": session.Challenge})
	if _, err := restoreWebAuthnSession(*session, digest, client); err == nil {
		t.Fatal("accepted unredacted session")
	}
	if _, err := restoreWebAuthnSession(redacted, digest[:31], client); err == nil {
		t.Fatal("accepted truncated digest")
	}
}
