// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// A single explicitly encoded cost bounds both stored-hash parsing and work. Cost
// upgrades require an explicit migration policy, not attacker-selected parameters.
const passwordHashPrefix = "$argon2id$v=19$m=65536,t=3,p=1$"

func hashPassword(password string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	return encodePassword(password, salt[:]), nil
}

func encodePassword(password string, salt []byte) string {
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return passwordHashPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

func verifyPassword(encoded, password string) bool {
	if len(encoded) != len(passwordHashPrefix)+22+1+43 || !strings.HasPrefix(encoded, passwordHashPrefix) {
		return false
	}
	parts := strings.Split(encoded[len(passwordHashPrefix):], "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// The dummy is not a credential. Its fixed salt and known password only provide
// the identical Argon2 cost for an unknown account; callers must always deny it.
// Cache construction of this immutable hash, never password verification: each
// unknown-account login still performs the full production Argon2 work.
var dummyPasswordHash = sync.OnceValue(func() string {
	return encodePassword("lindm unknown-account timing only", []byte("lindm-dummy-salt!"))
})

func localWebAuthn(publicURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("identity: WebAuthn requires an HTTPS public origin")
	}
	return webauthn.New(&webauthn.Config{
		RPID:                   u.Hostname(),
		RPDisplayName:          "lindm",
		RPOrigins:              []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
}

type localWebAuthnUser struct {
	ID          uuid.UUID
	Username    string
	Credentials []webauthn.Credential
}

var _ webauthn.User = (*localWebAuthnUser)(nil)

func (u *localWebAuthnUser) WebAuthnID() []byte                         { return u.ID[:] }
func (u *localWebAuthnUser) WebAuthnName() string                       { return u.Username }
func (u *localWebAuthnUser) WebAuthnDisplayName() string                { return u.Username }
func (u *localWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// redactWebAuthnSession separates the challenge digest from the library session
// for persistence. The original session remains usable for the browser options.
func redactWebAuthnSession(session webauthn.SessionData) (webauthn.SessionData, []byte) {
	digest := sha256.Sum256([]byte(session.Challenge))
	session.Challenge = ""
	return session, digest[:]
}

// restoreWebAuthnSession recovers only a digest-matched client challenge. It does
// not validate a ceremony: pass the returned session and the very same client
// response to the library verifier. The caller owns atomic one-use consumption
// and expiry of persisted sessions; no stateless helper can prevent exact replay.
func restoreWebAuthnSession(session webauthn.SessionData, challengeHash, clientDataJSON []byte) (webauthn.SessionData, error) {
	if session.Challenge != "" || len(challengeHash) != sha256.Size || len(clientDataJSON) > 16*1024 {
		return webauthn.SessionData{}, errors.New("identity: invalid stored WebAuthn challenge")
	}
	var client struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientDataJSON, &client); err != nil || len(client.Challenge) < 16 || len(client.Challenge) > 1024 {
		return webauthn.SessionData{}, errors.New("identity: invalid WebAuthn client challenge")
	}
	digest := sha256.Sum256([]byte(client.Challenge))
	if subtle.ConstantTimeCompare(digest[:], challengeHash) != 1 {
		return webauthn.SessionData{}, errors.New("identity: WebAuthn challenge mismatch")
	}
	session.Challenge = client.Challenge
	return session, nil
}
