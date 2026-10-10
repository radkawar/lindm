// Package webauthnlab implements a laboratory-only P-256 software authenticator.
// It produces real WebAuthn registration and signed assertion responses, not
// verifier mocks. It provides no hardware protection or evidence of human presence
// and must never be imported by production code.
package webauthnlab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator retains one private credential in memory. Callers own assertion
// counters so negative tests can deliberately exercise replay and missing UV.
type Authenticator struct {
	key    *ecdsa.PrivateKey
	id     [32]byte
	rpHash [32]byte
}

func New(rpID string) (*Authenticator, error) {
	if rpID == "" {
		return nil, errors.New("webauthnlab: missing relying party ID")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{key: key, rpHash: sha256.Sum256([]byte(rpID))}
	if _, err := rand.Read(a.id[:]); err != nil {
		return nil, err
	}
	return a, nil
}

// Response returns credential JSON and the exact clientDataJSON it binds. The
// RP ID is fixed at construction; changing origin cannot change that binding.
func (a *Authenticator) Response(challenge, origin string, register, uv bool, counter uint32) ([]byte, []byte, error) {
	if a == nil || a.key == nil || challenge == "" {
		return nil, nil, errors.New("webauthnlab: missing credential or challenge")
	}
	kind := "webauthn.get"
	if register {
		kind = "webauthn.create"
	}
	client, err := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		return nil, nil, err
	}
	auth := make([]byte, 37)
	copy(auth, a.rpHash[:])
	auth[32] = 1
	if uv {
		auth[32] |= 4
	}
	binary.BigEndian.PutUint32(auth[33:], counter)
	response := map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(client)}
	if register {
		auth[32] |= 64
		auth = append(auth, make([]byte, 16)...)
		auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.id)))
		auth = append(auth, a.id[:]...)
		public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			return nil, nil, err
		}
		auth = append(auth, public...)
		attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": auth, "attStmt": map[string]any{}})
		if err != nil {
			return nil, nil, err
		}
		response["attestationObject"] = base64.RawURLEncoding.EncodeToString(attestation)
	} else {
		clientHash := sha256.Sum256(client)
		var payload [69]byte
		copy(payload[:37], auth)
		copy(payload[37:], clientHash[:])
		digest := sha256.Sum256(payload[:])
		signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
		if err != nil {
			return nil, nil, err
		}
		response["authenticatorData"] = base64.RawURLEncoding.EncodeToString(auth)
		response["signature"] = base64.RawURLEncoding.EncodeToString(signature)
	}
	id := base64.RawURLEncoding.EncodeToString(a.id[:])
	body, err := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": response})
	return body, client, err
}
