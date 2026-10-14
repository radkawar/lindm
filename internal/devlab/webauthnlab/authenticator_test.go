// SPDX-License-Identifier: Apache-2.0

package webauthnlab

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestCredentialTransferPreservesAssertionIdentity(t *testing.T) {
	original, err := New("localhost")
	if err != nil {
		t.Fatal(err)
	}
	id, encoded, err := original.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	transferred, err := Import("localhost", id, encoded)
	if err != nil {
		t.Fatal(err)
	}
	clear(id)
	clear(encoded)
	body, client, err := transferred.Response("fresh-challenge", "https://localhost:24444", false, true, 42)
	if err != nil {
		t.Fatal(err)
	}
	var assertion struct {
		ID       string `json:"id"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &assertion); err != nil {
		t.Fatal(err)
	}
	if assertion.ID != base64.RawURLEncoding.EncodeToString(original.id[:]) {
		t.Fatal("transferred authenticator changed registered credential ID")
	}
	auth, err := base64.RawURLEncoding.DecodeString(assertion.Response.AuthenticatorData)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 37 || !bytes.Equal(auth[:32], original.rpHash[:]) || binary.BigEndian.Uint32(auth[33:]) != 42 || auth[32]&5 != 5 {
		t.Fatal("transferred authenticator changed relying party, counter, or user verification")
	}
	signature, err := base64.RawURLEncoding.DecodeString(assertion.Response.Signature)
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(client)
	payload := append(auth, clientHash[:]...)
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&original.key.PublicKey, digest[:], signature) {
		t.Fatal("transferred assertion is not signed by registered key")
	}
}

func TestImportRejectsInvalidCredential(t *testing.T) {
	authenticator, err := New("localhost")
	if err != nil {
		t.Fatal(err)
	}
	id, key, err := authenticator.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	otherCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := x509.MarshalPKCS8PrivateKey(otherCurve)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(otherKey)
	for _, test := range []struct {
		name, rp string
		id, key  []byte
	}{
		{"missing relying party", "", id, key},
		{"short ID", "localhost", id[:31], key},
		{"long ID", "localhost", append(id, 1), key},
		{"malformed key", "localhost", id, []byte("not a key")},
		{"wrong curve", "localhost", id, otherKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Import(test.rp, test.id, test.key); err == nil {
				t.Fatal("invalid transferred credential accepted")
			}
		})
	}
}
