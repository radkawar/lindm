// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pgped25519 "github.com/ProtonMail/go-crypto/openpgp/ed25519"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestNativeSignerExcludesActualSPKIRegardlessOfOpenPGPFingerprint(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		public crypto.PublicKey
		packet *packet.PublicKey
	}{{"ed25519", edPublic, packet.NewEd25519PublicKey(time.Unix(1760000000, 0), &pgped25519.PublicKey{Point: edPublic})}, {"rsa", &rsaPrivate.PublicKey, packet.NewRSAPublicKey(time.Unix(1760000000, 0), &rsaPrivate.PublicKey)}} {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := test.packet.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
			fingerprint := strings.ToUpper(hex.EncodeToString(test.packet.Fingerprint))
			der, err := x509.MarshalPKIXPublicKey(test.public)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(der)
			pin := hex.EncodeToString(digest[:])
			if strings.EqualFold(pin, fingerprint) {
				t.Fatal("test did not exercise distinct OpenPGP and SPKI identities")
			}
			if err := rejectPublicPacket(encoded.Bytes(), fingerprint, []string{"  " + strings.ToUpper(pin) + "  "}); err == nil {
				t.Fatal("native signer accepted cross-domain public-key reuse")
			}
			if err := rejectPublicPacket(encoded.Bytes(), fingerprint, []string{strings.Repeat("0", 64)}); err != nil {
				t.Fatal(err)
			}
			if err := rejectPublicPacket(encoded.Bytes(), fingerprint, []string{"malformed"}); err == nil {
				t.Fatal("native signer ignored malformed exclusion")
			}
			if err := rejectPublicPacket(encoded.Bytes(), strings.Repeat("0", 40), []string{pin}); err == nil {
				t.Fatal("native signer accepted mismatched exported primary key")
			}
		})
	}
}
