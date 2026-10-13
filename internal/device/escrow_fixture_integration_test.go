//go:build integration

package device

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"testing"

	"lindm/internal/escrow"
)

// fixtureEscrowTransportKey owns the integration binary's read-only RSA-3072
// ingress key. GenerateKey completes its precomputation before publication;
// escrow.New validates it and OAEP decryption only reads it. Never mutate or
// clear this key, or reuse it for device enrollment or execution authority.
var fixtureEscrowTransportKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
})

// newFixtureCustody shares only immutable transport key material. Every fixture
// owns a fresh custody object and random AES-256 KEK; records, data keys and
// nonces still follow the production custody path.
func newFixtureCustody(t *testing.T) *escrow.Custody {
	t.Helper()
	key, err := fixtureEscrowTransportKey()
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	defer clear(kek)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	custody, err := escrow.New(key, kek)
	if err != nil {
		t.Fatal(err)
	}
	return custody
}

// Concurrent custody must share only the transport key, never the KEK or records.
func TestIntegrationEscrowCustodyIsolation(t *testing.T) {
	t.Parallel()
	first, second := newFixtureCustody(t), newFixtureCustody(t)
	if first == second || first.WrappingKeyID() == second.WrappingKeyID() {
		t.Fatal("independent fixtures share custody or wrapping keys")
	}
	publicDER := first.PublicKey()
	if first.KeyID() != second.KeyID() || !bytes.Equal(publicDER, second.PublicKey()) {
		t.Fatal("immutable transport key was regenerated")
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 3072 {
		t.Fatal("fixture transport key is not RSA-3072")
	}
	detached := first.PublicKey()
	detached[0] ^= 1
	if !bytes.Equal(publicDER, first.PublicKey()) || !bytes.Equal(publicDER, second.PublicKey()) {
		t.Fatal("caller mutated custody public key material")
	}
	binding := []byte("isolated-fixture/device/generation/action/slot")
	secret := bytes.Repeat([]byte("a"), 64)
	ciphertext, err := escrow.SealForServer(publicDER, binding, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name           string
		custody, other *escrow.Custody
	}{
		{name: "first", custody: first, other: second},
		{name: "second", custody: second, other: first},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record, err := test.custody.OpenAndSeal(binding, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := test.other.Reveal(binding, record); err == nil {
				t.Fatal("another fixture disclosed a durable record")
			}
			plaintext, err := test.custody.Reveal(binding, record)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plaintext)
			if !bytes.Equal(plaintext, secret) {
				t.Fatal("shared transport key changed the escrow secret")
			}
			if !bytes.Equal(publicDER, test.custody.PublicKey()) {
				t.Fatal("custody mutated shared transport key material")
			}
		})
	}
}
