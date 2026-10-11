package escrow

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// These tests catch cross-device/slot ciphertext transplantation, unauthenticated
// database edits, accidental plaintext storage and wrong-key restore disclosure.
func TestRecoveryEnvelopeBindingAndTampering(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	custody, err := New(key, kek)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("immutable-device/generation/action/LUKS-UUID/new-slot-7")
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	encrypted, err := SealForServer(custody.PublicKey(), binding, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, secret) {
		t.Fatal("plaintext in transport")
	}
	if _, err := custody.OpenAndSeal([]byte("other-device"), encrypted); err == nil {
		t.Fatal("accepted transplanted transport")
	}
	record, err := custody.OpenAndSeal(binding, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record.Ciphertext, secret) || bytes.Contains(record.WrappedKey, secret) {
		t.Fatal("plaintext in durable record")
	}
	digest := sha256.Sum256(secret)
	if !bytes.Equal(record.SecretSHA256, digest[:]) {
		t.Fatal("wrong recovery digest")
	}
	got, err := custody.Reveal(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("recovery key changed")
	}
	clear(got)
	if _, err := custody.Reveal([]byte("other-slot"), record); err == nil {
		t.Fatal("accepted transplanted durable record")
	}
	for _, field := range []string{"wrapped", "ciphertext", "digest", "key_id"} {
		t.Run(field, func(t *testing.T) {
			changed := &Record{KeyID: record.KeyID, WrappedKey: bytes.Clone(record.WrappedKey), Ciphertext: bytes.Clone(record.Ciphertext), SecretSHA256: bytes.Clone(record.SecretSHA256)}
			switch field {
			case "wrapped":
				changed.WrappedKey[0] ^= 1
			case "ciphertext":
				changed.Ciphertext[0] ^= 1
			case "digest":
				changed.SecretSHA256[0] ^= 1
			case "key_id":
				changed.KeyID = "different-key"
			}
			if _, err := custody.Reveal(binding, changed); err == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
	otherKEK := bytes.Clone(kek)
	otherKEK[0] ^= 1
	other, err := New(key, otherKEK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Reveal(binding, record); err == nil {
		t.Fatal("wrong wrapping key disclosed secret")
	}
	second, err := custody.OpenAndSeal(binding, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(record.WrappedKey, second.WrappedKey) || bytes.Equal(record.Ciphertext, second.Ciphertext) {
		t.Fatal("data keys/nonces reused")
	}
}

func TestRecoveryCustodyRejectsWeakKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(key, make([]byte, 32)); err == nil {
		t.Fatal("accepted weak RSA key")
	}
	if _, err := New(nil, make([]byte, 32)); err == nil {
		t.Fatal("accepted missing transport key")
	}
	if _, err := SealForServer(nil, []byte("binding"), make([]byte, 32)); err == nil {
		t.Fatal("accepted invalid public key")
	}
}

func testCustody(t *testing.T) (*Custody, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	custody, err := New(key, kek)
	if err != nil {
		t.Fatal(err)
	}
	return custody, kek
}

// A recovery-key transport must never be accepted as a local-admin password
// (or vice versa), and durable records cannot be revealed in the other domain.
func TestLocalAdminDomainSeparation(t *testing.T) {
	custody, _ := testCustody(t)
	binding := []byte("device/generation/action/account/uid")
	password := []byte("JBSWY3DPEHPK3PXPJBSWY3DPEH")
	recoveryKey := bytes.Repeat([]byte("a"), 64)
	adminTransport, err := SealLocalAdminPassword(custody.PublicKey(), binding, password)
	if err != nil {
		t.Fatal(err)
	}
	recoveryTransport, err := SealForServer(custody.PublicKey(), binding, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.OpenAndSeal(binding, adminTransport); err == nil {
		t.Fatal("recovery custody accepted a local-admin transport")
	}
	if _, err := custody.OpenAndSealLocalAdminPassword(binding, recoveryTransport); err == nil {
		t.Fatal("local-admin custody accepted a recovery transport")
	}
	if _, err := custody.OpenAndSealLocalAdminPassword([]byte("other-action"), adminTransport); err == nil {
		t.Fatal("local-admin custody accepted a rebound transport")
	}
	record, err := custody.OpenAndSealLocalAdminPassword(binding, adminTransport)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record.Ciphertext, password) || bytes.Contains(record.WrappedKey, password) {
		t.Fatal("plaintext in durable record")
	}
	if _, err := custody.Reveal(binding, record); err == nil {
		t.Fatal("recovery reveal opened a local-admin record")
	}
	got, err := custody.RevealLocalAdminPassword(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, password) {
		t.Fatal("password changed in custody")
	}
	clear(got)
	if _, err := SealLocalAdminPassword(custody.PublicKey(), binding, []byte("short")); err == nil {
		t.Fatal("accepted a password below the minimum size")
	}
}

// Managed secret records store no digest, bind their exact version binding and
// open only under the same KEK.
func TestSecretRecordBindingAndCustody(t *testing.T) {
	custody, kek := testCustody(t)
	binding := []byte("secret/version/purpose/subject")
	material := []byte("$6$saltsalt$hash")
	record, err := custody.SealSecret(binding, material)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record.Ciphertext, material) || bytes.Contains(record.WrappedKey, material) {
		t.Fatal("plaintext in durable record")
	}
	if record.KeyID != custody.WrappingKeyID() {
		t.Fatal("record does not name its KEK")
	}
	if _, err := custody.OpenSecret([]byte("secret/version+1/purpose/subject"), record); err == nil {
		t.Fatal("accepted a record under another version binding")
	}
	tampered := &SecretRecord{KeyID: record.KeyID, WrappedKey: bytes.Clone(record.WrappedKey), Ciphertext: bytes.Clone(record.Ciphertext)}
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if _, err := custody.OpenSecret(binding, tampered); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	otherKEK := bytes.Clone(kek)
	otherKEK[0] ^= 1
	other, err := New(custody.transport, otherKEK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenSecret(binding, record); err == nil {
		t.Fatal("wrong wrapping key disclosed secret")
	}
	got, err := custody.OpenSecret(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, material) {
		t.Fatal("material changed in custody")
	}
	clear(got)
	if _, err := custody.SealSecret(binding, nil); err == nil {
		t.Fatal("accepted empty material")
	}
}
