// Package escrow owns recovery-secret transport decryption and per-record envelope
// encryption. It does not authorize reveal, persist records, or sign durability
// receipts: callers must do those at their transactional domain boundary.
package escrow

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

const transportDomain = "lindm-recovery-transport-v1\x00"
const storageDomain = "lindm-recovery-storage-v1\x00"

// Record contains only ciphertext and nonsecret identifiers. Binding is the
// deterministic protobuf encoding of the immutable recovery target/action/slot.
// Persist that binding alongside this record; never reconstruct it from mutable
// inventory or the current device enrollment generation.
type Record struct {
	KeyID        string
	WrappedKey   []byte
	Ciphertext   []byte
	SecretSHA256 []byte
}

// Custody retains distinct transport and wrapping keys loaded by the checked
// configuration boundary. Its fields cannot be serialized accidentally.
type Custody struct {
	transport   *rsa.PrivateKey
	wrapping    cipher.AEAD
	publicDER   []byte
	transportID string
	wrappingID  string
}

func (c *Custody) String() string   { return "recovery escrow custody (redacted)" }
func (c *Custody) GoString() string { return c.String() }
func (c *Custody) MarshalJSON() ([]byte, error) {
	return nil, errors.New("recovery escrow custody cannot be serialized")
}

// New validates key material before serving any action. RSA-OAEP is only the
// ingress transport; each durable record gets a separate random AES-256 key.
func New(transportPrivateKey *rsa.PrivateKey, kek []byte) (*Custody, error) {
	if transportPrivateKey == nil || transportPrivateKey.N == nil || transportPrivateKey.N.BitLen() < 3072 || transportPrivateKey.N.BitLen() > 4096 {
		return nil, errors.New("escrow: transport key must be RSA 3072 through 4096 bits")
	}
	if err := transportPrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf("escrow: validate transport key: %w", err)
	}
	if len(kek) != 32 {
		return nil, errors.New("escrow: wrapping key must contain 32 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("escrow: create wrapping cipher: %w", err)
	}
	wrapping, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("escrow: create wrapping AEAD: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&transportPrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("escrow: encode transport public key: %w", err)
	}
	publicDigest := sha256.Sum256(publicDER)
	keyDigest := bindingLabel("lindm-recovery-wrapping-key-v1\x00", kek)
	return &Custody{transport: transportPrivateKey, wrapping: wrapping, publicDER: publicDER, transportID: hex.EncodeToString(publicDigest[:]), wrappingID: hex.EncodeToString(keyDigest[:])}, nil
}

// PublicKey returns a detached PKIX DER public key for a signed execution plan.
func (c *Custody) PublicKey() []byte { return bytes.Clone(c.publicDER) }
func (c *Custody) KeyID() string     { return c.transportID }

// SealForServer encrypts a recovery key to the plan-authenticated server key.
// Binding must be the exact canonical RecoveryKeyBinding protobuf. Plaintext is
// caller-owned; the caller clears it immediately after local unlock verification.
func SealForServer(publicDER, binding, secret []byte) ([]byte, error) {
	if len(binding) == 0 || len(binding) > 4096 || len(secret) < 32 || len(secret) > 128 {
		return nil, errors.New("escrow: invalid binding or recovery key size")
	}
	if len(publicDER) > 1024 {
		return nil, errors.New("escrow: public key exceeds limit")
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, errors.New("escrow: invalid public key")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 {
		return nil, errors.New("escrow: transport public key must be RSA 3072 through 4096 bits")
	}
	label := bindingLabel(transportDomain, binding)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, secret, label[:])
	if err != nil {
		return nil, fmt.Errorf("escrow: encrypt recovery transport: %w", err)
	}
	return ciphertext, nil
}

// OpenAndSeal decrypts one authenticated device result and returns an envelope
// ready for durable storage. It never returns plaintext to the domain caller.
func (c *Custody) OpenAndSeal(binding, ciphertext []byte) (*Record, error) {
	if len(binding) == 0 || len(binding) > 4096 || len(ciphertext) != c.transport.Size() {
		return nil, errors.New("escrow: invalid recovery transport")
	}
	label := bindingLabel(transportDomain, binding)
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.transport, ciphertext, label[:])
	if err != nil {
		return nil, errors.New("escrow: recovery transport authentication failed")
	}
	defer clear(secret)
	if len(secret) < 32 || len(secret) > 128 {
		return nil, errors.New("escrow: invalid recovery key size")
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("escrow: generate data key: %w", err)
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("escrow: create data cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("escrow: create data AEAD: %w", err)
	}
	aad := bindingLabel(storageDomain, binding)
	digest := sha256.Sum256(secret)
	return &Record{
		KeyID:        c.wrappingID,
		WrappedKey:   c.wrapping.Seal(nil, nil, dek, aad[:]),
		Ciphertext:   aead.Seal(nil, nil, secret, aad[:]),
		SecretSHA256: bytes.Clone(digest[:]),
	}, nil
}

// Reveal is intentionally authorization-free cryptographic machinery. Callers
// must check dedicated permission, current target scope, step-up and any required
// two-person approval, and commit the reveal audit before exposing the result.
func (c *Custody) Reveal(binding []byte, record *Record) ([]byte, error) {
	if record == nil || record.KeyID != c.wrappingID || len(binding) == 0 || len(binding) > 4096 || len(record.WrappedKey) != 32+c.wrapping.Overhead() || len(record.Ciphertext) < 60 || len(record.Ciphertext) > 156 || len(record.SecretSHA256) != sha256.Size {
		return nil, errors.New("escrow: invalid durable record")
	}
	aad := bindingLabel(storageDomain, binding)
	dek, err := c.wrapping.Open(nil, nil, record.WrappedKey, aad[:])
	if err != nil {
		return nil, errors.New("escrow: data key authentication failed")
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("escrow: create data cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("escrow: create data AEAD: %w", err)
	}
	secret, err := aead.Open(nil, nil, record.Ciphertext, aad[:])
	if err != nil {
		return nil, errors.New("escrow: recovery key authentication failed")
	}
	digest := sha256.Sum256(secret)
	if !bytes.Equal(digest[:], record.SecretSHA256) {
		clear(secret)
		return nil, errors.New("escrow: recovery key digest mismatch")
	}
	return secret, nil
}

func bindingLabel(domain string, binding []byte) [sha256.Size]byte {
	var buffer [4096 + 64]byte
	n := copy(buffer[:], domain)
	n += copy(buffer[n:], binding)
	return sha256.Sum256(buffer[:n])
}
