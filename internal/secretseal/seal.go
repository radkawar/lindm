// SPDX-License-Identifier: Apache-2.0

// Package secretseal seals purpose-typed secret material to one device's
// attested HPKE recipient key and opens it on that device. It fixes the suite
// to DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 in base mode
// and binds every ciphertext to a deterministic SecretDeliveryBinding as AAD.
// It does not authorize delivery, resolve secret references, verify identity
// attestations or persist anything: callers own those decisions.
package secretseal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Suite identifiers recorded in DeviceEncryptionKeyAttestation.
const (
	KEMID  = 0x0020
	KDFID  = 0x0001
	AEADID = 0x0003
)

// MaxSealedBytes bounds one delivery: encapsulated key, 4096-byte material
// plus protobuf framing and the AEAD tag.
const MaxSealedBytes = 8192

const info = "lindm-secret-delivery-v1"

var (
	// ErrBinding rejects AAD that is absent, oversized or not canonical.
	ErrBinding = errors.New("secret_delivery_binding_invalid")
	// ErrOpen hides every authentication failure behind one reason.
	ErrOpen = errors.New("secret_delivery_rejected")
)

var marshal = proto.MarshalOptions{Deterministic: true}

// GenerateKey returns a new raw 32-byte X25519 recipient scalar. Callers store
// it only in protected executor state and clear their copies after use.
func GenerateKey(entropy io.Reader) ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("secretseal: generate recipient key: %w", err)
	}
	return key.Bytes(), nil
}

// PublicKey derives the raw recipient public key from a private scalar.
func PublicKey(private []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, errors.New("secretseal: invalid recipient private key")
	}
	return key.PublicKey().Bytes(), nil
}

// KeyID is the SHA-256 of a raw recipient public key, as bound in deliveries.
func KeyID(public []byte) []byte {
	digest := sha256.Sum256(public)
	return digest[:]
}

// Binding returns the canonical AAD for b. Sender and recipient both encode the
// binding they independently constructed; any difference fails authentication.
func Binding(b *agentv1.SecretDeliveryBinding) ([]byte, error) {
	if b == nil || b.GetResource() == nil || b.GetSecret() == nil || len(b.GetRecipientKeySha256()) != sha256.Size {
		return nil, ErrBinding
	}
	encoded, err := marshal.Marshal(b)
	if err != nil || len(encoded) == 0 || len(encoded) > 4096 {
		return nil, ErrBinding
	}
	return encoded, nil
}

// Seal encrypts material to recipientPublic under binding. The binding's
// recipient digest must name recipientPublic. Plaintext encodings are cleared.
func Seal(recipientPublic []byte, binding *agentv1.SecretDeliveryBinding, material *agentv1.SecretMaterial) ([]byte, error) {
	aad, err := Binding(binding)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(KeyID(recipientPublic), binding.GetRecipientKeySha256()) {
		return nil, ErrBinding
	}
	if material == nil || material.GetMaterial() == nil {
		return nil, errors.New("secretseal: material is required")
	}
	ecdhKey, err := ecdh.X25519().NewPublicKey(recipientPublic)
	if err != nil {
		return nil, errors.New("secretseal: invalid recipient public key")
	}
	public, err := hpke.NewDHKEMPublicKey(ecdhKey)
	if err != nil {
		return nil, fmt.Errorf("secretseal: recipient key: %w", err)
	}
	plaintext, err := marshal.Marshal(material)
	if err != nil {
		return nil, fmt.Errorf("secretseal: encode material: %w", err)
	}
	defer clear(plaintext)
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(info))
	if err != nil {
		return nil, fmt.Errorf("secretseal: create sender: %w", err)
	}
	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("secretseal: seal: %w", err)
	}
	sealed := append(enc, ciphertext...)
	if len(sealed) > MaxSealedBytes {
		return nil, errors.New("secretseal: sealed material exceeds limit")
	}
	return sealed, nil
}

// Open authenticates sealed under binding with the raw recipient scalar and
// returns the decoded material. The caller must call Clear on the result as
// soon as the single native use ends. Every failure is ErrOpen.
func Open(private []byte, binding *agentv1.SecretDeliveryBinding, sealed []byte) (*agentv1.SecretMaterial, error) {
	aad, err := Binding(binding)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || !bytes.Equal(KeyID(key.PublicKey().Bytes()), binding.GetRecipientKeySha256()) {
		return nil, ErrOpen
	}
	plaintext, err := openSuite(key, []byte(info), aad, sealed)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	material := &agentv1.SecretMaterial{}
	if err := proto.Unmarshal(plaintext, material); err != nil || material.GetMaterial() == nil || len(material.ProtoReflect().GetUnknown()) != 0 {
		Clear(material)
		return nil, ErrOpen
	}
	return material, nil
}

// openSuite is the fixed-suite single-message HPKE base-mode open of enc||ct.
func openSuite(key *ecdh.PrivateKey, infoBytes, aad, sealed []byte) ([]byte, error) {
	const encLen = 32
	if len(sealed) <= encLen || len(sealed) > MaxSealedBytes {
		return nil, ErrOpen
	}
	recipientKey, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, ErrOpen
	}
	recipient, err := hpke.NewRecipient(sealed[:encLen], recipientKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), infoBytes)
	if err != nil {
		return nil, ErrOpen
	}
	plaintext, err := recipient.Open(aad, sealed[encLen:])
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// Clear zeroizes every material arm in place. Material fields are bytes so no
// immutable string copy of the plaintext is created by decoding.
func Clear(material *agentv1.SecretMaterial) {
	if material == nil {
		return
	}
	clear(material.GetPasswordHash())
	clear(material.GetWifiPsk())
	clear(material.GetOpaque())
	material.Reset()
}
