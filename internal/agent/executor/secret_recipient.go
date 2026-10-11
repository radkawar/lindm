//go:build linux

package executor

import (
	"bytes"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/secretseal"
)

var (
	// errSecretDeliveryRejected hides which binding, key or ciphertext check failed.
	errSecretDeliveryRejected = errors.New("secret_delivery_rejected")
	// errEncryptionKeyUnavailable means the installed identity has no recipient key yet.
	errEncryptionKeyUnavailable = errors.New("encryption_key_unavailable")
)

// currentRecipientKeyID is the SHA-256 of the installed identity's raw X25519
// recipient key. The caller holds s.mu and passes state from s.enrolled.
func (s *Service) currentRecipientKeyID(loaded *bound) ([]byte, error) {
	if loaded == nil || loaded.cert == nil || loaded.encryptionPublic == nil {
		return nil, errEncryptionKeyUnavailable
	}
	return secretseal.KeyID(loaded.encryptionPublic), nil
}

// openSecretDelivery opens one sealed delivery for the installed identity with
// the current recipient key or the prior one while its credential is retained.
// The caller holds s.mu, passes state from s.enrolled and must secretseal.Clear
// the result after the single native use.
func (s *Service) openSecretDelivery(loaded *bound, binding *agentv1.SecretDeliveryBinding, sealed []byte) (*agentv1.SecretMaterial, error) {
	if loaded == nil || loaded.cert == nil || binding == nil || len(sealed) == 0 || len(sealed) > secretseal.MaxSealedBytes {
		return nil, errSecretDeliveryRejected
	}
	if binding.GetDeploymentId() != loaded.bootstrap.Root.GetDeploymentId() || binding.GetDeviceId() != loaded.state.GetDeviceId() || binding.GetEnrollmentGeneration() != loaded.state.GetEnrollmentGeneration() {
		return nil, errSecretDeliveryRejected
	}
	private := s.recipientKey(loaded, binding.GetRecipientKeySha256())
	if private == nil {
		return nil, errSecretDeliveryRejected
	}
	defer clear(private)
	material, err := secretseal.Open(private, binding, sealed)
	if err != nil {
		return nil, errSecretDeliveryRejected
	}
	return material, nil
}

// recipientKey returns a copy of the scalar whose public key ID is keyID, or nil.
func (s *Service) recipientKey(loaded *bound, keyID []byte) []byte {
	if loaded.encryptionPublic != nil && bytes.Equal(secretseal.KeyID(loaded.encryptionPublic), keyID) {
		return bytes.Clone(loaded.state.GetEncryptionPrivateKey())
	}
	if prior := loaded.prior; prior != nil && prior.encryptionPublic != nil && s.now().Before(prior.retain) && bytes.Equal(secretseal.KeyID(prior.encryptionPublic), keyID) {
		return bytes.Clone(loaded.state.GetPriorCredential().GetEncryptionPrivateKey())
	}
	return nil
}
