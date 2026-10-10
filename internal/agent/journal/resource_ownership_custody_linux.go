package journal

import (
	"errors"
	"strconv"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/privatecustody"
	"lindm/internal/protodata"
)

func ownershipSecretBinding(ledger *agentv1.ResourceOwnershipLedger, snapshot *agentv1.ResourceOwnershipSnapshot, role string) []byte {
	return privatecustody.Binding("lindm.resource-account-password.v1", ledger.GetInstallationId(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration(), strconv.Itoa(int(ledger.GetRef().GetKind())), ledger.GetRef().GetCanonicalKey(), strconv.FormatUint(ledger.GetRevision(), 10), role, snapshot.GetAccountPrivate().GetNativeGeneration())
}

func ownershipSnapshots(ledger *agentv1.ResourceOwnershipLedger) [3]*agentv1.ResourceOwnershipSnapshot {
	return [3]*agentv1.ResourceOwnershipSnapshot{ledger.GetBaseline(), ledger.GetLastApplied(), ledger.GetBeforeEffect()}
}

var ownershipSnapshotRoles = [3]string{"baseline", "last-applied", "before-effect"}

// Returned ledger snapshots retain the encrypted envelope alongside process-local
// plaintext so safe digests can use keyed tags rather than secret hash oracles.
func (s *Store) sealOwnershipSecrets(ledger *agentv1.ResourceOwnershipLedger) (*agentv1.ResourceOwnershipLedger, error) {
	for i, snapshot := range ownershipSnapshots(ledger) {
		private := snapshot.GetAccountPrivate()
		if private == nil {
			continue
		}
		if private.PasswordToken == nil {
			if private.GetEncryptedPasswordToken() != nil {
				return nil, ErrResourceOwnershipConflict
			}
			continue
		}
		if s.privateCustody == nil {
			return nil, ErrRecoveryHold
		}
		plaintext := []byte(private.GetPasswordToken())
		envelope, err := s.privateCustody.Seal(plaintext, ownershipSecretBinding(ledger, snapshot, ownershipSnapshotRoles[i]))
		clear(plaintext)
		if err != nil {
			return nil, ErrRecoveryHold
		}
		private.EncryptedPasswordToken = envelope
	}
	disk := proto.CloneOf(ledger)
	for _, snapshot := range ownershipSnapshots(disk) {
		if private := snapshot.GetAccountPrivate(); private != nil {
			private.PasswordToken = nil
		}
	}
	return disk, nil
}

func (s *Store) openOwnershipSecrets(ledger *agentv1.ResourceOwnershipLedger) error {
	if protodata.ValidateClosed(ledger.ProtoReflect()) != nil {
		return ErrRecoveryHold
	}
	for i, snapshot := range ownershipSnapshots(ledger) {
		private := snapshot.GetAccountPrivate()
		if private == nil {
			continue
		}
		// Never accept a legacy plaintext row or silently migrate it through WAL.
		if private.PasswordToken != nil {
			return ErrRecoveryHold
		}
		if private.GetEncryptedPasswordToken() == nil {
			continue
		}
		if s.privateCustody == nil {
			return ErrRecoveryHold
		}
		plaintext, err := s.privateCustody.Open(private.GetEncryptedPasswordToken(), ownershipSecretBinding(ledger, snapshot, ownershipSnapshotRoles[i]))
		if err != nil {
			return ErrRecoveryHold
		}
		if len(plaintext) > 4096 {
			clear(plaintext)
			return ErrRecoveryHold
		}
		private.PasswordToken = proto.String(string(plaintext))
		clear(plaintext)
	}
	return nil
}

// Strip secret plaintext and randomized ciphertext from a digest projection.
// The key ID and authenticated keyed equality tag bind the exact private value.
func redactOwnershipDigest(snapshot *agentv1.ResourceOwnershipSnapshot) error {
	private := snapshot.GetAccountPrivate()
	if private == nil {
		return nil
	}
	envelope := private.GetEncryptedPasswordToken()
	if private.PasswordToken != nil && (envelope == nil || len(envelope.GetEqualityTag()) != 32 || len(envelope.GetKeyId()) != 32) {
		return errors.New("ownership_digest_requires_encrypted_secret")
	}
	private.PasswordToken = nil
	if envelope != nil {
		envelope.Nonce = nil
		envelope.Ciphertext = nil
	}
	return nil
}

// PrivateDigest is the executor's narrow keyed-native-evidence capability.
// It returns no key material and never creates or repairs custody state.
func (s *Store) PrivateDigest(domain string, contents []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if s.privateCustody == nil {
		return nil, ErrRecoveryHold
	}
	digest, err := s.privateCustody.Digest(domain, contents)
	if err != nil {
		return nil, ErrRecoveryHold
	}
	return digest, nil
}
