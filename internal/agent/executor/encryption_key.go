// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/secretseal"
)

// errEncryptionKeyStale rejects an acknowledgment that does not name the exact
// current recipient key under the exact current certificate.
var errEncryptionKeyStale = errors.New("encryption_key_stale")

// PrepareEncryptionKey returns the current identity's signed attestation of the
// HPKE recipient key. The private scalar never leaves protected state.
func (s *Service) PrepareEncryptionKey(ctx context.Context, req *connect.Request[agentv1.PrepareEncryptionKeyRequest]) (*connect.Response[agentv1.PrepareEncryptionKeyResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareEncryptionKey(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) prepareEncryptionKey(ctx context.Context, req *agentv1.PrepareEncryptionKeyRequest) (*agentv1.PrepareEncryptionKeyResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.encryptionPublic == nil {
		if err := s.createEncryptionKey(ctx, loaded); err != nil {
			return nil, err
		}
	}
	identity, err := x509.MarshalPKIXPublicKey(loaded.identityPublic)
	if err != nil {
		return nil, errInternal
	}
	// The server compares this with device_certificates.public_key_fingerprint:
	// SHA-256 of the certificate key's DER SubjectPublicKeyInfo.
	identityDigest := sha256.Sum256(identity)
	claim := &agentv1.DeviceEncryptionKeyAttestation{
		DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(),
		EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), IdentityPublicKeySha256: identityDigest[:],
		KemId: secretseal.KEMID, KdfId: secretseal.KDFID, AeadId: secretseal.AEADID,
		PublicKey: bytes.Clone(loaded.encryptionPublic), CreatedAt: protoTimestamp(s.now()),
	}
	envelope, err := s.authority.Sign(ctx, claim, loaded.identityKey)
	if err != nil {
		return nil, err
	}
	keyID := secretseal.KeyID(loaded.encryptionPublic)
	return &agentv1.PrepareEncryptionKeyResponse{
		AttestationEnvelope: envelope, PublicKeySha256: keyID, CertificateSha256: fingerprint(loaded.cert),
		Acknowledged: bytes.Equal(loaded.state.GetEncryptionKeyAcknowledgedSha256(), keyID),
	}, nil
}

// createEncryptionKey gives a journal installed before secret delivery its
// recipient scalar through the same revision-checked commit as other state.
func (s *Service) createEncryptionKey(ctx context.Context, loaded *bound) error {
	key, err := secretseal.GenerateKey(s.entropy)
	if err != nil {
		return err
	}
	public, err := secretseal.PublicKey(key)
	if err != nil {
		clear(key)
		return errInternal
	}
	next := cloneState(loaded.state)
	next.EncryptionPrivateKey = key
	next.EncryptionKeyAcknowledgedSha256 = nil
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		clear(key)
		return err
	}
	loaded.state = next
	loaded.encryptionPublic = public
	return nil
}

// AcknowledgeEncryptionKey records the server's registration of the exact
// current key and certificate. It only suppresses re-registration.
func (s *Service) AcknowledgeEncryptionKey(ctx context.Context, req *connect.Request[agentv1.AcknowledgeEncryptionKeyRequest]) (*connect.Response[agentv1.AcknowledgeEncryptionKeyResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.acknowledgeEncryptionKey(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) acknowledgeEncryptionKey(ctx context.Context, req *agentv1.AcknowledgeEncryptionKeyRequest) (*agentv1.AcknowledgeEncryptionKeyResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.encryptionPublic == nil {
		return nil, errEncryptionKeyStale
	}
	keyID := secretseal.KeyID(loaded.encryptionPublic)
	if !bytes.Equal(req.GetPublicKeySha256(), keyID) || !bytes.Equal(req.GetCertificateSha256(), fingerprint(loaded.cert)) {
		return nil, errEncryptionKeyStale
	}
	if bytes.Equal(loaded.state.GetEncryptionKeyAcknowledgedSha256(), keyID) {
		return &agentv1.AcknowledgeEncryptionKeyResponse{}, nil
	}
	next := cloneState(loaded.state)
	next.EncryptionKeyAcknowledgedSha256 = keyID
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		return nil, err
	}
	return &agentv1.AcknowledgeEncryptionKeyResponse{}, nil
}
