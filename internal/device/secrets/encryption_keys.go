// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"encoding/hex"
	"errors"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/secretseal"
)

var (
	// errDeviceEncryptionKeyUnavailable: no key attested by a currently valid
	// certificate of the live generation; delivery is blocked, never unsealed.
	ErrDeviceEncryptionKeyUnavailable = rpcreason.Error(connect.CodeFailedPrecondition, "device_encryption_key_unavailable")
	// errDeviceEncryptionKeyConflict: the identity already attested another key,
	// or the key is registered under another identity of the generation.
	errDeviceEncryptionKeyConflict = rpcreason.Error(connect.CodeAlreadyExists, "device_encryption_key_conflict")
)

// RegisterEncryptionKey stores the HPKE recipient key attested by the
// presented certificate's identity key. Exact replays are idempotent.
func (s *Service) RegisterEncryptionKey(ctx context.Context, req *connect.Request[devicev1.RegisterEncryptionKeyRequest]) (*connect.Response[devicev1.RegisterEncryptionKeyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !core.ValidSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, core.Invalid("session_epoch")
	}
	if !core.ValidAuthorityProof(req.Msg.GetAttestationEnvelope()) {
		return nil, core.Invalid("attestation_envelope")
	}
	claim := new(agentv1.DeviceEncryptionKeyAttestation)
	if err := s.Authority.Verify(ctx, req.Msg.GetAttestationEnvelope(), claim, 1, principal.PublicKey); err != nil {
		return nil, core.ErrAuthorityRejected
	}
	identity, err := core.PublicKeyFingerprint(principal.PublicKey)
	if err != nil {
		return nil, core.ErrInternalState
	}
	if !s.AuthorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || !core.DigestEqual(claim.GetIdentityPublicKeySha256(), identity) {
		return nil, core.ErrAuthorityRejected
	}
	keyID := secretseal.KeyID(claim.GetPublicKey())
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.LockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return core.ErrSessionFenced
		}
		if !core.DigestEqual(authority.Certificate.PublicKeyFingerprint, identity) {
			return core.ErrAuthorityRejected
		}
		inserted, err := q.InsertDeviceEncryptionKey(ctx, devicedb.InsertDeviceEncryptionKeyParams{
			GenerationID: principal.GenerationID, PublicKeySha256: keyID, DeviceID: principal.DeviceID,
			IdentityKeyFingerprint: identity, KemID: int32(claim.GetKemId()), PublicKey: claim.GetPublicKey(),
			AttestationEnvelope: req.Msg.GetAttestationEnvelope(),
		})
		if err != nil {
			return err
		}
		if inserted == 0 {
			existing, err := q.GetDeviceEncryptionKeyByIdentity(ctx, devicedb.GetDeviceEncryptionKeyByIdentityParams{GenerationID: principal.GenerationID, IdentityKeyFingerprint: identity})
			if errors.Is(err, pgx.ErrNoRows) {
				return errDeviceEncryptionKeyConflict
			}
			if err != nil {
				return err
			}
			if !core.DigestEqual(existing, keyID) {
				return errDeviceEncryptionKeyConflict
			}
			return nil
		}
		return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), Action: auditkind.DeviceEncryptionKeyRegistered.String(), ResourceID: principal.GenerationID.String(), TargetDeviceID: &principal.DeviceID}, core.AuditDetails("key_sha256", hex.EncodeToString(keyID)))
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&devicev1.RegisterEncryptionKeyResponse{PublicKeySha256: keyID, CertificateSha256: append([]byte(nil), principal.Fingerprint...)}), nil
}

// currentDeviceEncryptionKey returns the raw recipient key that deliveries to
// generationID must be sealed to, read in the caller's transaction.
func CurrentDeviceEncryptionKey(ctx context.Context, q *devicedb.Queries, generationID uuid.UUID) ([]byte, error) {
	public, err := q.GetCurrentDeviceEncryptionKey(ctx, generationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceEncryptionKeyUnavailable
	}
	if err != nil {
		return nil, err
	}
	return public, nil
}
