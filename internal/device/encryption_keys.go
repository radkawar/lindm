package device

import (
	"context"
	"encoding/hex"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/secretseal"
)

const actionDeviceEncryptionKeyRegistered = "device_encryption_key.registered"

var (
	// errDeviceEncryptionKeyUnavailable: no key attested by a currently valid
	// certificate of the live generation; delivery is blocked, never unsealed.
	errDeviceEncryptionKeyUnavailable = rpcreason.Error(connect.CodeFailedPrecondition, "device_encryption_key_unavailable")
	// errDeviceEncryptionKeyConflict: the identity already attested another key,
	// or the key is registered under another identity of the generation.
	errDeviceEncryptionKeyConflict = rpcreason.Error(connect.CodeAlreadyExists, "device_encryption_key_conflict")
)

// RegisterEncryptionKey stores the HPKE recipient key attested by the
// presented certificate's identity key. Exact replays are idempotent.
func (s *Service) RegisterEncryptionKey(ctx context.Context, req *connect.Request[devicev1.RegisterEncryptionKeyRequest]) (*connect.Response[devicev1.RegisterEncryptionKeyResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, invalid("session_epoch")
	}
	if !validAuthorityProof(req.Msg.GetAttestationEnvelope()) {
		return nil, invalid("attestation_envelope")
	}
	claim := new(agentv1.DeviceEncryptionKeyAttestation)
	if err := s.authority.Verify(ctx, req.Msg.GetAttestationEnvelope(), claim, 1, principal.PublicKey); err != nil {
		return nil, errAuthorityRejected
	}
	identity, err := publicKeyFingerprint(principal.PublicKey)
	if err != nil {
		return nil, errInternalState
	}
	if !s.authorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || !digestEqual(claim.GetIdentityPublicKeySha256(), identity) {
		return nil, errAuthorityRejected
	}
	keyID := secretseal.KeyID(claim.GetPublicKey())
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return errSessionFenced
		}
		if !digestEqual(authority.certificate.PublicKeyFingerprint, identity) {
			return errAuthorityRejected
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
			if !digestEqual(existing, keyID) {
				return errDeviceEncryptionKeyConflict
			}
			return nil
		}
		return insertAudit(ctx, q, nil, actionDeviceEncryptionKeyRegistered, principal.GenerationID.String(), hex.EncodeToString(keyID))
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.RegisterEncryptionKeyResponse{PublicKeySha256: keyID, CertificateSha256: append([]byte(nil), principal.Fingerprint...)}), nil
}

// currentDeviceEncryptionKey returns the raw recipient key that deliveries to
// generationID must be sealed to, read in the caller's transaction.
func currentDeviceEncryptionKey(ctx context.Context, q *devicedb.Queries, generationID uuid.UUID) ([]byte, error) {
	public, err := q.GetCurrentDeviceEncryptionKey(ctx, generationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errDeviceEncryptionKeyUnavailable
	}
	if err != nil {
		return nil, err
	}
	return public, nil
}
