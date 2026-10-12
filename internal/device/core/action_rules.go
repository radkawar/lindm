package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/platform"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func ActionIntent(row devicedb.DeviceAction) (*agentv1.DeviceActionIntent, error) {
	intent := new(agentv1.DeviceActionIntent)
	if err := proto.Unmarshal(row.IntentDocument, intent); err != nil {
		return nil, ErrInternalState
	}
	return intent, nil
}

func RequireActionRestriction(ctx context.Context, q *devicedb.Queries, id uuid.UUID, spec *agentv1.DeviceActionSpec) error {
	if err := q.ExpireDeviceActionQuarantine(ctx, id); err != nil {
		return err
	}
	restriction, err := q.GetDeviceActionRestriction(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !restriction.Quarantined {
		return nil
	}
	if release := spec.GetReleaseQuarantine(); release != nil && release.GetQuarantineActionId() == restriction.ActionID.String() {
		return nil
	}
	return rpcreason.Error(connect.CodeFailedPrecondition, "device_quarantined")
}

// tpm2Available reports whether inventory positively observed a TPM 2.0 device.
// The collector reports sysfs tpm_version_major ("2"), not a marketing string.
func TPM2Available(tpm *inventoryv1.TpmDetails) bool {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	return tpm.GetPresent().GetStatus() == success && tpm.GetPresent().GetValue() &&
		tpm.GetVersion().GetStatus() == success && tpm.GetVersion().GetValue() == "2"
}

func LiveRootAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase().GetMode() == agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER
}

func EncryptionObservation(status *agentv1.DeviceActionStatus, luksUUID string) *agentv1.DeviceActionObservation {
	observation := status.GetBefore()
	if status.GetVerification() != nil {
		observation = status.GetVerification().GetAfter()
	}
	if luksUUID == "" || observation.GetTarget().GetLuksUuid() == luksUUID {
		return observation
	}
	for _, result := range status.GetVerification().GetCryptoEraseResults() {
		if result.GetTarget().GetLuksUuid() == luksUUID {
			selected := proto.CloneOf(observation)
			selected.Target = result.GetTarget()
			selected.Encrypted = !result.GetMetadataAbsent()
			selected.LuksHeaderBytes = result.GetHeaderBytes()
			return selected
		}
	}
	for _, target := range status.GetBefore().GetCryptoEraseTargets() {
		if target.GetTarget().GetLuksUuid() == luksUUID {
			selected := proto.CloneOf(status.GetBefore())
			selected.Target = target.GetTarget()
			selected.Encrypted = true
			selected.MetadataSha256 = target.GetMetadataSha256()
			selected.LuksHeaderBytes = target.GetLuksHeaderBytes()
			return selected
		}
	}
	return observation
}

func DeviceActionCapabilityError(capability, role string) error {
	failure := rpcreason.Error(connect.CodeFailedPrecondition, "device_action_capability_not_delegated")
	failure.Meta().Set("Lindm-Action-Capability", capability)
	failure.Meta().Set("Lindm-Signer-Role", role)
	return failure
}

// A configured online key is not authority for capabilities absent from the
// operator-approved delegation. Detect that prerequisite before signing work.
func DeviceActionSignerDelegated(delegation *agentv1.ExecutionDelegation, key ed25519.PrivateKey, role agentv1.ExecutionSignerRole, capability string) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	public := key[ed25519.SeedSize:]
	for _, delegate := range delegation.GetDelegates() {
		if delegate.GetRole() == role && slices.Contains(delegate.GetCapabilities(), capability) && bytes.Equal(delegate.GetKey().GetPublicKey(), public) {
			return true
		}
	}
	return false
}

// tpm2BindSupported refuses releases whose shipped systemd cannot take the
// owner secret from a descriptor (registry fact). An unobserved OS identity
// defers to the root provider's native probe; it is not a refusal reason.
func TPM2BindSupported(host devicedb.GetHostObservationRow) bool {
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	if host.OsIDStatus != success || host.OsVersionStatus != success {
		return true
	}
	return platform.Identify(platform.OSRelease{ID: host.OsIDValue, VersionID: host.OsVersionValue}).TPM2BindSupported()
}

// TPM2TokenReferencesRequired is the registry's identical systemd-tpm2 token
// reference count for the observed release (platform TPM2TokenReferences);
// 0 when the OS identity is unobserved.
func TPM2TokenReferencesRequired(host devicedb.GetHostObservationRow) uint32 {
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	if host.OsIDStatus != success || host.OsVersionStatus != success {
		return 0
	}
	return uint32(platform.Identify(platform.OSRelease{ID: host.OsIDValue, VersionID: host.OsVersionValue}).TPM2TokenReferences())
}

// TPM2TokenReferences is the most systemd-tpm2 tokens naming one keyslot in
// the public token inventory of an action observation.
func TPM2TokenReferences(observation *agentv1.DeviceActionObservation) uint32 {
	counts := make(map[uint32]uint32)
	var most uint32
	for _, token := range observation.GetLuksTokens() {
		if token.GetType() != "systemd-tpm2" || len(token.GetKeyslots()) != 1 {
			continue
		}
		counts[token.GetKeyslots()[0]]++
		most = max(most, counts[token.GetKeyslots()[0]])
	}
	return most
}

// SessionLockOnlyUnsupported refuses a lock action that would only request a
// logind session lock on a release whose desktop locker provably ignores it
// (registry Desktop.SessionLockUnsupported). A spec that also locks accounts
// or terminates sessions has an effect and proceeds; its session part keeps
// the executor's unreported evidence. An unobserved OS identity is not a
// refusal reason.
func SessionLockOnlyUnsupported(host devicedb.GetHostObservationRow, action *agentv1.LockSessionsAction) bool {
	if action == nil || len(action.GetUsernames()) != 0 || action.GetAllHumanAccounts() || action.GetTerminateSessions() {
		return false
	}
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	if host.OsIDStatus != success || host.OsVersionStatus != success {
		return false
	}
	return platform.Identify(platform.OSRelease{ID: host.OsIDValue, VersionID: host.OsVersionValue}).Desktop.SessionLockUnsupported != ""
}

// deviceActionNotBefore backdates an intent by the device clock tolerance but
// never before its signing delegation becomes valid: VerifyDeviceActionIntent
// requires the intent window inside the delegation's. Without the clamp every
// action created within MaxDeviceClockSkew of a newly valid delegation failed
// as an internal error. Resource intents apply the same bound.
func DeviceActionNotBefore(now time.Time, delegation *agentv1.ExecutionDelegation) time.Time {
	notBefore := now.Add(-trust.MaxDeviceClockSkew)
	if valid := delegation.GetNotBefore().AsTime(); valid.After(notBefore) {
		return valid
	}
	return notBefore
}

// message is a request's message, nil for a nil request.
func Message[T any](req *connect.Request[T]) *T {
	if req == nil {
		return nil
	}
	return req.Msg
}

func EncodeProfileCursor(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	var encoded [17]byte
	encoded[0] = 'P'
	copy(encoded[1:], id[:])
	return base64.RawURLEncoding.EncodeToString(encoded[:])
}

func DecodeProfileCursor(token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.Nil, nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 17 || decoded[0] != 'P' {
		return uuid.Nil, Invalid("page_token")
	}
	id, err := uuid.FromBytes(decoded[1:])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, Invalid("page_token")
	}
	return id, nil
}

// EncodeProfileSearchCursor is EncodeProfileCursor bound to a list's search: an
// empty search keeps the plain token; otherwise the token carries the first 16
// bytes of the search's SHA-256, so it continues only that search.
func EncodeProfileSearchCursor(id uuid.UUID, search string) string {
	if search == "" || id == uuid.Nil {
		return EncodeProfileCursor(id)
	}
	digest := sha256.Sum256([]byte(search))
	var encoded [33]byte
	encoded[0] = 'S'
	copy(encoded[1:17], id[:])
	copy(encoded[17:], digest[:16])
	return base64.RawURLEncoding.EncodeToString(encoded[:])
}

// DecodeProfileSearchCursor accepts only a token encoded for the same search.
func DecodeProfileSearchCursor(token, search string) (uuid.UUID, error) {
	if search == "" || token == "" {
		return DecodeProfileCursor(token)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 33 || decoded[0] != 'S' {
		return uuid.Nil, Invalid("page_token")
	}
	digest := sha256.Sum256([]byte(search))
	if !bytes.Equal(decoded[17:], digest[:16]) {
		return uuid.Nil, Invalid("page_token")
	}
	id, err := uuid.FromBytes(decoded[1:17])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, Invalid("page_token")
	}
	return id, nil
}
