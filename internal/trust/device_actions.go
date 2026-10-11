package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

// DeviceActionCapability returns one exact delegated capability, never a prefix.
func DeviceActionCapability(spec *agentv1.DeviceActionSpec) (string, error) {
	switch spec.GetAction().(type) {
	case *agentv1.DeviceActionSpec_EscrowRotate:
		return "device.escrow-rotate.v1", nil
	case *agentv1.DeviceActionSpec_Tpm2Bind:
		return "device.tpm2-bind.v1", nil
	case *agentv1.DeviceActionSpec_LockSessions:
		return "device.lock-sessions.v1", nil
	case *agentv1.DeviceActionSpec_ReleaseLock:
		return "device.release-lock.v1", nil
	case *agentv1.DeviceActionSpec_Quarantine:
		return "device.quarantine.v1", nil
	case *agentv1.DeviceActionSpec_ReleaseQuarantine:
		return "device.release-quarantine.v1", nil
	case *agentv1.DeviceActionSpec_CryptoErase:
		return "device.crypto-erase.v1", nil
	case *agentv1.DeviceActionSpec_Sanitize:
		return "device.sanitize.v1", nil
	case *agentv1.DeviceActionSpec_Restart:
		return "device.restart.v1", nil
	case *agentv1.DeviceActionSpec_Shutdown:
		return "device.shutdown.v1", nil
	case *agentv1.DeviceActionSpec_RefreshInventory:
		return "device.refresh-inventory.v1", nil
	case *agentv1.DeviceActionSpec_LocalAdminPasswordRotate:
		return "device.local-admin-rotate.v1", nil
	default:
		return "", errors.New("unsupported device action capability")
	}
}

// DeviceActionDigest hashes closed deterministic protobuf, not JSON or a DSSE
// envelope. Intent envelope hashes must instead cover the exact signed bytes.
func DeviceActionDigest(message proto.Message) ([32]byte, error) {
	if message == nil || !message.ProtoReflect().IsValid() {
		return [32]byte{}, errors.New("missing device action digest payload")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return [32]byte{}, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// VerifyDeviceActionIntent authenticates only preflight. Root/delegation must
// already be authenticated; callers enforce device, generation and sequence fences.
func (v *ExecutionVerifier) VerifyDeviceActionIntent(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.DeviceActionIntent, error) {
	if len(envelope) == 0 || len(envelope) > 32768 {
		return nil, errors.New("invalid device action intent size")
	}
	// This untrusted parse selects an exact key scope only. No parsed field is
	// returned or acted on until Authority.Verify independently validates DSSE.
	var selection struct {
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &selection); err != nil {
		return nil, errors.New("invalid device action intent envelope")
	}
	candidate := new(agentv1.DeviceActionIntent)
	if err := proto.Unmarshal(selection.Payload, candidate); err != nil {
		return nil, errors.New("invalid device action intent payload")
	}
	capability, err := DeviceActionCapability(candidate.GetSpec())
	if err != nil {
		return nil, err
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, capability, now)
	if err != nil {
		return nil, err
	}
	intent := new(agentv1.DeviceActionIntent)
	if err := v.authority.Verify(ctx, envelope, intent, 1, keys...); err != nil {
		return nil, err
	}
	if err := v.deviceActionIntentBinding(root, delegation, intent, now); err != nil {
		return nil, err
	}
	return intent, nil
}

func (v *ExecutionVerifier) deviceActionIntentBinding(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, intent *agentv1.DeviceActionIntent, now time.Time) error {
	if err := v.authority.validateExecutionMessage(intent); err != nil {
		return err
	}
	if intent.GetDeploymentId() != v.deploymentID || intent.GetRootVersion() != root.GetVersion() || intent.GetDelegationVersion() != delegation.GetVersion() || intent.GetRecoveryEpoch() < delegation.GetMinimumRecoveryEpoch() {
		return errors.New("device action authority binding rejected")
	}
	if !validServiceInterval(now, intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) {
		return errors.New("device action intent validity rejected")
	}
	digest, err := DeviceActionDigest(intent.GetSpec())
	if err != nil || !bytes.Equal(digest[:], intent.GetSpecSha256()) {
		return errors.New("device action spec digest rejected")
	}
	return nil
}

// VerifyDeviceActionStart binds current start-role authority to protected intent
// and root-generated preflight. The executor separately consumes its boottime
// deadline durably, and must not automatically repeat an irreversible effect.
func (v *ExecutionVerifier) VerifyDeviceActionStart(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge, now time.Time) (*agentv1.DeviceActionStartGrant, error) {
	capability, err := DeviceActionCapability(intent.GetSpec())
	if err != nil {
		return nil, err
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, capability, now)
	if err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid device action start size")
	}
	grant := new(agentv1.DeviceActionStartGrant)
	if err := v.authority.Verify(ctx, envelope, grant, 1, keys...); err != nil {
		return nil, err
	}
	return v.verifyDeviceActionGrant(root, delegation, intent, challenge, grant, now, actionNativeEffect)
}

type actionGrantPurpose uint8

const (
	actionNativeEffect actionGrantPurpose = iota
	actionRecoveryBoot
	actionRecoveryEffect
)

func (v *ExecutionVerifier) verifyDeviceActionGrant(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge, grant *agentv1.DeviceActionStartGrant, now time.Time, purpose actionGrantPurpose) (*agentv1.DeviceActionStartGrant, error) {
	if err := v.deviceActionIntentBinding(root, delegation, intent, now); err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(challenge); err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(grant); err != nil {
		return nil, err
	}
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetActionSequence() != intent.GetActionSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetSpecSha256(), intent.GetSpecSha256()) {
		return nil, errors.New("device action challenge target rejected")
	}
	plan := challenge.GetNativePlan()
	planDigest, err := DeviceActionDigest(plan)
	if err != nil || !bytes.Equal(planDigest[:], challenge.GetNativePlanSha256()) || !proto.Equal(plan.GetSpec(), intent.GetSpec()) || plan.GetActionId() != intent.GetActionId() || !plan.GetBefore().GetSupported() {
		return nil, errors.New("device action native plan rejected")
	}
	if rotate := intent.GetSpec().GetEscrowRotate(); rotate != nil {
		binding := plan.GetRecoveryBinding()
		if binding == nil || binding.GetDeviceId() != intent.GetDeviceId() || binding.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || binding.GetActionId() != intent.GetActionId() || binding.GetLuksUuid() != rotate.GetTarget().GetLuksUuid() {
			return nil, errors.New("device action recovery binding rejected")
		}
		if slices.Contains(plan.GetBefore().GetOccupiedKeyslots(), binding.GetNewKeyslot()) {
			return nil, errors.New("device action recovery slot is already occupied")
		}
	}
	if rotate := intent.GetSpec().GetLocalAdminPasswordRotate(); rotate != nil {
		if !localAdminBindingMatches(plan.GetLocalAdminBinding(), intent) {
			return nil, errors.New("device action local-admin binding rejected")
		}
	} else if plan.GetLocalAdminBinding() != nil {
		return nil, errors.New("device action local-admin binding rejected")
	}
	erase, sanitize := intent.GetSpec().GetCryptoErase(), intent.GetSpec().GetSanitize()
	destructive := erase != nil || sanitize != nil
	liveRoot := erase.GetMode() == agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER
	if sanitize.GetRecovery() != nil && purpose == actionNativeEffect {
		return nil, errors.New("original-device recovery requires purpose-scoped authority")
	}
	if purpose == actionRecoveryBoot && sanitize.GetRecovery() == nil {
		return nil, errors.New("boot authority requires a recovery action")
	}
	if liveRoot {
		if err := validateLiveRootScope(intent.GetSpec(), plan); err != nil {
			return nil, err
		}
	} else if destructive && purpose != actionRecoveryBoot && (!plan.GetBefore().GetRecoveryEnvironment() || !plan.GetBefore().GetOffTargetJournal()) {
		return nil, errors.New("destructive action requires offline recovery qualification")
	}
	if sanitize.GetNvmeScope() != nil && !proto.Equal(sanitize.GetNvmeScope(), plan.GetBefore().GetNvmeSanitize().GetScope()) {
		return nil, errors.New("native sanitize scope rejected")
	}
	if !validServiceInterval(now, challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime(), intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime()) {
		return nil, errors.New("device action challenge validity rejected")
	}
	if !proto.Equal(grant.GetChallenge(), challenge) || grant.GetActorId() != intent.GetActorId() || grant.GetAuthorizationVersion() != intent.GetAuthorizationVersion() || grant.GetRootVersion() != root.GetVersion() || grant.GetDelegationVersion() != delegation.GetVersion() {
		return nil, errors.New("device action start binding rejected")
	}
	if !validServiceInterval(now, grant.GetNotBefore().AsTime(), grant.GetExpiresAt().AsTime(), challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime()) {
		return nil, errors.New("device action start validity rejected")
	}
	if destructive && len(grant.GetApprovals()) != 2 {
		return nil, errors.New("destructive action requires two human approvals")
	}
	for _, approval := range grant.GetApprovals() {
		binding := approval.GetBinding()
		if binding.GetDeviceId() != intent.GetDeviceId() || binding.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || !bytes.Equal(binding.GetSpecSha256(), intent.GetSpecSha256()) || !proto.Equal(binding.GetExpiresAt(), intent.GetExpiresAt()) {
			return nil, errors.New("device action approval binding rejected")
		}
		if approval.GetActorId() == intent.GetActorId() && approval.GetAuthorizationVersion() != intent.GetAuthorizationVersion() {
			return nil, errors.New("device action approval authorization version rejected")
		}
	}
	return grant, nil
}

// VerifyDeviceActionEscrowReceipt permits only completing the original staged
// rotation (LUKS slot retirement or local-admin password set). It is not new
// destructive authority and may outlive intent expiry. Current trust still
// governs the receipt; exact consumed receipts are recovered from the journal
// rather than interpreted as permission to repeat the second phase.
func (v *ExecutionVerifier) VerifyDeviceActionEscrowReceipt(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, record *agentv1.DeviceActionRecord, now time.Time) (*agentv1.DeviceActionEscrowReceipt, error) {
	spec := record.GetIntent().GetSpec()
	if record == nil || (spec.GetEscrowRotate() == nil && spec.GetLocalAdminPasswordRotate() == nil) || record.GetVerification().GetEscrow() == nil || record.GetStartedAt() == nil {
		return nil, errors.New("missing staged device action escrow")
	}
	capability, err := DeviceActionCapability(spec)
	if err != nil {
		return nil, err
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, capability, now)
	if err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 16384 {
		return nil, errors.New("invalid escrow receipt size")
	}
	receipt := new(agentv1.DeviceActionEscrowReceipt)
	if err := v.authority.Verify(ctx, envelope, receipt, 1, keys...); err != nil {
		return nil, err
	}
	intent, escrow := record.GetIntent(), record.GetVerification().GetEscrow()
	digest, err := DeviceActionDigest(escrow)
	if err != nil {
		return nil, err
	}
	if receipt.GetDeploymentId() != v.deploymentID || receipt.GetDeploymentId() != intent.GetDeploymentId() || receipt.GetDeviceId() != intent.GetDeviceId() || receipt.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || receipt.GetActionId() != intent.GetActionId() || !bytes.Equal(receipt.GetIntentSha256(), record.GetIntentSha256()) || !bytes.Equal(receipt.GetEscrowSha256(), digest[:]) || !bytes.Equal(receipt.GetRecoveryKeySha256(), escrow.GetRecoveryKeySha256()) || receipt.GetNewKeyslot() != escrow.GetNewKeyslot() || receipt.GetLuksUuid() != escrow.GetLuksUuid() || receipt.GetEscrowKeyId() != escrow.GetEscrowKeyId() || receipt.GetRootVersion() != root.GetVersion() || receipt.GetDelegationVersion() != delegation.GetVersion() || !proto.Equal(receipt.GetLocalAdmin(), escrow.GetLocalAdmin()) {
		return nil, errors.New("device action escrow receipt binding rejected")
	}
	// The receipt kind must be the signed action's kind: a recovery receipt can
	// never authorize a password set, nor a local-admin receipt a slot retirement.
	if spec.GetLocalAdminPasswordRotate() != nil {
		if !localAdminBindingMatches(escrow.GetLocalAdmin(), intent) || escrow.GetEscrowKeyId() != spec.GetLocalAdminPasswordRotate().GetEscrowKeyId() {
			return nil, errors.New("device action escrow receipt binding rejected")
		}
	} else if escrow.GetLocalAdmin() != nil || escrow.GetLuksUuid() != spec.GetEscrowRotate().GetTarget().GetLuksUuid() {
		return nil, errors.New("device action escrow receipt binding rejected")
	}
	// StoredAt records the original durable custody commit, not signature
	// issuance. A current signer may attest that same commit after rollover.
	stored := receipt.GetStoredAt().AsTime()
	if stored.After(now) {
		return nil, errors.New("device action escrow receipt validity rejected")
	}
	return receipt, nil
}

// localAdminBindingMatches requires the root-planned binding to name the exact
// signed device, generation, action and account, with a non-root UID.
func localAdminBindingMatches(binding *agentv1.LocalAdminPasswordBinding, intent *agentv1.DeviceActionIntent) bool {
	return binding != nil && binding.GetDeviceId() == intent.GetDeviceId() && binding.GetEnrollmentGeneration() == intent.GetEnrollmentGeneration() && binding.GetActionId() == intent.GetActionId() && binding.GetAccountName() == intent.GetSpec().GetLocalAdminPasswordRotate().GetAccountName() && binding.GetAccountName() != "root" && binding.GetAccountUid() != 0
}

func validateLiveRootScope(spec *agentv1.DeviceActionSpec, plan *agentv1.DeviceActionPlan) error {
	targets, prepared := spec.GetCryptoErase().GetTargets(), plan.GetCryptoEraseTargets()
	observed := plan.GetBefore().GetCryptoEraseTargets()
	if len(targets) == 0 || len(prepared) != len(targets) || len(observed) != len(targets) || !plan.GetBefore().GetEncrypted() {
		return errors.New("incomplete live-root encrypted scope")
	}
	rootCount := 0
	for _, target := range targets {
		matches := 0
		for _, candidate := range prepared {
			if proto.Equal(candidate.GetTarget(), target) {
				matches++
				if candidate.GetRootBacking() {
					rootCount++
				}
				observedMatches := 0
				for _, observation := range observed {
					if proto.Equal(candidate, observation) {
						observedMatches++
					}
				}
				if observedMatches != 1 {
					return errors.New("live-root observed scope changed")
				}
			}
		}
		if matches != 1 {
			return errors.New("live-root target missing or duplicated")
		}
	}
	if rootCount != 1 {
		return errors.New("live-root scope must identify its root backing volume")
	}
	return nil
}
