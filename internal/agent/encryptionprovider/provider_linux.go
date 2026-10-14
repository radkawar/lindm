// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package encryptionprovider evaluates root LUKS2 compliance without changing
// storage, enrolling keys or claiming native ownership. Native observations run
// through the narrowly privileged read-only adapter; signed escrow history is
// authenticated by the executor. Unmet requirements remain drift, not successful
// remediation. Release stops evaluation and has no inverse or native effect.
package encryptionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "encryption.compliance.v1"

var (
	ErrUnsupported  = errors.New("encryptionprovider: unsupported")
	ErrConflict     = errors.New("encryptionprovider: precondition conflict")
	ErrNotConverged = errors.Join(resource.ErrNotConverged, errors.New("encryptionprovider: requirements not satisfied"))
)

// Config is supplied only by the authenticated executor composition root. Observe
// may cross its fixed native read-only helper boundary; no profile chooses code.
// AuthenticatedEscrow must authenticate the complete protected action history,
// receipt signature/delegation at receipt acceptance, and current device generation.
// Missing/invalid/expired authority is never replaced by local recovery config.
type Config struct {
	ExecutorIncarnation string
	Platform            *resourcev1.PlatformProduct
	Ownership           *agentv1.ResourceOwnershipBinding
	Observe             func(context.Context) (*actionprovider.RootEncryptionEvidence, error)
	AuthenticatedEscrow func(context.Context, string) (*agentv1.DeviceActionRecord, error)
}
type Provider struct {
	config  Config
	boot    string
	backend *resourcev1.BackendSelection
	clock   func() time.Time
	mu      sync.Mutex
	closed  bool
}

var _ resourceprovider.Provider = (*Provider)(nil)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })

func validate(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ErrUnsupported
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	v, err := validator()
	if err != nil {
		return err
	}
	return v.Validate(message)
}
func Open(ctx context.Context, c Config) (*Provider, error) {
	if ctx == nil || c.Observe == nil {
		return nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validate(c.Platform); err != nil {
		return nil, err
	}
	if err := validate(c.Ownership); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	c.Platform = proto.CloneOf(c.Platform)
	c.Ownership = proto.CloneOf(c.Ownership)
	p := &Provider{config: c, boot: strings.TrimSpace(string(boot)), clock: time.Now, backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_LUKS_COMPLIANCE, NativeVersion: "2", ProviderVersion: "1", Product: proto.CloneOf(c.Platform)}}
	return p, nil
}
func (p *Provider) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }
func desiredState(d *resourcev1.EncryptionComplianceDesired) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}, State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: proto.CloneOf(d)}}
}
func (p *Provider) desired(d *resourcev1.ResourceDesiredState) error {
	if p.closed {
		return ErrUnsupported
	}
	if err := resource.ValidateDesired(d); err != nil {
		return err
	}
	if d.GetEncryptionCompliance() == nil {
		return ErrUnsupported
	}
	return nil
}
func digest(message proto.Message) ([]byte, error) {
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func (p *Provider) observe(ctx context.Context, d *resourcev1.EncryptionComplianceDesired) (*resourcev1.ResourceObservation, error) {
	native, err := p.config.Observe(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	arm := &resourcev1.EncryptionComplianceObservation{}
	metadata := &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.New(p.clock()), Backend: proto.CloneOf(p.backend), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}
	if err != nil || native == nil {
		metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
		metadata.Reason = "root_storage_graph_or_luks_metadata_unavailable"
		if errors.Is(err, os.ErrPermission) {
			metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_PERMISSION_DENIED
		}
		sum := sha256.Sum256([]byte(metadata.Reason))
		arm.EvidenceSha256 = sum[:]
	} else {
		if len(native.NativeSHA256) != sha256.Size {
			return nil, ErrConflict
		}
		arm.LuksRoot = proto.Bool(native.LUKSRoot)
		arm.TpmBound = proto.Bool(native.TPMBound)
		arm.EscrowVerified = proto.Bool(false)
		if native.LUKSRoot {
			if len(native.MetadataSHA256) != sha256.Size {
				return nil, ErrConflict
			}
			if err := projectRootIdentity(arm, native.Target); err != nil {
				return nil, err
			}
			arm.MetadataSha256 = bytes.Clone(native.MetadataSHA256)
			if p.config.AuthenticatedEscrow != nil {
				for _, recovery := range native.Recovery {
					record, err := p.config.AuthenticatedEscrow(ctx, recovery.ActionID)
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					if err != nil || !matchesEscrow(native, recovery, record) {
						continue
					}
					receipt := sha256.Sum256(record.GetEscrowReceiptEnvelope())
					arm.EscrowVerified = proto.Bool(true)
					arm.EscrowKeyslot = proto.Uint32(recovery.Keyslot)
					arm.EscrowReceiptSha256 = receipt[:]
					break
				}
			}
		} else if native.TPMBound || native.Target != nil || len(native.Recovery) != 0 {
			return nil, ErrConflict
		}
		var reasons []string
		if !arm.GetLuksRoot() {
			reasons = append(reasons, "root_not_luks2_manual_offline_encryption_required")
		}
		if d.GetRequireEscrow() && !arm.GetEscrowVerified() {
			reasons = append(reasons, "current_root_slot_authenticated_escrow_proof_missing")
		}
		if d.GetRequireTpm() && !arm.GetTpmBound() {
			reasons = append(reasons, "current_root_tpm_pcr_unlock_proof_missing")
		}
		metadata.Reason = strings.Join(reasons, "; ")
		proof, err := digest(arm)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		h.Write(native.NativeSHA256)
		h.Write(proof)
		arm.EvidenceSha256 = h.Sum(nil)
	}
	metadata.NativeRevision, err = digest(arm)
	if err != nil {
		return nil, err
	}
	o := &resourcev1.ResourceObservation{Ref: desiredState(d).GetRef(), Metadata: metadata, Observed: &resourcev1.ResourceObservation_EncryptionCompliance{EncryptionCompliance: arm}}
	if err := resource.ValidateObservation(o); err != nil {
		return nil, err
	}
	return o, nil
}

// A token label alone cannot establish escrow or detect replacement of a slot.
// The final verified metadata fingerprint must still match the acknowledged
// rotation's protected history. Subsequent header changes require renewed proof.
func matchesEscrow(native *actionprovider.RootEncryptionEvidence, recovery actionprovider.RootRecoveryEvidence, r *agentv1.DeviceActionRecord) bool {
	if r == nil || r.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || len(r.GetEscrowReceiptEnvelope()) == 0 || r.GetEscrowConfirmedAt() == nil || r.GetReceiptRoot() == nil || len(r.GetReceiptDelegationEnvelope()) == 0 {
		return false
	}
	intent := r.GetIntent()
	v := r.GetVerification()
	escrow := v.GetEscrow()
	return intent.GetActionId() == recovery.ActionID && proto.Equal(intent.GetSpec().GetEscrowRotate().GetTarget(), native.Target) && v.GetVerified() && escrow != nil && escrow.GetLuksUuid() == native.Target.GetLuksUuid() && escrow.GetNewKeyslot() == recovery.Keyslot && len(recovery.KeySHA256) == sha256.Size && bytes.Equal(escrow.GetRecoveryKeySha256(), recovery.KeySHA256) && bytes.Equal(v.GetAfter().GetMetadataSha256(), native.MetadataSHA256)
}

// Observe reads root-encryption compliance through the native observer.
func (p *Provider) Observe(ctx context.Context, d *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.desired(d); err != nil {
		return nil, err
	}
	return p.observe(ctx, d.GetEncryptionCompliance())
}

func (p *Provider) Plan(ctx context.Context, d *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.desired(d); err != nil {
		return nil, err
	}
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	before, err := p.observe(ctx, d.GetEncryptionCompliance())
	if err != nil {
		return nil, err
	}
	desiredHash, err := resource.DesiredDigest(d)
	if err != nil {
		return nil, err
	}
	observationHash, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(d)
	if err != nil {
		return nil, err
	}
	// Bind signed ownership context, but never acquire a fake native baseline.
	ownershipHash, err := digest(p.config.Ownership)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(d.GetRef()), Operation: operation, DesiredSha256: desiredHash[:], ObservationSha256: observationHash[:], Before: before, Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ownershipHash, Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED}, Plan: &resourcev1.ResourcePlan_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionCompliancePlan{Desired: proto.CloneOf(d.GetEncryptionCompliance()), Before: proto.CloneOf(before.GetEncryptionCompliance()), Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE}}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func (p *Provider) validatePlan(plan *resourcev1.ResourcePlan) error {
	if err := resource.ValidatePlan(plan); err != nil {
		return err
	}
	if plan.GetEncryptionCompliance() == nil {
		return ErrUnsupported
	}
	if err := p.desired(desiredState(plan.GetEncryptionCompliance().GetDesired())); err != nil {
		return err
	}
	hash, err := digest(p.config.Ownership)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, plan.GetOwnershipRevisionSha256()) || !proto.Equal(plan.GetBackend(), p.backend) {
		return ErrConflict
	}
	return nil
}
func (p *Provider) verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	d := plan.GetEncryptionCompliance().GetDesired()
	after, err := p.observe(ctx, d)
	if err != nil {
		return nil, err
	}
	observed := after.GetEncryptionCompliance()
	checks := &resourcev1.EncryptionComplianceChecks{LuksRootRequirementMet: observed.GetLuksRoot(), EscrowRequirementMet: !d.GetRequireEscrow() || observed.GetEscrowVerified(), TpmRequirementMet: !d.GetRequireTpm() || observed.GetTpmBound(), EvidenceComplete: after.GetMetadata().GetObservationStatus() == resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}
	checks.Converged = checks.LuksRootRequirementMet && checks.EscrowRequirementMet && checks.TpmRequirementMet && checks.EvidenceComplete
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.Converged {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE
		checks.Converged = false
	}
	hash, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	v := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: hash[:], After: after, Disposition: disposition, Checks: &resourcev1.ResourceVerification_EncryptionCompliance{EncryptionCompliance: checks}}
	if err := resource.ValidateVerification(v); err != nil {
		return nil, err
	}
	return v, nil
}
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.verify(ctx, plan)
}
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Observation has no native effect: do not call or consume an effect permit.
	v, err := p.verify(ctx, plan)
	if err != nil {
		return nil, err
	}
	if v.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED {
		return v, fmt.Errorf("%w: %s", ErrNotConverged, v.GetAfter().GetMetadata().GetReason())
	}
	return v, nil
}

// Remediations are typed references to existing imperative workflows, never
// authority to submit a DeviceActionSpec. Root encryption has no automatic action.
func Remediations(v *resourcev1.ResourceVerification) []*agentv1.ResourceActionRemediation {
	if v == nil || v.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED {
		return nil
	}
	o := v.GetAfter().GetEncryptionCompliance()
	c := v.GetEncryptionCompliance()
	if !o.GetLuksRoot() {
		return nil
	}
	target, err := rootIdentityTarget(o)
	if err != nil {
		return nil
	}
	var result []*agentv1.ResourceActionRemediation
	if !c.GetEscrowRequirementMet() {
		result = append(result, &agentv1.ResourceActionRemediation{Target: proto.CloneOf(target), Action: &agentv1.ResourceActionRemediation_EscrowRotate{EscrowRotate: &emptypb.Empty{}}})
	}
	if !c.GetTpmRequirementMet() {
		result = append(result, &agentv1.ResourceActionRemediation{Target: proto.CloneOf(target), Action: &agentv1.ResourceActionRemediation_Tpm2Bind{Tpm2Bind: &emptypb.Empty{}}})
	}
	return result
}

func projectRootIdentity(o *resourcev1.EncryptionComplianceObservation, target *agentv1.StorageTarget) error {
	if err := validate(target); err != nil {
		return err
	}
	if target.GetLuksUuid() == "" {
		return ErrConflict
	}
	switch target.GetIdentityBasis() {
	case agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL:
		o.RootIdentityBasis = resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL
	case agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS:
		o.RootIdentityBasis = resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS
	default:
		return ErrUnsupported
	}
	o.RootLuksUuid = proto.String(target.GetLuksUuid())
	o.RootWwn = target.GetWwn()
	o.RootSerial = target.GetSerial()
	o.RootSizeBytes = target.GetSizeBytes()
	o.RootGptDiskGuid = target.GetGptDiskGuid()
	o.RootDiskSizeBytes = target.GetDiskSizeBytes()
	return nil
}

func rootIdentityTarget(o *resourcev1.EncryptionComplianceObservation) (*agentv1.StorageTarget, error) {
	target := &agentv1.StorageTarget{LuksUuid: o.GetRootLuksUuid(), Wwn: o.GetRootWwn(), Serial: o.GetRootSerial(), SizeBytes: o.GetRootSizeBytes(), GptDiskGuid: o.GetRootGptDiskGuid(), DiskSizeBytes: o.GetRootDiskSizeBytes()}
	switch o.GetRootIdentityBasis() {
	case resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL:
		target.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL
	case resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS:
		target.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS
	default:
		return nil, ErrUnsupported
	}
	if err := validate(target); err != nil {
		return nil, err
	}
	if target.GetLuksUuid() == "" {
		return nil, ErrConflict
	}
	return target, nil
}
