//go:build linux

package definitionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
)

func sameOwner(a, b *agentv1.ResourceOwnershipBinding) bool {
	if a == nil || b == nil || len(a.GetSources()) == 0 || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for _, source := range a.GetSources() {
		count := 0
		for _, other := range b.GetSources() {
			if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}
func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if before.GetObservation().GetSystemdDefinition().GetDaemonReloadPending() || before.GetObservation().GetSystemdDefinition().GetTimerJobPending() {
		return ErrConflict
	}
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if !sameOwner(owner, ledger.GetOwner()) {
			return ErrConflict
		}
		if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED && !journal.DefinitionOwnershipMatches(ledger.GetLastApplied(), before, ledger.GetOwnedDimensions()) {
			return ErrConflict
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return ErrBaselineUnknown
	}
	if before.GetObservation().GetSystemdDefinition().GetExists() && (owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || owner.GetPolicy().GetAdoptionApprovalId() == "") {
		return ErrConflict
	}
	return nil
}
func dimensions(desired *resourcev1.SystemdDefinitionDesired) []agentv1.ResourceOwnedDimension {
	out := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_FILE}
	if desired.GetTimer() != nil {
		out = append(out, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_ENABLEMENT, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_RUNTIME)
	}
	return out
}

// targetImage never accepts server-provided inverse content. A release can use
// only the exact private baseline whose last effect still owns every dimension.
func targetImage(ctx context.Context, desired *resourcev1.ResourceDesiredState, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target := proto.CloneOf(before)
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED || ledger.GetLastApplied() == nil || ledger.GetBaseline() == nil {
			return nil, ErrBaselineUnknown
		}
		if !journal.DefinitionOwnershipMatches(ledger.GetLastApplied(), before, ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			return target, nil
		}
		if ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			return nil, ErrUnsupported
		}
		target.DefinitionFile = proto.CloneOf(ledger.GetBaseline().GetDefinitionFile())
		target.Observation.Observed = &resourcev1.ResourceObservation_SystemdDefinition{SystemdDefinition: proto.CloneOf(ledger.GetBaseline().GetObservation().GetSystemdDefinition())}
		return target, nil
	}
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		return nil, ErrUnsupported
	}
	data, err := Render(desired)
	if err != nil {
		return nil, err
	}
	f := target.DefinitionFile
	o := target.Observation.GetSystemdDefinition()
	if desired.GetSystemdDefinition().GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED && before.GetDefinitionFile().GetState().GetExists() {
			return nil, ErrBaselineUnknown
		}
		f.State.Exists = false
		f.State.File = nil
		f.Content = nil
		f.Xattrs = nil
		f.State.SecurityMetadataSha256 = nativefile.XattrDigest(nil)
		o.Effective = nil
		o.Exists = false
		o.OwnedFile = nil
		o.FileState = proto.CloneOf(f.State)
		if desired.GetSystemdDefinition().GetTimer() != nil {
			o.TimerEnabled = proto.Bool(false)
			o.TimerActive = proto.Bool(false)
			o.TimerInstallLinks = nil
			o.TimerInvocationId = nil
			o.TimerUnitFileState = "absent"
			o.TimerScheduleSha256 = emptyDigest()
		}
		return target, nil
	}
	f.ParentMissing = false
	f.State.Exists = true
	f.Content = bytes.Clone(data)
	digest := sha256.Sum256(data)
	f.State.File = &resourcev1.FileIdentity{Path: f.State.GetPath(), Uid: 0, Gid: 0, Mode: 0644, Sha256: digest[:]}
	if !before.GetDefinitionFile().GetState().GetExists() {
		// Parent custody (or the exact absent-parent/grandparent evidence) was
		// already captured. Resolve the final path's native label before gating.
		f.Xattrs, err = nativefile.CreationXattrs(ctx, f.State.GetPath(), 0644)
		if err != nil {
			return nil, err
		}
		f.State.SecurityMetadataSha256 = nativefile.XattrDigest(f.GetXattrs())
	}
	o.Exists = true
	o.OwnedFile = proto.CloneOf(f.State.File)
	o.FileState = proto.CloneOf(f.State)
	o.Effective = proto.CloneOf(desired.GetSystemdDefinition())
	if timer := desired.GetSystemdDefinition().GetTimer(); timer != nil {
		o.TimerEnabled = proto.Bool(timer.GetEnabled())
		o.TimerActive = proto.Bool(timer.GetEnabled())
	} else {
		if o.EffectiveOptions == nil {
			return nil, ErrUnsupported
		}
		drop := desired.GetSystemdDefinition().GetDropIn()
		if drop.CpuWeight != nil {
			o.EffectiveOptions.CpuWeight = uint64(drop.GetCpuWeight())
		}
		if drop.MemoryMaxBytes != nil {
			o.EffectiveOptions.MemoryMax = drop.GetMemoryMaxBytes()
		}
		if drop.TasksMax != nil {
			o.EffectiveOptions.TasksMax = uint64(drop.GetTasksMax())
		}
		if drop.NoNewPrivileges != nil {
			o.EffectiveOptions.NoNewPrivileges = drop.GetNoNewPrivileges()
		}
	}
	return target, nil
}
func imageEqual(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	x, y := a.GetDefinitionFile(), b.GetDefinitionFile()
	return x != nil && y != nil && x.GetState().GetExists() == y.GetState().GetExists() && x.GetState().GetPath() == y.GetState().GetPath() && x.GetState().GetFile().GetUid() == y.GetState().GetFile().GetUid() && x.GetState().GetFile().GetGid() == y.GetState().GetFile().GetGid() && x.GetState().GetFile().GetMode() == y.GetState().GetFile().GetMode() && bytes.Equal(x.GetContent(), y.GetContent()) && bytes.Equal(x.GetState().GetSecurityMetadataSha256(), y.GetState().GetSecurityMetadataSha256())
}
func messageDigest(message proto.Message) ([]byte, error) {
	if message == nil || !message.ProtoReflect().IsValid() {
		return emptyDigest(), nil
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func inverseBinding(before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.OwnershipInverseBinding, error) {
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	last, err := messageDigest(ledger.GetLastApplied())
	if err != nil {
		return nil, err
	}
	native, err := messageDigest(before.GetObservation().GetSystemdDefinition())
	if err != nil {
		return nil, err
	}
	// Metadata timestamps are not inverse content or native identity.
	inverse, err := messageDigest(target.GetDefinitionFile())
	if err != nil {
		return nil, err
	}
	return &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: native, InverseSha256: inverse}, nil
}
func sameObserved(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return proto.Equal(a.GetDefinitionFile(), b.GetDefinitionFile()) && proto.Equal(a.GetObservation().GetSystemdDefinition(), b.GetObservation().GetSystemdDefinition()) && a.GetObservation().GetMetadata().GetBootId() == b.GetObservation().GetMetadata().GetBootId()
}
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.config.Journal.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
