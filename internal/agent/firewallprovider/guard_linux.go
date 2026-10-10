//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

// Guard is implemented by the independent protected rollback supervisor. Arm is
// durable before the first gated effect. Confirm requires fresh authenticated
// controller and external packet evidence; return does not mean merely "sent".
// The provider does not import the supervisor or grant itself confirmation.
type Guard interface {
	Arm(context.Context, *agentv1.NativeResourceTransactionRequest) error
	Applied(context.Context, *agentv1.NativeResourceTransactionRequest, *agentv1.ResourceOwnershipSnapshot) error
	Confirm(context.Context, *agentv1.NativeResourceTransactionRequest, *agentv1.ResourceOwnershipSnapshot) error
	Committed(context.Context, *agentv1.NativeResourceTransactionRequest, *agentv1.ResourceOwnershipSnapshot) error
}

func pendingContent(before, target *agentv1.ResourceOwnershipSnapshot, generation string) ([]byte, error) {
	pending := proto.CloneOf(target.GetFirewall().GetPersistent())
	if pending == nil {
		pending = proto.CloneOf(before.GetFirewall().GetPersistent())
		if pending == nil {
			return nil, ErrConflict
		}
		pending.Desired.Presence = resourcev1.Presence_PRESENCE_ABSENT
	}
	pending.Phase = agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_PENDING
	pending.Generation = generation
	return (proto.MarshalOptions{Deterministic: true}).Marshal(pending)
}

// CapturePendingNative reconstructs the exact postkernel effect after a helper
// died before Applied could be fsynced. Only the original typed target generation
// and exact derived PENDING/COMMITTED file are accepted, never arbitrary drift.
func CapturePendingNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, request *agentv1.NativeResourceTransactionRequest) (*agentv1.ResourceOwnershipSnapshot, error) {
	current, kind, err := captureGuardState(ctx, config, request)
	if err != nil {
		return nil, err
	}
	compiled, err := compileTarget(request.GetTarget(), config)
	if err != nil {
		return nil, err
	}
	if (kind != "pending" && kind != "target") || !nativeEqual(current.GetFirewall(), compiled.snapshot()) {
		return nil, ErrConflict
	}
	return current, nil
}
func captureGuardState(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, request *agentv1.NativeResourceTransactionRequest) (result *agentv1.ResourceOwnershipSnapshot, fileKind string, err error) {
	if os.Geteuid() != 0 {
		return nil, "", ErrUnsupported
	}
	for _, message := range []proto.Message{config, request} {
		if err := validateMessage(message); err != nil {
			return nil, "", err
		}
	}
	if err := resource.ValidatePlan(request.GetPlan()); err != nil {
		return nil, "", err
	}
	if request.GetPlan().GetFirewallZone() == nil || request.GetActionId() != request.GetPlan().GetFirewallZone().GetGeneration() {
		return nil, "", ErrConflict
	}
	zone := request.GetPlan().GetRef().GetCanonicalKey()
	if request.GetBefore().GetFirewall().GetTable() != tableName(zone) || request.GetTarget().GetFirewall().GetTable() != tableName(zone) {
		return nil, "", ErrConflict
	}
	configuration, err := messageDigest(config)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(configuration, request.GetPlan().GetFirewallZone().GetConfigurationSha256()) {
		return nil, "", ErrConflict
	}
	namespace, err := namespaceIdentity()
	if err != nil {
		return nil, "", err
	}
	boot, err := smallRead("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return nil, "", err
	}
	connection, err := openNetlink(ctx)
	if err != nil {
		return nil, "", err
	}
	defer func() { err = errors.Join(err, connection.close()) }()
	current, foreign, err := connection.observe(tableName(zone))
	if err != nil {
		return nil, "", err
	}
	if current.GetConflict() {
		return nil, "", ErrConflict
	}
	template := proto.CloneOf(request.GetBefore().GetObservation())
	template.Metadata.BootId = strings.TrimSpace(string(boot))
	template.Metadata.ObservedAt = timestamppb.Now()
	template.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_TRANSIENT
	template.Metadata.Reason = "connectivity confirmation or rollback pending"
	file, err := nativefile.Capture(StatePath(zone), template)
	if err != nil {
		return nil, "", err
	}
	pending, err := pendingContent(request.GetBefore(), request.GetTarget(), request.GetActionId())
	if err != nil && !targetMatches(request.GetBefore(), request.GetTarget()) {
		return nil, "", err
	}
	rollbackPending, rollbackErr := pendingContent(request.GetTarget(), request.GetBefore(), request.GetActionId())
	switch {
	case bytes.Equal(file.GetManagedFileContent(), request.GetTarget().GetFirewall().GetPersistenceContent()) && file.GetObservation().GetManagedFile().GetExists() == request.GetTarget().GetFirewall().GetPersistenceFile().GetExists():
		fileKind = "target"
	case pending != nil && bytes.Equal(file.GetManagedFileContent(), pending):
		fileKind = "pending"
	case rollbackErr == nil && bytes.Equal(file.GetManagedFileContent(), rollbackPending):
		fileKind = "rollback"
	case bytes.Equal(file.GetManagedFileContent(), request.GetBefore().GetFirewall().GetPersistenceContent()) && file.GetObservation().GetManagedFile().GetExists() == request.GetBefore().GetFirewall().GetPersistenceFile().GetExists():
		fileKind = "before"
	default:
		return nil, "", ErrConflict
	}
	if file.GetObservation().GetManagedFile().GetExists() {
		identity := file.GetObservation().GetManagedFile().GetFile()
		if identity.GetUid() != 0 || identity.GetGid() != 0 || identity.GetMode() != 0600 {
			return nil, "", ErrConflict
		}
		state := &agentv1.FirewallPersistentState{}
		if err := proto.Unmarshal(file.GetManagedFileContent(), state); err != nil {
			return nil, "", err
		}
		if err := validateMessage(state); err != nil {
			return nil, "", err
		}
		current.Persistent = state
	}
	current.PersistenceFile = file.GetObservation().GetManagedFile()
	current.PersistenceContent = file.GetManagedFileContent()
	current.PersistenceXattrs = file.GetManagedFileXattrs()
	current.NetworkNamespaceSha256 = namespace
	expectedFile := request.GetBefore().GetFirewall().GetPersistenceFile()
	if fileKind == "target" || (!expectedFile.GetExists() && (fileKind == "pending" || fileKind == "rollback")) {
		expectedFile = request.GetTarget().GetFirewall().GetPersistenceFile()
	}
	if !bytes.Equal(current.GetPersistenceFile().GetAncestrySha256(), expectedFile.GetAncestrySha256()) || !bytes.Equal(current.GetPersistenceFile().GetSecurityMetadataSha256(), expectedFile.GetSecurityMetadataSha256()) {
		return nil, "", ErrConflict
	}
	digest, err := nativeDigest(current)
	if err != nil {
		return nil, "", err
	}
	persistent := sha256.Sum256(current.GetPersistenceContent())
	o := proto.CloneOf(request.GetBefore().GetObservation().GetFirewallZone())
	o.Exists = len(current.GetUserdata()) != 0
	o.OwnershipUserdata = bytes.Clone(current.GetUserdata())
	o.NativeIdentitySha256 = digest
	o.KernelRulesSha256 = digest
	o.PersistentSha256 = persistent[:]
	o.NetworkNamespaceSha256 = namespace
	o.Conflict = true
	o.ForeignTables = foreign
	o.PersistentReady = false
	template.Observed = &resourcev1.ResourceObservation_FirewallZone{FirewallZone: o}
	template.Metadata.NativeRevision = digest
	return &agentv1.ResourceOwnershipSnapshot{Observation: template, Firewall: current}, fileKind, nil
}

// RollbackNative is callable only by the protected supervisor with its durable
// original request. It restores no object outside the dedicated zone. A missing
// Applied record permits reconstruction from exact target generation/expressions
// plus its PENDING file; it never grants a retry of the forward transaction.
// After a reboot, absence plus that exact pending file permits baseline replay.
func RollbackNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, request *agentv1.NativeResourceTransactionRequest, applied *agentv1.ResourceOwnershipSnapshot, beforeRollback func(context.Context) error) error {
	if beforeRollback == nil {
		return ErrUnsupported
	}
	current, kind, err := captureGuardState(ctx, config, request)
	if err != nil {
		return err
	}
	alreadyBefore, err := rollbackDecision(current, request.GetBefore(), request.GetTarget(), applied, config, kind)
	if err != nil {
		return err
	}
	if alreadyBefore {
		return beforeRollback(ctx)
	}
	return commitNative(ctx, config, current, request.GetBefore(), request.GetActionId(), beforeRollback, nil, nil)
}

// This predicate receives only captureGuardState's exact file classifications.
// It is shared with isolated-kernel tests without bypassing host-namespace custody.
func rollbackDecision(current, baseline, target, applied *agentv1.ResourceOwnershipSnapshot, config *agentv1.NativeFirewallProviderConfig, kind string) (bool, error) {
	beforeCompiled, err := compileTarget(baseline, config)
	if err != nil {
		return false, err
	}
	targetCompiled, err := compileTarget(target, config)
	if err != nil {
		return false, err
	}
	isBefore := nativeEqual(current.GetFirewall(), beforeCompiled.snapshot())
	isTarget := nativeEqual(current.GetFirewall(), targetCompiled.snapshot())
	rebootAbsent := current.GetObservation().GetMetadata().GetBootId() != baseline.GetObservation().GetMetadata().GetBootId() && len(current.GetFirewall().GetUserdata()) == 0
	if !isBefore && !isTarget && !rebootAbsent {
		return false, ErrConflict
	}
	if isBefore && !rebootAbsent && len(baseline.GetFirewall().GetRules()) != 0 && !rawExpressionsMatch(current.GetFirewall().GetRules(), baseline.GetFirewall().GetRules()) {
		return false, ErrConflict
	}
	if isBefore && (kind == "before" || (targetMatches(baseline, target) && kind == "target")) {
		return true, nil
	}
	if kind != "pending" && kind != "rollback" && kind != "target" {
		return false, ErrConflict
	}
	if isTarget && applied != nil && (!nativeEqual(current.GetFirewall(), applied.GetFirewall()) || !rawExpressionsMatch(current.GetFirewall().GetRules(), applied.GetFirewall().GetRules())) {
		return false, fmt.Errorf("%w: rollback expression drift", ErrConflict)
	}
	return false, nil
}
