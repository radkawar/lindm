// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// ApplyNative applies one transaction under the helper's connectivity guard and
// returns the after-image read back from the kernel, like every other kind.
func ApplyNative(ctx context.Context, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, guard Guard, beforeEffect func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
	config := env.Config.GetFirewallProvider()
	if err := applyNative(ctx, config, request, guard, beforeEffect); err != nil {
		return nil, err
	}
	return ReadNative(ctx, config, request.GetBefore().GetObservation())
}

// applyNative independently derives the complete target from a validated closed
// plan and protected ownership baseline. Caller-provided private bytes are never
// treated as a netlink program. No persistent file or kernel effect precedes gate.
func applyNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, request *agentv1.NativeResourceTransactionRequest, guard Guard, beforeEffect func(context.Context) error) error {
	if guard == nil || beforeEffect == nil || os.Geteuid() != 0 {
		return ErrUnsupported
	}
	for _, message := range []proto.Message{config, request} {
		if err := validateMessage(message); err != nil {
			return err
		}
	}
	plan := request.GetPlan()
	if err := resource.ValidatePlan(plan); err != nil {
		return err
	}
	if plan.GetFirewallZone() == nil || plan.GetFirewallZone().GetGeneration() != request.GetActionId() {
		return ErrConflict
	}
	before, err := ReadNative(ctx, config, request.GetBefore().GetObservation())
	if err != nil {
		return err
	}
	if !sameNativeBefore(before, request.GetBefore()) || !proto.Equal(before.GetObservation().GetFirewallZone(), plan.GetBefore().GetFirewallZone()) || !before.GetObservation().GetFirewallZone().GetPersistentReady() {
		return ErrConflict
	}
	ledger := request.GetOwnership()
	if !proto.Equal(ledger.GetRef(), plan.GetRef()) || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrConflict
	}
	if err := acquisitionAllowed(ledger.GetOwner(), before, ledger, plan.GetOperation()); err != nil {
		return err
	}
	// Claiming a new object advances the ledger after the signed plan was made;
	// its protected exact baseline must still match the planned observation.
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED {
		if !sameNativeBefore(before, ledger.GetBaseline()) {
			return ErrConflict
		}
	} else {
		digest, err := journal.ResourceOwnershipDigest(ledger)
		if err != nil || !bytes.Equal(digest[:], plan.GetOwnershipRevisionSha256()) {
			return errors.Join(ErrConflict, err)
		}
	}
	target, err := targetSnapshot(plan.GetFirewallZone().GetDesired(), before, ledger, plan.GetOperation(), ledger.GetOwner(), config, plan.GetFirewallZone().GetGeneration(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration())
	if err != nil {
		return err
	}
	if !targetMatches(target, request.GetTarget()) {
		return ErrConflict
	}
	kernel, err := nativeDigest(target.GetFirewall())
	if err != nil {
		return err
	}
	persistent := sha256.Sum256(target.GetFirewall().GetPersistenceContent())
	configuration, err := messageDigest(config)
	if err != nil {
		return err
	}
	if !bytes.Equal(kernel, plan.GetFirewallZone().GetCompiledRulesetSha256()) || !bytes.Equal(persistent[:], plan.GetFirewallZone().GetTargetPersistentSha256()) || !bytes.Equal(configuration, plan.GetFirewallZone().GetConfigurationSha256()) {
		return ErrConflict
	}
	if err := guard.Arm(ctx, request); err != nil {
		return err
	}
	applied := func(ctx context.Context) error {
		snapshot, err := CapturePendingNative(ctx, config, request)
		if err != nil {
			return err
		}
		if err := guard.Applied(ctx, request, snapshot); err != nil {
			return err
		}
		if err := guard.Confirm(ctx, request, snapshot); err != nil {
			return err
		}
		fresh, err := CapturePendingNative(ctx, config, request)
		if err != nil {
			return err
		}
		if !nativeEqual(fresh.GetFirewall(), snapshot.GetFirewall()) || !rawExpressionsMatch(fresh.GetFirewall().GetRules(), snapshot.GetFirewall().GetRules()) {
			return ErrConflict
		}
		return nil
	}
	committed := func(ctx context.Context) error {
		snapshot, err := ReadNative(ctx, config, request.GetBefore().GetObservation())
		if err != nil {
			return err
		}
		if !targetMatches(snapshot, target) || !snapshot.GetObservation().GetFirewallZone().GetPersistentReady() {
			return ErrConflict
		}
		return guard.Committed(ctx, request, snapshot)
	}
	return commitNative(ctx, config, before, target, plan.GetFirewallZone().GetGeneration(), beforeEffect, applied, committed)
}
func sameNativeBefore(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return a.GetObservation().GetMetadata().GetBootId() == b.GetObservation().GetMetadata().GetBootId() && bytes.Equal(a.GetFirewall().GetNetworkNamespaceSha256(), b.GetFirewall().GetNetworkNamespaceSha256()) && managedMatch(a, b)
}
func compileTarget(target *agentv1.ResourceOwnershipSnapshot, config *agentv1.NativeFirewallProviderConfig) (*compiledTable, error) {
	if target.GetFirewall().GetPersistent() == nil {
		return &compiledTable{name: target.GetFirewall().GetTable()}, nil
	}
	compiled, err := compile(target.GetFirewall().GetPersistent(), config)
	if err != nil {
		return nil, err
	}
	if !nativeEqual(compiled.snapshot(), target.GetFirewall()) {
		return nil, ErrConflict
	}
	return compiled, nil
}
func commitNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, before, target *agentv1.ResourceOwnershipSnapshot, generation string, beforeEffect func(context.Context) error, afterKernel, afterCommit func(context.Context) error) (err error) {
	compiled, err := compileTarget(target, config)
	if err != nil {
		return err
	}
	if compiled.name != before.GetFirewall().GetTable() || before.GetFirewall().GetPersistenceFile().GetPath() != StatePath(before.GetObservation().GetRef().GetCanonicalKey()) || target.GetFirewall().GetPersistenceFile().GetPath() != before.GetFirewall().GetPersistenceFile().GetPath() {
		return ErrConflict
	}
	connection, err := openNetlink(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, connection.close()) }()
	fresh, _, err := connection.observe(before.GetFirewall().GetTable())
	if err != nil {
		return err
	}
	if !nativeEqual(fresh, before.GetFirewall()) {
		return ErrConflict
	}
	namespace, err := namespaceIdentity()
	if err != nil || !bytes.Equal(namespace, before.GetFirewall().GetNetworkNamespaceSha256()) {
		return errors.Join(ErrConflict, err)
	}
	if err := checkInterfaces(config); err != nil {
		return err
	}
	if targetMatches(before, target) {
		if err := beforeEffect(ctx); err != nil {
			return err
		}
		if afterKernel != nil {
			if err := afterKernel(ctx); err != nil {
				return err
			}
		}
		if afterCommit != nil {
			return afterCommit(ctx)
		}
		return ctx.Err()
	}
	pendingContent, err := pendingContent(before, target, generation)
	if err != nil {
		return err
	}
	// Preserve nativefile's own ctime/mtime revision: the enclosing observation's
	// revision describes nftables, not this independently held inode.
	beforeFile, err := nativefile.Capture(before.GetFirewall().GetPersistenceFile().GetPath(), before.GetObservation())
	if err != nil {
		return err
	}
	expectedFile := persistenceImage(before)
	if !proto.Equal(beforeFile.GetObservation().GetManagedFile(), expectedFile.GetObservation().GetManagedFile()) || !bytes.Equal(beforeFile.GetManagedFileContent(), expectedFile.GetManagedFileContent()) || !bytes.Equal(nativefile.XattrDigest(beforeFile.GetManagedFileXattrs()), nativefile.XattrDigest(expectedFile.GetManagedFileXattrs())) {
		return ErrConflict
	}
	pendingFile := fileTarget(beforeFile, pendingContent)
	if !beforeFile.GetObservation().GetManagedFile().GetExists() {
		pendingFile.ManagedFileXattrs = target.GetFirewall().GetPersistenceXattrs()
		pendingFile.Observation.GetManagedFile().SecurityMetadataSha256 = nativefile.XattrDigest(pendingFile.GetManagedFileXattrs())
	}
	transaction, err := nativefile.Prepare(beforeFile, pendingFile)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, transaction.Close()) }()
	written, err := transaction.Commit(ctx, beforeEffect)
	if err != nil {
		return err
	}
	// The durable PENDING marker is deliberately left behind on every error.
	// Neither helper restart nor boot restoration may retry this native batch.
	if !nativeEqual(fresh, compiled.snapshot()) {
		if err := connection.replace(fresh, compiled); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	after, _, err := connection.observe(compiled.name)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if !nativeEqual(after, compiled.snapshot()) {
		return fmt.Errorf("%w: applied table %s reads back differently", ErrOutcomeUnknown, compiled.name)
	}
	if len(target.GetFirewall().GetRules()) != 0 && len(target.GetFirewall().GetRules()[0].GetRawExpressionsSha256()) != 0 && !rawExpressionsMatch(after.GetRules(), target.GetFirewall().GetRules()) {
		return fmt.Errorf("%w: applied table %s raw expressions differ", ErrOutcomeUnknown, compiled.name)
	}
	if afterKernel != nil {
		if err := afterKernel(ctx); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	finalFile := fileTarget(written, target.GetFirewall().GetPersistenceContent())
	finalFile.ManagedFileXattrs = target.GetFirewall().GetPersistenceXattrs()
	finalFile.Observation.GetManagedFile().SecurityMetadataSha256 = nativefile.XattrDigest(finalFile.GetManagedFileXattrs())
	final, err := nativefile.Prepare(written, finalFile)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	defer func() { err = errors.Join(err, final.Close()) }()
	if _, err := final.Commit(ctx, func(ctx context.Context) error { return ctx.Err() }); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if afterCommit != nil {
		return afterCommit(ctx)
	}
	return nil
}

// ReplayNative is invoked solely by the installed fixed boot unit. It never
// retries a PENDING transaction or reinstalls a same-boot missing table. Committed
// root-custody typed state authorizes a fresh boot reconstruction, not arbitrary
// supplied expressions. Root configuration drift blocks replay before any effect.
func ReplayNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig) (err error) {
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	if err := validateMessage(config); err != nil {
		return err
	}
	if _, err := namespaceIdentity(); err != nil {
		return err
	}
	if err := rootPath(StateDirectory, false); err != nil {
		return err
	}
	directory, err := os.Open(StateDirectory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	entries, err := directory.ReadDir(65)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > 64 {
		return ErrUnsupported
	}
	boot, err := smallRead("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return err
	}
	version, err := smallRead("/proc/sys/kernel/osrelease", 128)
	if err != nil {
		return err
	}
	configuration, err := messageDigest(config)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pb") {
			return ErrConflict
		}
		zone := strings.TrimSuffix(entry.Name(), ".pb")
		ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: zone}
		if err := resource.ValidateRef(ref); err != nil {
			return err
		}
		template := &resourcev1.ResourceObservation{Ref: ref, Metadata: &resourcev1.ObservationMetadata{BootId: strings.TrimSpace(string(boot)), ExecutorIncarnation: zone, ObservedAt: timestamppb.Now(), Backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_NFTABLES, NativeVersion: strings.TrimSpace(string(version)), ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "linux", Product: "native boot restoration", Version: strings.TrimSpace(string(version)), Architecture: runtime.GOARCH}}}}
		file, err := nativefile.Capture(StatePath(zone), template)
		if err != nil {
			return err
		}
		identity := file.GetObservation().GetManagedFile().GetFile()
		if identity.GetUid() != 0 || identity.GetGid() != 0 || identity.GetMode() != 0600 {
			return ErrConflict
		}
		state := &agentv1.FirewallPersistentState{}
		if err := proto.Unmarshal(file.GetManagedFileContent(), state); err != nil {
			return err
		}
		if err := replayStateValid(state, zone, configuration); err != nil {
			return err
		}
		if err := replayOne(ctx, config, template, file, state); err != nil {
			return fmt.Errorf("restore firewall zone %s: %w", zone, err)
		}
	}
	return nil
}
func replayStateValid(state *agentv1.FirewallPersistentState, zone string, configuration []byte) error {
	if err := validateMessage(state); err != nil {
		return err
	}
	if state.GetPhase() != agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED {
		return fmt.Errorf("%w: persisted zone transaction is %s, not committed", ErrOutcomeUnknown, state.GetPhase())
	}
	if state.GetDesired().GetZoneId() != zone || !bytes.Equal(state.GetConfigurationSha256(), configuration) {
		return ErrConflict
	}
	return nil
}
func replayOne(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, template *resourcev1.ResourceObservation, file *agentv1.ResourceOwnershipSnapshot, state *agentv1.FirewallPersistentState) (err error) {
	if err := checkInterfaces(config); err != nil {
		return err
	}
	compiled, err := compile(state, config)
	if err != nil {
		return err
	}
	connection, err := openNetlink(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, connection.close()) }()
	observed, _, err := connection.observe(compiled.name)
	if err != nil {
		return err
	}
	if nativeEqual(observed, compiled.snapshot()) {
		return nil
	}
	if len(observed.GetUserdata()) != 0 || observed.GetConflict() || state.GetAppliedBootId() == template.GetMetadata().GetBootId() {
		return ErrConflict
	}
	namespace, err := namespaceIdentity()
	if err != nil {
		return err
	}
	observed.NetworkNamespaceSha256 = namespace
	observed.PersistenceFile = file.GetObservation().GetManagedFile()
	observed.PersistenceContent = file.GetManagedFileContent()
	observed.PersistenceXattrs = file.GetManagedFileXattrs()
	observed.Persistent = state
	before := &agentv1.ResourceOwnershipSnapshot{Observation: template, Firewall: observed}
	target := proto.CloneOf(before)
	target.Firewall = compiled.snapshot()
	target.Firewall.NetworkNamespaceSha256 = namespace
	target.Firewall.Persistent = proto.CloneOf(state)
	target.Firewall.Persistent.AppliedBootId = template.GetMetadata().GetBootId()
	content, err := (proto.MarshalOptions{Deterministic: true}).Marshal(target.Firewall.Persistent)
	if err != nil {
		return err
	}
	target.Firewall.PersistenceContent = content
	target.Firewall.PersistenceFile = file.GetObservation().GetManagedFile()
	target.Firewall.PersistenceXattrs = file.GetManagedFileXattrs()
	return commitNative(ctx, config, before, target, state.GetGeneration(), func(ctx context.Context) error { return ctx.Err() }, nil, nil)
}
