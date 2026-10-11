//go:build linux

// Package actionprovider implements opt-in Linux imperative device actions. The
// root executor authenticates authority and supplies a durable before-effect gate;
// the protected journal also retains local account ownership before shadow changes.
// Operations are serialized locally, never automatically retried; native failures
// retain outcome_unknown. Root and narrowly allowlisted native devices are
// required. Native observations are not cold-boot or physical qualification.
package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/custody"
	"lindm/internal/resource"
)

var (
	ErrUnsupported    = errors.New("device_action_unsupported")
	ErrConflict       = errors.New("device_action_precondition")
	ErrOutcomeUnknown = errors.New("device_action_outcome_unknown")
	ErrNotVerified    = errors.New("device_action_not_verified")
	ErrCredential     = errors.New("device_action_credential_required")
)

type Options struct {
	Config *agentv1.DeviceActionProviderConfig
	// AccountJournal is the executor's protected ownership ledger and the
	// installation private custody for a generated local-admin password.
	AccountJournal *journal.Store
	// SealRecovery must seal exact ASCII recovery bytes with the supplied binding
	// to the signed spec's escrow key. It must never retain plaintext.
	SealRecovery func(context.Context, *agentv1.RecoveryKeyBinding, *agentv1.DeviceActionSpec, []byte) ([]byte, error)
	// SealLocalAdmin seals one generated local-admin password with its exact
	// binding to the signed spec's escrow key. It must never retain plaintext.
	SealLocalAdmin func(context.Context, *agentv1.LocalAdminPasswordBinding, *agentv1.DeviceActionSpec, []byte) ([]byte, error)
	// TrustedRecoveryCustody authenticates the exact signed sanitize recovery
	// spec against durable TPM custody. Only the root recovery-run composition
	// supplies this callback; configuration alone never permits a RAM journal.
	TrustedRecoveryCustody func(context.Context, *agentv1.DeviceActionSpec) error
}

type Provider struct {
	config          *agentv1.DeviceActionProviderConfig
	validate        protovalidate.Validator
	seal            func(context.Context, *agentv1.RecoveryKeyBinding, *agentv1.DeviceActionSpec, []byte) ([]byte, error)
	recoveryCustody func(context.Context, *agentv1.DeviceActionSpec) error
	localAdmin      *localAdminNative
	run             nativeRunner
	sessionNative   func(context.Context, string) ([]graphicalSession, error)
	openPower       func(context.Context) (powerBus, func() error, error)
	openSystemd     func(context.Context) (systemdBus, func() error, error)
	patchNowDir     string
	bootID          func() (string, error)
	accounts        *accountLocker
	resolve         func(context.Context, *agentv1.DeviceActionSpec, bool) (*targetHandle, error)
	flushHeader     func(*os.File) error
	gate            chan struct{}
	clock           func() time.Time
}

func New(options Options) (*Provider, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: root_required", ErrUnsupported)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.DeviceActionProviderConfig{}, &agentv1.DeviceActionSpec{}, &agentv1.DeviceActionPlan{}, &agentv1.DeviceActionVerification{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	config := options.Config
	if config == nil {
		config = &agentv1.DeviceActionProviderConfig{}
	}
	if err := validator.Validate(config); err != nil {
		return nil, err
	}
	if options.TrustedRecoveryCustody != nil && !config.GetRecoveryEnvironment() {
		return nil, fmt.Errorf("%w: recovery_environment_required", ErrUnsupported)
	}
	if config.GetAllowQuarantine() && (config.GetQuarantineSeconds() == 0 || config.GetQuarantineSeconds() > 300 || len(config.GetManagementEndpoints()) == 0) {
		return nil, fmt.Errorf("%w: bounded_quarantine_required", ErrUnsupported)
	}
	if config.GetProtectedStateDirectory() != "" {
		if err := privateStateDirectory(config.GetProtectedStateDirectory()); err != nil {
			return nil, err
		}
	}
	for i, target := range config.GetTargets() {
		for _, prior := range config.GetTargets()[:i] {
			if proto.Equal(prior.GetTarget(), target.GetTarget()) {
				return nil, fmt.Errorf("%w: duplicate_target", ErrUnsupported)
			}
		}
		if target.GetAllowRecoveryRotation() && options.SealRecovery == nil {
			return nil, fmt.Errorf("%w: escrow_custody_required", ErrUnsupported)
		}
		sanitizeAllowed := target.GetAllowOverwrite() || target.GetAllowDiscard() || len(target.GetNativeSanitizeMethods()) != 0
		if target.GetAllowCryptoErase() || sanitizeAllowed {
			cryptoQualified := !target.GetAllowCryptoErase() || config.GetRecoveryEnvironment() || config.GetAllowLiveRootCryptoErase()
			sanitizeQualified := !sanitizeAllowed || config.GetRecoveryEnvironment() || config.GetAllowRecoveryHandoff()
			stateRequired := target.GetAllowCryptoErase() || !config.GetAllowRecoveryHandoff()
			if !cryptoQualified || !sanitizeQualified || (stateRequired && config.GetProtectedStateDirectory() == "") || target.GetQualificationId() == "" {
				return nil, fmt.Errorf("%w: destructive_qualification_required", ErrUnsupported)
			}
		}
	}
	if len(config.GetLocalAdminAccounts()) != 0 && (options.AccountJournal == nil || options.SealLocalAdmin == nil) {
		return nil, fmt.Errorf("%w: escrow_custody_required", ErrUnsupported)
	}
	p := &Provider{config: proto.CloneOf(config), validate: validator, seal: options.SealRecovery, recoveryCustody: options.TrustedRecoveryCustody, run: runNative, gate: make(chan struct{}, 1), clock: time.Now}
	p.sessionNative = logindSessions
	p.openPower = openLogindPower
	p.openSystemd = openSystemd
	p.patchNowDir = resource.OSUpdatePatchNowDir
	p.bootID = powerBootID
	p.accounts, err = newAccountLocker(options.AccountJournal, config)
	if err != nil {
		return nil, err
	}
	p.resolve = p.openTarget
	if len(config.GetLocalAdminAccounts()) != 0 {
		p.localAdmin = &localAdminNative{seal: options.SealLocalAdmin, custody: options.AccountJournal, accounts: p.accounts.readAccounts, root: p.accounts.root}
	}
	p.flushHeader = flushBlockHeader
	return p, nil
}

// privateStateDirectory requires a strict root-owned ancestry and a private leaf.
func privateStateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return ErrUnsupported
	}
	if err := custody.PrivateDirectory(path); err != nil {
		if errors.Is(err, custody.ErrUnsafe) {
			return fmt.Errorf("%w: unprotected_state_directory", ErrUnsupported)
		}
		return err
	}
	return nil
}

func (p *Provider) begin(ctx context.Context) (context.Context, func(), error) {
	if p == nil || p.gate == nil || ctx == nil {
		return nil, nil, ErrUnsupported
	}
	// A full-disk overwrite can be long; caller cancellation still fences every
	// chunk. Native helpers each have their own much shorter 90-second deadline.
	ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	select {
	case p.gate <- struct{}{}:
		return ctx, func() { <-p.gate; cancel() }, nil
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	}
}

func (p *Provider) validatePlan(plan *agentv1.DeviceActionPlan) error {
	if plan == nil {
		return ErrConflict
	}
	if err := p.validate.Validate(plan); err != nil {
		return err
	}
	if !plan.GetBefore().GetSupported() {
		return ErrUnsupported
	}
	return nil
}

func (p *Provider) Observe(ctx context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return p.observe(ctx, spec)
}

func (p *Provider) observe(ctx context.Context, spec *agentv1.DeviceActionSpec) (_ *agentv1.DeviceActionObservation, err error) {
	if err := p.validate.Validate(spec); err != nil {
		return nil, err
	}
	if _, ok := powerAction(spec); ok {
		return p.observePower(ctx, spec)
	}
	if spec.GetPatchNow() != nil {
		return p.observePatchNow(ctx)
	}
	if LiveRootHeaderErase(spec) {
		return p.observeLiveRoot(ctx, spec)
	}
	observation := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true}
	if spec.GetRefreshInventory() != nil {
		return observation, nil
	}
	unsupported := func(reason string) (*agentv1.DeviceActionObservation, error) {
		observation.Supported = false
		observation.Reason = reason
		return observation, nil
	}
	if target := specTarget(spec); target != nil {
		observation.Target = proto.CloneOf(target)
		qualification, e := p.qualified(target)
		if e != nil {
			return unsupported("target_not_allowlisted")
		}
		allowed := spec.GetEscrowRotate() != nil && qualification.GetAllowRecoveryRotation() || spec.GetTpm2Bind() != nil && qualification.GetAllowTpm2Binding() || spec.GetCryptoErase() != nil && qualification.GetAllowCryptoErase()
		if action := spec.GetSanitize(); action != nil {
			allowed = action.GetMethod() == agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE && qualification.GetAllowOverwrite() || action.GetMethod() == agentv1.SanitizeMethod_SANITIZE_METHOD_DISCARD && qualification.GetAllowDiscard() || nativeSanitizeAllowed(qualification, action.GetMethod())
		}
		if !allowed {
			return unsupported("operation_not_qualified")
		}
		handle, e := p.resolve(ctx, spec, false)
		if e != nil {
			return nil, e
		}
		defer func() { err = errors.Join(err, handle.file.Close()) }()
		if target.GetLuksUuid() != "" {
			id, e := p.crypt(ctx, handle.file, []string{"luksUUID", descriptor(0)})
			if e != nil {
				return nil, e
			}
			if strings.TrimSpace(string(id)) != target.GetLuksUuid() {
				return nil, ErrConflict
			}
			metadata, hash, e := p.metadata(ctx, handle.file)
			if e != nil {
				return nil, e
			}
			if e := p.populateLUKSObservation(observation, metadata, hash); e != nil {
				return nil, e
			}
			if spec.GetCryptoErase() != nil {
				extent, e := luksHeaderExtent(handle.file, metadata, target.GetSizeBytes())
				if e != nil {
					return nil, e
				}
				observation.LuksHeaderBytes = extent
			}
			if spec.GetEscrowRotate() != nil || spec.GetTpm2Bind() != nil {
				if !ownerPresent(metadata, qualification.GetOwnerRecoveryKeyslot()) {
					return unsupported("independent_owner_recovery_required")
				}
				if _, e := freeSlot(metadata); e != nil {
					return unsupported("no_free_keyslot")
				}
				if _, e := freeToken(metadata); e != nil {
					return unsupported("no_free_token")
				}
			}
			if action := spec.GetEscrowRotate(); action != nil && action.RetireKeyslot != nil && (!slices.Contains(observation.LindmKeyslots, action.GetRetireKeyslot()) || action.GetRetireKeyslot() == qualification.GetOwnerRecoveryKeyslot()) {
				return unsupported("retirement_requires_managed_slot")
			}
			if spec.GetTpm2Bind() != nil {
				if _, e := os.Stat("/dev/tpmrm0"); e != nil {
					return unsupported("tpm2_resource_manager_unavailable")
				}
				version, e := p.run(ctx, nativeRequest{command: cryptenroll, args: []string{"--version"}})
				if e != nil {
					return unsupported("systemd_cryptenroll_unavailable")
				}
				if !cryptenrollBindsTPM2(version) {
					return unsupported("systemd_cryptenroll_tpm2_binding_unsupported")
				}
			}
		} else {
			if encryptedTree(handle.node) {
				return unsupported("sanitize_requires_unencrypted_media")
			}
			if spec.GetSanitize().GetMethod() == agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE && !handle.node.Rotational {
				return unsupported("overwrite_requires_rotational_media")
			}
			if nativeSanitizeMethod(spec.GetSanitize().GetMethod()) {
				observation.NvmeSanitize, err = p.observeNVMe(ctx, spec, handle)
				if errors.Is(err, ErrUnsupported) {
					return unsupported("nvme_method_or_scope_unsupported")
				}
				if err != nil {
					return nil, err
				}
			}
		}
		if destructive(spec) {
			observation.RecoveryEnvironment = true
			observation.OffTargetJournal = true
		}
		return observation, nil
	}
	switch spec.GetAction().(type) {
	case *agentv1.DeviceActionSpec_LocalAdminPasswordRotate:
		return p.observeLocalAdmin(ctx, spec, observation)
	case *agentv1.DeviceActionSpec_LockSessions:
		if !p.config.GetAllowSessionLock() {
			return unsupported("session_lock_not_qualified")
		}
		observation.SessionsLocked, observation.MetadataSha256, err = p.sessions(ctx, spec.GetLockSessions().GetTerminateSessions())
		if err == nil {
			err = p.observeAccountLock(ctx, spec, observation)
		}
	case *agentv1.DeviceActionSpec_ReleaseLock:
		err = p.observeReleaseLock(ctx, spec, observation)
	case *agentv1.DeviceActionSpec_Quarantine, *agentv1.DeviceActionSpec_ReleaseQuarantine:
		if !p.config.GetAllowQuarantine() {
			return unsupported("quarantine_not_qualified")
		}
		if action := spec.GetQuarantine(); action != nil {
			for _, endpoint := range action.GetManagementEndpoints() {
				if !slices.Contains(p.config.GetManagementEndpoints(), endpoint) {
					return unsupported("management_endpoint_not_pinned")
				}
			}
			if len(action.GetManagementEndpoints()) != len(p.config.GetManagementEndpoints()) {
				return unsupported("all_management_endpoints_required")
			}
		}
		tables, e := p.quarantineTables(ctx)
		if e != nil {
			return nil, e
		}
		if action := spec.GetReleaseQuarantine(); action != nil {
			table, e := quarantineTable(action.GetQuarantineActionId())
			if e != nil {
				return nil, e
			}
			if tables[table] {
				observation.Quarantined, _, err = p.quarantineActive(ctx, table)
			}
		} else {
			for table := range tables {
				active, _, e := p.quarantineActive(ctx, table)
				if e != nil {
					return nil, e
				}
				observation.Quarantined = observation.Quarantined || active
			}
		}
	default:
		return unsupported("unknown_action")
	}
	return observation, err
}

func (p *Provider) Plan(ctx context.Context, spec *agentv1.DeviceActionSpec, before *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.validate.Validate(spec); err != nil {
		return nil, err
	}
	if before == nil || !before.GetSupported() {
		return nil, ErrUnsupported
	}
	if !proto.Equal(before.GetTarget(), specTarget(spec)) {
		return nil, ErrConflict
	}
	plan := &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), Before: proto.CloneOf(before)}
	if LiveRootHeaderErase(spec) {
		if err := p.liveRootScope(spec); err != nil {
			return nil, err
		}
		if len(before.GetCryptoEraseTargets()) != len(spec.GetCryptoErase().GetTargets()) {
			return nil, ErrConflict
		}
		for index, target := range before.GetCryptoEraseTargets() {
			if !proto.Equal(target.GetTarget(), spec.GetCryptoErase().GetTargets()[index]) {
				return nil, ErrConflict
			}
			plan.CryptoEraseTargets = append(plan.CryptoEraseTargets, proto.CloneOf(target))
		}
	}
	if spec.GetLocalAdminPasswordRotate() != nil {
		account := before.GetLocalAdmin()
		if account == nil || account.GetAccountName() != spec.GetLocalAdminPasswordRotate().GetAccountName() || account.GetAccountUid() == 0 {
			return nil, ErrConflict
		}
		// Runtime fills device/generation/action identity; the account and UID
		// observed here are frozen into the signed plan and the OAEP label.
		plan.LocalAdminBinding = &agentv1.LocalAdminPasswordBinding{AccountName: account.GetAccountName(), AccountUid: account.GetAccountUid()}
	}
	if action := spec.GetEscrowRotate(); action != nil {
		slot := uint32(0)
		for ; slot < 32 && slices.Contains(before.GetOccupiedKeyslots(), slot); slot++ {
		}
		if slot == 32 {
			return nil, ErrUnsupported
		}
		// The exact new slot is part of the signed native plan and custody AAD.
		// Runtime fills identity fields without replacing this chosen slot.
		plan.RecoveryBinding = &agentv1.RecoveryKeyBinding{LuksUuid: action.GetTarget().GetLuksUuid(), NewKeyslot: slot}
	}
	return plan, nil
}

func samePrecondition(before, fresh *agentv1.DeviceActionObservation) bool {
	return fresh.GetSupported() && proto.Equal(before.GetTarget(), fresh.GetTarget()) && before.GetEncrypted() == fresh.GetEncrypted() && before.GetRecoveryEnvironment() == fresh.GetRecoveryEnvironment() && before.GetOffTargetJournal() == fresh.GetOffTargetJournal() && bytes.Equal(before.GetMetadataSha256(), fresh.GetMetadataSha256()) && proto.Equal(before.GetNvmeSanitize(), fresh.GetNvmeSanitize())
}

func (p *Provider) Apply(ctx context.Context, plan *agentv1.DeviceActionPlan, credential []byte, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	if gate == nil {
		return nil, ErrConflict
	}
	if _, ok := powerAction(plan.GetSpec()); ok {
		return p.applyPower(ctx, plan, gate)
	}
	if plan.GetSpec().GetPatchNow() != nil {
		return p.applyPatchNow(ctx, plan, gate)
	}
	if plan.GetSpec().GetRefreshInventory() != nil {
		// Collection and durable transport publication belong to the executor.
		return nil, ErrUnsupported
	}
	if LiveRootHeaderErase(plan.GetSpec()) {
		return p.applyLiveRoot(ctx, plan, gate)
	}
	if plan.GetSpec().GetLocalAdminPasswordRotate() != nil {
		// The two escrow-before-effect phases have dedicated entry points.
		return nil, ErrUnsupported
	}
	fresh, err := p.observe(ctx, plan.GetSpec())
	if err != nil {
		return nil, err
	}
	if !samePrecondition(plan.GetBefore(), fresh) {
		return nil, ErrConflict
	}
	if specTarget(plan.GetSpec()) != nil {
		target, e := p.resolve(ctx, plan.GetSpec(), true)
		if e != nil {
			return nil, e
		}
		defer func() { err = errors.Join(err, target.file.Close()) }()
		switch plan.GetSpec().GetAction().(type) {
		case *agentv1.DeviceActionSpec_EscrowRotate:
			return p.rotate(ctx, plan, target, credential, gate)
		case *agentv1.DeviceActionSpec_Tpm2Bind:
			err = p.bindTPM(ctx, plan, target, credential, gate)
		case *agentv1.DeviceActionSpec_CryptoErase:
			return p.erase(ctx, plan, target, gate)
		case *agentv1.DeviceActionSpec_Sanitize:
			return p.sanitize(ctx, plan, target, gate)
		}
	} else {
		switch plan.GetSpec().GetAction().(type) {
		case *agentv1.DeviceActionSpec_LockSessions:
			if err = gate(ctx); err != nil {
				return nil, err
			}
			err = p.applyAccountLock(ctx, plan)
			if err == nil {
				err = p.lockSessions(ctx, plan.GetSpec().GetLockSessions().GetTerminateSessions())
			}
		case *agentv1.DeviceActionSpec_ReleaseLock:
			if err = gate(ctx); err != nil {
				return nil, err
			}
			err = p.applyReleaseLock(ctx, plan)
		case *agentv1.DeviceActionSpec_Quarantine:
			err = p.applyQuarantine(ctx, plan, gate)
		case *agentv1.DeviceActionSpec_ReleaseQuarantine:
			table, e := quarantineTable(plan.GetSpec().GetReleaseQuarantine().GetQuarantineActionId())
			if e != nil {
				return nil, e
			}
			tables, e := p.quarantineTables(ctx)
			if e != nil {
				return nil, e
			}
			if err = gate(ctx); err != nil {
				return nil, err
			}
			if tables[table] {
				err = p.removeQuarantine(ctx, table)
			}
		}
	}
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return p.verify(ctx, plan, &agentv1.DeviceActionVerification{After: fresh})
}

func (p *Provider) Verify(ctx context.Context, plan *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) (*agentv1.DeviceActionVerification, error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	return p.verify(ctx, plan, result)
}

func (p *Provider) verify(ctx context.Context, plan *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) (_ *agentv1.DeviceActionVerification, err error) {
	if result == nil {
		return nil, ErrNotVerified
	}
	if _, ok := powerAction(plan.GetSpec()); ok {
		// Only the executor's later boot observation can confirm a restart.
		return nil, ErrNotVerified
	}
	if plan.GetSpec().GetPatchNow() != nil {
		// Only Apply observes the started unit; installation is patch status.
		return nil, ErrNotVerified
	}
	if plan.GetSpec().GetRefreshInventory() != nil {
		return nil, ErrUnsupported
	}
	if LiveRootHeaderErase(plan.GetSpec()) {
		// All raw verification was performed against pinned descriptors before
		// Apply returned. Never rediscover erased targets or reload their metadata.
		return nil, ErrUnsupported
	}
	if destructive(plan.GetSpec()) {
		return p.verifyDestruction(ctx, plan, result)
	}
	if plan.GetSpec().GetQuarantine() != nil {
		table, e := quarantineTable(plan.GetActionId())
		if e != nil {
			return nil, e
		}
		active, digest, e := p.quarantineActive(ctx, table)
		if e != nil {
			return nil, e
		}
		if !active {
			return nil, ErrNotVerified
		}
		return &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true, Quarantined: true, MetadataSha256: digest}, Evidence: quarantineEvidence(p.config.GetQuarantineSeconds())}, nil
	}
	after, err := p.observe(ctx, plan.GetSpec())
	if err != nil {
		return nil, err
	}
	verification := proto.CloneOf(result)
	verification.After = after
	switch plan.GetSpec().GetAction().(type) {
	case *agentv1.DeviceActionSpec_EscrowRotate:
		if result.GetEscrow() == nil || !bytes.Equal(after.GetMetadataSha256(), result.GetEscrow().GetMetadataSha256()) {
			return nil, ErrNotVerified
		}
		// Staged recovery is deliberately not successful until receipt confirmation.
		verification.Verified = false
		return verification, nil
	case *agentv1.DeviceActionSpec_Tpm2Bind:
		target, e := p.resolve(ctx, plan.GetSpec(), false)
		if e != nil {
			return nil, e
		}
		defer func() { err = errors.Join(err, target.file.Close()) }()
		metadata, _, e := p.metadata(ctx, target.file)
		if e != nil {
			return nil, e
		}
		wanted := slices.Clone(plan.GetSpec().GetTpm2Bind().GetPcrs())
		slices.Sort(wanted)
		matched := false
		for id, token := range metadata.Tokens {
			actual := slices.Clone(token.PCRs)
			slices.Sort(actual)
			if token.Type == "systemd-tpm2" && slices.Equal(wanted, actual) && len(token.Keyslots) == 1 {
				slot, e := slotNumber(token.Keyslots[0])
				if e != nil {
					return nil, e
				}
				if !slices.Contains(plan.GetBefore().GetOccupiedKeyslots(), slot) {
					if _, e := p.crypt(ctx, target.file, []string{"open", "--type", "luks2", "--test-passphrase", "--token-only", "--token-id", id, descriptor(0)}); e != nil {
						return nil, errors.Join(ErrNotVerified, e)
					}
					matched = true
				}
			}
		}
		if !matched || !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) {
			return nil, ErrNotVerified
		}
		verification.Evidence = "Native systemd TPM2 token and newly allocated slot observed with exact explicit PCR policy; independent owner recovery retained. Cold-boot/physical TPM validation is separate."
	case *agentv1.DeviceActionSpec_LockSessions:
		if !after.GetSessionsLocked() {
			after, err = p.awaitSessionLock(ctx, plan.GetSpec())
			if err != nil {
				return nil, err
			}
			verification.After = after
		}
		verification.Evidence = sessionLockEvidence()
		if plan.GetSpec().GetLockSessions().GetTerminateSessions() {
			verification.Evidence = "logind D-Bus LockSessions and TerminateSession requested; no graphical user sessions remain. Terminated sessions cannot be restored."
		}
		if err := p.verifyAccountLock(ctx, plan, verification); err != nil {
			return nil, err
		}
	case *agentv1.DeviceActionSpec_ReleaseLock:
		if err := p.verifyAccountLock(ctx, plan, verification); err != nil {
			return nil, err
		}
	case *agentv1.DeviceActionSpec_ReleaseQuarantine:
		if after.GetQuarantined() {
			return nil, ErrNotVerified
		}
		verification.Evidence = "Original action-owned nft quarantine absent; unrelated firewall policy unchanged."
	default:
		return nil, ErrUnsupported
	}
	verification.Verified = true
	return verification, nil
}

// SandboxDevices resolves only locally qualified identities to real native block
// paths for packaging's narrow PrivateDevices bind/DeviceAllow drop-in. It does
// not grant an action permission or modify a device. A LUKS target is named by
// its approved UUID alias rather than its boot-local kernel name: the drop-in
// outlives the boot, and kernel names can be reassigned between boots (a
// virtio-SCSI root moved from sda to sdb on RHEL 10.2 once a second disk was
// attached), which made the executor's mount namespace setup fail.
func (p *Provider) SandboxDevices(ctx context.Context) (_ []string, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var devices []string
	for _, qualified := range p.config.GetTargets() {
		spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: qualified.GetTarget()}}}
		target, e := p.resolve(ctx, spec, false)
		if e != nil {
			return nil, e
		}
		path, e := sandboxTargetPath(qualified.GetTarget(), target, unix.Stat)
		if e = errors.Join(e, target.file.Close()); e != nil {
			return nil, e
		}
		if !slices.Contains(devices, path) {
			devices = append(devices, path)
		}
		if qualified.GetAllowTpm2Binding() {
			var st unix.Stat_t
			if e := unix.Stat("/dev/tpmrm0", &st); e == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR && !slices.Contains(devices, "/dev/tpmrm0") {
				devices = append(devices, "/dev/tpmrm0")
			}
		}
	}
	slices.Sort(devices)
	return devices, nil
}

// stableTargetAlias is the udev alias derived from the approved identity itself,
// so it resolves to the same identity on every boot. Only LUKS targets have one.
func stableTargetAlias(target *agentv1.StorageTarget) string {
	if uuid := target.GetLuksUuid(); uuid != "" {
		return "/dev/disk/by-uuid/" + uuid
	}
	return ""
}

// sandboxTargetPath requires the alias to resolve to exactly the pinned,
// identity-verified node. A missing or diverging alias fails closed rather than
// silently pinning a boot-local name.
func sandboxTargetPath(target *agentv1.StorageTarget, handle *targetHandle, stat func(string, *unix.Stat_t) error) (string, error) {
	alias := stableTargetAlias(target)
	if alias == "" {
		return handle.node.Path, nil
	}
	var aliased unix.Stat_t
	if err := stat(alias, &aliased); err != nil {
		return "", fmt.Errorf("%w: stable_target_alias_unavailable", ErrConflict)
	}
	if aliased.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(aliased.Rdev), unix.Minor(aliased.Rdev)) != handle.node.Device {
		return "", fmt.Errorf("%w: stable_target_alias_mismatch", ErrConflict)
	}
	return alias, nil
}
