//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// VMDeviceActionsOptions configures a maintained native lane, never production
// action authority. Only signed official image manifests and disposable VMs run.
type VMDeviceActionsOptions struct {
	Repository      string
	BuildRepository string
	Scenario        string
	WipePhase       string
	EncryptionPhase string
	// TPMBoots is how many consecutive unattended cold boots must unlock
	// through the product TPM2 bind without a prompt (0 means 1; phases tpm
	// and tpm-repair).
	TPMBoots int
	// LegacyAgentRevision is the build repository commit (or ref) whose agent
	// performs the original TPM2 bind; required for, and only valid with,
	// phase tpm-repair.
	LegacyAgentRevision string
	LabBinary           string
	LindmdBinary        string
	Encrypted           EncryptedVMOptions
	RecoveryManifest    *labv1.ImageManifest
	// RedHatTokenFile is required only by subscription-entitled original-device
	// recovery, whose unregistered vendor cloud image needs entitled boot tooling.
	RedHatTokenFile string
	// RecoveryBootMode is "" (owned systemd-boot UKI) or "measured-grub"
	// (stock shim+GRUB, vendor kernel, TPM-attested initramfs).
	RecoveryBootMode string
	// Ukify is the host's ukify for the owned-boot recovery UKI; empty is the
	// system /usr/bin/ukify. Lab hosts without systemd-ukify (the Sparks)
	// select a privately provisioned, digest-pinned copy.
	Ukify string
	// BootstrapFirmwareVars is the separately package-pinned noSB template for
	// an unsigned installer (owner-key original recovery, or the owner Secure
	// Boot TPM phase). Final owner trust uses Encrypted.Firmware instead.
	BootstrapFirmwareVars string
	// ownerSecureBoot is the TPM phase's run-only owner signer and target.
	ownerSecureBoot *actionOwnerSecureBoot
}

type VMDeviceActionsResult struct {
	Scenario                string                         `json:"scenario"`
	Compliance              *VMResourceKindEvidence        `json:"encryption_compliance,omitempty"`
	HostStart               *HostResourceEvidence          `json:"host_start,omitempty"`
	HostFailure             *HostResourceEvidence          `json:"host_failure,omitempty"`
	HostObservationError    string                         `json:"host_observation_error,omitempty"`
	WipePhase               string                         `json:"wipe_phase,omitempty"`
	EncryptionPhase         string                         `json:"encryption_phase,omitempty"`
	ImageID                 string                         `json:"image_id"`
	ImageSHA256             string                         `json:"image_sha256"`
	PackageSHA256           string                         `json:"package_sha256"`
	LabSHA256               string                         `json:"lab_sha256"`
	LindmdSHA256            string                         `json:"lindmd_sha256"`
	SignerFingerprint       string                         `json:"package_signer"`
	Firmware                *EncryptedFirmwareEvidence     `json:"firmware"`
	Runtime                 *vmRuntimeEvidence             `json:"runtime"`
	RecipeVersion           string                         `json:"installer_recipe_version"`
	Database                string                         `json:"isolated_database"`
	DeviceID                string                         `json:"device_id"`
	Target                  actionNativeTarget             `json:"target"`
	Escrow                  *actionDispatchEvidence        `json:"escrow"`
	EncryptionInventory     *actionEncryptionEvidence      `json:"encryption_inventory"`
	RetiredRecoveryBoot     *actionBootEvidence            `json:"retired_recovery_boot"`
	CustodyKEKVerified      bool                           `json:"custody_kek_verified"`
	RevealAuditVerified     bool                           `json:"reveal_audit_verified"`
	RecoveryBoot            *actionBootEvidence            `json:"recovery_boot"`
	CommittedRotation       *actionDispatchEvidence        `json:"committed_rotation"`
	CommittedRecoveryBoot   *actionBootEvidence            `json:"committed_recovery_boot"`
	RetiredSlotAbsent       bool                           `json:"retired_slot_absent"`
	Lock                    *actionDispatchEvidence        `json:"lock"`
	LockRelease             *actionDispatchEvidence        `json:"lock_release"`
	AccountLocks            []*actionAccountLockEvidence   `json:"account_locks"`
	DesktopInitialLogind    string                         `json:"desktop_initial_logind,omitempty"`
	DesktopProfile          string                         `json:"desktop_profile"`
	LockVerification        string                         `json:"lock_verification_evidence,omitempty"`
	AccountsNoDesktop       bool                           `json:"account_locks_without_desktop,omitempty"`
	DesktopBefore           *actionDesktopEvidence         `json:"desktop_before"`
	DesktopAfter            *actionDesktopEvidence         `json:"desktop_after"`
	DesktopAfterRelease     *actionDesktopEvidence         `json:"desktop_after_release"`
	Quarantine              []*actionDispatchEvidence      `json:"quarantine"`
	QuarantineEffective     bool                           `json:"quarantine_effective"`
	QuarantineDNSPreserved  bool                           `json:"quarantine_dns_preserved"`
	QuarantineHostEndpoints bool                           `json:"quarantine_host_endpoints_verified"`
	ReleaseEffective        bool                           `json:"release_effective"`
	ExpiryWithoutExecutor   bool                           `json:"expiry_without_executor"`
	Denials                 []actionDenialEvidence         `json:"denials"`
	InterruptedRotation     *actionDispatchEvidence        `json:"interrupted_rotation"`
	CrashRecoveryBoots      []*actionBootEvidence          `json:"crash_recovery_boots"`
	RetainedSlots           []uint32                       `json:"retained_slots"`
	CrashRootState          string                         `json:"crash_root_state"`
	CrashServerState        string                         `json:"crash_server_state"`
	Recovery                *actionRecoveryEvidence        `json:"recovery"`
	LiveErase               *actionLiveEraseEvidence       `json:"original_live_root_erase"`
	LiveEraseReportLoss     *actionLiveEraseEvidence       `json:"original_live_root_erase_report_loss"`
	OriginalRecovery        []*actionSignedHandoffEvidence `json:"original_signed_recovery"`
	TPMBind                 *actionDispatchEvidence        `json:"tpm_bind"`
	TPMInventory            *actionEncryptionEvidence      `json:"tpm_inventory"`
	TPMBoot                 *UnlockOutcome                 `json:"tpm_unattended_boot"`
	TPMBoots                []*tpmUnattendedBoot           `json:"tpm_unattended_boots,omitempty"`
	// TPMTokenReferences is how many systemd-tpm2 tokens the bind left
	// referencing its one sealed keyslot (platform TPM2TokenReferences).
	TPMTokenReferences int `json:"tpm_token_references,omitempty"`
	// Reference repair (phase tpm-repair): the legacy agent's bind, the native
	// upgrade to the current package and the credential-less repair bind.
	LegacyAgentRevision       string                    `json:"legacy_agent_revision,omitempty"`
	LegacyPackageSHA256       string                    `json:"legacy_package_sha256,omitempty"`
	UpgradedAgentVersion      string                    `json:"upgraded_agent_version,omitempty"`
	TPMLegacyInventory        *actionEncryptionEvidence `json:"tpm_legacy_inventory,omitempty"`
	TPMLegacyTokenReferences  int                       `json:"tpm_legacy_token_references,omitempty"`
	TPMBoundKeyslot           *uint32                   `json:"tpm_bound_keyslot,omitempty"`
	TPMLegacyServerReferences *tpmServerReferences      `json:"tpm_legacy_server_token_references,omitempty"`
	TPMReferenceRepair        *actionDispatchEvidence   `json:"tpm_reference_repair,omitempty"`
	// TPMReferenceRepairKeyslot is the keyslot the agent's signed observation
	// froze for repair (DeviceActionObservation.tpm2_reference_repair_keyslot).
	TPMReferenceRepairKeyslot   *uint32               `json:"tpm_reference_repair_keyslot,omitempty"`
	TPMReferenceRepairNotNeeded string                `json:"tpm_reference_repair_not_needed,omitempty"`
	TPMServerReferences         *tpmServerReferences  `json:"tpm_server_token_references,omitempty"`
	TPMAbsentDenial             *actionDenialEvidence `json:"tpm_absent_denial,omitempty"`
	TPMBindingDenial            *actionDenialEvidence `json:"tpm_binding_unsupported_denial,omitempty"`
	// TPMBootUnsupported records the observed passphrase prompt after a real
	// TPM2 bind on a release whose boot path cannot use TPM2 tokens.
	TPMBootUnsupported    *actionUnsupportedEvidence `json:"tpm_unattended_boot_unsupported,omitempty"`
	TPMPolicyBind         *actionDispatchEvidence    `json:"tpm_policy_mismatch_bind,omitempty"`
	TPMPolicyRejectedBoot *UnlockOutcome             `json:"tpm_policy_rejected_boot,omitempty"`
	TPMPolicyRecoveryBoot *UnlockOutcome             `json:"tpm_policy_revealed_key_recovery,omitempty"`
	PCRBefore             string                     `json:"pcr7_before_extension,omitempty"`
	PCRAfter              string                     `json:"pcr7_after_extension,omitempty"`
	// OwnerSecureBoot records each TPM-phase clone's transition to owner
	// Secure Boot trust on a release without vendor Secure Boot trust.
	OwnerSecureBoot []*actionOwnerSecureBootEvidence `json:"owner_secure_boot,omitempty"`
	StartedAt       time.Time                        `json:"started_at"`
	FinishedAt      time.Time                        `json:"finished_at"`
	Passed          bool                             `json:"passed"`
	Failure         string                           `json:"failure,omitempty"`
	Boundaries      []string                         `json:"boundaries"`
}

type actionMachine struct {
	vm                   *EncryptedVM
	release              *platform.Release
	connection           *actionGuestConnection
	fixture              *devlab.AuthorityFixture
	deviceID, generation string
	target               actionNativeTarget
	boot                 UnlockOutcome
	desktop              *labDesktop
	// packages stays open only when the package set carries an upgrade: the
	// legacy install's pinned trust and signed source serve UpgradeAgent.
	packages  *nativeGuestPackages
	upgrade   packaging.Artifact
	ownerBoot *actionOwnerSecureBootEvidence
}

func openActionMachine(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest) (_ *actionMachine, err error) {
	vm, err := NewEncryptedVM(ctx, manifest, options.Encrypted)
	if err != nil {
		return nil, err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	desktop, err := actionLaneDesktop(options, release)
	if err != nil {
		return nil, errors.Join(err, vm.Close())
	}
	machine := &actionMachine{vm: vm, fixture: fixture, desktop: desktop, release: release}
	defer func() {
		if err != nil {
			err = errors.Join(err, machine.Close())
		}
	}()
	machine.boot, err = vm.ColdBoot(ctx, vm.InitialUnlockSecret())
	if err != nil {
		return nil, fmt.Errorf("initial cold boot: %w", err)
	}
	if !machine.boot.PromptSeen {
		return nil, errors.New("initial unbound encrypted clone did not request owner credential")
	}
	// Some initramfs keep cryptsetup authentication errors in the journal and
	// do not necessarily repeat their serial prompt on rejection. Route only
	// this service's normal diagnostics to the lab console so a wrong-key test
	// observes an explicit authentication failure, never infers one from timeout.
	// Modify the disposable clone, not the immutable golden or product package.
	if guest := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion()).Lab.Guest; guest.CryptsetupConsole {
		if err := enableCryptsetupConsole(ctx, vm.guest, guest.Initrd); err != nil {
			return nil, err
		}
	}
	if _, err := observeEncryptedGuest(ctx, vm, options.Encrypted.Firmware.SecureBoot); err != nil {
		return nil, fmt.Errorf("observe encrypted guest: %w", err)
	}
	vm.guest.captureDiagnostics = options.Encrypted.DiagnosticsDir != ""
	if err := installActionPrerequisites(ctx, vm.guest, manifest, true); err != nil {
		return nil, diagnoseActionFailure(ctx, vm.guest, fmt.Errorf("install native action prerequisites: %w", err))
	}
	if options.ownerSecureBoot != nil {
		if machine.ownerBoot, err = machine.enrollOwnerSecureBoot(ctx, options.ownerSecureBoot); err != nil {
			return nil, diagnoseActionFailure(ctx, vm.guest, fmt.Errorf("enroll owner Secure Boot: %w", err))
		}
		vm.guest.captureDiagnostics = options.Encrypted.DiagnosticsDir != ""
		if _, err := observeEncryptedGuest(ctx, vm, true); err != nil {
			return nil, fmt.Errorf("observe owner Secure Boot guest: %w", err)
		}
	}
	targets, err := observeActionTargets(ctx, vm)
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		if target.Identity.GetLuksUuid() == "" {
			continue
		}
		if machine.target.Identity != nil {
			return nil, errors.New("native action lane requires one installed encrypted root partition")
		}
		machine.target = target
	}
	if machine.target.Identity == nil {
		return nil, errors.New("installed encrypted root target unavailable")
	}
	if packages.upgrade.Path == "" {
		err = packages.Install(ctx, vm.guest, options.LabBinary)
	} else {
		machine.packages, err = packages.installFirst(ctx, vm.guest, options.LabBinary)
		machine.upgrade = packages.upgrade
	}
	if err != nil {
		return nil, diagnoseActionFailure(ctx, vm.guest, fmt.Errorf("install agent packages: %w", err))
	}
	provider := &agentv1.DeviceActionProviderConfig{AllowSessionLock: true, AllowQuarantine: true, ManagementEndpoints: []string{"127.0.0.1", "10.0.2.2"}, DnsServers: []string{"10.0.2.3"}, QuarantineSeconds: 60, Targets: []*agentv1.QualifiedActionTarget{{Target: machine.target.Identity, OwnerRecoveryKeyslot: 0, AllowRecoveryRotation: true, AllowTpm2Binding: options.Encrypted.Hardware.TPM}}}
	if err := configureActionGuest(ctx, vm.guest, provider, nil); err != nil {
		return nil, err
	}
	machine.connection, err = connectActionGuest(ctx, vm.guest, fixture)
	if err != nil {
		return nil, err
	}
	issued, _, err := enrollActionGuest(ctx, vm.guest, control, delegation)
	if err != nil {
		return nil, err
	}
	machine.deviceID, machine.generation = issued.GetDeviceId(), issued.GetEnrollmentGeneration()
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return nil, err
	}
	return machine, nil
}

func (m *actionMachine) Close() error {
	var err error
	if m.packages != nil {
		err = m.packages.Close()
		m.packages = nil
	}
	if m.connection != nil {
		err = errors.Join(err, m.connection.Close())
		m.connection = nil
	}
	return errors.Join(err, m.vm.Close())
}

// record copies the opened machine's public identity into a phase result.
func (m *actionMachine) record(ctx context.Context, result *VMDeviceActionsResult) error {
	result.Firmware, result.DeviceID, result.Target = m.vm.firmware, m.deviceID, m.target
	result.RecipeVersion = encryptedRecipeVersion
	runtime, err := m.vm.guest.runtimeEvidence(ctx)
	if err != nil {
		return err
	}
	runtime.SeedDisk = false
	result.Runtime = runtime
	return nil
}

func (m *actionMachine) PowerOff(ctx context.Context) error {
	if m.connection != nil {
		if err := m.connection.Close(); err != nil {
			return err
		}
		m.connection = nil
	}
	return m.vm.PowerOff(ctx)
}

func (m *actionMachine) Reconnect(ctx context.Context) error {
	var err error
	m.connection, err = connectActionGuest(ctx, m.vm.guest, m.fixture)
	if err != nil {
		return err
	}
	if _, err := waitGuestExecutorReady(ctx, m.vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	return lifecycleCommand(ctx, m.vm.guest, "resume installed action relay after cold boot", "systemctl restart lindm-agent.service")
}

// DeviceActionsVM runs real HTTP authorization, packaged native effects and
// independent cold-boot/storage/network/session oracles. Any unsupported phase
// fails the lane; no unexecuted scenario is recorded as a pass.
func DeviceActionsVM(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions) (result *VMDeviceActionsResult, err error) {
	if options.Scenario == "" {
		options.Scenario = "all"
	}
	if options.Scenario != "all" && options.Scenario != "encryption" && options.Scenario != "wipe" && options.Scenario != "compliance" {
		return nil, errors.New("device action scenario must be all, encryption, wipe or compliance")
	}
	if options.WipePhase != "" && (options.Scenario != "wipe" || !slices.Contains([]string{"live-actions", "lock-quarantine", "live-erase", "live-report-loss", "recovery-nvme", "recovery-sata", "recovery-attestation-refusal"}, options.WipePhase)) {
		return nil, errors.New("wipe phase requires scenario wipe and a supported native phase")
	}
	if options.RecoveryBootMode != "" && (options.RecoveryBootMode != recoveryBootMeasured || !slices.Contains([]string{"recovery-nvme", "recovery-sata", "recovery-attestation-refusal"}, options.WipePhase)) {
		return nil, errors.New("recovery boot mode measured-grub requires an original-device recovery phase")
	}
	if options.WipePhase == "recovery-attestation-refusal" && options.RecoveryBootMode != recoveryBootMeasured {
		return nil, errors.New("attestation refusal phase requires recovery boot mode measured-grub")
	}
	tpmPhase := options.EncryptionPhase == "tpm" || options.EncryptionPhase == "tpm-repair"
	if options.BootstrapFirmwareVars != "" && !slices.Contains([]string{"recovery-nvme", "recovery-sata"}, options.WipePhase) && !tpmPhase {
		return nil, errors.New("bootstrap firmware variables require an explicit original-device recovery phase or a TPM encryption phase")
	}
	if err := validateEncryptionPhase(options); err != nil {
		return nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if err := validateManifest(options.RecoveryManifest); err != nil {
		return nil, err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	if err := recoveryReleaseMatches(release, manifestRelease(options.RecoveryManifest)); err != nil {
		return nil, err
	}
	for _, c := range deviceActionCapabilities(options.Scenario, options.WipePhase) {
		if err := release.Gate(c); err != nil {
			return nil, err
		}
	}
	if err := ownedBootFixtureAvailable(release, manifest.GetArchitecture(), options.Scenario, options.WipePhase, options.RecoveryBootMode); err != nil {
		return nil, err
	}
	if err := validateVMRedHatToken(release, options.RedHatTokenFile); err != nil {
		return nil, err
	}
	desktop, err := actionLaneDesktop(options, release)
	if err != nil {
		return nil, err
	}
	// Only the lock/quarantine phase never boots through a TPM2 token, so a
	// desktop whose vendor initramfs cannot unlock with TPM2 still qualifies it.
	// Releases without any TPM early-boot variant (registry Lab.TPM.Unsupported)
	// run every phase and record the unattended TPM boot as an observed
	// unsupported outcome.
	lockOnly := options.Scenario == "wipe" && options.WipePhase == "lock-quarantine"
	noTPMBoot := noTPMBootReason(manifest)
	if noTPMBoot != "" && options.Encrypted.TPMBoot {
		return nil, errors.New(noTPMBoot)
	}
	if (!options.Encrypted.TPMBoot && !lockOnly && noTPMBoot == "") || options.Encrypted.Hardware == nil || !options.Encrypted.Hardware.AllowNetwork {
		return nil, errors.New("device actions require an unbound TPM-capable boot stack (except -wipe-phase lock-quarantine or a release without one), explicit topology and signed-package egress")
	}
	result = &VMDeviceActionsResult{ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), StartedAt: time.Now().UTC(), Boundaries: []string{
		"Shared QEMU emulated topology, software TPM2 and pinned firmware only; no physical TPM, firmware or media qualification.",
		"Quarantine probes a guest namespace peer, allowed QEMU-gateway host endpoint, blocked routed host endpoint and explicit DNS; management traverses pinned SSH-forwarding endpoints.",
		"Recovery keys remain memory-only and are typed as literal lowercase hexadecimal, never decoded to raw random bytes.",
		"Approval negatives exercise real escrow reveal and real destructive mTLS start authorization after root preflight; destructive positive starts require two distinct local WebAuthn humans.",
		"Independent off-target recovery enrollment is an external operator workflow, not production automatic recovery credential handoff.",
		"TPM-present runs prove unattended cold boot and a deliberately mismatched emulated PCR7 policy with owner recovery; TPM-absent runs, and releases whose systemd-cryptenroll predates descriptor unlock, require an explicit server bind denial instead.",
	}}
	if desktop != nil {
		result.DesktopProfile = desktop.name
		result.Boundaries = append(result.Boundaries, "Installer "+desktop.name+" session lock is verified through logind LockedHint and the desktop's own locker oracle ("+desktop.locker+"), not a physical display observation or boot lock.")
	} else {
		result.Boundaries = append(result.Boundaries, "Headless server golden without a desktop session or display; no session lock is qualified.")
	}
	if options.EncryptionPhase == "tpm-repair" {
		result.Boundaries = append(result.Boundaries, "TPM reference repair: the legacy agent binary is compiled from `git archive` of build-repository revision "+options.LegacyAgentRevision+" and packaged as "+actionLegacyAgentVersion+" in the current lab packaging layout and signer (only the agent binary is legacy); it binds with the owner credential, is upgraded in place to the current "+actionCurrentAgentVersion+" package through the guest's native manager, and the identical signed PCR 7 bind is then dispatched without any credential. Emulated swtpm only; no field-upgraded device or production package history is qualified.")
	}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		result.Passed = err == nil
		if err != nil {
			var hostErr error
			result.HostFailure, hostErr = captureHostResources()
			if hostErr != nil {
				result.HostObservationError = hostErr.Error()
			}
			result.Failure = err.Error()
		}
	}()
	result.HostStart, err = captureHostResources()
	if err != nil {
		return result, err
	}
	result.Scenario, result.WipePhase = options.Scenario, options.WipePhase
	ctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	result.LabSHA256, err = dispatchFileDigest(options.LabBinary)
	if err != nil {
		return result, err
	}
	result.LindmdSHA256, err = dispatchFileDigest(options.LindmdBinary)
	if err != nil {
		return result, err
	}
	if tpmPhase && options.BootstrapFirmwareVars != "" {
		options.ownerSecureBoot, err = prepareActionOwnerSecureBoot(manifest, &options)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, options.ownerSecureBoot.signer.Close()) }()
		result.Boundaries = append(result.Boundaries, "Owner Secure Boot: the official installer's unsigned boot chain was installed under the package-pinned noSB bootstrap template; a lab-private owner signer signed systemd-boot and a UKI built on each clone from its installed kernel and initramfs, only that certificate was added to the clone's private firmware db, and every TPM2 bind and unattended boot ran with Secure Boot enforced under that owner trust. This is not vendor shim trust or physical firmware.")
	}
	packages, err := buildActionPackages(ctx, manifest, VMBuildRepository(options.Repository, options.BuildRepository), options.LegacyAgentRevision, options.Encrypted.WorkDir)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	result.PackageSHA256, result.SignerFingerprint = packages.artifact.SHA256, packages.fingerprint
	if packages.upgrade.Path != "" {
		// PackageSHA256 stays the current agent under test; the legacy package
		// is recorded beside its resolved source commit.
		result.PackageSHA256, result.LegacyPackageSHA256, result.LegacyAgentRevision = packages.upgrade.SHA256, packages.artifact.SHA256, packages.legacyRevision
	}
	// Resolve a potentially cold installer before creating bounded online
	// delegation and local sessions. NewEncryptedVM reuses this verified cache.
	if !strings.HasPrefix(options.WipePhase, "recovery-") {
		if _, err := encryptedGolden(ctx, manifest, options.Encrypted); err != nil {
			return result, err
		}
	}
	fixture, err := devlab.OpenDeviceActionAuthorityFixture(ctx, options.Repository, options.LindmdBinary)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	// Runs before Close removes the log: a rejected device sync is only a
	// reason code on the guest ("invalid_argument: constraint").
	defer func() {
		if err != nil && options.Encrypted.DiagnosticsDir != "" {
			err = errors.Join(err, saveFixtureServerLog(fixture, options.Encrypted.DiagnosticsDir))
		}
	}()
	result.Database = fixture.DatabaseName
	delegation, err := fixture.ConfigureDeviceActions(ctx)
	if err != nil {
		return result, fmt.Errorf("configure isolated device-action authority: %w", err)
	}
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return result, fmt.Errorf("open isolated device-action control plane: %w", err)
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	approver, err := fixture.OpenApproverSession(ctx)
	if err != nil {
		return result, fmt.Errorf("open isolated device-action approver: %w", err)
	}
	defer func() {
		if approver != nil {
			err = errors.Join(err, approver.Close(context.WithoutCancel(ctx)))
		}
	}()
	if err := control.applyExecutionAuthority(ctx, delegation, 1, 1, 0); err != nil {
		return result, fmt.Errorf("admit isolated device-action authority: %w", err)
	}
	switch options.EncryptionPhase {
	case "tpm":
		result.EncryptionPhase = options.EncryptionPhase
		return result, nativeTPMScenario(ctx, manifest, options, packages, fixture, control, delegation, result)
	case "tpm-repair":
		result.EncryptionPhase = options.EncryptionPhase
		return result, nativeTPMReferenceRepair(ctx, manifest, options, packages, fixture, control, delegation, result)
	}
	if options.Scenario == "wipe" && options.WipePhase != "" && options.WipePhase != "lock-quarantine" && options.WipePhase != "live-actions" {
		result.WipePhase = options.WipePhase
		return result, nativeWipeEffectPhases(ctx, manifest, options, packages, fixture, control, approver, delegation, result)
	}
	machine, err := openActionMachine(ctx, manifest, options, packages, fixture, control, delegation)
	if err != nil {
		return result, fmt.Errorf("prepare native device-action machine: %w", err)
	}
	defer func() { err = errors.Join(err, machine.Close()) }()
	if err := machine.record(ctx, result); err != nil {
		return result, err
	}
	if options.Scenario == "compliance" {
		return result, nativeComplianceScenario(ctx, machine, control, result)
	}
	if options.Scenario == "wipe" {
		return result, nativeWipeScenarios(ctx, manifest, options, packages, fixture, control, approver, delegation, machine, result)
	}
	ownerCredential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(ownerCredential)
	encryption, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: machine.deviceID}))
	if err != nil {
		return result, err
	}
	rotate := &agentv1.EscrowRotateAction{Target: machine.target.Identity, EscrowKeyId: encryption.Msg.GetEscrowKeyId(), EscrowPublicKey: encryption.Msg.GetEscrowPublicKey()}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}})
	result.Escrow, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, ownerCredential, false)
	if err != nil {
		return result, err
	}
	oldKey, err := revealNativeRecovery(ctx, control.session, approver, machine.deviceID, result.Escrow.ActionID)
	if err != nil {
		return result, err
	}
	defer clear(oldKey)
	if err := fixture.VerifyRecoveryCustody(ctx, result.Escrow.ActionID, oldKey); err != nil {
		return result, err
	}
	result.CustodyKEKVerified, result.RevealAuditVerified = true, true
	result.EncryptionInventory, err = captureActionEncryption(ctx, machine, control)
	if err != nil {
		return result, err
	}
	if err := machine.PowerOff(ctx); err != nil {
		return result, err
	}
	if err := compareActionEncryption(ctx, machine.vm, result.EncryptionInventory); err != nil {
		return result, err
	}
	result.RecoveryBoot, err = actionRecoveryBoot(ctx, machine.vm, oldKey, machine.boot.BootID, "server-revealed-first-recovery-key")
	if err != nil {
		return result, err
	}
	machine.boot = result.RecoveryBoot.Boot
	if err := machine.Reconnect(ctx); err != nil {
		return result, err
	}
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return result, err
	}
	if result.Escrow.NewKeyslot == nil {
		return result, errors.New("initial escrow result omitted managed keyslot")
	}
	rotate.RetireKeyslot = result.Escrow.NewKeyslot
	request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}})
	result.CommittedRotation, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, ownerCredential, false)
	if err != nil {
		return result, err
	}
	replacement, err := revealNativeRecovery(ctx, control.session, approver, machine.deviceID, result.CommittedRotation.ActionID)
	if err != nil {
		return result, err
	}
	if err := machine.PowerOff(ctx); err != nil {
		return result, err
	}
	committedHeaders, err := machine.vm.Headers(ctx)
	if err != nil {
		return result, err
	}
	committedSlots, err := actionHeaderSlots(committedHeaders, machine.target.Identity.GetLuksUuid())
	if err != nil {
		return result, err
	}
	if result.CommittedRotation.NewKeyslot == nil || !slices.Contains(committedSlots, 0) || !slices.Contains(committedSlots, *result.CommittedRotation.NewKeyslot) || slices.Contains(committedSlots, *result.Escrow.NewKeyslot) {
		return result, errors.New("durable receipt did not retire only the old managed recovery slot")
	}
	result.RetiredSlotAbsent = true
	result.RetiredRecoveryBoot, err = rejectActionRecoveryBoot(ctx, machine.vm, oldKey, "retired-server-revealed-recovery-key")
	if err != nil {
		clear(replacement)
		return result, err
	}
	clear(oldKey)
	oldKey = replacement
	defer clear(oldKey)
	result.CommittedRecoveryBoot, err = actionRecoveryBoot(ctx, machine.vm, oldKey, machine.boot.BootID, "server-revealed-replacement-after-retirement")
	if err != nil {
		return result, err
	}
	machine.boot = result.CommittedRecoveryBoot.Boot
	if err := machine.Reconnect(ctx); err != nil {
		return result, err
	}
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return result, err
	}
	if options.Scenario != "encryption" {
		if err := nativeLockScenarios(ctx, machine, control, result); err != nil {
			return result, err
		}
		if err := nativeQuarantineScenarios(ctx, machine, control, result); err != nil {
			return result, err
		}
	}
	result.Denials, err = nativeApprovalNegatives(ctx, fixture, control.session, &approver, machine.deviceID, result.CommittedRotation.ActionID)
	if err != nil {
		return result, err
	}
	revealDenials, err := nativeRevealRequirements(ctx, fixture, control.session, &approver, machine.deviceID, result.CommittedRotation.ActionID)
	if err != nil {
		return result, err
	}
	result.Denials = append(result.Denials, revealDenials...)
	offline, err := nativeOfflineDenial(ctx, machine.vm, control.session, machine.deviceID, machine.generation)
	if err != nil {
		return result, err
	}
	result.Denials = append(result.Denials, offline)
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return result, err
	}
	rotate.RetireKeyslot = result.CommittedRotation.NewKeyslot
	request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}})
	result.InterruptedRotation, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, ownerCredential, true)
	if err != nil {
		return result, err
	}
	newKey, err := revealNativeRecovery(ctx, control.session, approver, machine.deviceID, result.InterruptedRotation.ActionID)
	if err != nil {
		return result, err
	}
	defer clear(newKey)
	if err := machine.connection.Close(); err != nil {
		return result, err
	}
	machine.connection = nil
	if err := machine.vm.Kill(); err != nil {
		return result, err
	}
	headers, err := machine.vm.Headers(ctx)
	if err != nil {
		return result, err
	}
	result.RetainedSlots, err = actionHeaderSlots(headers, machine.target.Identity.GetLuksUuid())
	if err != nil {
		return result, err
	}
	if result.InterruptedRotation.NewKeyslot == nil || !slices.Contains(result.RetainedSlots, 0) || !slices.Contains(result.RetainedSlots, *result.CommittedRotation.NewKeyslot) || !slices.Contains(result.RetainedSlots, *result.InterruptedRotation.NewKeyslot) {
		return result, errors.New("crash did not retain independent owner, old and new recovery slots")
	}
	for index, key := range [][]byte{oldKey, newKey} {
		boot, err := actionRecoveryBoot(ctx, machine.vm, key, machine.boot.BootID, []string{"old-recovery-after-crash", "new-recovery-after-crash"}[index])
		if err != nil {
			return result, err
		}
		result.CrashRecoveryBoots = append(result.CrashRecoveryBoots, boot)
		machine.boot = boot.Boot
		if err := machine.Reconnect(ctx); err != nil {
			return result, err
		}
		path, err := prepareActionStatusFile(ctx, machine.vm.guest, result.InterruptedRotation.ActionID)
		if err != nil {
			return result, err
		}
		status, err := nativeActionStatus(ctx, machine.vm.guest, path)
		if err != nil {
			return result, err
		}
		if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			return result, errors.New("interrupted rotation was not retained outcome_unknown")
		}
		result.CrashRootState = status.GetState().String()
		result.CrashServerState, err = waitCrashServerState(ctx, control, result.InterruptedRotation.ActionID)
		if err != nil {
			return result, err
		}
		if _, err := machine.vm.Run(ctx, "sudo -n rm -- "+nativeQuote(path), nil); err != nil {
			return result, err
		}
		if err := machine.PowerOff(ctx); err != nil {
			return result, err
		}
	}
	if options.Scenario == "encryption" {
		if err := machine.Close(); err != nil {
			return result, err
		}
		return result, nativeTPMScenario(ctx, manifest, options, packages, fixture, control, delegation, result)
	}
	result.Recovery, err = nativeRecoveryDestruction(ctx, machine.vm, options.RecoveryManifest, packages, options.LabBinary, fixture, control, &approver, delegation, machine.target.Identity.GetLuksUuid())
	if err != nil {
		return result, err
	}
	if err := machine.Close(); err != nil {
		return result, err
	}
	if err := nativeTPMScenario(ctx, manifest, options, packages, fixture, control, delegation, result); err != nil {
		return result, err
	}
	result.LiveErase, err = nativeLiveEraseScenario(ctx, manifest, options, packages, fixture, control, approver, delegation, false)
	if err != nil {
		return result, err
	}
	result.LiveEraseReportLoss, err = nativeLiveEraseScenario(ctx, manifest, options, packages, fixture, control, approver, delegation, true)
	if err != nil {
		return result, err
	}
	for _, bus := range []string{"nvme", "sata"} {
		recovery, recoveryErr := nativeOriginalRecoveryScenario(ctx, options, packages, fixture, control, approver, delegation, bus)
		result.OriginalRecovery = append(result.OriginalRecovery, recovery)
		if recoveryErr != nil {
			return result, recoveryErr
		}
	}
	return result, nil
}

// deviceActionCapabilities are the registry capabilities one device-action
// run exercises.
func deviceActionCapabilities(scenario, wipePhase string) []platform.Capability {
	switch {
	case scenario == "all":
		return []platform.Capability{platform.Encryption, platform.Wipe, platform.ReportLoss, platform.Lock, platform.RecoverySanitize}
	case scenario != "wipe": // encryption and its compliance
		return []platform.Capability{platform.Encryption}
	}
	switch wipePhase {
	case "live-actions":
		return []platform.Capability{platform.Wipe, platform.ReportLoss, platform.Lock}
	case "lock-quarantine":
		return []platform.Capability{platform.Lock}
	case "live-erase":
		return []platform.Capability{platform.Wipe}
	case "live-report-loss":
		return []platform.Capability{platform.ReportLoss}
	case "recovery-nvme", "recovery-sata":
		return []platform.Capability{platform.RecoverySanitize}
	default:
		return []platform.Capability{platform.Wipe, platform.ReportLoss, platform.Lock, platform.RecoverySanitize}
	}
}

// actionLaneDesktop resolves the golden's lab desktop. A headless server
// golden has none and is admitted only when no selected scenario locks a
// desktop session.
func actionLaneDesktop(options VMDeviceActionsOptions, release *platform.Release) (*labDesktop, error) {
	if options.Encrypted.Desktop != "" {
		return labDesktopFor(options.Encrypted.Desktop, release)
	}
	if slices.Contains(deviceActionCapabilities(options.Scenario, options.WipePhase), platform.Lock) {
		return nil, errors.New("device action lock scenarios require an installer desktop golden")
	}
	return nil, nil
}

func nativeQuarantineScenarios(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) (err error) {
	if err := setupActionNetworkOracle(ctx, machine.vm); err != nil {
		return err
	}
	hostOracle, err := newActionHostNetworkOracle()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, hostOracle.Close()) }()
	if err := hostOracle.Probe(ctx, machine.vm, false); err != nil {
		return err
	}
	for phase := range 2 {
		request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"127.0.0.1", "10.0.2.2"}}}})
		quarantine, _, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
		if err != nil {
			return err
		}
		result.Quarantine = append(result.Quarantine, quarantine)
		if err := probeActionNetwork(ctx, machine.vm, false); err != nil {
			return err
		}
		result.QuarantineEffective = true
		if _, err := machine.vm.Run(ctx, "answer=$(dig @10.0.2.3 example.com A +short +time=3 +tries=1) && test -n \"$answer\"", nil); err != nil {
			// The failure alone was exit 9 (no reply) with no output
			// (pop2404-lock-quarantine-10): record the full query and the
			// active ruleset so the drop point is visible.
			state, stateErr := machine.vm.Run(ctx, "dig @10.0.2.3 example.com A +time=3 +tries=1 2>&1 || true; sudo -n nft list ruleset 2>&1 || true", nil)
			return fmt.Errorf("quarantine explicit DNS egress oracle: %w (native state: %q)", errors.Join(err, stateErr), state)
		}
		result.QuarantineDNSPreserved = true
		if err := hostOracle.Probe(ctx, machine.vm, true); err != nil {
			return err
		}
		result.QuarantineHostEndpoints = true
		if phase == 0 {
			request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{QuarantineActionId: quarantine.ActionID}}})
			release, _, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
			if err != nil {
				return err
			}
			result.Quarantine = append(result.Quarantine, release)
			if err := probeActionNetwork(ctx, machine.vm, true); err != nil {
				return err
			}
			if err := hostOracle.Probe(ctx, machine.vm, false); err != nil {
				return err
			}
			result.ReleaseEffective = true
		} else {
			if err := lifecycleCommand(ctx, machine.vm.guest, "stop executor independently of kernel quarantine timer", "systemctl stop lindm-agent.service lindm-executor.service"); err != nil {
				return err
			}
			if err := waitActionNetworkExpiry(ctx, machine.vm, quarantine.StartedAt.Add(90*time.Second)); err != nil {
				return err
			}
			if err := hostOracle.Probe(ctx, machine.vm, false); err != nil {
				return err
			}
			result.ExpiryWithoutExecutor = true
			if err := lifecycleCommand(ctx, machine.vm.guest, "resume executor after native expiry", "systemctl start lindm-executor.service lindm-agent.service"); err != nil {
				return err
			}
			// Native expiry has already been observed with the executor absent.
			// Clear the server's longer conservative fence through signed release.
			request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{QuarantineActionId: quarantine.ActionID}}})
			release, _, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
			if err != nil {
				return err
			}
			result.Quarantine = append(result.Quarantine, release)
		}
	}
	return nil
}

func nativeTPMScenario(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest, result *VMDeviceActionsResult) (err error) {
	machine, err := openActionMachine(ctx, manifest, options, packages, fixture, control, delegation)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, machine.Close()) }()
	if machine.ownerBoot != nil {
		result.OwnerSecureBoot = append(result.OwnerSecureBoot, machine.ownerBoot)
	}
	if options.EncryptionPhase == "tpm" {
		if err := machine.record(ctx, result); err != nil {
			return err
		}
	}
	request := tpmBindRequest(machine)
	if refused, err := tpmBindRefused(ctx, machine, control, request, options.Encrypted.Hardware.TPM, result); refused || err != nil {
		return err
	}
	credential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(credential)
	result.TPMBind, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, credential, false)
	if err != nil {
		return err
	}
	result.TPMInventory, err = captureActionEncryption(ctx, machine, control)
	if err != nil {
		return err
	}
	result.TPMTokenReferences = boundTPMTokenReferences(result.TPMInventory.Tokens)
	if want := machine.release.TPM2TokenReferences(); result.TPMTokenReferences != want {
		return fmt.Errorf("TPM2 bind wrote %d systemd-tpm2 token references to its keyslot, want %d for %s", result.TPMTokenReferences, want, machine.release.Name)
	}
	if err := machine.PowerOff(ctx); err != nil {
		return err
	}
	if err := compareActionEncryption(ctx, machine.vm, result.TPMInventory); err != nil {
		return err
	}
	if !options.Encrypted.TPMBoot {
		return tpmBootUnsupported(ctx, manifest, machine, result)
	}
	// The PCR7-mismatch phase enrolls a second clone through the isolated
	// control plane, so it runs while the admin session is fresh: 30 GNOME
	// cold boots outlasted the session (enrollment grant "unauthenticated").
	// The boot series then needs only this powered-off guest.
	if err := nativeTPMMismatch(ctx, manifest, options, packages, fixture, control, delegation, result); err != nil {
		return err
	}
	return unattendedTPMBoots(ctx, machine, max(options.TPMBoots, 1), options.Encrypted.DiagnosticsDir, result)
}

// enableCryptsetupConsole rebuilds the running kernel's registry-named initrd
// with the console drop-in. Debian's dracut reports its progress on stderr
// (Fedora's is silent), so success is the exit status, not empty stderr.
func enableCryptsetupConsole(ctx context.Context, vm *guestVM, initrd string) error {
	result, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(cryptsetupConsoleScript(initrd)), nil, 64<<10, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("enable cryptsetup rejection oracle: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("enable cryptsetup rejection oracle: exit %d: %s", result.ExitCode, bytes.TrimSpace(result.Stderr))
	}
	return nil
}

func cryptsetupConsoleScript(initrd string) string {
	return `mkdir -p /etc/systemd/system/systemd-cryptsetup@.service.d
printf '[Service]\nStandardOutput=journal+console\nStandardError=journal+console\nEnvironment=SYSTEMD_LOG_TARGET=console\n' > /etc/systemd/system/systemd-cryptsetup@.service.d/lab-console.conf
kernel=$(uname -r)
dracut --quiet --force --include /etc/systemd/system/systemd-cryptsetup@.service.d /etc/systemd/system/systemd-cryptsetup@.service.d "$(printf ` + nativeQuote(initrd) + ` "$kernel")" "$kernel"`
}

// recoveryReleaseMatches requires the off-target recovery root to run the
// target's native package base: the recovery operator installs the same
// native agent package. A derivative (Linux Mint) recovers from its base
// release's cloud image, never from an unrelated release.
func recoveryReleaseMatches(target, recovery *platform.Release) error {
	if !target.Known() || !recovery.Known() || target.Native().Key != recovery.Native().Key {
		return fmt.Errorf("recovery image %s does not run the native package base of %s", recovery.Name, target.Name)
	}
	return nil
}

// ownedBootFixtureAvailable refuses the owned systemd-boot UKI recovery fixture
// where the release cannot build its ordinary UKI on the guest architecture;
// measured GRUB lanes run.
func ownedBootFixtureAvailable(release *platform.Release, architecture, scenario, wipePhase, bootMode string) error {
	recovery := scenario == "all" || (scenario == "wipe" && (wipePhase == "" || wipePhase == "recovery-nvme" || wipePhase == "recovery-sata"))
	reason := release.Lab.OwnedBootUnavailableFor(architecture)
	if !recovery || bootMode == recoveryBootMeasured || reason == "" {
		return nil
	}
	return fmt.Errorf("platform: owned-boot recovery fixture unavailable on %s %s: %s; use -recovery-boot-mode %s", release.Name, architecture, reason, recoveryBootMeasured)
}
