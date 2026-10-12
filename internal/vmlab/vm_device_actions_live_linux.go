//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
)

// provisionActionDataVolume formats only the run-owned extra disk discovered by
// its emulated serial/WWN. The passphrase travels through a no-swap root unit's
// stdin; neither a host disk nor a host TPM is ever selected by this fixture.
func provisionActionDataVolume(ctx context.Context, machine *actionMachine) (*actionNativeTarget, error) {
	targets, err := observeActionTargets(ctx, machine.vm)
	if err != nil {
		return nil, err
	}
	var selected *actionNativeTarget
	for i := range targets {
		candidate := &targets[i]
		if candidate.Identity.GetSerial() != "lindm-lab-1" || candidate.Identity.GetLuksUuid() != "" || candidate.Type != "disk" {
			continue
		}
		if selected != nil {
			return nil, errors.New("ambiguous owned live-erase data disk")
		}
		selected = candidate
	}
	if selected == nil {
		return nil, errors.New("live-erase fixture requires an owned unencrypted extra disk")
	}
	probe := `test "$(ulimit -c)" = 0; IFS=: read -r hierarchy controllers group < /proc/self/cgroup; test "$hierarchy" = 0; test "$(cat "/sys/fs/cgroup$group/memory.swap.max")" = 0; exit 23`
	scoped, err := machine.vm.guest.runResult(ctx, actionSecretScopeCommand("/bin/sh -eu -c "+nativeQuote(probe)), nil, 4096, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if scoped.ExitCode != 23 {
		return nil, fmt.Errorf("native credential scope did not prove no-swap/no-core and exact exit propagation: exit %d: %s", scoped.ExitCode, scoped.Stderr)
	}
	credential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(credential)
	command := actionSecretScopeCommand("/usr/sbin/cryptsetup luksFormat --type luks2 --batch-mode --key-file=- " + nativeQuote(selected.Path))
	if _, err := machine.vm.Run(ctx, command, bytes.NewReader(credential)); err != nil {
		return nil, err
	}
	// luksFormat writes media directly; lsblk reads udev's filesystem metadata.
	// Publish the changed signature and wait for that observation to complete.
	if err := lifecycleCommand(ctx, machine.vm.guest, "refresh formatted data disk identity", "udevadm trigger --action=change "+nativeQuote(selected.Path)+" && udevadm settle --timeout=30"); err != nil {
		return nil, err
	}
	targets, err = observeActionTargets(ctx, machine.vm)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		candidate := &targets[i]
		if candidate.Path == selected.Path && candidate.Identity.GetSerial() == selected.Identity.GetSerial() && candidate.Identity.GetWwn() == selected.Identity.GetWwn() && candidate.Identity.GetSizeBytes() == selected.Identity.GetSizeBytes() && candidate.Identity.GetLuksUuid() != "" {
			return candidate, nil
		}
	}
	return nil, errors.New("native data LUKS identity was not established on the owned extra disk")
}

type actionRejectedBootEvidence struct {
	CredentialKind   string    `json:"credential_kind"`
	ObservedAt       time.Time `json:"observed_at"`
	DeadlineExceeded bool      `json:"deadline_exceeded"`
}

type actionLiveEraseEvidence struct {
	ReportBlocked             bool                               `json:"report_blocked"`
	DeviceID                  string                             `json:"original_device_id"`
	Firmware                  *EncryptedFirmwareEvidence         `json:"firmware"`
	Runtime                   *vmRuntimeEvidence                 `json:"runtime"`
	RecipeVersion             string                             `json:"installer_recipe_version"`
	Targets                   []actionNativeTarget               `json:"frozen_targets"`
	Escrows                   []*actionDispatchEvidence          `json:"escrows"`
	ProvisionInventoryRefresh *actionDispatchEvidence            `json:"provision_inventory_refresh,omitempty"`
	RecoveryBoot              *actionBootEvidence                `json:"pre_erase_recovery_boot"`
	DataRecoveryVerified      bool                               `json:"data_recovery_verified_before_erase"`
	ActionID                  string                             `json:"action_id"`
	ApprovalID                string                             `json:"approval_id"`
	RequesterID               string                             `json:"requester_id"`
	ApproverID                string                             `json:"approver_id"`
	ServerState               string                             `json:"server_state"`
	AttestedBeforePoweroff    bool                               `json:"attested_before_poweroff"`
	Results                   []*agentv1.CryptoEraseTargetResult `json:"attested_target_results"`
	RootDiagnostic            *liveRootDiagnostic                `json:"live_root_diagnostic,omitempty"`
	PoweroffTimer             *actionPoweroffTimerEvidence       `json:"independent_poweroff_timer"`
	ForcedPoweroffObservedAt  time.Time                          `json:"forced_poweroff_observed_at"`
	AllHeadersAbsent          bool                               `json:"all_headers_absent"`
	RejectedBoots             []actionRejectedBootEvidence       `json:"post_erase_boots"`
	DestructiveDenials        []actionDenialEvidence             `json:"destructive_approval_denials"`
	Boundary                  string                             `json:"boundary"`
}

func nativeLiveEraseScenario(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver *devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, reportBlocked bool) (_ *actionLiveEraseEvidence, err error) {
	evidence := &actionLiveEraseEvidence{ReportBlocked: reportBlocked, Boundary: "Original installed live root plus separately escrowed data volume; current disposable virtual disks only. Golden sources, host backing storage, escrow history and backups are not erased or claimed unrecoverable."}
	hardware := *options.Encrypted.Hardware
	hardware.ExtraDisks = 1
	options.Encrypted.Hardware = &hardware
	machine, err := openActionMachine(ctx, manifest, options, packages, fixture, control, delegation)
	if err != nil {
		return evidence, err
	}
	defer func() { err = errors.Join(err, machine.Close()) }()
	defer func() { err = diagnoseActionFailure(ctx, machine.vm.guest, err) }()
	evidence.DeviceID = machine.deviceID
	evidence.Firmware, evidence.RecipeVersion = machine.vm.firmware, encryptedRecipeVersion
	evidence.Runtime, err = machine.vm.guest.runtimeEvidence(ctx)
	if err != nil {
		return evidence, err
	}
	evidence.Runtime.SeedDisk = false
	dataTarget, err := provisionActionDataVolume(ctx, machine)
	if err != nil {
		return evidence, err
	}
	evidence.Targets = []actionNativeTarget{machine.target, *dataTarget}
	provider := &agentv1.DeviceActionProviderConfig{AllowLiveRootCryptoErase: true, ProtectedStateDirectory: "/var/lib/lindm/executor"}
	targets := make([]*agentv1.StorageTarget, 0, len(evidence.Targets))
	for _, target := range evidence.Targets {
		targets = append(targets, target.Identity)
		provider.Targets = append(provider.Targets, &agentv1.QualifiedActionTarget{Target: target.Identity, OwnerRecoveryKeyslot: 0, AllowRecoveryRotation: true, AllowCryptoErase: true, QualificationId: "disposable-original-live-root-and-data-luks2"})
	}
	if err := configureActionGuest(ctx, machine.vm.guest, provider, nil); err != nil {
		return evidence, err
	}
	if _, err := waitGuestExecutorReady(ctx, machine.vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return evidence, err
	}
	if err := lifecycleCommand(ctx, machine.vm.guest, "verify reconfigured live aggregate relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
		return evidence, err
	}
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return evidence, err
	}
	// The just-formatted data volume has a new LUKS identity. Publish that
	// protected native observation before requesting either escrow action.
	refresh := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
	evidence.ProvisionInventoryRefresh, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, refresh, nil, false)
	if err != nil {
		return evidence, fmt.Errorf("publish formatted live-root target inventory: %w", err)
	}
	custody, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: machine.deviceID}))
	if err != nil {
		return evidence, err
	}
	owner := []byte(machine.vm.InitialUnlockSecret())
	defer clear(owner)
	var keys [][]byte
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, target := range targets {
		rotate := &agentv1.EscrowRotateAction{Target: target, EscrowKeyId: custody.Msg.GetEscrowKeyId(), EscrowPublicKey: custody.Msg.GetEscrowPublicKey()}
		request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}})
		action, _, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, request, owner, false)
		if err != nil {
			return evidence, err
		}
		evidence.Escrows = append(evidence.Escrows, action)
		key, err := revealNativeRecovery(ctx, control.session, approver, machine.deviceID, action.ActionID)
		if err != nil {
			return evidence, err
		}
		keys = append(keys, key)
	}
	testDataKey := actionSecretScopeCommand("/usr/sbin/cryptsetup open --type luks2 --test-passphrase --key-file=- " + nativeQuote(dataTarget.Path))
	if _, err := machine.vm.Run(ctx, testDataKey, bytes.NewReader(keys[1])); err != nil {
		return evidence, err
	}
	evidence.DataRecoveryVerified = true
	if err := machine.PowerOff(ctx); err != nil {
		return evidence, err
	}
	headers, err := machine.vm.HeadersAll(ctx)
	if err != nil {
		return evidence, err
	}
	if len(headers) != len(targets) {
		return evidence, errors.New("live aggregate has an unaccounted encrypted volume or missing header")
	}
	for _, target := range targets {
		if _, err := actionHeaderSlots(headers, target.GetLuksUuid()); err != nil {
			return evidence, err
		}
	}
	evidence.RecoveryBoot, err = actionRecoveryBoot(ctx, machine.vm, keys[0], machine.boot.BootID, "original-root-escrow-before-live-erase")
	if err != nil {
		return evidence, err
	}
	if err := machine.Reconnect(ctx); err != nil {
		return evidence, err
	}
	if err := waitNativeActionPresence(ctx, control.session, machine.deviceID); err != nil {
		return evidence, err
	}
	finishDiagnostics, err := observeActionGuest(ctx, machine.vm.guest)
	if err != nil {
		return evidence, err
	}
	defer func() {
		if finishDiagnostics != nil {
			err = finishDiagnostics(err)
		}
	}()
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: targets}}})
	if !reportBlocked {
		// The same complete target set remains locally qualified in either
		// order, but its signed protobuf digest must not cross approval.
		changed := proto.CloneOf(request.GetSpec())
		changed.GetCryptoErase().Targets[0], changed.GetCryptoErase().Targets[1] = changed.GetCryptoErase().Targets[1], changed.GetCryptoErase().Targets[0]
		evidence.DestructiveDenials, err = nativeDestructiveSpecNegatives(ctx, machine.vm.guest, fixture, control.session, &approver, machine.deviceID, machine.generation, request.GetSpec(), changed, []string{"destructive_self_approval", "destructive_spec_digest_changed", "destructive_expired_approval"})
		if err != nil {
			return evidence, err
		}
		request = actionRequestFor(machine.deviceID, machine.generation, request.GetSpec())
	}
	if err := approveNativeAction(ctx, control.session, approver, request); err != nil {
		return evidence, err
	}
	evidence.ApprovalID, evidence.RequesterID, evidence.ApproverID = request.ApprovalId, control.session.AccountID, approver.AccountID
	if reportBlocked {
		if err := lifecycleCommand(ctx, machine.vm.guest, "reserve live erase for report-loss relay", "systemctl stop lindm-agent.service"); err != nil {
			return evidence, err
		}
	}
	created, err := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	if err != nil {
		return evidence, err
	}
	evidence.ActionID = created.Msg.GetAction().GetActionId()
	defer func() { err = diagnoseNativeAction(ctx, machine.vm.guest, evidence.ActionID, err) }()
	started := time.Now()
	if reportBlocked {
		input, err := protojson.Marshal(&agentv1.GetDeviceActionRequest{ActionId: evidence.ActionID})
		if err != nil {
			return evidence, err
		}
		output, err := runActionProbe(ctx, machine.vm.guest, "live-erase-no-report", input, 128<<10, 45*time.Second)
		if err != nil {
			return evidence, err
		}
		admitted := new(agentv1.StartDeviceActionResponse)
		if err := protojson.Unmarshal(output, admitted); err != nil {
			return evidence, err
		}
		if admitted.GetStatus().GetStartedAt() == nil {
			return evidence, errors.New("live report-loss probe did not consume start authority")
		}
		evidence.PoweroffTimer, err = observeLivePoweroffTimer(ctx, machine.vm)
		if err != nil {
			return evidence, err
		}
		if err := machine.vm.NetworkLink(ctx, false); err != nil {
			return evidence, err
		}
	} else {
		if err := lifecycleCommand(ctx, machine.vm.guest, "verify live aggregate erase relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
			return evidence, err
		}
		finishRootDiagnostic := monitorLiveRoot(ctx, machine.vm.guest, evidence.ActionID)
		status, err := waitLiveEraseAttestation(ctx, machine.vm, control.session, evidence.ActionID)
		evidence.RootDiagnostic = finishRootDiagnostic()
		if status != nil {
			evidence.ServerState = status.GetState().String()
			evidence.Results = status.GetVerification().GetCryptoEraseResults()
		}
		if err != nil {
			return evidence, err
		}
		if err := validateLiveEraseResults(targets, status.GetVerification().GetCryptoEraseResults()); err != nil {
			return evidence, err
		}
		evidence.Results = status.GetVerification().GetCryptoEraseResults()
		evidence.AttestedBeforePoweroff = true
		evidence.ServerState = status.GetState().String()
		evidence.PoweroffTimer, err = observeLivePoweroffTimer(ctx, machine.vm)
		if err != nil {
			return evidence, err
		}
	}
	// Observe the helper's actual activation, not the earlier durable StartedAt.
	// Two seconds are explicit SSH/QMP observer grace, not a longer guest timer.
	forcedOffDeadline := evidence.PoweroffTimer.ObservedAt.Add(122*time.Second - time.Duration(evidence.PoweroffTimer.AgeMillis)*time.Millisecond)
	if overall := started.Add(150 * time.Second); overall.Before(forcedOffDeadline) {
		forcedOffDeadline = overall
	}
	deadline, cancel := context.WithDeadline(ctx, forcedOffDeadline)
	defer cancel()
	select {
	case <-machine.vm.guest.done:
		evidence.ForcedPoweroffObservedAt = time.Now().UTC()
	case <-deadline.Done():
		return evidence, errors.New("live erase did not independently force poweroff within its observed bound")
	}
	if reportBlocked {
		state, err := control.session.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: evidence.ActionID}))
		if err != nil {
			return evidence, err
		}
		if state.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			return evidence, errors.New("lost live erase report was not preserved outcome_unknown")
		}
		evidence.ServerState = state.Msg.GetAction().GetStatus().GetState().String()
	}
	// Release the post-unlock console observer before deliberately attempting
	// the later credential-rejection boots.
	_ = finishDiagnostics(nil)
	finishDiagnostics = nil
	if err := machine.connection.Close(); err != nil {
		return evidence, err
	}
	machine.connection = nil
	if err := machine.vm.Kill(); err != nil {
		return evidence, err
	}
	headers, err = machine.vm.HeadersAll(ctx)
	if err != nil {
		return evidence, err
	}
	if len(headers) != 0 {
		return evidence, errors.New("live aggregate retained an independently discoverable LUKS header")
	}
	evidence.AllHeadersAbsent = true
	for index, key := range [][]byte{owner, keys[0]} {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Minute)
		boot, rejected := machine.vm.ColdBoot(attempt, string(key))
		cancel()
		if ctx.Err() != nil {
			return evidence, ctx.Err()
		}
		if rejected == nil || boot.Accepted || !errors.Is(rejected, context.DeadlineExceeded) {
			return evidence, fmt.Errorf("erased-root cold boot did not demonstrate bounded rejection: %w", rejected)
		}
		evidence.RejectedBoots = append(evidence.RejectedBoots, actionRejectedBootEvidence{CredentialKind: []string{"original-owner", "server-revealed-root-recovery"}[index], ObservedAt: time.Now().UTC(), DeadlineExceeded: true})
	}
	return evidence, nil
}

func waitLiveEraseAttestation(ctx context.Context, vm *EncryptedVM, owner *devlab.OwnerSession, actionID string) (*agentv1.DeviceActionStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := owner.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: actionID}))
		if err != nil {
			return nil, err
		}
		status := response.Msg.GetAction().GetStatus()
		if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			select {
			case <-vm.guest.done:
				return status, errors.New("live-root attestation was not observed while the original machine was still running")
			default:
				return status, nil
			}
		}
		if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED || status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED {
			return status, errors.New("live-root erase did not reach verified native completion")
		}
		select {
		case <-ctx.Done():
			return status, errors.New("live-root final attestation deadline")
		case <-vm.guest.done:
			return status, errors.New("original machine powered off before attestation was observed")
		case <-ticker.C:
		}
	}
}

func validateLiveEraseResults(targets []*agentv1.StorageTarget, results []*agentv1.CryptoEraseTargetResult) error {
	if len(targets) != len(results) {
		return errors.New("aggregate erase result target count mismatch")
	}
	for _, target := range targets {
		matches := 0
		for _, result := range results {
			if !proto.Equal(target, result.GetTarget()) {
				continue
			}
			matches++
			if !result.GetNativeLuksErase() || !result.GetRawZeroVerified() || !result.GetMetadataAbsent() || result.GetHeaderBytes() == 0 {
				return errors.New("aggregate erase omitted native/raw/header proof for a target")
			}
		}
		if matches != 1 {
			return errors.New("aggregate erase omitted or duplicated a frozen target")
		}
	}
	return nil
}

type actionPoweroffTimerEvidence struct {
	ActiveMonotonicMicros  uint64    `json:"active_enter_monotonic_micros"`
	AgeMillis              int64     `json:"age_at_observation_millis"`
	ObservedAt             time.Time `json:"observed_at"`
	ObservationGraceMillis int64     `json:"observation_grace_millis"`
}

func observeLivePoweroffTimer(ctx context.Context, vm *EncryptedVM) (*actionPoweroffTimerEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		output, err := vm.Run(ctx, "systemctl show --value -p ActiveEnterTimestampMonotonic lindm-live-root-poweroff.service; cat /proc/uptime", nil)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(output))
		if len(fields) != 3 {
			return nil, errors.New("independent poweroff timer did not expose an activation clock")
		}
		active, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, err
		}
		uptime, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, err
		}
		if active != 0 {
			age := time.Duration(uptime*float64(time.Second)) - time.Duration(active)*time.Microsecond
			if age < -20*time.Millisecond || age >= 120*time.Second {
				return nil, errors.New("independent poweroff timer activation is outside its fixed bound")
			}
			if age < 0 {
				age = 0
			}
			return &actionPoweroffTimerEvidence{ActiveMonotonicMicros: active, AgeMillis: age.Milliseconds(), ObservedAt: time.Now().UTC(), ObservationGraceMillis: 2000}, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
