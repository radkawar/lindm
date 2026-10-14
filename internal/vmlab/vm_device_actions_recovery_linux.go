// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
)

type actionRecoveryEvidence struct {
	ImageID               string                  `json:"recovery_image_id"`
	ImageSHA256           string                  `json:"recovery_image_sha256"`
	Runtime               *vmRuntimeEvidence      `json:"recovery_runtime"`
	DeviceID              string                  `json:"recovery_executor_device_id"`
	Target                actionNativeTarget      `json:"target"`
	Secondary             actionNativeTarget      `json:"secondary"`
	Sanitize              *actionDispatchEvidence `json:"sanitize"`
	SanitizeSamplesZero   bool                    `json:"sanitize_samples_zero"`
	DestructiveDenials    []actionDenialEvidence  `json:"destructive_approval_denials"`
	EraseActionID         string                  `json:"erase_action_id"`
	EraseServerState      string                  `json:"erase_server_state"`
	NoLUKSHeaders         bool                    `json:"no_luks_headers"`
	PostEraseBootRejected bool                    `json:"post_erase_boot_rejected"`
	Boundary              string                  `json:"boundary"`
}

func nativeRecoveryDestruction(ctx context.Context, target *EncryptedVM, manifest *labv1.ImageManifest, packages *actionNativePackage, labBinary string, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver **devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, luksUUID string) (_ *actionRecoveryEvidence, err error) {
	result := &actionRecoveryEvidence{ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), Boundary: "Independent verified cloud recovery root, separately enrolled executor, off-target journal and identity; operator-owned attachment, not production automated recovery handoff. QEMU rotational SCSI disk overwrite and local header destruction only; no SSD firmware, physical media, escrow deletion or backup destruction claim."}
	recovery, err := target.BootRecovery(ctx, manifest, VMHardwareOptions{StorageBus: "virtio-scsi", ExtraDisks: 1, AllowNetwork: true})
	if recovery != nil {
		defer func() { err = errors.Join(err, recovery.Close()) }()
	}
	if err != nil {
		return result, err
	}
	result.Runtime, err = recovery.guest.runtimeEvidence(ctx)
	if err != nil {
		return result, err
	}
	result.Runtime.DiskCount++
	if err := installActionPrerequisites(ctx, recovery.guest, manifest, true); err != nil {
		return result, err
	}
	if err := packages.Install(ctx, recovery.guest, labBinary); err != nil {
		return result, err
	}
	connection, err := connectActionGuest(ctx, recovery.guest, fixture)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, connection.Close()) }()
	data, err := recovery.Run(ctx, "sudo -n lsblk --json --tree --bytes --output PATH,TYPE,SIZE,WWN,SERIAL,UUID,FSTYPE", nil)
	if err != nil {
		return result, err
	}
	targets, err := actionNativeTargets(data)
	if err != nil {
		return result, err
	}
	for _, candidate := range targets {
		if candidate.Identity.GetLuksUuid() == luksUUID && candidate.Identity.GetSerial() == "lindm-recovery-target" {
			result.Target = candidate
		}
		if candidate.Identity.GetLuksUuid() == "" && candidate.Identity.GetSerial() == "lindm-lab-1" {
			result.Secondary = candidate
		}
	}
	if result.Target.Identity == nil || result.Secondary.Identity == nil {
		return result, errors.New("recovery did not observe exact encrypted and secondary targets")
	}
	provider := &agentv1.DeviceActionProviderConfig{RecoveryEnvironment: true, ProtectedStateDirectory: "/var/lib/lindm/executor", Targets: []*agentv1.QualifiedActionTarget{
		{Target: result.Target.Identity, AllowCryptoErase: true, QualificationId: "disposable-qemu-local-header-destruction"},
		{Target: result.Secondary.Identity, AllowOverwrite: true, QualificationId: "disposable-qemu-rotational-scsi-overwrite"},
	}}
	if err := configureActionGuest(ctx, recovery.guest, provider, nil); err != nil {
		return result, err
	}
	issued, _, err := enrollActionGuest(ctx, recovery.guest, control, delegation)
	if err != nil {
		return result, err
	}
	result.DeviceID = issued.GetDeviceId()
	if err := waitNativeActionPresence(ctx, control.session, result.DeviceID); err != nil {
		return result, err
	}
	// Seed all verification offsets on this independently identified, unmounted
	// disposable disk. No caller-selected host path or target disk is writable.
	size := result.Secondary.Identity.GetSizeBytes()
	if size < 3<<20 {
		return result, errors.New("secondary disk is too small for distinct samples")
	}
	for _, offset := range []uint64{0, (size / 2) / (1 << 20), size/(1<<20) - 1} {
		command := fmt.Sprintf("sudo -n dd if=/dev/urandom of=%s bs=1M count=1 seek=%d conv=notrunc,fsync status=none", nativeQuote(result.Secondary.Path), offset)
		if _, err := recovery.Run(ctx, command, nil); err != nil {
			return result, err
		}
		if err := actionSanitizeSample(ctx, recovery.guest, result.Secondary.Path, offset, false); err != nil {
			return result, err
		}
	}
	result.DestructiveDenials, err = nativeDestructiveApprovalNegatives(ctx, recovery.guest, fixture, control.session, approver, result.DeviceID, issued.GetEnrollmentGeneration(), result.Secondary.Identity, result.Target.Identity)
	if err != nil {
		return result, err
	}
	for _, offset := range []uint64{0, (size / 2) / (1 << 20), size/(1<<20) - 1} {
		if err := actionSanitizeSample(ctx, recovery.guest, result.Secondary.Path, offset, false); err != nil {
			return result, err
		}
	}
	request := actionRequestFor(result.DeviceID, issued.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: result.Secondary.Identity, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE}}})
	if err := approveNativeAction(ctx, control.session, *approver, request); err != nil {
		return result, err
	}
	result.Sanitize, _, err = dispatchNativeAction(ctx, recovery.guest, control.session, request, nil, false)
	if err != nil {
		return result, err
	}
	for _, offset := range []uint64{0, (size / 2) / (1 << 20), size/(1<<20) - 1} {
		if err := actionSanitizeSample(ctx, recovery.guest, result.Secondary.Path, offset, true); err != nil {
			return result, err
		}
	}
	result.SanitizeSamplesZero = true
	request = actionRequestFor(result.DeviceID, issued.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Target: result.Target.Identity, Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE}}})
	if err := approveNativeAction(ctx, control.session, *approver, request); err != nil {
		return result, err
	}
	created, err := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	if err != nil {
		return result, err
	}
	result.EraseActionID = created.Msg.GetAction().GetActionId()
	if err := lifecycleCommand(ctx, recovery.guest, "verify authorized recovery erase relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
		return result, err
	}
	shutdown, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	select {
	case <-recovery.guest.done:
	case <-shutdown.Done():
		return result, errors.New("recovery executor did not power off after authorized erase")
	}
	server, err := control.session.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: result.EraseActionID}))
	if err != nil {
		return result, err
	}
	state := server.Msg.GetAction().GetStatus().GetState()
	if state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN && state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		return result, errors.New("erase has neither accepted final evidence nor explicit server outcome_unknown")
	}
	result.EraseServerState = state.String()
	if err := connection.Close(); err != nil {
		return result, err
	}
	connection.forwards = nil
	if err := recovery.Close(); err != nil {
		return result, err
	}
	headers, err := target.Headers(ctx)
	if err != nil {
		return result, err
	}
	if len(headers) != 0 {
		return result, errors.New("independent appliance still discovers LUKS headers after erase")
	}
	result.NoLUKSHeaders = true
	boot, bootErr := target.ColdBoot(ctx, target.InitialUnlockSecret())
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if bootErr == nil || boot.Accepted {
		return result, errors.New("erased installed root unexpectedly cold booted")
	}
	if !errors.Is(bootErr, context.DeadlineExceeded) {
		return result, fmt.Errorf("post-erase boot did not complete a bounded unlock observation: %w", bootErr)
	}
	result.PostEraseBootRejected = true
	return result, nil
}

// nativeActionPresenceTimeout bounds waiting for fresh presence and inventory.
const nativeActionPresenceTimeout = 3 * time.Minute

func waitNativeActionPresence(ctx context.Context, owner *devlab.OwnerSession, deviceID string) error {
	return waitNativeDevicePresence(ctx, owner, deviceID, true)
}

// waitNativeDevicePresence waits for fresh presence and, with inventory, a
// recent host inventory. A RefreshInventory action is what publishes the
// inventory, so its dispatch needs presence only: a long lane's last refresh
// was 8 min old after a reboot (layers-ubuntu24-tier1-41).
func waitNativeDevicePresence(ctx context.Context, owner *devlab.OwnerSession, deviceID string, inventory bool) error {
	ctx, cancel := context.WithTimeout(ctx, nativeActionPresenceTimeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var seen, host *timestamppb.Timestamp
	stale := func() error {
		return fmt.Errorf("real server has no fresh device presence and inventory within %s (last seen %s, last host inventory %s)", nativeActionPresenceTimeout, presenceTime(seen), presenceTime(host))
	}
	for {
		response, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceID}))
		if err != nil {
			if ctx.Err() != nil {
				return errors.Join(stale(), err)
			}
			return err
		}
		now := time.Now()
		seen = response.Msg.GetDevice().GetLastSeenAt()
		host = response.Msg.GetHost().GetReceivedAt()
		fresh := !inventory || host != nil && now.Sub(host.AsTime()) < 4*time.Minute
		if seen != nil && now.Sub(seen.AsTime()) < 30*time.Second && fresh {
			return nil
		}
		select {
		case <-ctx.Done():
			return stale()
		case <-ticker.C:
		}
	}
}

func presenceTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return "never"
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

func actionSanitizeSample(ctx context.Context, vm *guestVM, path string, offset uint64, zero bool) error {
	command := "sudo -n bash -euo pipefail -c " + nativeQuote(fmt.Sprintf("dd if=%s bs=1M count=1 skip=%d iflag=fullblock status=none | cmp -n 1048576 - /dev/zero", nativeQuote(path), offset))
	sample, err := vm.runResult(ctx, command, nil, 4096, 10*time.Second)
	if err != nil {
		return err
	}
	expected := 1
	if zero {
		expected = 0
	}
	if sample.ExitCode != expected {
		return fmt.Errorf("independent sanitize sample exit=%d expected=%d", sample.ExitCode, expected)
	}
	return nil
}
