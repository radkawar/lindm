//go:build linux

package vmlab

import (
	"context"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
)

func nativeWipeScenarios(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver *devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, machine *actionMachine, result *VMDeviceActionsResult) (err error) {
	defer func() { err = diagnoseActionFailure(ctx, machine.vm.guest, err) }()
	finishDiagnostics, err := observeActionGuest(ctx, machine.vm.guest)
	if err != nil {
		return err
	}
	defer func() { err = finishDiagnostics(err) }()
	result.WipePhase = options.WipePhase
	result.DesktopBefore, err = waitActionDesktop(ctx, machine.vm, false)
	if err != nil {
		return err
	}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}})
	result.Lock, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err != nil {
		return err
	}
	result.DesktopAfter, err = waitActionDesktop(ctx, machine.vm, true)
	if err != nil {
		return err
	}
	request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: result.Lock.ActionID}}})
	result.LockRelease, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err != nil {
		return err
	}
	if err = nativeQuarantineScenarios(ctx, machine, control, result); err != nil {
		return err
	}
	if err := nativeAccountLockScenarios(ctx, machine, control, result); err != nil {
		return err
	}
	offline, err := nativeOfflineDenial(ctx, machine.vm, control.session, machine.deviceID, machine.generation)
	if err != nil {
		return err
	}
	result.Denials = append(result.Denials, offline)
	if err = machine.Close(); err != nil {
		return err
	}
	if options.WipePhase == "lock-quarantine" {
		return nil
	}
	return nativeWipeEffectPhases(ctx, manifest, options, packages, fixture, control, approver, delegation, result)
}

func nativeWipeEffectPhases(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver *devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, result *VMDeviceActionsResult) (err error) {
	if options.WipePhase == "" || options.WipePhase == "live-erase" {
		result.LiveErase, err = nativeLiveEraseScenario(ctx, manifest, options, packages, fixture, control, approver, delegation, false)
		if err != nil {
			return err
		}
	}
	if options.WipePhase == "" || options.WipePhase == "live-report-loss" {
		result.LiveEraseReportLoss, err = nativeLiveEraseScenario(ctx, manifest, options, packages, fixture, control, approver, delegation, true)
		if err != nil {
			return err
		}
	}
	for _, bus := range []string{"nvme", "sata"} {
		if options.WipePhase != "" && options.WipePhase != "recovery-"+bus {
			continue
		}
		recovery, recoveryErr := nativeOriginalRecoveryScenario(ctx, options, packages, fixture, control, approver, delegation, bus)
		result.OriginalRecovery = append(result.OriginalRecovery, recovery)
		if recoveryErr != nil {
			return recoveryErr
		}
	}
	return nil
}
