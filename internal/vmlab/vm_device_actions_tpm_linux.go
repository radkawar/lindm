//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
)

// nativeTPMMismatch binds against a deliberately extended PCR in a fresh swtpm
// clone. The next real firmware boot resets/measures PCR7 independently, so the
// sealed token must refuse that changed policy while owner recovery still works.
// No host TPM, host firmware or golden TPM state is touched.
func nativeTPMMismatch(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest, result *VMDeviceActionsResult) (err error) {
	machine, err := openActionMachine(ctx, manifest, options, packages, fixture, control, delegation)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, machine.Close()) }()
	approver, err := fixture.OpenApproverSession(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, approver.Close(context.WithoutCancel(ctx))) }()
	encryption, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: machine.deviceID}))
	if err != nil {
		return err
	}
	rotate := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: machine.target.Identity, EscrowKeyId: encryption.Msg.GetEscrowKeyId(), EscrowPublicKey: encryption.Msg.GetEscrowPublicKey()}}})
	ownerKey := []byte(machine.vm.InitialUnlockSecret())
	defer clear(ownerKey)
	escrowResult, _, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, rotate, ownerKey, false)
	if err != nil {
		return err
	}
	recoveryKey, err := revealNativeRecovery(ctx, control.session, approver, machine.deviceID, escrowResult.ActionID)
	if err != nil {
		return err
	}
	defer clear(recoveryKey)
	before, err := machine.vm.Run(ctx, "sudo -n tpm2_pcrread sha256:7", nil)
	if err != nil {
		return err
	}
	if _, err := machine.vm.Run(ctx, "sudo -n tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000", nil); err != nil {
		return err
	}
	after, err := machine.vm.Run(ctx, "sudo -n tpm2_pcrread sha256:7", nil)
	if err != nil {
		return err
	}
	result.PCRBefore, result.PCRAfter = strings.TrimSpace(string(before)), strings.TrimSpace(string(after))
	if result.PCRBefore == "" || result.PCRAfter == "" || result.PCRBefore == result.PCRAfter {
		return errors.New("emulated PCR7 did not change before policy binding")
	}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: machine.target.Identity, Pcrs: []uint32{7}}}})
	credential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(credential)
	result.TPMPolicyBind, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, credential, false)
	if err != nil {
		return err
	}
	if err := machine.PowerOff(ctx); err != nil {
		return err
	}
	boot, rejected := machine.vm.ColdBoot(ctx, "")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if rejected == nil || boot.Accepted || !boot.PromptSeen {
		return errors.New("changed measured PCR policy did not require independent recovery")
	}
	result.TPMPolicyRejectedBoot = &boot
	recoveryText, err := actionRecoveryText(recoveryKey)
	if err != nil {
		return err
	}
	recovered, err := machine.vm.ColdBoot(ctx, recoveryText)
	if err != nil {
		return err
	}
	if !recovered.Accepted || !recovered.PromptSeen || recovered.BootID == machine.boot.BootID {
		return errors.New("server-revealed recovery credential failed cold recovery after TPM policy mismatch")
	}
	result.TPMPolicyRecoveryBoot = &recovered
	return nil
}
