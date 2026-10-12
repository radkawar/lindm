//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/devlab"
)

// maxTPMBoots bounds the unattended cold-boot regression (-tpm-boots).
const maxTPMBoots = 100

// tpmUnattendedBoot is one recorded cold boot after the product TPM2 bind. The
// unlock log is systemd-cryptsetup's own journal: token unseal failures and
// tpm2-tss errors, never key material. The serial console stays private.
type tpmUnattendedBoot struct {
	Boot int `json:"boot"`
	UnlockOutcome
	// UnsealFailures counts "Failed to unseal secret using TPM2": each is one
	// token unseal a later token reference absorbed, unless the boot prompted.
	UnsealFailures int `json:"unseal_failures"`
	// PCRChanged counts tpm2-tss reports of 0x128 (TPM_RC_PCR_CHANGED).
	PCRChanged   int      `json:"pcr_changed"`
	UnlockLog    []string `json:"unlock_log"`
	SerialSHA256 string   `json:"serial_sha256"`
}

// unattendedTPMBoots cold-boots the bound machine boots times. Every boot must
// unlock through the TPM2 token without a prompt and with a new boot ID; a
// prompted boot is completed with the owner secret only to retain its journal.
func unattendedTPMBoots(ctx context.Context, machine *actionMachine, boots int, diagnostics string, result *VMDeviceActionsResult) error {
	seen := map[string]bool{machine.boot.BootID: true}
	for index := range boots {
		if index > 0 {
			if err := machine.PowerOff(ctx); err != nil {
				return err
			}
		}
		record, err := unattendedTPMBoot(ctx, machine.vm, index+1, diagnostics)
		if record != nil {
			result.TPMBoots = append(result.TPMBoots, record)
		}
		if err != nil {
			return fmt.Errorf("TPM unattended cold boot %d of %d: %w", index+1, boots, err)
		}
		if !record.Accepted || record.PromptSeen || seen[record.BootID] {
			return fmt.Errorf("TPM binding did not unlock unattended cold boot %d of %d", index+1, boots)
		}
		seen[record.BootID] = true
	}
	result.TPMBoot = &result.TPMBoots[0].UnlockOutcome
	return nil
}

func unattendedTPMBoot(ctx context.Context, vm *EncryptedVM, boot int, diagnostics string) (*tpmUnattendedBoot, error) {
	serial := nativeexec.NewBuffer(4 << 20)
	outcome, bootErr := vm.UnattendedColdBoot(ctx, vm.InitialUnlockSecret(), serial)
	record := &tpmUnattendedBoot{Boot: boot, UnlockOutcome: outcome}
	digest := sha256.Sum256(serial.Bytes())
	record.SerialSHA256 = hex.EncodeToString(digest[:])
	saved := writeTPMBootDiagnostic(diagnostics, fmt.Sprintf("tpm-boot-%03d-serial.log", boot), serial.Bytes())
	if bootErr != nil {
		return record, errors.Join(bootErr, saved)
	}
	journal, err := vm.Run(ctx, "sudo -n journalctl -b -o short-monotonic --no-pager SYSLOG_IDENTIFIER=systemd-cryptsetup", nil)
	if err != nil {
		return record, errors.Join(fmt.Errorf("read unlock journal: %w", err), saved)
	}
	// The initrd's entries can be listed twice (its runtime journal and the
	// flushed copy); an entry is its monotonic timestamp, PID and message.
	seen := make(map[string]bool)
	for line := range strings.Lines(string(journal)) {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		if strings.Contains(line, "Failed to unseal secret using TPM2") {
			record.UnsealFailures++
		}
		if strings.Contains(line, "ErrorCode (0x00000128)") {
			record.PCRChanged++
		}
		if len(record.UnlockLog) < 200 {
			record.UnlockLog = append(record.UnlockLog, line)
		}
	}
	return record, errors.Join(saved, writeTPMBootDiagnostic(diagnostics, fmt.Sprintf("tpm-boot-%03d-journal.txt", boot), journal))
}

// writeTPMBootDiagnostic keeps a new owner-only copy when a diagnostics parent
// was requested; the record carries only digests and the unlock log.
func writeTPMBootDiagnostic(diagnostics, name string, data []byte) (err error) {
	if diagnostics == "" {
		return nil
	}
	file, err := os.OpenFile(filepath.Join(diagnostics, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	_, err = file.Write(data)
	return err
}

// boundTPMTokenReferences is the most systemd-tpm2 tokens naming one keyslot
// in the public token inventory: the lane's single bind on a fresh golden.
func boundTPMTokenReferences(tokens []*agentv1.LUKSTokenObservation) int {
	counts := make(map[uint32]int)
	most := 0
	for _, token := range tokens {
		if token.GetType() != "systemd-tpm2" || len(token.GetKeyslots()) != 1 {
			continue
		}
		counts[token.GetKeyslots()[0]]++
		most = max(most, counts[token.GetKeyslots()[0]])
	}
	return most
}

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
		return errors.Join(err, diagnoseTPMPolicyBind(ctx, machine.vm.guest, machine.target.Identity.GetLuksUuid()))
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

// diagnoseTPMPolicyBind keeps the guest's own reason a bind against the
// extended PCR 7 did not verify: cryptsetup's token unlock messages (lines
// naming TPM, token, unseal, PCR or policy, never JSON or header bytes), the
// current PCR 7 banks, an automatic pcrlock policy and the systemd version.
func diagnoseTPMPolicyBind(ctx context.Context, vm *guestVM, luksUUID string) error {
	if !vmValidID(luksUUID) {
		return nil
	}
	script := `dev=/dev/disk/by-uuid/` + luksUUID + `
cryptsetup --debug open --type luks2 --test-passphrase --token-only --token-type systemd-tpm2 "$dev" 2>&1 | grep -iE 'tpm|token|unseal|pcr|policy|session|srk|error|fail' | grep -v '[{}]' | tail -60
echo "exit=$?"
tpm2_pcrread sha1:7+sha256:7 2>&1
ls -l /var/lib/systemd/pcrlock.json /run/systemd/pcrlock.json /etc/systemd/tpm2-pcr-public-key.pem 2>&1
systemd-cryptenroll --version 2>&1 | head -1
journalctl -b --no-pager -n 40 -t systemd-cryptenroll -t cryptsetup 2>&1`
	result, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote(script), nil, 256<<10, time.Minute)
	if err != nil {
		return fmt.Errorf("collect TPM policy-bind diagnostics: %w", err)
	}
	data, err := json.Marshal(struct {
		Source         string
		ExitCode       int
		Stdout, Stderr string
	}{"tpm-policy-bind-token-unlock", result.ExitCode, string(result.Stdout), string(result.Stderr)})
	if err != nil {
		return err
	}
	path, err := saveGuestDiagnostics(actionDiagnosticsDirectory(vm), data)
	if err != nil {
		return err
	}
	return fmt.Errorf("private TPM policy-bind diagnostics saved to %q", path)
}
