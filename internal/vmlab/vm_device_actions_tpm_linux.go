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
	"slices"
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

// tpmBoundKeyslot is the one keyslot every systemd-tpm2 token names and how
// many tokens reference it. A token naming several keyslots, tokens naming
// different keyslots, or no token at all is not a single product bind.
func tpmBoundKeyslot(tokens []*agentv1.LUKSTokenObservation) (keyslot uint32, references int, err error) {
	for _, token := range tokens {
		if token.GetType() != "systemd-tpm2" {
			continue
		}
		if len(token.GetKeyslots()) != 1 {
			return 0, 0, fmt.Errorf("systemd-tpm2 token %d names %d keyslots, want one", token.GetTokenId(), len(token.GetKeyslots()))
		}
		if references > 0 && token.GetKeyslots()[0] != keyslot {
			return 0, 0, fmt.Errorf("systemd-tpm2 tokens name keyslots %d and %d, want one sealed keyslot", keyslot, token.GetKeyslots()[0])
		}
		keyslot = token.GetKeyslots()[0]
		references++
	}
	if references == 0 {
		return 0, 0, errors.New("no systemd-tpm2 token after the TPM2 bind")
	}
	return keyslot, references, nil
}

// verifyTPMReferenceRepair requires that the repair changed no keyslot and left
// exactly want systemd-tpm2 token references, all naming the legacy bind's
// keyslot.
func verifyTPMReferenceRepair(legacy, repaired *actionEncryptionEvidence, keyslot uint32, want int) error {
	if repaired.LUKSUUID != legacy.LUKSUUID {
		return errors.New("reference repair observed a different LUKS volume")
	}
	before, after := slices.Sorted(slices.Values(legacy.Keyslots)), slices.Sorted(slices.Values(repaired.Keyslots))
	if !slices.Equal(before, after) {
		return fmt.Errorf("reference repair changed the keyslot set from %v to %v", before, after)
	}
	slot, references, err := tpmBoundKeyslot(repaired.Tokens)
	if err != nil {
		return fmt.Errorf("after reference repair: %w", err)
	}
	if slot != keyslot {
		return fmt.Errorf("after reference repair systemd-tpm2 tokens name keyslot %d, want the legacy bind's keyslot %d", slot, keyslot)
	}
	if references != want {
		return fmt.Errorf("after reference repair keyslot %d has %d systemd-tpm2 token references, want %d", keyslot, references, want)
	}
	return nil
}

// tpmServerReferences is the server's GetDeviceEncryption count of systemd-tpm2
// token references on the bound keyslot and the release's requirement.
type tpmServerReferences struct {
	References uint32 `json:"references"`
	Required   uint32 `json:"required"`
}

func captureTPMServerReferences(ctx context.Context, control *vmControlPlane, deviceID string) (*tpmServerReferences, error) {
	response, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: deviceID}))
	if err != nil {
		return nil, err
	}
	return &tpmServerReferences{References: response.Msg.GetTpm2TokenReferences(), Required: response.Msg.GetTpm2TokenReferencesRequired()}, nil
}

// tpmBindRequest is the lane's signed TPM2 bind of the encrypted root to PCR 7.
func tpmBindRequest(machine *actionMachine) *adminv1.CreateDeviceActionRequest {
	return actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: machine.target.Identity, Pcrs: []uint32{7}}}})
}

// tpmBindRefused records the real server's refusal where no bind can run: no
// emulated TPM, or a release whose systemd-cryptenroll cannot take the owner
// secret from a descriptor. It reports whether the phase ends with that denial.
func tpmBindRefused(ctx context.Context, machine *actionMachine, control *vmControlPlane, request *adminv1.CreateDeviceActionRequest, tpm bool, result *VMDeviceActionsResult) (bool, error) {
	if !tpm {
		_, rejected := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
		denial, err := actionDenial("tpm_absent", rejected, connect.CodeFailedPrecondition)
		if err != nil {
			return true, err
		}
		if denial.Reason != "device_action_tpm2_unavailable" {
			return true, errors.New("TPM-absent variant failed a different prerequisite")
		}
		result.TPMAbsentDenial = &denial
		return true, nil
	}
	if !machine.release.TPM2BindSupported() {
		// The real server must refuse before signing any intent.
		_, rejected := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
		denial, err := actionDenial("tpm_binding_unsupported", rejected, connect.CodeFailedPrecondition)
		if err != nil {
			return true, err
		}
		if denial.Reason != "device_action_tpm2_binding_unsupported" {
			return true, fmt.Errorf("TPM binding on %s failed a different prerequisite: %s", machine.release.Name, denial.Reason)
		}
		result.TPMBindingDenial = &denial
		return true, nil
	}
	return false, nil
}

// tpmBootUnsupported observes the passphrase prompt of a powered-off bound
// machine whose vendor boot path has no lab TPM early-boot variant: the bound
// token is expected to be unusable, so unattended unlock is reported as
// unsupported rather than skipped.
func tpmBootUnsupported(ctx context.Context, manifest *labv1.ImageManifest, machine *actionMachine, result *VMDeviceActionsResult) error {
	boot, err := machine.vm.ColdBoot(ctx, "")
	if err == nil || !boot.PromptSeen || boot.Accepted {
		return errors.Join(errors.New("vendor boot path did not request its passphrase after TPM2 bind"), err)
	}
	result.TPMBootUnsupported = &actionUnsupportedEvidence{Reason: noTPMBootReason(manifest), Boot: boot}
	return nil
}

// UpgradeAgent upgrades the installed legacy package in place to the set's
// current version through the same pinned native manager and signed source;
// the manager asserts the installed package version, binary stamp and digest.
// The package's configure step restarts both services. The SSH forwards to
// the isolated server are host-side and survive; the relay is resumed against
// the still-enrolled executor, and both running services must execute the
// upgraded binary.
func (m *actionMachine) UpgradeAgent(ctx context.Context) error {
	if m.packages == nil {
		return errors.New("agent upgrade requires a package set with a later version")
	}
	err := m.packages.Upgrade(ctx)
	err = errors.Join(err, m.packages.Close())
	m.packages = nil
	if err != nil {
		return err
	}
	if _, err := waitGuestExecutorReady(ctx, m.vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, m.vm.guest, "resume upgraded action relay", "systemctl restart lindm-agent.service"); err != nil {
		return err
	}
	return lifecycleCommand(ctx, m.vm.guest, "assert running upgraded agent binary", runningAgentBinaryCommand(m.upgrade.PayloadSHA256))
}

// runningAgentBinaryCommand checks the executable image of each packaged
// service's main process, not merely the file on disk: a service still running
// the replaced binary keeps its original inode.
func runningAgentBinaryCommand(payloadSHA256 string) string {
	return `for unit in lindm-executor.service lindm-agent.service; do
pid=$(systemctl show --property=MainPID --value "$unit")
test "$pid" -gt 0
printf '%s  %s\n' ` + nativeQuote(strings.ToLower(payloadSHA256)) + ` "/proc/$pid/exe" | sha256sum --check --status
done`
}

// nativeTPMReferenceRepair qualifies the repair of a device bound by an agent
// that wrote fewer systemd-tpm2 token references than its release needs: the
// legacy package binds with the owner credential, the native manager upgrades
// it to the current package, and the identical signed PCR 7 bind, dispatched
// with no credential, must add only the missing references to the same
// keyslot. The repaired bind must then unlock every unattended cold boot.
func nativeTPMReferenceRepair(ctx context.Context, manifest *labv1.ImageManifest, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest, result *VMDeviceActionsResult) (err error) {
	if packages.upgrade.Path == "" {
		return errors.New("TPM reference repair requires a legacy package and its upgrade")
	}
	machine, err := openActionMachine(ctx, manifest, options, packages, fixture, control, delegation)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, machine.Close()) }()
	if err := machine.record(ctx, result); err != nil {
		return err
	}
	request := tpmBindRequest(machine)
	if refused, err := tpmBindRefused(ctx, machine, control, request, options.Encrypted.Hardware.TPM, result); refused || err != nil {
		return err
	}
	credential := []byte(machine.vm.InitialUnlockSecret())
	defer clear(credential)
	result.TPMBind, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, credential, false)
	if err != nil {
		return fmt.Errorf("legacy agent TPM2 bind: %w", err)
	}
	result.TPMLegacyInventory, err = captureActionEncryption(ctx, machine, control)
	if err != nil {
		return err
	}
	keyslot, references, err := tpmBoundKeyslot(result.TPMLegacyInventory.Tokens)
	if err != nil {
		return fmt.Errorf("legacy agent TPM2 bind: %w", err)
	}
	result.TPMBoundKeyslot, result.TPMLegacyTokenReferences = &keyslot, references
	if references != 1 {
		return fmt.Errorf("legacy agent wrote %d systemd-tpm2 token references to keyslot %d, want 1", references, keyslot)
	}
	want := machine.release.TPM2TokenReferences()
	result.TPMLegacyServerReferences, err = captureTPMServerReferences(ctx, control, machine.deviceID)
	if err != nil {
		return err
	}
	if got := result.TPMLegacyServerReferences; got.References != uint32(references) || got.Required != uint32(want) {
		return fmt.Errorf("server reports %d of %d required TPM2 token references after the legacy bind, want %d of %d", got.References, got.Required, references, want)
	}
	if err := machine.UpgradeAgent(ctx); err != nil {
		return fmt.Errorf("upgrade guest agent to %s: %w", packages.upgrade.Version, err)
	}
	result.UpgradedAgentVersion = packages.upgrade.Version
	if want == 1 {
		result.TPMReferenceRepairNotNeeded = fmt.Sprintf("%s requires %d systemd-tpm2 token reference; the legacy bind already satisfies it, so no repair bind was dispatched", machine.release.Name, want)
	} else {
		repair := actionRequestFor(machine.deviceID, machine.generation, request.GetSpec())
		var status *agentv1.DeviceActionStatus
		result.TPMReferenceRepair, status, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, repair, nil, false)
		if err != nil {
			return fmt.Errorf("credential-less TPM2 reference repair: %w", err)
		}
		result.TPMReferenceRepairKeyslot = status.GetBefore().Tpm2ReferenceRepairKeyslot
		if got := result.TPMReferenceRepairKeyslot; got == nil || *got != keyslot {
			return fmt.Errorf("agent observation did not freeze a reference repair of keyslot %d", keyslot)
		}
	}
	result.TPMInventory, err = captureActionEncryption(ctx, machine, control)
	if err != nil {
		return err
	}
	if err := verifyTPMReferenceRepair(result.TPMLegacyInventory, result.TPMInventory, keyslot, want); err != nil {
		return err
	}
	result.TPMTokenReferences = want
	result.TPMServerReferences, err = captureTPMServerReferences(ctx, control, machine.deviceID)
	if err != nil {
		return err
	}
	if got := result.TPMServerReferences; got.References != uint32(want) || got.Required != uint32(want) {
		return fmt.Errorf("server reports %d of %d required TPM2 token references after reference repair, want %d of %d", got.References, got.Required, want, want)
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
	return unattendedTPMBoots(ctx, machine, max(options.TPMBoots, 1), options.Encrypted.DiagnosticsDir, result)
}

// validateEncryptionPhase admits the separately recorded encryption phases
// and their options before any build, image or fixture work.
func validateEncryptionPhase(options VMDeviceActionsOptions) error {
	phase := options.EncryptionPhase
	tpmPhase := phase == "tpm" || phase == "tpm-repair"
	if phase != "" && (options.Scenario != "encryption" || !tpmPhase) {
		return errors.New("encryption phase requires scenario encryption and phase tpm or tpm-repair")
	}
	if options.TPMBoots < 0 || options.TPMBoots > maxTPMBoots || (options.TPMBoots > 1 && !tpmPhase) {
		return fmt.Errorf("-tpm-boots is 1 to %d and more than one requires -encryption-phase tpm or tpm-repair", maxTPMBoots)
	}
	if (options.LegacyAgentRevision != "") != (phase == "tpm-repair") {
		return errors.New("-legacy-agent-revision is required for, and only valid with, -encryption-phase tpm-repair")
	}
	if phase != "tpm-repair" {
		return nil
	}
	if !legacyRevisionPattern.MatchString(options.LegacyAgentRevision) || strings.Contains(options.LegacyAgentRevision, "..") {
		return fmt.Errorf("-legacy-agent-revision %q is not a commit ID or ref name", options.LegacyAgentRevision)
	}
	if options.Encrypted.Hardware == nil || !options.Encrypted.Hardware.TPM {
		return errors.New("-encryption-phase tpm-repair binds through the emulated TPM; -tpm=false is refused")
	}
	return nil
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
