// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/measuredboot"
)

type encryptedGuestEvidence struct {
	TPMVersion string            `json:"tpm_version"`
	SecureBoot bool              `json:"secure_boot"`
	SetupMode  bool              `json:"setup_mode"`
	Headers    []EncryptedHeader `json:"headers"`
	// Ordinary firmware/loader measurements are evidence, not a recovery pass.
	EventLogSHA256 string `json:"ordinary_event_log_sha256,omitempty"`
	EventLog       []byte `json:"ordinary_event_log,omitempty"`
}

// EncryptedSmokeEvidence contains no unlock secrets, SSH keys or raw console.
// It qualifies this virtual machine tuple, not physical recovery or sanitization.
type EncryptedSmokeEvidence struct {
	ImageID          string                            `json:"image_id"`
	ImageSHA256      string                            `json:"image_sha256"`
	ISOSignerPin     string                            `json:"iso_signer_pin"`
	RecipeVersion    string                            `json:"recipe_version"`
	Firmware         *EncryptedFirmwareEvidence        `json:"firmware"`
	Runtime          *vmRuntimeEvidence                `json:"runtime"`
	ApplianceKernel  *EncryptedApplianceKernelEvidence `json:"appliance_kernel,omitempty"`
	TPMBoot          bool                              `json:"tpm_boot_stack"`
	Desktop          string                            `json:"desktop"`
	StartedAt        time.Time                         `json:"started_at"`
	CompletedAt      time.Time                         `json:"completed_at"`
	Boots            []UnlockOutcome                   `json:"boots"`
	Guest            *encryptedGuestEvidence           `json:"guest"`
	OutOfBandHeaders []EncryptedHeader                 `json:"out_of_band_headers"`
	HeadersMatch     bool                              `json:"headers_match"`
	Failure          string                            `json:"failure,omitempty"`
}

// EncryptedSmoke installs/reuses a signed-ISO golden, cold boots a disposable
// clone twice, asserts native encryption/TPM/firmware, then compares independent
// powered-off LUKS metadata to the guest's actual cryptsetup observations.
func EncryptedSmoke(ctx context.Context, m *labv1.ImageManifest, opts EncryptedVMOptions) (result *EncryptedSmokeEvidence, err error) {
	evidence := &EncryptedSmokeEvidence{StartedAt: time.Now().UTC(), RecipeVersion: encryptedRecipeVersion}
	defer func() {
		result = evidence
		evidence.CompletedAt = time.Now().UTC()
		if err != nil {
			evidence.Failure = err.Error()
		}
	}()
	if m != nil {
		evidence.ImageID, evidence.ImageSHA256 = m.Id, m.Sha256
		evidence.ISOSignerPin = m.SignerFingerprint
	}
	evidence.TPMBoot, evidence.Desktop = opts.TPMBoot, opts.Desktop
	evidence.ApplianceKernel, err = encryptedSuperminKernelEvidence(ctx)
	if err != nil {
		return nil, err
	}
	vm, err := NewEncryptedVM(ctx, m, opts)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.Close()) }()
	firmware := *vm.firmware
	firmware.CodePath, firmware.VarsPath = "firmware-code.fd", "nvram.fd"
	evidence.Firmware = &firmware
	for range 2 {
		boot, err := vm.ColdBoot(ctx, vm.InitialUnlockSecret())
		evidence.Boots = append(evidence.Boots, boot)
		if err != nil {
			return nil, err
		}
		if !boot.PromptSeen {
			return nil, errors.New("passphrase smoke boot did not observe a LUKS prompt")
		}
		evidence.Runtime, err = vm.guest.runtimeEvidence(ctx)
		if err != nil {
			return nil, err
		}
		evidence.Runtime.SeedDisk = false
		guest, err := observeEncryptedGuest(ctx, vm, opts.Firmware.SecureBoot)
		if err != nil {
			return nil, err
		}
		evidence.Guest = guest
		shutdown, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = vm.PowerOff(shutdown)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	if evidence.Boots[0].BootID == evidence.Boots[1].BootID {
		return nil, errors.New("cold boots did not change guest boot ID")
	}
	evidence.OutOfBandHeaders, err = vm.Headers(ctx)
	if err != nil {
		return nil, err
	}
	evidence.HeadersMatch, err = encryptedHeadersEqual(evidence.Guest.Headers, evidence.OutOfBandHeaders)
	if err != nil {
		return nil, err
	}
	if !evidence.HeadersMatch {
		return nil, errors.New("independent LUKS metadata differs from guest observation")
	}
	return evidence, nil
}

func observeEncryptedGuest(ctx context.Context, vm *EncryptedVM, secureBoot bool) (*encryptedGuestEvidence, error) {
	// Keep failures attributable to one native operation. Never publish raw
	// stderr: root paths and native diagnostics can contain private guest data.
	if _, err := encryptedPostureCommand(ctx, vm, "encrypted root ancestry", `root=$(findmnt -n -o SOURCE /)
root=${root%%\[*}
test -b "$root"
lsblk -s -r -n -o TYPE "$root" | grep -qx crypt`); err != nil {
		return nil, err
	}
	var fields []string
	for _, probe := range []struct{ name, command string }{
		{"TPM version", `if [ -r /sys/class/tpm/tpm0/tpm_version_major ]; then cat /sys/class/tpm/tpm0/tpm_version_major; else printf "absent\n"; fi`},
		{"UEFI SecureBoot variable", `od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`},
		{"UEFI SetupMode variable", `od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c`},
	} {
		data, err := encryptedPostureCommand(ctx, vm, probe.name, probe.command)
		if err != nil {
			return nil, err
		}
		fields = append(fields, strings.Fields(string(data))...)
	}
	expectedTPM := "absent"
	if vm.hardware.TPM {
		expectedTPM = "2"
	}
	if len(fields) != 3 || fields[0] != expectedTPM || (fields[1] != "0" && fields[1] != "1") || (fields[2] != "0" && fields[2] != "1") {
		return nil, errors.New("guest did not report selected TPM and valid UEFI security state")
	}
	result := &encryptedGuestEvidence{TPMVersion: fields[0], SecureBoot: fields[1] == "1", SetupMode: fields[2] == "1"}
	if result.SecureBoot != secureBoot || (secureBoot && result.SetupMode) {
		return nil, errors.New("observed Secure Boot state does not match selected firmware variant")
	}
	headers, err := vm.Run(ctx, `sudo sh -eu -c '
first=1
printf "["
lsblk -rpn -o NAME,FSTYPE | while read -r device fstype; do
 if [ "$fstype" = crypto_LUKS ]; then
  if [ "$first" = 0 ]; then printf ","; fi
  first=0
  uuid=$(cryptsetup luksUUID "$device")
  printf "{\"device\":\"%s\",\"uuid\":\"%s\",\"json\":" "$device" "$uuid"
  cryptsetup luksDump --dump-json-metadata "$device"
  printf "}"
 fi
done
printf "]"
'`, nil)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(headers, &result.Headers); err != nil {
		return nil, fmt.Errorf("decode guest LUKS metadata: %w", err)
	}
	if len(result.Headers) == 0 {
		return nil, errors.New("guest contains no observed LUKS2 headers")
	}
	if vm.hardware.TPM {
		log, err := vm.guest.run(ctx, "sudo -n cat /sys/kernel/security/tpm0/binary_bios_measurements", nil, measuredboot.MaxEventLogBytes, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("observe encrypted ordinary boot event log: %w", err)
		}
		if _, err := measuredboot.ParseEventLog(log); err != nil {
			return nil, fmt.Errorf("parse encrypted ordinary boot event log: %w", err)
		}
		digest := sha256.Sum256(log)
		result.EventLogSHA256, result.EventLog = hex.EncodeToString(digest[:]), log
	}
	return result, nil
}

// These commands inspect only public boot posture, but a native error can quote
// a private device path. Retain fixed native failure reasons, not quoted values.
func encryptedPostureCommand(ctx context.Context, vm *EncryptedVM, phase, command string) ([]byte, error) {
	if vm.guest == nil {
		return nil, errors.New("encrypted posture requires a running guest")
	}
	result, err := vm.guest.runResult(ctx, "sudo -n env LC_ALL=C sh -eu -c "+nativeQuote(command), nil, 16<<10, time.Minute)
	if err != nil {
		return nil, fmt.Errorf("observe %s: %w", phase, err)
	}
	if result.ExitCode != 0 || len(strings.TrimSpace(string(result.Stderr))) != 0 {
		return nil, fmt.Errorf("observe %s: guest exit %d; %s", phase, result.ExitCode, encryptedPostureDiagnostic(result.Stderr))
	}
	return result.Stdout, nil
}

func encryptedPostureDiagnostic(stderr []byte) string {
	var reasons []string
	for _, reason := range []string{"No such file or directory", "Permission denied", "Operation not permitted", "not a block device", "command not found", "not found", "Input/output error", "Invalid argument", "Illegal seek", "cannot skip past end of combined input"} {
		if strings.Contains(string(stderr), reason) {
			reasons = append(reasons, reason)
		}
	}
	if len(reasons) != 0 {
		return strings.Join(reasons, "; ") + " (guest paths and other stderr redacted)"
	}
	return fmt.Sprintf("unclassified native failure (stderr bytes %d; private text withheld)", len(stderr))
}
