//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

type encryptedGuestEvidence struct {
	TPMVersion string            `json:"tpm_version"`
	SecureBoot bool              `json:"secure_boot"`
	SetupMode  bool              `json:"setup_mode"`
	Headers    []EncryptedHeader `json:"headers"`
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
	posture, err := vm.Run(ctx, `sudo sh -eu -c '
root=$(findmnt -n -o SOURCE /)
root=${root%%\[*}
lsblk -s -r -n -o TYPE "$root" | grep -qx crypt
if [ -r /sys/class/tpm/tpm0/tpm_version_major ]; then cat /sys/class/tpm/tpm0/tpm_version_major; else printf "absent\n"; fi
od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
'`, nil)
	if err != nil {
		return nil, fmt.Errorf("observe encrypted root/TPM/UEFI: %w", err)
	}
	fields := strings.Fields(string(posture))
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
	return result, nil
}
