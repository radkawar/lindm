//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/measuredboot"
	"lindm/internal/platform"
)

// recoveryBootMeasured is the maintained flag value for stock shim+GRUB with a
// TPM-attested lindm initramfs; the default remains the owned systemd-boot UKI.
const recoveryBootMeasured = "measured-grub"

type actionStockBootEvidence struct {
	// LoaderInfo is empty when the vendor GRUB has no `bli` module (GRUB older
	// than 2.12); the guest's measured readiness then proves the GRUB boot.
	LoaderInfo        string `json:"running_loader_info"`
	ESPAvailableBytes uint64 `json:"unchanged_vendor_esp_available_bytes"`
	BootFilesystem    string `json:"boot_filesystem"`
	EventLogSHA256    string `json:"ordinary_event_log_sha256,omitempty"`
	// EventLog is the ordinary boot's TCG log, retained so a release's GRUB
	// measurement form can become a parser fixture.
	EventLog   []byte `json:"ordinary_event_log,omitempty"`
	TPMPresent bool   `json:"tpm_present"`
}

// provisionActionStockBoot keeps the vendor boot chain: no loader, key, ESP or
// NVRAM change. It only installs the recovery closure inputs (through a
// temporary Red Hat registration on entitled releases, removed before any
// action) and formats the independent off-target state disk, exactly as the
// UKI fixture does.
func provisionActionStockBoot(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest, entitlement actionOwnedBootEntitlement) (_ *actionOwnedBootEvidence, _ *actionStockBootEvidence, err error) {
	evidence, stock := &actionOwnedBootEvidence{}, &actionStockBootEvidence{TPMPresent: vm.hardware.TPM}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	install, err := labInstallCommand(release, release.Lab.Guest.MeasuredBoot)
	if err != nil {
		return evidence, stock, fmt.Errorf("measured GRUB fixture requires a maintained package recipe: %w", err)
	}
	root, state, err := actionOwnedCloudTargets(ctx, vm)
	if err != nil {
		return evidence, stock, err
	}
	evidence.OriginalTarget, evidence.StateTarget = *root, *state
	var registration *vmRedHatRegistration
	if release.Lab.Entitlement {
		evidence.RedHat = new(VMRedHatEvidence)
		if registration, err = registerRHELOwnedBoot(ctx, vm, entitlement, evidence.RedHat); err != nil {
			return evidence, stock, err
		}
	}
	installed, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(install), nil, 1<<20, 15*time.Minute)
	if err == nil && installed.ExitCode != 0 {
		err = fmt.Errorf("install measured recovery prerequisites: guest exit %d: %s", installed.ExitCode, installed.Stderr)
	}
	if err = errors.Join(err, releaseRHELOwnedBoot(ctx, vm, registration)); err != nil {
		return evidence, stock, err
	}
	initial, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id; uname -r", nil, 4096, 10*time.Second)
	if err != nil {
		return evidence, stock, err
	}
	fields := strings.Fields(string(initial))
	if len(fields) != 2 || !vmValidID(fields[0]) || strings.ContainsAny(fields[1], "/\\\x00") {
		return evidence, stock, errors.New("invalid original guest boot identity")
	}
	evidence.OriginalBootID, evidence.ConvertedBootID, evidence.KernelRelease = fields[0], fields[0], fields[1]
	stateUUID := uuid.NewString()
	evidence.StateUUID = stateUUID
	configure := "mkfs.ext4 -F -U " + nativeQuote(stateUUID) + " " + nativeQuote(state.Path) + "; install -d -m0700 /var/lib/lindm-recovery; mount -t ext4 -o nosuid,nodev,noexec " + nativeQuote(state.Path) + " /var/lib/lindm-recovery; chmod 0700 /var/lib/lindm-recovery; printf '%s\\n' " + nativeQuote("UUID="+stateUUID+" /var/lib/lindm-recovery ext4 defaults,nosuid,nodev,noexec 0 2") + " >> /etc/fstab"
	configured, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(configure), nil, 8192, 3*time.Minute)
	if err != nil {
		return evidence, stock, err
	}
	if configured.ExitCode != 0 {
		return evidence, stock, fmt.Errorf("prepare off-target recovery state: guest exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	if stock.LoaderInfo, err = observeStockFirmware(ctx, vm); err != nil {
		return evidence, stock, err
	}
	evidence.LoaderInfo, evidence.SecureBoot, evidence.SetupMode = stock.LoaderInfo, true, false
	observed, err := vm.run(ctx, "df -B1 --output=avail /boot/efi | tail -n 1; findmnt --noheadings --output FSTYPE --target /boot", nil, 4096, 10*time.Second)
	if err != nil {
		return evidence, stock, err
	}
	lines := strings.Fields(string(observed))
	if len(lines) != 2 {
		return evidence, stock, errors.New("invalid stock ESP or /boot observation")
	}
	if stock.ESPAvailableBytes, err = strconv.ParseUint(lines[0], 10, 64); err != nil {
		return evidence, stock, err
	}
	stock.BootFilesystem = lines[1]
	if vm.hardware.TPM {
		log, err := vm.run(ctx, "sudo -n cat /sys/kernel/security/tpm0/binary_bios_measurements", nil, measuredboot.MaxEventLogBytes, 10*time.Second)
		if err != nil {
			return evidence, stock, fmt.Errorf("observe ordinary measured-boot event log: %w", err)
		}
		if _, err := measuredboot.ParseEventLog(log); err != nil {
			return evidence, stock, fmt.Errorf("ordinary measured-boot event log: %w", err)
		}
		digest := sha256.Sum256(log)
		stock.EventLogSHA256, stock.EventLog = hex.EncodeToString(digest[:]), log
	}
	if _, err := vm.run(ctx, "sudo -n mount -o remount,umask=0077 /boot/efi", nil, 4096, 15*time.Second); err != nil {
		return evidence, stock, err
	}
	return evidence, stock, nil
}

// The vendor GRUB `bli` module (GRUB 2.12+) publishes LoaderInfo, which must
// then name GRUB; without it the identity stays empty. Secure Boot must be in
// user mode with the firmware's own enrolled keys.
func observeStockFirmware(ctx context.Context, vm *guestVM) (string, error) {
	const variables = "/sys/firmware/efi/efivars/"
	for _, flag := range []struct {
		name  string
		value byte
	}{{"SecureBoot", 1}, {"SetupMode", 0}} {
		raw, err := vm.run(ctx, "sudo -n cat "+nativeQuote(variables+flag.name+"-8be4df61-93ca-11d2-aa0d-00e098032b8c"), nil, 32, 10*time.Second)
		if err != nil {
			return "", err
		}
		if len(raw) != 5 || raw[4] != flag.value {
			return "", errors.New("stock firmware did not enforce Secure Boot user mode")
		}
	}
	const loaderInfo = variables + "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
	present, err := vm.runResult(ctx, "test -e "+nativeQuote(loaderInfo), nil, 64, 10*time.Second)
	if err != nil {
		return "", err
	}
	if present.ExitCode != 0 {
		return "", nil
	}
	raw, err := vm.run(ctx, "sudo -n cat "+nativeQuote(loaderInfo), nil, 4096, 10*time.Second)
	if err != nil {
		return "", err
	}
	if len(raw) < 6 || len(raw)%2 != 0 {
		return "", errors.New("invalid actual EFI loader identity")
	}
	wide := make([]uint16, (len(raw)-4)/2)
	for i := range wide {
		wide[i] = binary.LittleEndian.Uint16(raw[4+2*i:])
	}
	loader := strings.TrimRight(string(utf16.Decode(wide)), "\x00")
	if !strings.HasPrefix(loader, "GRUB ") {
		return "", errors.New("stock guest did not boot vendor GRUB")
	}
	return loader, nil
}
