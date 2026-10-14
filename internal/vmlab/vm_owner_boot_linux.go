// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// recoveryBootstrapFirmware never relabels archiso as firmware-trusted. Its
// separate noSB template is package-pinned by the normal firmware staging path.
func recoveryBootstrapFirmware(manifest *labv1.ImageManifest, selected EncryptedFirmwareOptions, bootstrapVars, mode string) (EncryptedFirmwareOptions, error) {
	if platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion()).Lab.Installer != platform.ArchISO {
		if bootstrapVars != "" {
			return selected, errors.New("bootstrap firmware variables require the explicit Arch owner-UKI recovery baseline")
		}
		return selected, nil
	}
	if _, err := archRecoveryInstallerImage(manifest); err != nil {
		return selected, err
	}
	if mode != "" || !selected.SecureBoot || selected.OwnedDBCertificate == "" || bootstrapVars == "" {
		return selected, errors.New("arch owner recovery requires UKI, Secure Boot, owner db enrollment and explicit non-Secure-Boot bootstrap firmware variables")
	}
	selected.Vars, selected.SecureBoot, selected.OwnedDBCertificate = bootstrapVars, false, ""
	return selected, nil
}

// coldBootOwnerFirmware changes only a successfully powered-off disposable VM.
// The baseline golden remains unsigned/noSB and cacheable; signed artifacts and
// signer-specific NVRAM live only in this run, never in a reusable golden.
func (vm *guestVM) coldBootOwnerFirmware(ctx context.Context, firmware EncryptedFirmwareOptions) (poweredOff time.Time, err error) {
	if !firmware.SecureBoot || firmware.OwnedDBCertificate == "" || vm.firmware == nil || vm.hardware.Firmware == nil || vm.hardware.Firmware.SecureBoot {
		return time.Time{}, errors.New("owner trust transition requires an initial noSB guest and an enrolled Secure Boot target")
	}
	staging, err := os.MkdirTemp(vm.dir, ".owner-firmware-")
	if err != nil {
		return time.Time{}, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	final, err := prepareEncryptedFirmware(ctx, staging, firmware)
	if err != nil {
		return time.Time{}, err
	}
	if final.CodeSHA256 != vm.firmware.CodeSHA256 || !final.OwnedDBEnrolled {
		return time.Time{}, errors.New("owner trust transition must retain firmware code and enroll the exact owner signer")
	}
	shutdown, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := vm.run(shutdown, "sudo -n systemd-run --quiet --on-active=2s --unit=lindm-lab-owner-poweroff /usr/bin/systemctl poweroff", nil, 4096, 15*time.Second); err != nil {
		return time.Time{}, err
	}
	select {
	case <-shutdown.Done():
		return time.Time{}, shutdown.Err()
	case <-vm.done:
		if vm.waitErr != nil || vm.cmd.ProcessState == nil || !vm.cmd.ProcessState.Success() {
			return time.Time{}, errors.New("owner trust transition requires an observed successful QEMU poweroff")
		}
	}
	poweredOff = time.Now().UTC()
	if vm.tpm != nil {
		// The powered-off QEMU ended its swtpm; boot on the same TPM state.
		select {
		case <-vm.tpm.done:
		case <-time.After(30 * time.Second):
			return poweredOff, errors.Join(errors.New("swtpm did not exit after guest poweroff"), vm.tpm.stop())
		}
		if err := vm.startTPM(ctx); err != nil {
			return poweredOff, fmt.Errorf("restart swtpm for owner-enrolled cold boot: %w", err)
		}
	}
	if vm.client != nil {
		_ = vm.client.Close()
		vm.client = nil
	}
	// No running QEMU can retain an old NVRAM descriptor beyond this boundary.
	if err := os.Rename(final.VarsPath, filepath.Join(vm.dir, "nvram.fd")); err != nil {
		return poweredOff, err
	}
	final.CodePath, final.VarsPath = filepath.Join(vm.dir, "firmware-code.fd"), filepath.Join(vm.dir, "nvram.fd")
	vm.firmware, vm.hardware.Firmware = final, &firmware
	_, port, err := net.SplitHostPort(vm.address)
	if err != nil {
		return poweredOff, err
	}
	args, err := configuredVMArguments(vm.hardware, vm.dir, port, true)
	if err != nil {
		return poweredOff, err
	}
	if err := vm.startProcess(ctx, args); err != nil {
		return poweredOff, err
	}
	if err := vm.connect(ctx); err != nil {
		return poweredOff, fmt.Errorf("cold boot owner-enrolled firmware: %w", err)
	}
	certificate, err := readOwnedFirmwareCertificate(firmware.OwnedDBCertificate)
	if err != nil {
		return poweredOff, err
	}
	db, err := vm.run(ctx, "sudo -n cat /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f", nil, 4<<20, 15*time.Second)
	if err != nil {
		return poweredOff, err
	}
	if len(db) <= 4 {
		return poweredOff, errors.New("running firmware db is unavailable")
	}
	if err := ownedFirmwareDBContains(db[4:], certificate.Raw); err != nil {
		return poweredOff, fmt.Errorf("running firmware owner trust: %w", err)
	}
	return poweredOff, nil
}
