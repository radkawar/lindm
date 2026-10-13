//go:build linux

package vmlab

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// actionOwnerSecureBoot is a TPM lane's Secure Boot target on a release whose
// own media has no vendor Secure Boot trust (Quirks.RecoveryOwnerKey). The
// installer golden stays unsigned under the package-pinned noSB bootstrap
// template; each clone then installs an owner-signed systemd-boot and UKI,
// receives only this run's owner certificate in its private db and cold-boots
// with Secure Boot enforced before any TPM2 bind.
type actionOwnerSecureBoot struct {
	signer   *actionBootSigner
	firmware EncryptedFirmwareOptions
}

// actionOwnerSecureBootEvidence names the signed artifacts and the first boot
// under owner trust; the signing key never leaves the lab host's run directory.
type actionOwnerSecureBootEvidence struct {
	SignerPEMSHA256   string                     `json:"signer_pem_sha256"`
	KernelRelease     string                     `json:"kernel_release"`
	SystemdBootSHA256 string                     `json:"signed_systemd_boot_sha256"`
	UKISHA256         string                     `json:"signed_uki_sha256"`
	BootstrapBootID   string                     `json:"bootstrap_boot_id"`
	PoweroffAt        time.Time                  `json:"owner_enrollment_poweroff_at"`
	OwnerBoot         UnlockOutcome              `json:"owner_secure_boot"`
	LoaderStatus      string                     `json:"loader_status"`
	LoaderInfo        string                     `json:"running_loader_info"`
	Firmware          *EncryptedFirmwareEvidence `json:"owner_firmware"`
}

// prepareActionOwnerSecureBoot creates the run's owner signer and replaces the
// golden's firmware with the noSB bootstrap template; the selected Secure Boot
// firmware becomes the owner-enrolled target.
func prepareActionOwnerSecureBoot(manifest *labv1.ImageManifest, options *VMDeviceActionsOptions) (*actionOwnerSecureBoot, error) {
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	if !release.Quirks.RecoveryOwnerKey || release.Lab.Installer != platform.ArchISO || manifest.GetEdition() != release.Lab.RecoveryInstallerEdition {
		return nil, errors.New("owner Secure Boot TPM lane requires an owner-key release's systemd-boot installer edition")
	}
	if !options.Encrypted.Firmware.SecureBoot || options.Encrypted.Firmware.OwnedDBCertificate != "" {
		return nil, errors.New("owner Secure Boot TPM lane requires selected Secure Boot firmware without another owner certificate")
	}
	signer, err := newActionBootSigner(options.Encrypted.WorkDir)
	if err != nil {
		return nil, err
	}
	target := options.Encrypted.Firmware
	target.OwnedDBCertificate = signer.certificate
	bootstrap := options.Encrypted.Firmware
	bootstrap.Vars, bootstrap.SecureBoot = options.BootstrapFirmwareVars, false
	options.Encrypted.Firmware = bootstrap
	return &actionOwnerSecureBoot{signer: signer, firmware: target}, nil
}

// enrollOwnerSecureBoot converts this disposable clone, booted under the noSB
// bootstrap firmware, to owner trust: it builds a UKI from the installed kernel,
// initramfs and command line, signs it and systemd-boot on the lab host,
// installs both on the ESP, swaps only the powered-off clone's NVRAM for the
// owner-enrolled Secure Boot template and cold-boots with the owner passphrase.
func (m *actionMachine) enrollOwnerSecureBoot(ctx context.Context, owner *actionOwnerSecureBoot) (_ *actionOwnerSecureBootEvidence, err error) {
	vm := m.vm.guest
	evidence := &actionOwnerSecureBootEvidence{SignerPEMSHA256: hex.EncodeToString(owner.signer.certificateSHA256), BootstrapBootID: m.boot.BootID}
	// The installer already added the registry's owned-boot tools
	// (Lab.Guest.OwnedBoot: systemd-ukify); nothing is installed here.
	release, err := vm.run(ctx, "uname -r", nil, 256, 10*time.Second)
	if err != nil {
		return evidence, err
	}
	evidence.KernelRelease = strings.TrimSpace(string(release))
	if evidence.KernelRelease == "" || strings.ContainsAny(evidence.KernelRelease, "/\\\x00 ") || m.release.Lab.Guest.Kernel == "" || m.release.Lab.Guest.Initrd == "" {
		return evidence, errors.New("owner boot requires the release's registry kernel and initramfs paths")
	}
	kernel := strings.ReplaceAll(m.release.Lab.Guest.Kernel, "%s", evidence.KernelRelease)
	initrd := strings.ReplaceAll(m.release.Lab.Guest.Initrd, "%s", evidence.KernelRelease)
	loader, stub, fallback := "systemd-bootx64.efi", "linuxx64.efi.stub", "BOOTX64.EFI"
	if vm.hardware.Architecture == "aarch64" {
		loader, stub, fallback = "systemd-bootaa64.efi", "linuxaa64.efi.stub", "BOOTAA64.EFI"
	}
	// systemd-boot passes initrd= for its Type #1 entry; the UKI embeds that
	// initramfs, so the stub must not also load one from the ESP.
	prepare := "command -v ukify; install -d -m 0700 /run/lindm-owner-boot; esp=$(bootctl --print-esp-path); test -f \"$esp/EFI/systemd/" + loader + "\"; " +
		"tr ' ' '\\n' < /proc/cmdline | grep -v -e '^initrd=' -e '^$' | tr '\\n' ' ' > /run/lindm-owner-boot/cmdline; " +
		"ukify build --linux=" + nativeQuote(kernel) + " --initrd=" + nativeQuote(initrd) + " --stub=" + nativeQuote("/usr/lib/systemd/boot/efi/"+stub) + " --cmdline=@/run/lindm-owner-boot/cmdline --output=/run/lindm-owner-boot/uki-unsigned.efi"
	prepared, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(prepare), nil, 8192, 10*time.Minute)
	if err != nil {
		return evidence, err
	}
	if prepared.ExitCode != 0 {
		return evidence, fmt.Errorf("build owner UKI: guest exit %d: %s", prepared.ExitCode, prepared.Stderr)
	}
	for _, item := range []struct{ source, name string }{{"/usr/lib/systemd/boot/efi/" + loader, "loader"}, {"/run/lindm-owner-boot/uki-unsigned.efi", "uki"}} {
		// Both clones of one run share the signer directory.
		unsigned := filepath.Join(owner.signer.dir, item.name+"-"+evidence.BootstrapBootID+"-unsigned.efi")
		signed := filepath.Join(owner.signer.dir, item.name+"-"+evidence.BootstrapBootID+"-signed.efi")
		if _, err := downloadActionBootFile(ctx, vm, item.source, unsigned, 512<<20); err != nil {
			return evidence, err
		}
		if err := owner.signer.sign(ctx, unsigned, signed); err != nil {
			return evidence, err
		}
		digest, err := dispatchFileDigest(signed)
		if err != nil {
			return evidence, err
		}
		if item.name == "loader" {
			evidence.SystemdBootSHA256 = digest
		} else {
			evidence.UKISHA256 = digest
		}
		if err := uploadActionBootFile(ctx, vm, signed, "/run/lindm-owner-boot/"+item.name+"-signed.efi"); err != nil {
			return evidence, err
		}
	}
	// The fresh owner NVRAM has no boot entries: firmware starts the signed
	// removable-path loader, which boots only the signed UKI.
	configure := "esp=$(bootctl --print-esp-path); install -m0600 /run/lindm-owner-boot/loader-signed.efi \"$esp/EFI/systemd/" + loader + "\"; install -D -m0600 /run/lindm-owner-boot/loader-signed.efi \"$esp/EFI/BOOT/" + fallback + "\"; install -D -m0600 /run/lindm-owner-boot/uki-signed.efi \"$esp/EFI/Linux/lindm-owner.efi\"; printf 'default lindm-owner.efi\\ntimeout 0\\n' > \"$esp/loader/loader.conf\"; sync"
	configured, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(configure), nil, 8192, 3*time.Minute)
	if err != nil {
		return evidence, err
	}
	if configured.ExitCode != 0 {
		return evidence, fmt.Errorf("install owner signed boot: guest exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	if err := m.PowerOff(ctx); err != nil {
		return evidence, err
	}
	evidence.PoweroffAt = time.Now().UTC()
	if err := m.vm.enrollOwnerFirmware(ctx, owner.firmware); err != nil {
		return evidence, err
	}
	evidence.Firmware = m.vm.firmware
	evidence.OwnerBoot, err = m.vm.ColdBoot(ctx, m.vm.InitialUnlockSecret())
	if err != nil {
		return evidence, fmt.Errorf("cold boot owner-enrolled Secure Boot: %w", err)
	}
	if !evidence.OwnerBoot.PromptSeen || evidence.OwnerBoot.BootID == evidence.BootstrapBootID {
		return evidence, errors.New("owner Secure Boot was not observed on a new passphrase-unlocked boot")
	}
	m.boot = evidence.OwnerBoot
	evidence.LoaderInfo, err = observeActionOwnedFirmware(ctx, m.vm.guest)
	if err != nil {
		return evidence, err
	}
	certificate, err := readOwnedFirmwareCertificate(owner.firmware.OwnedDBCertificate)
	if err != nil {
		return evidence, err
	}
	db, err := m.vm.guest.run(ctx, "sudo -n cat /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f", nil, 4<<20, 15*time.Second)
	if err != nil {
		return evidence, err
	}
	if len(db) <= 4 {
		return evidence, errors.New("running firmware db is unavailable")
	}
	if err := ownedFirmwareDBContains(db[4:], certificate.Raw); err != nil {
		return evidence, fmt.Errorf("running firmware owner trust: %w", err)
	}
	status, err := m.vm.guest.runResult(ctx, "sudo -n bootctl status --no-pager", nil, 32<<10, 15*time.Second)
	if err != nil {
		return evidence, err
	}
	if status.ExitCode != 0 {
		return evidence, fmt.Errorf("observe owner signed systemd-boot: guest exit %d", status.ExitCode)
	}
	if err := ownedBootStatusNotices(status.Stderr); err != nil {
		return evidence, err
	}
	evidence.LoaderStatus = string(status.Stdout)
	return evidence, nil
}

// enrollOwnerFirmware replaces only this powered-off clone's NVRAM with the
// package-pinned Secure Boot template plus the run's owner db certificate. The
// firmware code, disk and TPM state are retained; the next cold boot enforces
// Secure Boot under owner trust. The cacheable golden is never changed.
func (v *EncryptedVM) enrollOwnerFirmware(ctx context.Context, firmware EncryptedFirmwareOptions) (err error) {
	if v.closed || v.guest != nil || v.recoveryActive {
		return errors.New("owner firmware enrollment requires a powered-off encrypted clone")
	}
	if !firmware.SecureBoot || firmware.OwnedDBCertificate == "" || v.firmware == nil || v.hardware.Firmware == nil || v.hardware.Firmware.SecureBoot {
		return errors.New("owner trust transition requires a noSB clone and an owner-enrolled Secure Boot target")
	}
	staging, err := os.MkdirTemp(v.dir, ".owner-firmware-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	final, err := prepareEncryptedFirmware(ctx, staging, firmware)
	if err != nil {
		return err
	}
	if final.CodeSHA256 != v.firmware.CodeSHA256 || !final.OwnedDBEnrolled {
		return errors.New("owner trust transition must retain firmware code and enroll the exact owner signer")
	}
	if err := os.Rename(final.VarsPath, filepath.Join(v.dir, "nvram.fd")); err != nil {
		return err
	}
	final.CodePath, final.VarsPath = filepath.Join(v.dir, "firmware-code.fd"), filepath.Join(v.dir, "nvram.fd")
	v.firmware, v.hardware.Firmware = final, &firmware
	return nil
}
