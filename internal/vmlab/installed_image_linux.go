//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// installerImage describes a vendor installer whose authenticated media produce
// a local immutable qcow2 golden disk, never a vendor-signed cloud image. Only
// boot configuration and an unattended recipe are remastered; the vendor
// kernel, initrd and signed bootloaders remain unchanged.
type installerImage struct {
	// label prefixes diagnostics, for example "debian".
	label string
	// installer selects the vendor boot-configuration and recipe layout.
	installer platform.Installer
	// cache is the private subdirectory of the image cache.
	cache string
	// version binds the recipe and machine layout into the cache identity.
	// Bump it when either changes: cached installs are never edited in place.
	version   string
	memoryMiB int
	// exitOnReboot ends the installer QEMU on a guest reboot request, for
	// installers whose unattended mode can only reboot (Ubiquity's
	// noninteractive frontend), so the vendor media never boots twice.
	exitOnReboot bool
	recipe       func(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error)
	// offline denies installer egress for the signed-DVD capture bootstrap.
	offline bool
	// consoleDiagnostics retains a bounded, redacted serial tail when the
	// installer fails. Only recipes without unlock secrets may set it.
	consoleDiagnostics bool
	// diagnostics is the failure sink of an unencrypted capture or golden install.
	diagnostics *installerDiagnostics
	// firstBootDiagnostics retains only failed unencrypted installed boots.
	firstBootDiagnostics bool
	// snapshot is populated only for the Tumbleweed recipe before rendering.
	snapshot *tumbleweedSnapshotRepository
	// bindSources, when set, authenticates network installation sources
	// outside the ISO. It runs before and after the installer under a phase
	// label and must fail closed.
	bindSources func(ctx context.Context, root *os.Root, staging, phase string) error
	// install, when set, replaces recipe remastering and runImageInstaller for
	// vendors with a documented unattended path on unmodified media (Omarchy's
	// cidata drive). It borrows the verified ISO descriptor and must leave the
	// installed and provisioned disk at <dir>/image.
	install func(ctx context.Context, dir string, iso *os.File, sourceDigest string, hardware VMHardwareOptions) error
	// probes run as root inside the first installed boot, after cloud-init
	// consumed a fresh NoCloud seed.
	probes []installedProbe
}

type installedProbe struct{ label, script string }

// installerImageFor returns nil for manifests that already name a bootable
// cloud disk. Installer editions are validated before any acquisition against
// the registry installer of the manifest's release.
func installerImageFor(m *labv1.ImageManifest) (*installerImage, error) {
	switch m.GetEdition() {
	case "netinst":
		return debianInstallerImage(m)
	case tumbleweedInstallerEdition:
		return tumbleweedInstallerImage(m)
	case popInstallerEdition, popEncryptedInstallerEdition:
		// A live ISO is never a cloud disk: the encrypted-lane edition is
		// rejected here rather than booted.
		return popInstallerImage(m)
	case mintInstallerEdition, mintEncryptedInstallerEdition:
		return mintInstallerImage(m)
	case omarchyInstallerEdition, omarchyEncryptedInstallerEdition:
		// Installer-only media: the encrypted-lane edition is rejected here.
		return omarchyInstallerImage(m)
	case archRecoveryInstallerEdition:
		return archRecoveryInstallerImage(m)
	default:
		return nil, nil
	}
}

// installedImage derives the golden disk from an authenticated installer. The
// caller reauthenticates the ISO even on reuse. Local disk digests detect cache
// corruption, not a vendor signature on our installed machine. Only owned
// staging is ever partitioned.
func installedImage(ctx context.Context, m *labv1.ImageManifest, spec *installerImage, source *VerifiedImage, cacheDir, workDir string, hardware VMHardwareOptions) (_ *VerifiedImage, err error) {
	if hardware.Firmware == nil {
		return nil, fmt.Errorf("%s installer requires explicit UEFI firmware code, variables, package and version", spec.label)
	}
	if spec.installer == platform.ArchISO && hardware.Firmware.SecureBoot {
		return nil, errors.New("official archiso is unsigned: install with explicit non-Secure-Boot bootstrap firmware before owner enrollment")
	}
	root, err := openCache(ctx, filepath.Join(cacheDir, spec.cache), true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	firmwareDir, err := os.MkdirTemp(root.Name(), ".firmware-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(firmwareDir)) }()
	if _, err := prepareEncryptedFirmware(ctx, firmwareDir, *hardware.Firmware); err != nil {
		return nil, err
	}
	codeDigest, err := encryptedFileDigest(filepath.Join(firmwareDir, "firmware-code.fd"))
	if err != nil {
		return nil, err
	}
	varsDigest, err := encryptedFileDigest(filepath.Join(firmwareDir, "nvram.fd"))
	if err != nil {
		return nil, err
	}
	identity := strings.Join([]string{spec.version, source.SHA256, m.Version, hardware.Architecture, hardware.StorageBus, codeDigest, varsDigest, hardware.Firmware.Package, hardware.Firmware.Version, fmt.Sprint(hardware.Firmware.SecureBoot)}, "\n")
	if m.GetRepositorySnapshotManifestSha256() != "" {
		identity += "\nrepository-closure:" + m.GetRepositorySnapshotManifestSha256()
	}
	sum := sha256.Sum256([]byte(identity))
	id := hex.EncodeToString(sum[:])
	lock, err := lockImage(ctx, root, id)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	entry := "sha256-" + id
	partial := "." + entry + ".partial"
	if err := root.RemoveAll(partial); err != nil {
		return nil, err
	}
	if _, err := root.Lstat(entry); err == nil {
		return loadInstalledImage(ctx, root, entry)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := root.Mkdir(partial, 0700); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.RemoveAll(partial)) }()
	dir := filepath.Join(root.Name(), partial)
	for _, name := range []string{"firmware-code.fd", "nvram.fd"} {
		if err := copyEncryptedFile(filepath.Join(firmwareDir, name), filepath.Join(dir, name), 0600); err != nil {
			return nil, err
		}
	}
	snapshot, err := startImageRepositorySnapshot(ctx, m, cacheDir, "10.0.2.2")
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		defer func() { err = errors.Join(err, snapshot.Close()) }()
		if spec.snapshot == nil {
			return nil, errors.New("tumbleweed installer recipe lacks repository snapshot binding")
		}
		*spec.snapshot = tumbleweedSnapshotRepository{URL: snapshot.URL, CAPEM: snapshot.CAPEM}
	}
	// Pin the exact verified descriptor during remastering. A pathname rename
	// cannot switch media between the digest check and xorriso's inherited fd.
	iso, err := openRegular(source.Path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, iso.Close()) }()
	actual, err := digestInstalledImage(ctx, iso)
	if err != nil {
		return nil, err
	}
	if actual.SHA256 != source.SHA256 || actual.Size != source.Size {
		return nil, fmt.Errorf("verified %s installer changed before remastering", spec.label)
	}
	installer := ""
	if spec.install == nil {
		_, loginPublic, err := encryptedKey()
		if err != nil {
			return nil, err
		}
		hostPrivate, hostPublic, err := encryptedKey()
		if err != nil {
			return nil, err
		}
		recipe, err := spec.recipe(installerDisk(hardware.StorageBus), hardware.Architecture, source.SHA256, loginPublic, string(hostPrivate), hostPublic)
		if err != nil {
			return nil, err
		}
		installer, err = prepareInstallerFileForMachine(ctx, dir, iso, spec.installer, recipe, hardware.Architecture)
		if err != nil {
			return nil, err
		}
		if spec.consoleDiagnostics {
			kind := installerFailureSnapshot
			if spec.installer == platform.ArchISO {
				kind = installerFailureArchISO
			}
			spec.diagnostics = newInstallerDiagnostics(hardware.goldenDiagnosticsParent(workDir), kind, hardware.Architecture, source.SHA256, loginPublic, string(hostPrivate), hostPublic, string(recipe))
		}
	}
	if _, err := hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "image", "24G"); err != nil {
		return nil, err
	}
	if spec.bindSources != nil && snapshot == nil {
		if err := spec.bindSources(ctx, root, partial, "before"); err != nil {
			return nil, err
		}
	}
	if spec.install != nil {
		err = spec.install(ctx, dir, iso, source.SHA256, hardware)
	} else {
		err = runImageInstaller(ctx, dir, installer, spec, hardware)
	}
	if err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Refused().Err())
		}
		return nil, err
	}
	if spec.bindSources != nil && snapshot == nil {
		if err := spec.bindSources(ctx, root, partial, "after"); err != nil {
			return nil, err
		}
	}
	if err := validateInstalledImage(ctx, filepath.Join(dir, "image"), workDir, source.SHA256, spec, hardware); err != nil {
		return nil, err
	}
	image, err := openRegular(filepath.Join(dir, "image"))
	if err != nil {
		return nil, err
	}
	result, hashErr := digestInstalledImage(ctx, image)
	if err := errors.Join(hashErr, image.Close()); err != nil {
		return nil, err
	}
	if err := root.WriteFile(partial+"/sha256", []byte(result.SHA256+"\n"), 0600); err != nil {
		return nil, err
	}
	// Remastered media and recipe carry private SSH material; publish only the
	// installed disk and its integrity pin, never installer staging or variables.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		if item.Name() != "image" && item.Name() != "sha256" {
			if err := root.RemoveAll(partial + "/" + item.Name()); err != nil {
				return nil, err
			}
		}
	}
	if err := publishImageCache(root, partial, entry, []string{"image", "sha256"}); err != nil {
		return nil, err
	}
	result.Path = filepath.Join(root.Name(), entry, "image")
	return result, nil
}

func digestInstalledImage(ctx context.Context, file *os.File) (*VerifiedImage, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > 32<<30 {
		return nil, errors.New("installer image size must be positive and at most 32 GiB")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(contextReader{ctx: ctx, reader: file}, info.Size()+1))
	if err != nil {
		return nil, err
	}
	if count != info.Size() {
		return nil, errors.New("installer image changed while hashing")
	}
	return &VerifiedImage{SHA256: hex.EncodeToString(digest.Sum(nil)), Size: count}, nil
}

func loadInstalledImage(ctx context.Context, root *os.Root, entry string) (_ *VerifiedImage, err error) {
	info, err := root.Lstat(entry)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("installed image cache entry must be a directory")
	}
	pin, err := readCacheFile(root, entry+"/sha256", 65)
	if err != nil {
		return nil, err
	}
	if len(pin) != 65 || pin[64] != '\n' {
		return nil, errors.New("invalid installed image cache pin")
	}
	path := filepath.Join(root.Name(), entry, "image")
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	result, err := digestInstalledImage(ctx, file)
	if err != nil {
		return nil, err
	}
	if result.SHA256 != string(pin[:64]) {
		return nil, errors.New("installed image cache digest mismatch; inspect before explicit removal")
	}
	result.Path = path
	return result, nil
}

func installerDisk(storage string) string {
	switch storage {
	case "virtio-blk":
		return "/dev/vda"
	case "nvme":
		return "/dev/nvme0n1"
	default:
		return "/dev/sda"
	}
}

// runImageInstaller boots vendor EFI/kernel payloads from privately remastered
// media. Only the disposable guest receives network access and disk writes.
func runImageInstaller(ctx context.Context, dir, installer string, spec *installerImage, hardware VMHardwareOptions) (err error) {
	relative, err := filepath.Rel(dir, installer)
	if err != nil || !filepath.IsLocal(relative) || strings.ContainsAny(relative, ",\r\n") {
		return fmt.Errorf("%s installer media must remain inside private staging", spec.label)
	}
	machine, cpu := "q35", "max"
	if hardware.Architecture == "aarch64" {
		machine = "virt"
	}
	if hardware.Accelerator == "kvm" {
		cpu = "host"
	}
	machine += ",accel=" + hardware.Accelerator
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		machine += ",smm=on"
	}
	network := "user,id=net0"
	if spec.offline {
		network += ",restrict=on"
	}
	// Encrypted installers discard serial, which can contain unlock secrets.
	// Unencrypted profiles may opt into a separate bounded, redacted sink.
	serial, console := "null", io.Writer(nil)
	if spec.diagnostics != nil {
		serial, console = "stdio", spec.diagnostics
	}
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-serial", serial, "-monitor", "none", "-machine", machine, "-cpu", cpu, "-m", fmt.Sprint(spec.memoryMiB), "-smp", "2",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=firmware-code.fd", "-drive", "if=pflash,format=raw,unit=1,file=nvram.fd",
		"-drive", "if=none,id=disk,format=qcow2,file=image", "-device", "virtio-rng-pci",
		"-netdev", network, "-device", "virtio-net-pci,netdev=net0,id=nic0",
		"-drive", "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=" + relative,
		"-device", "virtio-scsi-pci,id=installer-scsi", "-device", "scsi-cd,bus=installer-scsi.0,drive=installer,bootindex=0"}
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	if spec.exitOnReboot {
		args = append(args, "-no-reboot")
	}
	args = append(args, vmStorageArguments(hardware, []string{"disk"}, 1)...)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	var process *encryptedProcess
	defer func() {
		if err != nil && spec.diagnostics != nil {
			var processLog *vmLog
			if process != nil {
				processLog = process.log
			}
			err = spec.diagnostics.saveFailure(dir, processLog, err)
		}
	}()
	process, err = startEncryptedProcessOutput(ctx, dir, nil, console, "qemu-system-"+hardware.Architecture, args...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, process.stop()) }()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%s installer deadline: %w", spec.label, ctx.Err())
	case <-process.done:
		if process.err != nil {
			return fmt.Errorf("%s installer failed: %w; %s", spec.label, process.err, process.log.diagnostic(dir))
		}
		return nil
	}
}

func validateInstalledImage(ctx context.Context, path, workDir, sourceDigest string, spec *installerImage, hardware VMHardwareOptions) (err error) {
	base, err := openRegular(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, base.Close()) }()
	// Prove an installed boot and fresh pinned NoCloud SSH, not merely an
	// installer process exit. Validation writes only a disposable overlay.
	hardware.AllowNetwork, hardware.TPM, hardware.Desktop, hardware.ExtraDisks = false, false, false, 0
	if spec.firstBootDiagnostics {
		hardware.bootDiagnostics = newInstallerDiagnostics(hardware.goldenDiagnosticsParent(workDir), installerFailureFirstBoot, hardware.Architecture, sourceDigest)
	}
	vm, err := newConfiguredGuestVM(ctx, base, workDir, false, &hardware)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	defer func() {
		if err != nil && hardware.bootDiagnostics != nil {
			err = hardware.bootDiagnostics.saveFailure(vm.dir, vm.log, err)
		}
	}()
	if err := vm.connect(ctx); err != nil {
		return fmt.Errorf("%s installed boot: %w", spec.label, err)
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return fmt.Errorf("%s installed cloud_init: %w", spec.label, err)
	}
	for _, probe := range spec.probes {
		// The source marker deliberately remains root-only under the installer
		// provisioning umask. Do not relax its permissions for the lab account.
		command := "sudo -n sh -eu -c " + nativeQuote(probe.script)
		if _, err := vm.run(ctx, command, nil, 4096, time.Minute); err != nil {
			return fmt.Errorf("%s installed %s: %w", spec.label, probe.label, err)
		}
	}
	return nil
}

// installerSourceMarkerPath records the authenticated installer digest inside
// the installed system, readable only by root.
const installerSourceMarkerPath = "/etc/lindm-lab-installer-source"

func installerSourceMarkerProbe(path, digest string) string {
	return "test \"$(cat -- " + nativeQuote(path) + ")\" = " + nativeQuote(digest)
}
