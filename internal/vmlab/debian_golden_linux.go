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
)

// debianInstalledImage derives a local immutable qcow2 from an authenticated
// installer, never from unsigned Debian cloud metadata. The caller reauthenticates
// the ISO even on reuse. Local disk digests detect cache corruption, not a vendor
// signature on our installed machine. Only owned staging is ever partitioned.
func debianInstalledImage(ctx context.Context, m *labv1.ImageManifest, source *VerifiedImage, cacheDir, workDir string, hardware VMHardwareOptions) (_ *VerifiedImage, err error) {
	if m.Distribution != "debian" || (m.Version != "12" && m.Version != "13") || m.Edition != "netinst" || !strings.HasSuffix(m.ImageFilename, "-netinst.iso") || m.ChecksumMode != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		return nil, errors.New("debian installed image requires a signed Debian 12 or 13 netinst manifest")
	}
	if hardware.Firmware == nil {
		return nil, errors.New("debian netinst requires explicit UEFI firmware code, variables, package and version")
	}
	root, err := openCache(ctx, filepath.Join(cacheDir, "debian-installed"), true)
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
	identity := strings.Join([]string{debianInstallerRecipeVersion, source.SHA256, m.Version, hardware.Architecture, hardware.StorageBus, codeDigest, varsDigest, hardware.Firmware.Package, hardware.Firmware.Version, fmt.Sprint(hardware.Firmware.SecureBoot)}, "\n")
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
		return loadDebianInstalledImage(ctx, root, entry)
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
	_, loginPublic, err := encryptedKey()
	if err != nil {
		return nil, err
	}
	hostPrivate, hostPublic, err := encryptedKey()
	if err != nil {
		return nil, err
	}
	recipe, err := debianInstallerRecipe(m.Version, debianInstallerDisk(hardware.StorageBus), hardware.Architecture, source.SHA256, loginPublic, string(hostPrivate), hostPublic)
	if err != nil {
		return nil, err
	}
	// Pin the exact verified descriptor during remastering. A pathname rename
	// cannot switch media between the digest check and xorriso's inherited fd.
	iso, err := openRegular(source.Path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, iso.Close()) }()
	actual, err := digestDebianImage(ctx, iso)
	if err != nil {
		return nil, err
	}
	if actual.SHA256 != source.SHA256 || actual.Size != source.Size {
		return nil, errors.New("verified Debian installer changed before remastering")
	}
	installer, err := prepareInstallerFileForMachine(ctx, dir, iso, "debian", recipe, hardware.Architecture)
	if err != nil {
		return nil, err
	}
	if _, err := hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "image", "24G"); err != nil {
		return nil, err
	}
	if err := runDebianInstaller(ctx, dir, installer, hardware); err != nil {
		return nil, err
	}
	if err := validateDebianInstallation(ctx, filepath.Join(dir, "image"), workDir, m, hardware); err != nil {
		return nil, err
	}
	image, err := openRegular(filepath.Join(dir, "image"))
	if err != nil {
		return nil, err
	}
	result, hashErr := digestDebianImage(ctx, image)
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

func digestDebianImage(ctx context.Context, file *os.File) (*VerifiedImage, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > 32<<30 {
		return nil, errors.New("debian image size must be positive and at most 32 GiB")
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
		return nil, errors.New("debian image changed while hashing")
	}
	return &VerifiedImage{SHA256: hex.EncodeToString(digest.Sum(nil)), Size: count}, nil
}

func loadDebianInstalledImage(ctx context.Context, root *os.Root, entry string) (_ *VerifiedImage, err error) {
	info, err := root.Lstat(entry)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("debian installed cache entry must be a directory")
	}
	pin, err := readCacheFile(root, entry+"/sha256", 65)
	if err != nil {
		return nil, err
	}
	if len(pin) != 65 || pin[64] != '\n' {
		return nil, errors.New("invalid Debian installed cache pin")
	}
	path := filepath.Join(root.Name(), entry, "image")
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	result, err := digestDebianImage(ctx, file)
	if err != nil {
		return nil, err
	}
	if result.SHA256 != string(pin[:64]) {
		return nil, errors.New("debian installed cache digest mismatch; inspect before explicit removal")
	}
	result.Path = path
	return result, nil
}

func validateDebianInstallation(ctx context.Context, path, workDir string, m *labv1.ImageManifest, hardware VMHardwareOptions) (err error) {
	base, err := openRegular(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, base.Close()) }()
	// Prove an installed boot and fresh pinned NoCloud SSH, not merely an
	// installer process exit. Validation writes only a disposable overlay.
	hardware.AllowNetwork, hardware.TPM, hardware.Desktop, hardware.ExtraDisks = false, false, false, 0
	vm, err := newConfiguredGuestVM(ctx, base, workDir, false, &hardware)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	if err := vm.connect(ctx); err != nil {
		return fmt.Errorf("debian installed boot: %w", err)
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return fmt.Errorf("debian installed cloud_init: %w", err)
	}
	for _, probe := range []struct{ label, script string }{
		{"distribution", ". /etc/os-release; test \"$ID\" = debian"},
		{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(m.Version)},
		{"source_marker", debianSourceMarkerProbe("/etc/lindm-lab-installer-source", m.Sha256)},
		{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
		{"package_tool", "command -v dpkg-query >/dev/null"},
		{"privilege_tool", "command -v sudo >/dev/null"},
	} {
		// The source marker deliberately remains root-only under the installer
		// provisioning umask. Do not relax its permissions for the lab account.
		command := "sudo -n sh -eu -c " + nativeQuote(probe.script)
		if _, err := vm.run(ctx, command, nil, 4096, time.Minute); err != nil {
			return fmt.Errorf("debian installed %s: %w", probe.label, err)
		}
	}
	return nil
}

func debianSourceMarkerProbe(path, digest string) string {
	return "test \"$(cat -- " + nativeQuote(path) + ")\" = " + nativeQuote(digest)
}
