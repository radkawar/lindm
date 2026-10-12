//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// Bump when installer recipes or machine layout change. Cached installs are never
// edited in place; firmware bytes and signed ISO digest also bind the cache key.
const encryptedRecipeVersion = "encrypted-installer-v3"

type encryptedGoldenState struct {
	Dir      string                     `json:"-"`
	Secret   string                     `json:"secret"`
	LoginKey []byte                     `json:"login_key"`
	HostKey  []byte                     `json:"host_key"`
	Firmware *EncryptedFirmwareEvidence `json:"firmware"`
	Files    map[string]string          `json:"files"`
}

func encryptedKey() ([]byte, string, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func encryptedGolden(ctx context.Context, m *labv1.ImageManifest, opts EncryptedVMOptions) (_ *encryptedGoldenState, err error) {
	if err = validateManifest(m); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(m.ImageFilename, ".iso") {
		return nil, errors.New("encrypted lab requires an official installer ISO manifest")
	}
	media := encryptedInstallerMedia(m)
	if media.release.Lab.Installer == platform.ArchISO && opts.Firmware.SecureBoot {
		return nil, errors.New("official Arch installer has no vendor Secure Boot trust; select non-Secure-Boot firmware and qualify owner trust separately")
	}
	if media.release.Lab.Installer == platform.AutoYaST {
		if m.GetRepositorySnapshotManifestSha256() == "" {
			return nil, errors.New("encrypted AutoYaST requires a retained signed repository snapshot closure")
		}
		if _, err = tumbleweedInstallerImage(m); err != nil {
			return nil, err
		}
	}
	if err = media.release.Gate(platform.Encryption); err != nil {
		return nil, err
	}
	omarchy := media.release.Lab.Installer == platform.OmarchyCidata
	if omarchy {
		if err = omarchyEncryptedOptions(&opts, m); err != nil {
			return nil, err
		}
	}
	hardware, err := encryptedMachineHardware(m, opts)
	if err != nil {
		return nil, err
	}
	// The installer always builds the same portable virtio root with a TPM
	// wherever the guest kernel can observe one; test-only controller,
	// extra-disk and TPM-absent variants are overlay choices.
	hardware.StorageBus, hardware.ExtraDisks = "virtio-blk", 0
	hardware.TPM = encryptedGuestTPMObservable(m, hardware.Architecture)
	hardware.Desktop = opts.Desktop != ""
	if opts.CacheDir == "" {
		opts.CacheDir = ".cache/lab/images"
	}
	if opts.GoldenDir == "" {
		opts.GoldenDir = ".cache/lab/encrypted"
	}
	root, err := openCache(ctx, opts.GoldenDir, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	firmwareDir, err := os.MkdirTemp(root.Name(), ".firmware-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(firmwareDir)) }()
	fw, err := prepareEncryptedFirmware(ctx, firmwareDir, opts.Firmware)
	if err != nil {
		return nil, err
	}
	// Hash selected source bytes independently of temporary copied paths.
	codeDigest, err := encryptedFileDigest(filepath.Join(firmwareDir, "firmware-code.fd"))
	if err != nil {
		return nil, err
	}
	varsDigest, err := encryptedFileDigest(filepath.Join(firmwareDir, "nvram.fd"))
	if err != nil {
		return nil, err
	}
	id := encryptedGoldenID(m, opts, codeDigest, varsDigest, fw.OwnedDBCertificateSHA256, hardware.TPM)
	lock, err := lockImage(ctx, root, id)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	entry := filepath.Join(root.Name(), "golden-"+id)
	if _, err = os.Lstat(entry); err == nil {
		return loadEncryptedGolden(entry)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	references, referenceErr := os.ReadDir(filepath.Join(root.Name(), ".references", filepath.Base(entry)))
	if referenceErr != nil && !errors.Is(referenceErr, os.ErrNotExist) {
		return nil, referenceErr
	}
	if len(references) != 0 {
		return nil, errors.New("missing encrypted golden is referenced by persistent VMs; refusing replacement")
	}
	if opts.RequireCachedGolden {
		return nil, errors.New("pinned encrypted golden is absent; provision it explicitly with lab vm encrypted before read-only inspection")
	}
	verified, err := (Fetcher{}).Fetch(ctx, m, opts.CacheDir)
	if err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(root.Name(), ".install-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	state := &encryptedGoldenState{Dir: staging, Firmware: fw}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	state.Secret = hex.EncodeToString(secret)
	var loginPublic, hostPublic string
	state.LoginKey, loginPublic, err = encryptedKey()
	if err != nil {
		return nil, err
	}
	state.HostKey, hostPublic, err = encryptedKey()
	if err != nil {
		return nil, err
	}
	if err = copyEncryptedFile(filepath.Join(firmwareDir, "firmware-code.fd"), filepath.Join(staging, "firmware-code.fd"), 0444); err != nil {
		return nil, err
	}
	if err = copyEncryptedFile(filepath.Join(firmwareDir, "nvram.fd"), filepath.Join(staging, "nvram.fd"), 0600); err != nil {
		return nil, err
	}
	if err = os.Mkdir(filepath.Join(staging, "tpm"), 0700); err != nil {
		return nil, err
	}
	if _, err = hostCommand(ctx, staging, "qemu-img", nil, "create", "-f", "qcow2", "disk.qcow2", "24G"); err != nil {
		return nil, err
	}
	snapshot, err := startImageRepositorySnapshot(ctx, m, opts.CacheDir, "10.0.2.2")
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		defer func() { err = errors.Join(err, snapshot.Close()) }()
		media.snapshot = &tumbleweedSnapshotRepository{URL: snapshot.URL, CAPEM: snapshot.CAPEM}
	}
	config, err := encryptedSSHConfig(state.LoginKey, state.HostKey)
	if err != nil {
		return nil, err
	}
	vm := &EncryptedVM{dir: staging, config: config, firmware: fw, initialSecret: state.Secret, cacheDir: opts.CacheDir, hardware: hardware}
	defer func() { err = errors.Join(err, vm.Kill()) }()
	if omarchy {
		// Vendor cidata install on the unmodified ISO plus documented lab
		// provisioning; the generic first cold boot below still applies.
		if err = omarchyEncryptedInstall(ctx, m, staging, verified, hardware, state); err != nil {
			return nil, err
		}
	} else {
		recipe, err := encryptedInstallerRecipeForMachine(media, state.Secret, loginPublic, string(state.HostKey), hostPublic, opts.Desktop, opts.TPMBoot, hardware.Architecture)
		if err != nil {
			return nil, err
		}
		installer, err := prepareEncryptedInstallerForMachine(ctx, staging, verified.Path, media.release.Lab.Installer, recipe, hardware.Architecture)
		if err != nil {
			return nil, err
		}
		// Debian's netinst fetches its whole GNOME task from the signed archive
		// during installation; 45 minutes did not cover it on the shared lab link.
		installctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
		defer cancel()
		if err = vm.start(installctx, installer); err != nil {
			return nil, err
		}
		serial, err := vm.serial(installctx)
		if err != nil {
			return nil, err
		}
		console := io.Discard
		if opts.InstallerLog != "" {
			// Opt-in diagnostics only: the installer console can echo lab
			// configuration, so the log is a new owner-only file, never evidence.
			logFile, openErr := os.OpenFile(opts.InstallerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if openErr != nil {
				return nil, fmt.Errorf("create private installer console log: %w", openErr)
			}
			defer func() { err = errors.Join(err, logFile.Close()) }()
			console = &cappedWriter{w: logFile, remaining: maxInstallerLogBytes}
			vm.bootConsole = console
		}
		drained := make(chan struct{})
		go func() { _, _ = io.Copy(console, serial); close(drained) }()
		select {
		case <-installctx.Done():
			err = fmt.Errorf("encrypted installer deadline: %w", installctx.Err())
		case <-vm.guest.done:
			if !vm.guest.cmd.ProcessState.Success() {
				err = errors.New("encrypted installer QEMU exited unsuccessfully")
			}
		}
		closeErr := serial.Close()
		<-drained
		if err = errors.Join(err, closeErr, vm.Kill()); err != nil {
			return nil, err
		}
	}
	if _, err = vm.ColdBoot(ctx, state.Secret); err != nil {
		return nil, fmt.Errorf("first encrypted installed boot: %w", err)
	}
	if _, err = observeEncryptedGuest(ctx, vm, opts.Firmware.SecureBoot); err != nil {
		return nil, err
	}
	if omarchy {
		if err = omarchyEncryptedProbes(ctx, vm, m); err != nil {
			return nil, err
		}
	}
	shutdown, stop := context.WithTimeout(ctx, 2*time.Minute)
	err = vm.PowerOff(shutdown)
	stop()
	if err != nil {
		return nil, err
	}
	// Publish only machine state; recipes and modified installer media contain
	// credentials and are not evidence. The staged build is removed after copying.
	publish, err := os.MkdirTemp(root.Name(), ".publish-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(publish)) }()
	if err = copyEncryptedState(staging, publish); err != nil {
		return nil, err
	}
	if err = os.Rename(filepath.Join(staging, "disk.qcow2"), filepath.Join(publish, "disk.qcow2")); err != nil {
		return nil, err
	}
	state.Files, err = encryptedStateDigests(publish)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(publish, "state.json"), data, 0400); err != nil {
		return nil, err
	}
	for name := range state.Files {
		if err = os.Chmod(filepath.Join(publish, name), 0400); err != nil {
			return nil, err
		}
	}
	for name := range state.Files {
		file, openErr := openRegular(filepath.Join(publish, name))
		if openErr != nil {
			return nil, openErr
		}
		if err = errors.Join(file.Sync(), file.Close()); err != nil {
			return nil, err
		}
	}
	metadata, err := openRegular(filepath.Join(publish, "state.json"))
	if err != nil {
		return nil, err
	}
	if err = errors.Join(metadata.Sync(), metadata.Close()); err != nil {
		return nil, err
	}
	if err = syncDirectory(root, filepath.Base(publish)); err != nil {
		return nil, err
	}
	if err = os.Rename(publish, entry); err != nil {
		return nil, err
	}
	if err = syncDirectory(root, "."); err != nil {
		return nil, err
	}
	state.Dir = entry
	return state, nil
}

func loadEncryptedGolden(dir string) (*encryptedGoldenState, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("golden cache entry is not a directory")
	}
	data, err := readRegular(filepath.Join(dir, "state.json"), 1<<20)
	if err != nil {
		return nil, err
	}
	var state encryptedGoldenState
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	actual, err := encryptedStateDigests(dir)
	if err != nil {
		return nil, err
	}
	if len(actual) != len(state.Files) {
		return nil, errors.New("golden machine state changed; refusing cache reuse")
	}
	for name, digest := range actual {
		if state.Files[name] != digest {
			return nil, fmt.Errorf("golden machine state digest mismatch: %s", name)
		}
	}
	state.Dir = dir
	return &state, nil
}

func encryptedStateDigests(dir string) (map[string]string, error) {
	hashes := make(map[string]string)
	for _, name := range []string{"disk.qcow2", "firmware-code.fd", "nvram.fd", "tpm"} {
		err := filepath.WalkDir(filepath.Join(dir, name), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("symlink in encrypted machine state")
			}
			relative, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			digest, err := encryptedFileDigest(path)
			if err != nil {
				return err
			}
			hashes[relative] = digest
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return hashes, nil
}

func encryptedFileDigest(path string) (_ string, err error) {
	f, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyEncryptedFile(source, destination string, mode fs.FileMode) (err error) {
	sourceFile, err := openRegular(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, sourceFile.Close()) }()
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, destinationFile.Close()) }()
	if _, err = io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}
	return destinationFile.Sync()
}

func copyEncryptedState(source, destination string) error {
	names := []string{"firmware-code.fd", "nvram.fd", "tpm"}
	for _, name := range names {
		err := filepath.WalkDir(filepath.Join(source, name), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, relative)
			if d.IsDir() {
				return os.Mkdir(target, 0700)
			}
			if !d.Type().IsRegular() {
				return errors.New("nonregular encrypted machine state")
			}
			return copyEncryptedFile(path, target, 0600)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func encryptedConvert(ctx context.Context, dir, source, destination string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", source, destination)
	cmd.Dir = dir
	cmd.WaitDelay = 2 * time.Second
	log := new(vmLog)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("flatten encrypted snapshot: %w; %s", err, log.diagnostic(dir))
	}
	return os.Chmod(destination, 0600)
}

// maxInstallerLogBytes bounds an opt-in installer console log.
const maxInstallerLogBytes = 32 << 20

// cappedWriter keeps at most remaining bytes and silently drops the rest, so
// a chatty console is still drained without growing the log without bound.
type cappedWriter struct {
	w         io.Writer
	remaining int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if keep := min(int64(len(p)), c.remaining); keep > 0 {
		written, err := c.w.Write(p[:keep])
		c.remaining -= int64(written)
		if err != nil {
			return written, err
		}
	}
	return len(p), nil
}

// encryptedGoldenID binds every input that changes the installed machine. A
// TPM-absent golden (a tuple whose kernel cannot observe the attached TPM)
// gets its own dimension; the identities of TPM goldens are unchanged.
func encryptedGoldenID(m *labv1.ImageManifest, opts EncryptedVMOptions, codeDigest, varsDigest, ownedDBCertificateSHA256 string, tpm bool) string {
	ownedDBKey := ""
	if ownedDBCertificateSHA256 != "" {
		ownedDBKey = "\nowned-db:" + ownedDBCertificateSHA256
	}
	if !tpm {
		ownedDBKey += "\ntpm:absent"
	}
	// Installers whose recipe is versioned with the installed-image recipe
	// extend the version; existing goldens' identities are unchanged.
	recipeVersion := encryptedRecipeVersion
	switch platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.Installer {
	case platform.Ubiquity:
		recipeVersion += "\n" + mintEncryptedRecipeVersion
	case platform.OmarchyCidata:
		recipeVersion += "\n" + omarchyInstallerRecipeVersion
	}
	if platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.Installer == platform.ArchISO {
		ownedDBKey += "\narchiso-v2:" + m.GetEdition() + "\nrepository:" + m.GetRepositorySnapshotDate()
	}
	if platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.Installer == platform.AutoYaST {
		ownedDBKey += "\nautoyast-encrypted-v1\n" + tumbleweedInstallerRecipeVersion
	}
	if m.GetRepositorySnapshotManifestSha256() != "" {
		ownedDBKey += "\nrepository-closure:" + m.GetRepositorySnapshotManifestSha256()
	}
	sum := sha256.Sum256([]byte(recipeVersion + "\n" + m.Sha256 + "\n" + codeDigest + "\n" + varsDigest + "\n" + opts.Firmware.Package + "\n" + opts.Firmware.Version + fmt.Sprint(opts.Firmware.SecureBoot) + "\n" + opts.Desktop + "\n" + fmt.Sprint(opts.TPMBoot) + ownedDBKey))
	return hex.EncodeToString(sum[:])
}
