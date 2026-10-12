package recoveryboot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/measuredtpm"
	"lindm/internal/custody"
	"lindm/internal/measuredboot"
	"lindm/internal/platform"
)

// Measured GRUB staging boots the unmodified vendor kernel through the stock
// shim+GRUB chain with an unsigned lindm initramfs. Nothing here is authority:
// the server verifies a fresh TPM quote before any start grant. The entry is
// added where the vendor GRUB already reads entries (a Boot Loader Spec file
// or grub.d's custom.cfg) and selected by that chain's native one-shot protocol.
// The BLS `~` prefix sorts last, leaving the ordinary default unchanged.
const (
	blsEntryPrefix     = "~lindm-recovery-"
	customEntryPrefix  = "lindm-recovery-"
	attestationPublic  = "attestation.pub"
	attestationPrivate = "attestation.priv"
	maximumBootEntry   = 64 << 10
	maximumGrubEnvList = 16 << 10
	maximumOSRelease   = 64 << 10
)

// GrubEnvRunner runs the platform's grub-editenv with args outside the
// executor sandbox and returns its bounded stdout. Only the executor supplies
// it; the editenv path comes from the platform registry, never a request.
type GrubEnvRunner func(ctx context.Context, editenv string, args ...string) ([]byte, error)

type measuredLayout struct {
	chain         platform.GRUBChain
	bootDirectory string
	entryDir      string
	entryID       string
	entryFile     string
	initrdFile    string
	bootFSUUID    string
	binding       *agentv1.RecoveryMeasuredBoot
}

// HostGRUBChain returns the registry's measured-recovery chain for this host's
// own os-release row. An unlisted release has none.
func HostGRUBChain() (platform.GRUBChain, error) {
	release, err := HostRecoveryPlatform()
	if err != nil {
		return platform.GRUBChain{}, err
	}
	return release.Quirks.RecoveryGRUB, nil
}

// HostRecoveryPlatform identifies the host's own bounded os-release record.
// Recovery callers share this lookup rather than inheriting a base distro's
// boot or owner-key requirements.
func HostRecoveryPlatform() (*platform.Release, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumOSRelease+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if len(data) > maximumOSRelease {
		return nil, errors.New("recoveryboot: os_release_too_large")
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	return platform.Identify(platform.OSRelease{ID: fields["ID"], VersionID: fields["VERSION_ID"], VariantID: fields["VARIANT_ID"]}), nil
}

func validChain(chain platform.GRUBChain) bool {
	if chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
		return chain.Editenv == "" && chain.BootDirectory != "" &&
			filepath.IsLocal(chain.ConfigDirectory) && strings.HasPrefix(chain.ConfigDirectory, "EFI/")
	}
	if chain.Editenv != "/usr/bin/grub2-editenv" && chain.Editenv != "/usr/bin/grub-editenv" {
		return false
	}
	switch chain.Entries {
	case platform.GRUBBLS:
		return true
	case platform.GRUBCustomConfig:
		return chain.ConfigDirectory == "grub" || chain.ConfigDirectory == "grub2"
	default:
		return false
	}
}

// currentGRUBBoot authenticates nothing; it reads what signed GRUB measured for
// this boot so staging reuses the exact vendor kernel GRUB path it loaded.
func currentGRUBBoot() (*measuredboot.Loaded, []measuredboot.Event, error) {
	data, err := measuredtpm.ReadEventLog()
	if err != nil {
		return nil, nil, err
	}
	events, err := measuredboot.ParseEventLog(data)
	if err != nil {
		return nil, nil, err
	}
	loaded, err := measuredboot.FinalGRUBBoot(events)
	if err != nil {
		return nil, nil, err
	}
	return loaded, events, nil
}

func measuredStageLayout(request StageRequest) (*measuredLayout, error) {
	if !uuidText(request.ActionID) || len(request.KernelSHA256) != sha256.Size || !validChain(request.GRUB) {
		return nil, errors.New("recoveryboot: invalid_measured_identity")
	}
	if err := rootDirectory(request.ESPPath); err != nil {
		return nil, err
	}
	layout := &measuredLayout{chain: request.GRUB, bootDirectory: request.ESPPath}
	switch request.GRUB.Entries {
	case platform.GRUBBLS, platform.GRUBBLSLoaderEntryOneShot:
		layout.entryDir = filepath.Join(request.ESPPath, "loader", "entries")
		layout.entryID = blsEntryPrefix + request.ActionID
		layout.entryFile = filepath.Join(layout.entryDir, layout.entryID+".conf")
	case platform.GRUBCustomConfig:
		layout.entryDir = filepath.Join(request.ESPPath, request.GRUB.ConfigDirectory)
		layout.entryID = customEntryPrefix + request.ActionID
		layout.entryFile = filepath.Join(layout.entryDir, "custom.cfg")
		var boot unix.Stat_t
		if err := unix.Stat(request.ESPPath, &boot); err != nil {
			return nil, err
		}
		uuid, err := bootFilesystemUUID(uint64(boot.Dev))
		if err != nil {
			return nil, err
		}
		layout.bootFSUUID = uuid
	}
	if err := rootDirectory(layout.entryDir); err != nil {
		return nil, err
	}
	current, _, err := currentGRUBBoot()
	if err != nil {
		return nil, fmt.Errorf("recoveryboot: measured_grub_boot_required: %w", err)
	}
	if !bytes.Equal(current.KernelSHA256, request.KernelSHA256) {
		return nil, errors.New("recoveryboot: measured_kernel_changed")
	}
	kernelFile, err := measuredKernelFile(request.ESPPath, request.GRUB, current.KernelPath)
	if err != nil {
		return nil, err
	}
	if err := matchesMeasuredKernel(kernelFile, request.KernelSHA256); err != nil {
		return nil, fmt.Errorf("recoveryboot: vendor_kernel_unavailable: %w", err)
	}
	options, err := measuredboot.KernelOptions(request.ActionID, request.SerialConsole)
	if err != nil {
		return nil, err
	}
	initrd := "lindm-recovery-" + request.ActionID + ".initrd"
	layout.initrdFile = filepath.Join(request.ESPPath, initrd)
	layout.binding = &agentv1.RecoveryMeasuredBoot{
		KernelSha256: bytes.Clone(request.KernelSHA256), KernelPath: current.KernelPath,
		KernelOptions: options, InitrdPath: path.Join(path.Dir(current.KernelPath), initrd),
	}
	if request.GRUB.Entries == platform.GRUBBLSLoaderEntryOneShot {
		layout.binding.InitrdPath = "/" + initrd
	}
	return layout, nil
}

// entry is the complete staged GRUB configuration. Both forms load exactly one
// kernel and one initramfs and run nothing after the initrd command, which is
// the sequence the server requires in the quoted event log.
func (l *measuredLayout) entry() []byte {
	if l.chain.Entries == platform.GRUBCustomConfig {
		// --unrestricted mirrors vendor entries: a GRUB superuser password
		// must not block the unattended one-shot boot. The explicit device
		// makes GRUB measure the same device-qualified paths as blscfg.
		return []byte("# lindm original-device recovery; removed by lindm rollback\nmenuentry 'lindm recovery " + strings.TrimPrefix(l.entryID, customEntryPrefix) + "' --unrestricted --id '" + l.entryID + "' {\n\tsearch --no-floppy --fs-uuid --set=root " + l.bootFSUUID + "\n\tlinux ($root)" + l.binding.GetKernelPath() + " " + l.binding.GetKernelOptions() + "\n\tinitrd ($root)" + l.binding.GetInitrdPath() + "\n}\n")
	}
	return []byte("title lindm recovery " + strings.TrimPrefix(l.entryID, blsEntryPrefix) + "\nversion lindm-recovery\nlinux " + l.binding.GetKernelPath() + "\ninitrd " + l.binding.GetInitrdPath() + "\noptions " + l.binding.GetKernelOptions() + "\ngrub_users $grub_users\ngrub_arg --unrestricted\ngrub_class lindm\n")
}

// bootCapacity accepts GRUB-readable writable Linux filesystems and FAT.
func bootCapacity(directory string, imageSize int64) (needed, available uint64, err error) {
	if err := rootDirectory(directory); err != nil {
		return 0, 0, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(directory, &filesystem); err != nil {
		return 0, 0, fmt.Errorf("recoveryboot: stat boot capacity: %w", err)
	}
	switch filesystem.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.MSDOS_SUPER_MAGIC:
	default:
		return 0, 0, errors.New("recoveryboot: qualified_boot_filesystem_required")
	}
	if filesystem.Flags&unix.ST_RDONLY != 0 {
		return 0, 0, errors.New("recoveryboot: writable_boot_filesystem_required")
	}
	filesystem.Type = unix.MSDOS_SUPER_MAGIC
	return espCapacity(imageSize, filesystem)
}

func readGrubEnv(ctx context.Context, run GrubEnvRunner, chain platform.GRUBChain) (map[string]string, error) {
	if run == nil {
		return nil, errors.New("recoveryboot: grub_environment_runner_required")
	}
	output, err := run(ctx, chain.Editenv, "-", "list")
	if err != nil {
		return nil, err
	}
	if len(output) > maximumGrubEnvList {
		return nil, errors.New("recoveryboot: grub_environment_too_large")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("recoveryboot: invalid_grub_environment")
		}
		values[key] = value
	}
	return values, nil
}

// measuredSnapshot covers every entry source the vendor GRUB reads (all BLS
// entries, or grub.cfg plus custom.cfg) and the GRUB selection variables.
// Boot-success counters are excluded because the ordinary OS updates them.
func measuredSnapshot(ctx context.Context, layout *measuredLayout, request StageRequest, staged bool) ([]byte, error) {
	hash := sha256.New()
	var files []string
	switch layout.chain.Entries {
	case platform.GRUBBLS, platform.GRUBBLSLoaderEntryOneShot:
		entries, err := os.ReadDir(layout.entryDir)
		if err != nil {
			return nil, err
		}
		if len(entries) > 1024 {
			return nil, errors.New("recoveryboot: too_many_boot_entries")
		}
		for _, entry := range entries {
			name := filepath.Join(layout.entryDir, entry.Name())
			if strings.HasPrefix(entry.Name(), "~") && (!staged || name != layout.entryFile) {
				return nil, errors.New("recoveryboot: foreign_last_sorted_entry")
			}
			files = append(files, name)
		}
	case platform.GRUBCustomConfig:
		files = append(files, filepath.Join(layout.entryDir, "grub.cfg"))
		if _, err := os.Lstat(layout.entryFile); err == nil {
			if !staged {
				return nil, errors.New("recoveryboot: foreign_custom_config")
			}
			files = append(files, layout.entryFile)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	default:
		return nil, errors.New("recoveryboot: invalid_measured_identity")
	}
	for _, name := range files {
		info, err := os.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > maximumBootEntry {
			return nil, errors.New("recoveryboot: unsafe_boot_entry")
		}
		digest, _, err := digestFile(name)
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(hash, "%s %x\n", filepath.Base(name), digest); err != nil {
			return nil, err
		}
	}
	if layout.chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
		snapshot, err := loaderEntrySnapshot(layout.bootDirectory, layout.chain, readEFString)
		if err != nil {
			return nil, err
		}
		hash.Write(snapshot)
	} else {
		env, err := readGrubEnv(ctx, request.GrubEnv, layout.chain)
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"next_entry", "saved_entry", "env_block"} {
			if _, err := fmt.Fprintf(hash, "%s=%s\n", key, env[key]); err != nil {
				return nil, err
			}
		}
	}
	if staged {
		if layout.chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
			kernel, err := measuredKernelFile(layout.bootDirectory, layout.chain, layout.binding.GetKernelPath())
			if err != nil {
				return nil, err
			}
			if err := matchesMeasuredKernel(kernel, request.KernelSHA256); err != nil {
				return nil, err
			}
		}
		for _, file := range []Ingredient{{Source: layout.initrdFile, SHA256: request.ImageSHA256}, {Source: layout.entryFile, SHA256: digestBytes(layout.entry())}} {
			if err := approved(file); err != nil {
				return nil, fmt.Errorf("recoveryboot: staged_artifact_digest_changed: %w", err)
			}
		}
	}
	return hash.Sum(nil), nil
}

func digestBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func secureBootEnforced() error {
	enabled, err := readinessSecureBoot(os.ReadFile)
	if err != nil || !enabled {
		return errors.Join(errors.New("recoveryboot: secure_boot_required"), err)
	}
	return nil
}

func preflightMeasured(ctx context.Context, request StageRequest) (*measuredLayout, error) {
	if os.Geteuid() != 0 || !uuidText(request.ActionID) || !uuidText(request.SourceBootID) || request.ImageSize <= 0 || request.TrustedTPMCustody != nil {
		return nil, errors.New("recoveryboot: invalid_stage_identity")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(boot)) != request.SourceBootID {
		return nil, errors.New("recoveryboot: source_boot_changed")
	}
	if _, _, err := bootCapacity(request.ESPPath, request.ImageSize); err != nil {
		return nil, err
	}
	if err := offTargetState(request.StateDirectory, request.TargetDevices); err != nil {
		return nil, err
	}
	if request.GRUB.Entries == platform.GRUBBLSLoaderEntryOneShot {
		if _, err := loaderEntryTopology(request.ESPPath); err != nil {
			return nil, err
		}
	}
	if err := secureBootEnforced(); err != nil {
		return nil, err
	}
	tpmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := measuredtpm.Available(tpmCtx); err != nil {
		return nil, fmt.Errorf("recoveryboot: tpm_attestation_unavailable: %w", err)
	}
	layout, err := measuredStageLayout(request)
	if err != nil {
		return nil, err
	}
	if err := VerifyImage(ctx, request.ImagePath, request.ImageSHA256); err != nil {
		return nil, err
	}
	info, err := os.Stat(request.ImagePath)
	if err != nil {
		return nil, err
	}
	if info.Size() != request.ImageSize {
		return nil, errors.New("recoveryboot: image_size_mismatch")
	}
	oneShot, err := measuredOneShot(ctx, request)
	if err != nil {
		return nil, err
	}
	if oneShot != "" {
		return nil, errors.New("recoveryboot: unrelated_oneshot_present")
	}
	if _, err := measuredSnapshot(ctx, layout, request, false); err != nil {
		return nil, err
	}
	for _, name := range []string{layout.entryFile, layout.initrdFile} {
		if _, err := os.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return nil, errors.Join(errors.New("recoveryboot: staged_path_occupied"), err)
		}
	}
	return layout, nil
}

// PrepareMeasured creates the restricted TPM attestation key and returns the
// binding the device signs into the handoff. Only TPM-wrapped key blobs are
// written, on the already qualified off-target state volume.
func PrepareMeasured(ctx context.Context, request StageRequest) (*agentv1.RecoveryMeasuredBoot, error) {
	if request.BootMode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		return nil, errors.New("recoveryboot: measured_boot_mode_required")
	}
	layout, err := preflightMeasured(ctx, request)
	if err != nil {
		return nil, err
	}
	tpmCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	public, private, err := measuredtpm.CreateAttestationKey(tpmCtx)
	if err != nil {
		return nil, fmt.Errorf("recoveryboot: create attestation key: %w", err)
	}
	if err := writeExclusive(filepath.Join(request.StateDirectory, attestationPublic), public, 0400); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(request.StateDirectory, attestationPrivate), private, 0400); err != nil {
		return nil, err
	}
	if err := syncDirectory(request.StateDirectory); err != nil {
		return nil, err
	}
	layout.binding.AttestationKeyPublic = public
	return layout.binding, nil
}

// LoadAttestationKey returns the TPM-wrapped blobs whose public area matches
// the authenticated handoff. The private blob is useless outside this TPM.
func LoadAttestationKey(stateDirectory string, expectedPublic []byte) (public, private []byte, err error) {
	if err := custody.PrivateDirectory(stateDirectory); err != nil {
		return nil, nil, err
	}
	read := func(name string) ([]byte, error) {
		fd, err := unix.Open(filepath.Join(stateDirectory, name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), name)
		defer func() { err = errors.Join(err, file.Close()) }()
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > 4096 {
			return nil, errors.New("recoveryboot: unsafe_attestation_key")
		}
		return io.ReadAll(io.LimitReader(file, 4096))
	}
	if public, err = read(attestationPublic); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(public, expectedPublic) {
		return nil, nil, errors.New("recoveryboot: attestation_key_binding_rejected")
	}
	if private, err = read(attestationPrivate); err != nil {
		return nil, nil, err
	}
	return public, private, nil
}

func stageMeasured(ctx context.Context, request StageRequest) (*Staged, error) {
	layout, err := preflightMeasured(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(request.CredentialPublicKey) != 32 {
		return nil, errors.New("recoveryboot: one_action_credential_required")
	}
	key, err := LoadKey(filepath.Join(request.StateDirectory, "action.key"))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if err := credentialMatches(key, request.CredentialPublicKey); err != nil {
		return nil, err
	}
	if _, _, err := LoadAttestationKey(request.StateDirectory, request.AttestationKeyPublic); err != nil {
		return nil, err
	}
	if err := copyESPImage(request, layout.initrdFile, bootCapacity); err != nil {
		return nil, err
	}
	if err := writeExclusive(layout.entryFile, layout.entry(), 0600); err != nil {
		return nil, err
	}
	for _, directory := range []string{layout.entryDir, layout.bootDirectory} {
		if err := syncDirectory(directory); err != nil {
			return nil, err
		}
	}
	snapshot, err := measuredSnapshot(ctx, layout, request, true)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(request.StateDirectory, "boot-snapshot"), snapshot, 0400); err != nil {
		return nil, err
	}
	if err := syncDirectory(request.StateDirectory); err != nil {
		return nil, err
	}
	return &Staged{request: request, entry: layout.entryID, image: layout.initrdFile, snapshot: snapshot, measured: layout}, nil
}

func (s *Staged) armMeasured(ctx context.Context, beforeArm func(context.Context) error) error {
	if beforeArm == nil {
		return errors.New("recoveryboot: durable_arm_gate_required")
	}
	if err := secureBootEnforced(); err != nil {
		return err
	}
	for range 2 {
		current, err := measuredSnapshot(ctx, s.measured, s.request, true)
		if err != nil {
			return err
		}
		if string(current) != string(s.snapshot) {
			return errors.New("recoveryboot: boot_configuration_changed")
		}
		if err := beforeArm(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.measured.chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
		if err := native(ctx, nil, "bootctl", "--esp-path="+s.request.ESPPath, "set-oneshot", s.entry); err != nil {
			return err
		}
		oneShot, err := measuredOneShot(ctx, s.request)
		if err != nil {
			return err
		}
		if oneShot != s.entry {
			return errors.New("recoveryboot: oneshot_not_armed")
		}
		return nil
	}
	if s.request.GrubEnv == nil {
		return errors.New("recoveryboot: grub_environment_runner_required")
	}
	if _, err := s.request.GrubEnv(ctx, s.measured.chain.Editenv, "-", "set", "next_entry="+s.entry); err != nil {
		return err
	}
	env, err := readGrubEnv(ctx, s.request.GrubEnv, s.measured.chain)
	if err != nil {
		return err
	}
	if env["next_entry"] != s.entry {
		return errors.New("recoveryboot: oneshot_not_armed")
	}
	return nil
}

func (s *Staged) rollbackMeasured(ctx context.Context) error {
	oneShot, err := measuredOneShot(ctx, s.request)
	if err != nil {
		return err
	}
	switch oneShot {
	case "":
	case s.entry:
		if s.measured.chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
			if err := native(ctx, nil, "bootctl", "--esp-path="+s.request.ESPPath, "set-oneshot", ""); err != nil {
				return err
			}
		} else if _, err := s.request.GrubEnv(ctx, s.measured.chain.Editenv, "-", "unset", "next_entry"); err != nil {
			return err
		}
	default:
		return errors.New("recoveryboot: oneshot_ownership_changed")
	}
	if err := approved(Ingredient{Source: s.measured.entryFile, SHA256: digestBytes(s.measured.entry())}); err != nil {
		return err
	}
	if err := VerifyImage(ctx, s.image, s.request.ImageSHA256); err != nil {
		return err
	}
	if err := os.Remove(s.measured.entryFile); err != nil {
		return err
	}
	if err := os.Remove(s.image); err != nil {
		return err
	}
	return errors.Join(syncDirectory(s.measured.entryDir), syncDirectory(s.measured.bootDirectory))
}

// ObserveMeasuredReadiness reports measured-GRUB facts. An unlisted release, a
// missing TPM resource manager or a boot without GRUB measurements is the
// explicit capability gate, never a fallback.
func ObserveMeasuredReadiness(ctx context.Context, bootDirectory string) (Readiness, error) {
	result := Readiness{BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if os.Geteuid() != 0 {
		return result, errors.New("recovery_readiness_root_required")
	}
	chain, err := HostGRUBChain()
	if err != nil || !validChain(chain) {
		return result, errors.New("recovery_readiness_measured_grub_unsupported")
	}
	switch chain.Entries {
	case platform.GRUBBLS, platform.GRUBBLSLoaderEntryOneShot:
		if err := rootDirectory(filepath.Join(bootDirectory, "loader", "entries")); err != nil {
			return result, errors.New("recovery_readiness_bls_entries_unavailable")
		}
	case platform.GRUBCustomConfig:
		// grub.d's 41_custom must have emitted its custom.cfg source into the
		// installed grub.cfg; the entry is never added by regenerating it.
		config, err := custody.ReadRoot(filepath.Join(bootDirectory, chain.ConfigDirectory, "grub.cfg"), maximumBootEntry, false)
		if err != nil || !bytes.Contains(config, []byte("/custom.cfg")) {
			return result, errors.New("recovery_readiness_grub_custom_unavailable")
		}
	}
	if chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
		if result.ESPUUID, err = loaderEntryTopology(bootDirectory); err != nil {
			return result, err
		}
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(bootDirectory, &filesystem); err != nil {
		return result, errors.New("recovery_readiness_boot_unreadable")
	}
	if !slices.Contains([]int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.MSDOS_SUPER_MAGIC}, int64(filesystem.Type)) {
		return result, errors.New("recovery_readiness_boot_filesystem_unsupported")
	}
	filesystem.Type = unix.MSDOS_SUPER_MAGIC
	if result.FreeBytes, result.AllocationUnitBytes, err = readinessCapacity(filesystem); err != nil {
		return result, err
	}
	if result.SecureBoot, err = readinessSecureBoot(os.ReadFile); err != nil {
		return result, err
	}
	tpmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := measuredtpm.Available(tpmCtx); err != nil {
		return result, errors.New("recovery_readiness_tpm_attestation_unavailable")
	}
	current, events, err := currentGRUBBoot()
	if err != nil {
		return result, errors.New("recovery_readiness_measured_grub_required")
	}
	if err := measuredboot.SecureBootEnabled(events); err != nil {
		return result, errors.New("recovery_readiness_secure_boot_unmeasured")
	}
	kernelFile, err := measuredKernelFile(bootDirectory, chain, current.KernelPath)
	if err != nil || matchesMeasuredKernel(kernelFile, current.KernelSHA256) != nil {
		return result, errors.New("recovery_readiness_vendor_kernel_changed")
	}
	if chain.Entries != platform.GRUBBLSLoaderEntryOneShot {
		if info, err := os.Stat(chain.Editenv); err != nil || !info.Mode().IsRegular() {
			return result, errors.New("recovery_readiness_grub_editenv_required")
		}
	}
	result.MeasuredKernelSHA256 = bytes.Clone(current.KernelSHA256)
	return result, ctx.Err()
}

// VerifyMeasuredBoot is local evidence inside the recovery initramfs: new boot,
// initramfs root, enforced Secure Boot and an event log whose final GRUB boot is
// exactly the handoff kernel, options and initramfs. The server's quote check,
// not this function, is the authority.
func VerifyMeasuredBoot(ctx context.Context, stateDirectory, actionID, sourceBootID string, measured *agentv1.RecoveryMeasuredBoot, imageSHA256 []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !uuidText(actionID) || !uuidText(sourceBootID) || measured == nil || len(imageSHA256) != sha256.Size {
		return "", errors.New("recoveryboot: invalid_boot_binding")
	}
	if err := custody.PrivateDirectory(stateDirectory); err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	bootID := strings.TrimSpace(string(boot))
	if !uuidText(bootID) || bootID == sourceBootID {
		return "", errors.New("recoveryboot: new_boot_required")
	}
	var root unix.Statfs_t
	if err := unix.Statfs("/", &root); err != nil {
		return "", err
	}
	if root.Type != unix.TMPFS_MAGIC && root.Type != unix.RAMFS_MAGIC {
		return "", errors.New("recoveryboot: initramfs_root_required")
	}
	if err := secureBootEnforced(); err != nil {
		return "", err
	}
	options, err := MeasuredKernelOptions()
	if err != nil {
		return "", err
	}
	if action, err := measuredboot.ActionFromKernelOptions(options); err != nil || action != actionID || options != measured.GetKernelOptions() {
		return "", errors.New("recoveryboot: loaded_options_mismatch")
	}
	current, events, err := currentGRUBBoot()
	if err != nil {
		return "", err
	}
	if err := measuredboot.SecureBootEnabled(events); err != nil {
		return "", err
	}
	if current.KernelPath != measured.GetKernelPath() || !bytes.Equal(current.KernelSHA256, measured.GetKernelSha256()) || current.KernelOptions != measured.GetKernelOptions() || current.InitrdPath != measured.GetInitrdPath() || !bytes.Equal(current.InitrdSHA256, imageSHA256) {
		return "", errors.New("recoveryboot: loaded_image_mismatch")
	}
	return bootID, nil
}

// MeasuredKernelOptions returns /proc/cmdline without GRUB's BOOT_IMAGE=
// prefix, which GRUB adds outside the measured kernel_cmdline options.
func MeasuredKernelOptions() (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return measuredOptions(data)
}

func measuredOptions(data []byte) (string, error) {
	if len(data) > 4096 {
		return "", errors.New("recoveryboot: kernel_options_too_long")
	}
	options := strings.TrimSuffix(string(data), "\n")
	if rest, ok := strings.CutPrefix(options, "BOOT_IMAGE="); ok {
		_, options, ok = strings.Cut(rest, " ")
		if !ok {
			return "", errors.New("recoveryboot: kernel_options_missing")
		}
	}
	return options, nil
}
