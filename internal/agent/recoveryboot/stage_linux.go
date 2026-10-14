// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"lindm/internal/custody"
	"lindm/internal/platform"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const loaderGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
const globalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
const efivars = "/sys/firmware/efi/efivars/"

type StageRequest struct {
	ImagePath           string
	ImageSHA256         []byte
	ImageSize           int64
	CertificatePath     string
	CertificateSHA256   []byte
	ESPPath             string
	StateDirectory      string
	ActionID            string
	SourceBootID        string
	TargetDevices       []string
	CredentialPublicKey []byte
	// TrustedTPMCustody is supplied only by the recoverycustody adapter. It must
	// verify the reserved TPM object/NV anchor binds this image, public key,
	// frozen targets and action. It is never a config/RPC boolean.
	TrustedTPMCustody func(context.Context) error
	CapsulePath       string
	CapsuleSHA256     []byte
	// BootMode selects UKI or measured GRUB. ESPPath is the registry's
	// vendor boot filesystem (/boot or the loader ESP). Measured GRUB needs
	// off-target custody and the chain's native one-shot selection protocol.
	BootMode             agentv1.RecoveryBootMode
	KernelSHA256         []byte
	SerialConsole        string
	AttestationKeyPublic []byte
	GRUB                 platform.GRUBChain
	GrubEnv              GrubEnvRunner
}

// Staged is an in-process handle, not an execution grant. Durable runtime state
// remains owned by recovery's journal. Arm never reboots the machine itself.
type Staged struct {
	request  StageRequest
	entry    string
	image    string
	snapshot []byte
	measured *measuredLayout
}

func VerifyImage(ctx context.Context, name string, digest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return approved(Ingredient{Source: name, SHA256: digest})
}

// Reboot requests the already-armed one-shot boot; it does not bypass init or
// retry a failed handoff. Callers durably consume BOOT authority first.
func Reboot(ctx context.Context) error {
	return native(ctx, nil, "systemctl", "reboot", "--no-block")
}

// CheckESPCapacity is a read-only check for the exact signed image size. Needed
// is rounded to filesystem allocation units; available excludes reserved blocks.
// It neither reserves space nor replaces Preflight's artifact and custody checks.
func CheckESPCapacity(espPath string, imageSize int64) (needed, available uint64, err error) {
	if err := rootDirectory(espPath); err != nil {
		return 0, 0, err
	}
	var esp unix.Statfs_t
	if err := unix.Statfs(espPath, &esp); err != nil {
		return 0, 0, fmt.Errorf("recoveryboot: stat ESP capacity: %w", err)
	}
	return espCapacity(imageSize, esp)
}

func espCapacity(imageSize int64, esp unix.Statfs_t) (needed, available uint64, err error) {
	if imageSize <= 0 {
		return 0, 0, errors.New("recoveryboot: invalid_image_size")
	}
	if esp.Type != unix.MSDOS_SUPER_MAGIC {
		return 0, 0, errors.New("recoveryboot: qualified_esp_required")
	}
	unit := esp.Frsize
	if unit == 0 {
		unit = esp.Bsize
	}
	if unit <= 0 {
		return 0, 0, errors.New("recoveryboot: invalid_esp_allocation_unit")
	}
	allocation := uint64(unit)
	blocks := uint64(imageSize) / allocation
	if uint64(imageSize)%allocation != 0 {
		blocks++
	}
	if blocks > ^uint64(0)/allocation || esp.Bavail > ^uint64(0)/allocation {
		return 0, 0, fmt.Errorf("recoveryboot: ESP capacity overflow: %w", unix.EOVERFLOW)
	}
	needed, available = blocks*allocation, esp.Bavail*allocation
	if needed > available {
		return needed, available, espInsufficient(needed, available, unix.ENOSPC)
	}
	return needed, available, nil
}

func espInsufficient(needed, available uint64, cause error) error {
	return fmt.Errorf("recoveryboot: device_action_esp_insufficient needed=%d available=%d: %w", needed, available, cause)
}

// Preflight authenticates the artifact, checks ESP capacity and qualifies
// off-target custody without creating a key, writing files, or changing boot state.
func Preflight(ctx context.Context, request StageRequest) error {
	if request.BootMode == agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		_, err := preflightMeasured(ctx, request)
		return err
	}
	if request.BootMode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI {
		return errors.New("recoveryboot: unsupported_boot_mode")
	}
	return preflight(ctx, request, CheckESPCapacity)
}

func preflight(ctx context.Context, request StageRequest, capacity func(string, int64) (uint64, uint64, error)) error {
	if os.Geteuid() != 0 || !uuidText(request.ActionID) || !uuidText(request.SourceBootID) || request.ImageSize <= 0 {
		return errors.New("recoveryboot: invalid_stage_identity")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != request.SourceBootID {
		return errors.New("recoveryboot: source_boot_changed")
	}
	if _, _, err := capacity(request.ESPPath, request.ImageSize); err != nil {
		return err
	}
	if request.TrustedTPMCustody != nil {
		if err := custody.PrivateDirectory(request.StateDirectory); err != nil {
			return err
		}
		if err := request.TrustedTPMCustody(ctx); err != nil {
			return err
		}
	} else if err := offTargetState(request.StateDirectory, request.TargetDevices); err != nil {
		return err
	}
	if err := approved(Ingredient{Source: request.CertificatePath, SHA256: request.CertificateSHA256}); err != nil {
		return err
	}
	if err := verifySecureBoot(request.CertificatePath); err != nil {
		return err
	}
	loader, err := readEFString("LoaderInfo", loaderGUID)
	if err != nil || !strings.HasPrefix(loader, "systemd-boot ") {
		return errors.New("recoveryboot: running_systemd_boot_required")
	}
	if err := VerifyImage(ctx, request.ImagePath, request.ImageSHA256); err != nil {
		return err
	}
	info, err := os.Stat(request.ImagePath)
	if err != nil {
		return err
	}
	if info.Size() != request.ImageSize {
		return errors.New("recoveryboot: image_size_mismatch")
	}
	if err := verifyAuthenticode(request.ImagePath, request.CertificatePath); err != nil {
		return err
	}
	one, err := readEFString("LoaderEntryOneShot", loaderGUID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if one != "" {
		return errors.New("recoveryboot: unrelated_oneshot_present")
	}
	if err := fixedDefault(request.ESPPath); err != nil {
		return err
	}
	if err := rootDirectory(filepath.Join(request.ESPPath, "EFI", "Linux")); err != nil {
		return err
	}
	_, err = bootSnapshot(request.ESPPath)
	return err
}

func Stage(ctx context.Context, request StageRequest) (*Staged, error) {
	request.ImageSHA256 = append([]byte(nil), request.ImageSHA256...)
	request.CertificateSHA256 = append([]byte(nil), request.CertificateSHA256...)
	request.CredentialPublicKey = append([]byte(nil), request.CredentialPublicKey...)
	request.CapsuleSHA256 = append([]byte(nil), request.CapsuleSHA256...)
	request.TargetDevices = append([]string(nil), request.TargetDevices...)
	request.KernelSHA256 = append([]byte(nil), request.KernelSHA256...)
	request.AttestationKeyPublic = append([]byte(nil), request.AttestationKeyPublic...)
	if request.BootMode == agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		return stageMeasured(ctx, request)
	}
	if err := Preflight(ctx, request); err != nil {
		return nil, err
	}
	if len(request.CredentialPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("recoveryboot: one_action_credential_required")
	}
	if request.TrustedTPMCustody == nil {
		key, err := LoadKey(filepath.Join(request.StateDirectory, "action.key"))
		if err != nil {
			return nil, err
		}
		defer clear(key)
		if err := credentialMatches(key, request.CredentialPublicKey); err != nil {
			return nil, err
		}
	} else if err := approved(Ingredient{Source: request.CapsulePath, SHA256: request.CapsuleSHA256}); err != nil {
		return nil, err
	}
	directory := filepath.Join(request.ESPPath, "EFI", "Linux")
	if err := rootDirectory(directory); err != nil {
		return nil, err
	}
	entry := "lindm-recovery-" + request.ActionID + ".efi"
	image := filepath.Join(directory, entry)
	if err := copyESPImage(request, image, CheckESPCapacity); err != nil {
		return nil, err
	}
	if request.TrustedTPMCustody != nil {
		capsule := filepath.Join(directory, "lindm-recovery-"+request.ActionID+".capsule")
		if err := copyApproved(Ingredient{Source: request.CapsulePath, SHA256: request.CapsuleSHA256}, capsule, 0600); err != nil {
			return nil, err
		}
	}
	snapshot, err := stagedSnapshot(request)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(request.StateDirectory, "boot-snapshot"), snapshot, 0400); err != nil {
		return nil, err
	}
	if err := copyApproved(Ingredient{Source: request.CertificatePath, SHA256: request.CertificateSHA256}, filepath.Join(request.StateDirectory, "image-signing.pem"), 0400); err != nil {
		return nil, err
	}
	if err := syncDirectory(directory); err != nil {
		return nil, err
	}
	if err := syncDirectory(request.StateDirectory); err != nil {
		return nil, err
	}
	return &Staged{request: request, entry: entry, image: image, snapshot: snapshot}, nil
}

func copyESPImage(request StageRequest, image string, capacity func(string, int64) (uint64, uint64, error)) error {
	needed, available, err := capacity(request.ESPPath, request.ImageSize)
	if err != nil {
		return err
	}
	if err := copyApproved(Ingredient{Source: request.ImagePath, SHA256: request.ImageSHA256}, image, 0600); err != nil {
		if errors.Is(err, unix.ENOSPC) {
			// A competing writer or directory growth can exhaust space after
			// preflight. Re-observe after copyApproved removes its partial file.
			_, current, capacityErr := capacity(request.ESPPath, request.ImageSize)
			if capacityErr == nil || errors.Is(capacityErr, unix.ENOSPC) {
				available = current
			} else {
				err = errors.Join(err, capacityErr)
			}
			return espInsufficient(needed, available, err)
		}
		return err
	}
	return nil
}

// Arm requires already durable BOOT consumption. beforeArm is a repeatable,
// read-only authority/freshness gate using CLOCK_BOOTTIME; it runs on both sides
// of the final image hash so suspend cannot extend a grant's lifetime.
func (s *Staged) Arm(ctx context.Context, beforeArm func(context.Context) error) error {
	if s.measured != nil {
		return s.armMeasured(ctx, beforeArm)
	}
	if err := VerifyImage(ctx, s.image, s.request.ImageSHA256); err != nil {
		return err
	}
	if err := approved(Ingredient{Source: s.request.CertificatePath, SHA256: s.request.CertificateSHA256}); err != nil {
		return err
	}
	if err := verifySecureBoot(s.request.CertificatePath); err != nil {
		return err
	}
	current, err := stagedSnapshot(s.request)
	if err != nil {
		return err
	}
	if string(current) != string(s.snapshot) {
		return errors.New("recoveryboot: boot_configuration_changed")
	}
	if s.request.TrustedTPMCustody != nil {
		if err := s.request.TrustedTPMCustody(ctx); err != nil {
			return err
		}
		if err := VerifyImage(ctx, filepath.Join(filepath.Dir(s.image), "lindm-recovery-"+s.request.ActionID+".capsule"), s.request.CapsuleSHA256); err != nil {
			return err
		}
	}
	if beforeArm == nil {
		return errors.New("recoveryboot: durable_arm_gate_required")
	}
	if err := beforeArm(ctx); err != nil {
		return err
	}
	// Bind the exact entry again after the authority check. The selected entry
	// name alone is not an image measurement.
	current, err = stagedSnapshot(s.request)
	if err != nil {
		return err
	}
	if string(current) != string(s.snapshot) {
		return errors.New("recoveryboot: staged_boot_changed_after_gate")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := beforeArm(ctx); err != nil {
		return err
	}
	return native(ctx, nil, "bootctl", "--esp-path="+s.request.ESPPath, "set-oneshot", s.entry)
}

// Rollback clears only our still-pending entry. If firmware consumed it, callers
// must retain UNKNOWN and must not infer that recovery ran or restart erasure.
func (s *Staged) Rollback(ctx context.Context) error {
	if s.measured != nil {
		return s.rollbackMeasured(ctx)
	}
	entry, err := readEFString("LoaderEntryOneShot", loaderGUID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if entry != "" && entry != s.entry {
		return errors.New("recoveryboot: oneshot_ownership_changed")
	}
	if entry == s.entry {
		if err := native(ctx, nil, "bootctl", "--esp-path="+s.request.ESPPath, "set-oneshot", ""); err != nil {
			return err
		}
	}
	if err := VerifyImage(ctx, s.image, s.request.ImageSHA256); err != nil {
		return err
	}
	if err := os.Remove(s.image); err != nil {
		return err
	}
	if s.request.TrustedTPMCustody != nil {
		capsule := filepath.Join(filepath.Dir(s.image), "lindm-recovery-"+s.request.ActionID+".capsule")
		if err := VerifyImage(ctx, capsule, s.request.CapsuleSHA256); err != nil {
			return err
		}
		if err := os.Remove(capsule); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(s.image))
}

// VerifyBoot observes a new boot, firmware enforcement, initramfs root and the
// EFI loader's selected entry plus systemd-stub identity. It is local boot
// evidence, not TPM attestation or proof against compromised root/firmware.
// The credential/journal MUST bind these expected fields before handoff.
func VerifyBoot(ctx context.Context, stateDirectory, actionID, sourceBootID string, imageSHA256, certificateSHA256 []byte) (string, error) {
	if !uuidText(actionID) || !uuidText(sourceBootID) {
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
	identifier, err := readEFString("LoaderEntrySelected", loaderGUID)
	if err != nil {
		return "", err
	}
	expected := "lindm-recovery-" + actionID + ".efi"
	if identifier != expected {
		return "", errors.New("recoveryboot: loaded_image_mismatch")
	}
	stub, err := readEFString("StubInfo", loaderGUID)
	if err != nil || !strings.HasPrefix(stub, "systemd-stub ") {
		return "", errors.New("recoveryboot: systemd_stub_required")
	}
	certificate := filepath.Join(stateDirectory, "image-signing.pem")
	if err := approved(Ingredient{Source: certificate, SHA256: certificateSHA256}); err != nil {
		return "", err
	}
	if err := verifySecureBoot(certificate); err != nil {
		return "", err
	}
	image := filepath.Join(stateDirectory, "booted.efi")
	if err := VerifyImage(ctx, image, imageSHA256); err != nil {
		return "", err
	}
	if err := verifyAuthenticode(image, certificate); err != nil {
		return "", err
	}
	return bootID, nil
}

func readEFString(name, guid string) (string, error) {
	data, err := os.ReadFile(efivars + name + "-" + guid)
	if err != nil {
		return "", err
	}
	if len(data) < 4 || len(data)%2 != 0 || len(data) > 65536 {
		return "", errors.New("recoveryboot: invalid_efi_variable")
	}
	words := make([]uint16, 0, (len(data)-4)/2)
	for i := 4; i < len(data); i += 2 {
		word := binary.LittleEndian.Uint16(data[i:])
		if word == 0 {
			break
		}
		words = append(words, word)
	}
	return string(utf16.Decode(words)), nil
}

func verifySecureBoot(certificate string) error {
	for _, variable := range []struct {
		name  string
		value byte
	}{{"SecureBoot", 1}, {"SetupMode", 0}} {
		data, err := os.ReadFile(efivars + variable.name + "-" + globalGUID)
		if err != nil {
			return err
		}
		if len(data) != 5 || data[4] != variable.value {
			return errors.New("recoveryboot: secure_boot_enforcement_required")
		}
	}
	cert, err := os.ReadFile(certificate)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("recoveryboot: single_signing_certificate_required")
	}
	db, err := os.ReadFile(efivars + "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	if err != nil {
		return err
	}
	if !certificateInDB(db, block.Bytes) {
		return errors.New("recoveryboot: signer_not_in_firmware_db")
	}
	return nil
}

func certificateInDB(data, certificate []byte) bool {
	// EFI_CERT_X509_GUID, encoded in EFI byte order.
	x509GUID := "\xa1\x59\xc0\xa5\xe4\x94\xa7\x4a\x87\xb5\xab\x15\x5c\x2b\xf0\x72"
	if len(data) < 4 {
		return false
	}
	data = data[4:]
	for len(data) > 0 {
		if len(data) < 28 {
			return false
		}
		size, header, signature := int(binary.LittleEndian.Uint32(data[16:])), int(binary.LittleEndian.Uint32(data[20:])), int(binary.LittleEndian.Uint32(data[24:]))
		if size < 28 || size > len(data) || header > size-28 || signature < 16 || (size-28-header)%signature != 0 {
			return false
		}
		if string(data[:16]) == x509GUID {
			for pos := 28 + header; pos < size; pos += signature {
				if string(data[pos+16:pos+signature]) == string(certificate) {
					return true
				}
			}
		}
		data = data[size:]
	}
	return false
}

func bootSnapshot(esp string) ([]byte, error) {
	hash := sha256.New()
	root := filepath.Join(esp, "loader")
	if err := rootDirectory(root); err != nil {
		return nil, err
	}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("recoveryboot: linked_boot_configuration")
		}
		digest, _, err := digestFile(name)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(hash, "%s %x\n", strings.TrimPrefix(name, esp), digest)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"LoaderEntryDefault", "LoaderEntryOneShot"} {
		value, err := readEFString(name, loaderGUID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if _, err := fmt.Fprintf(hash, "%s %s\n", name, value); err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func stagedSnapshot(request StageRequest) ([]byte, error) {
	config, err := bootSnapshot(request.ESPPath)
	if err != nil {
		return nil, err
	}
	artifacts, err := stagedArtifactSnapshot(request)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	if _, err := hash.Write(config); err != nil {
		return nil, err
	}
	if _, err := hash.Write(artifacts); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func stagedArtifactSnapshot(request StageRequest) ([]byte, error) {
	hash := sha256.New()
	files := []Ingredient{{Source: filepath.Join(request.ESPPath, "EFI", "Linux", "lindm-recovery-"+request.ActionID+".efi"), SHA256: request.ImageSHA256}}
	if request.TrustedTPMCustody != nil {
		files = append(files, Ingredient{Source: filepath.Join(request.ESPPath, "EFI", "Linux", "lindm-recovery-"+request.ActionID+".capsule"), SHA256: request.CapsuleSHA256})
	}
	for _, file := range files {
		info, err := os.Lstat(file.Source)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("recoveryboot: unsafe_staged_artifact")
		}
		digest, size, err := digestFile(file.Source)
		if err != nil {
			return nil, err
		}
		if !equalDigest(digest, file.SHA256) {
			return nil, errors.New("recoveryboot: staged_artifact_digest_changed")
		}
		if _, err := fmt.Fprintf(hash, "%s %d %x\n", filepath.Base(file.Source), size, digest); err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func credentialMatches(key ed25519.PrivateKey, expected []byte) error {
	if len(key) != ed25519.PrivateKeySize || len(expected) != ed25519.PublicKeySize || string(key[ed25519.SeedSize:]) != string(expected) {
		return errors.New("recoveryboot: one_action_credential_mismatch")
	}
	return nil
}

func fixedDefault(esp string) error {
	value, err := readEFString("LoaderEntryDefault", loaderGUID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if value == "" {
		data, err := os.ReadFile(filepath.Join(esp, "loader", "loader.conf"))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "default" {
				value = fields[1]
			}
		}
	}
	if value == "" || strings.ContainsAny(value, "*?[]@/\\") || strings.HasPrefix(value, "lindm-recovery-") {
		return errors.New("recoveryboot: fixed_ordinary_boot_default_required")
	}
	selected, err := readEFString("LoaderEntrySelected", loaderGUID)
	if err != nil {
		return err
	}
	if selected != value {
		return errors.New("recoveryboot: ordinary_default_not_current_entry")
	}
	return nil
}
