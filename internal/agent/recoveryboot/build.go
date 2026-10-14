// SPDX-License-Identifier: Apache-2.0

// Package recoveryboot builds closed recovery images and stages a single
// original-device handoff: a signed UKI through systemd-boot, or an unsigned
// initramfs with the vendor kernel through GRUB whose integrity the server
// verifies by TPM quote. It never authorizes an erase or treats staging as
// boot proof.
package recoveryboot

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
)

// Ingredient is a release-approved regular file. SHA256 is mandatory, including
// for kernel, stub, agent, configuration, certificates, libraries and modules.
type Ingredient struct {
	Source      string
	Destination string
	SHA256      []byte
	Executable  bool
}

// BuildRequest contains no device credential. Config is public recovery runtime
// configuration; one-action keys are provisioned separately on off-target media.
type BuildRequest struct {
	OutputDirectory string
	Kernel          Ingredient
	Stub            Ingredient
	// Agent is the static lindm-agent archived as the image's PID 1 (/init).
	Agent       Ingredient
	Config      Ingredient
	Files       []Ingredient
	SigningKey  string
	Certificate Ingredient
	StateUUID   string
	// ESPUUID identifies the prequalified FAT volume. The selected action is
	// discovered at boot; approved images never embed a future action ID.
	ESPUUID         string
	SourceDateEpoch int64
	// SerialConsole selects an optional signed diagnostic UART, not arbitrary
	// kernel arguments. The normal framebuffer console remains enabled. Measured
	// GRUB images take the console from staging options instead.
	SerialConsole string
	// BootMode selects a signed UKI or a measured-GRUB initramfs. Measured
	// builds take no stub, signing key or certificate and require StateUUID.
	BootMode agentv1.RecoveryBootMode
	// Ukify runs ukify with extra environment and arguments; nil runs the
	// custody-checked system /usr/bin/ukify. Only a lab build host without
	// systemd-ukify injects its privately provisioned, digest-pinned copy.
	Ukify func(ctx context.Context, env, args []string) error
}

type Artifact struct {
	Path              string
	SHA256            []byte
	Size              int64
	CertificateSHA256 []byte
	ClosurePath       string
	PCR11SHA256       []byte
	SizeEvidence      *SizeEvidence
	SizeEvidencePath  string
	// KernelSHA256 is the vendor kernel a measured initramfs was built for.
	KernelSHA256 []byte
}

func digestFile(name string) (_ []byte, size int64, err error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), size, nil
}

func approved(in Ingredient) error {
	info, err := os.Lstat(in.Source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("recoveryboot: unsafe_ingredient")
	}
	if len(in.SHA256) != sha256.Size {
		return errors.New("recoveryboot: ingredient_digest_required")
	}
	digest, _, err := digestFile(in.Source)
	if err != nil {
		return err
	}
	if !equalDigest(digest, in.SHA256) {
		return errors.New("recoveryboot: ingredient_digest_mismatch")
	}
	return nil
}

func equalDigest(a, b []byte) bool {
	return len(a) == sha256.Size && len(b) == sha256.Size && string(a) == string(b)
}

// Build runs only artifact tools against a newly owned private directory. It does
// not invoke bootctl, mount, TPM tools or change the running machine's firmware.
func Build(ctx context.Context, request BuildRequest) (_ *Artifact, err error) {
	if request.BootMode == agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		return buildMeasured(request)
	}
	if request.BootMode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI {
		return nil, errors.New("recoveryboot: unsupported_boot_mode")
	}
	if request.SourceDateEpoch < 0 || !fatUUID(request.ESPUUID) || (request.StateUUID != "" && !uuidText(request.StateUUID)) {
		return nil, errors.New("recoveryboot: invalid_build_identity")
	}
	commandLine, err := recoveryCommandLine(request.SerialConsole)
	if err != nil {
		return nil, err
	}
	inputs := []Ingredient{request.Kernel, request.Stub, request.Agent, request.Config, request.Certificate}
	inputs = append(inputs, request.Files...)
	for _, in := range inputs {
		if err := approved(in); err != nil {
			return nil, err
		}
	}
	if err := validateBuildClosure(request.Config, request.Files, request.BootMode); err != nil {
		return nil, err
	}
	if err := requireStaticAgent(request.Agent); err != nil {
		return nil, err
	}
	keyInfo, err := os.Lstat(request.SigningKey)
	if err != nil {
		return nil, err
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("recoveryboot: unsafe_signing_key")
	}
	// Mkdir, rather than MkdirAll, prohibits replacing an existing build.
	if err := os.Mkdir(request.OutputDirectory, 0700); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(request.OutputDirectory)
	if err != nil {
		return nil, err
	}
	// Copy approved bytes into the private build before invoking native tools.
	for i := range inputs {
		name := filepath.Join(dir, fmt.Sprintf("input-%04d", i))
		if err := copyApproved(inputs[i], name, 0600); err != nil {
			return nil, err
		}
		inputs[i].Source = name
	}
	request.Kernel, request.Stub, request.Agent, request.Config, request.Certificate = inputs[0], inputs[1], inputs[2], inputs[3], inputs[4]
	request.Files = inputs[5:]
	initrd := filepath.Join(dir, "recovery.initrd")
	closure, err := writeInitramfs(initrd, request)
	if err != nil {
		return nil, err
	}
	closurePath := filepath.Join(dir, "closure.txt")
	if err := writeExclusive(closurePath, []byte(closure), 0600); err != nil {
		return nil, err
	}
	osRelease := filepath.Join(dir, "os-release")
	if err := writeExclusive(osRelease, []byte("ID=lindm-recovery\nNAME=lindm-recovery\nVERSION_ID=1\n"), 0600); err != nil {
		return nil, err
	}
	unsigned := filepath.Join(dir, "unsigned.efi")
	image := filepath.Join(dir, "lindm-recovery.efi")
	ukify := request.Ukify
	if ukify == nil {
		ukify = func(ctx context.Context, env, args []string) error { return native(ctx, env, "ukify", args...) }
	}
	if err := ukify(ctx, []string{"SOURCE_DATE_EPOCH=" + strconv.FormatInt(request.SourceDateEpoch, 10)}, []string{"build", "--linux=" + request.Kernel.Source, "--initrd=" + initrd, "--stub=" + request.Stub.Source, "--cmdline=" + commandLine, "--os-release=@" + osRelease, "--output=" + unsigned}); err != nil {
		return nil, fmt.Errorf("recoveryboot: build unsigned UKI: %w", err)
	}
	if err := native(ctx, nil, "sbsign", "--key", request.SigningKey, "--cert", request.Certificate.Source, "--output", image, unsigned); err != nil {
		return nil, err
	}
	// The same Authenticode verifier that the device stager and recovery image
	// use checks the signed output against the approved certificate.
	if err := verifyAuthenticode(image, request.Certificate.Source); err != nil {
		return nil, err
	}
	digest, size, err := digestFile(image)
	if err != nil {
		return nil, err
	}
	pcr11, err := PredictPCR11(ctx, image, filepath.Join(dir, "measurement"))
	if err != nil {
		return nil, err
	}
	sizes, err := measureBuildSizes(request, initrd, image, size)
	if err != nil {
		return nil, err
	}
	sizes.SignedImageSHA256 = hex.EncodeToString(digest)
	sizePath := filepath.Join(dir, "component-sizes.json")
	if err := writeSizeEvidence(sizePath, sizes); err != nil {
		return nil, err
	}
	return &Artifact{Path: image, SHA256: digest, Size: size, CertificateSHA256: request.Certificate.SHA256, ClosurePath: closurePath, PCR11SHA256: pcr11, SizeEvidence: sizes, SizeEvidencePath: sizePath}, nil
}

// requireStaticAgent rejects a dynamically linked agent: it is PID 1 and must
// run before any loader or library exists.
func requireStaticAgent(agent Ingredient) error {
	binary, err := elf.Open(agent.Source)
	if err != nil {
		return fmt.Errorf("recoveryboot: executable ELF: %w", err)
	}
	dynamic := false
	for _, segment := range binary.Progs {
		if segment.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	if err := binary.Close(); err != nil {
		return err
	}
	if dynamic {
		return errors.New("recoveryboot: agent_must_be_static")
	}
	return nil
}

// buildMeasured emits the deterministic gzip initramfs itself as the release
// artifact. The vendor kernel is pinned by digest for its modules and the
// companion release descriptor; it is neither copied into nor signed with it.
func buildMeasured(request BuildRequest) (_ *Artifact, err error) {
	if request.SourceDateEpoch < 0 || request.ESPUUID != "" || !uuidText(request.StateUUID) || request.SerialConsole != "" || request.SigningKey != "" || request.Stub.Source != "" || request.Certificate.Source != "" {
		return nil, errors.New("recoveryboot: invalid_build_identity")
	}
	inputs := []Ingredient{request.Kernel, request.Agent, request.Config}
	inputs = append(inputs, request.Files...)
	for _, in := range inputs {
		if err := approved(in); err != nil {
			return nil, err
		}
	}
	if err := validateBuildClosure(request.Config, request.Files, request.BootMode); err != nil {
		return nil, err
	}
	if err := requireStaticAgent(request.Agent); err != nil {
		return nil, err
	}
	if err := os.Mkdir(request.OutputDirectory, 0700); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(request.OutputDirectory)
	if err != nil {
		return nil, err
	}
	for i := range inputs {
		name := filepath.Join(dir, fmt.Sprintf("input-%04d", i))
		if err := copyApproved(inputs[i], name, 0600); err != nil {
			return nil, err
		}
		inputs[i].Source = name
	}
	request.Kernel, request.Agent, request.Config = inputs[0], inputs[1], inputs[2]
	request.Files = inputs[3:]
	initrd := filepath.Join(dir, "lindm-recovery.initrd")
	closure, err := writeInitramfs(initrd, request)
	if err != nil {
		return nil, err
	}
	closurePath := filepath.Join(dir, "closure.txt")
	if err := writeExclusive(closurePath, []byte(closure), 0600); err != nil {
		return nil, err
	}
	digest, size, err := digestFile(initrd)
	if err != nil {
		return nil, err
	}
	sizes, err := measureBuildSizes(request, initrd, initrd, size)
	if err != nil {
		return nil, err
	}
	sizes.SignedImageSHA256 = hex.EncodeToString(digest)
	sizePath := filepath.Join(dir, "component-sizes.json")
	if err := writeSizeEvidence(sizePath, sizes); err != nil {
		return nil, err
	}
	return &Artifact{Path: initrd, SHA256: digest, Size: size, ClosurePath: closurePath, SizeEvidence: sizes, SizeEvidencePath: sizePath, KernelSHA256: append([]byte(nil), request.Kernel.SHA256...)}, nil
}

func recoveryCommandLine(serialConsole string) (string, error) {
	const base = "rdinit=/init panic=10 quiet"
	switch serialConsole {
	case "":
		return base, nil
	case "ttyS0,115200n8", "ttyAMA0,115200":
		return base + " console=tty0 console=" + serialConsole, nil
	default:
		return "", errors.New("recoveryboot: unsupported_serial_console")
	}
}

func copyApproved(in Ingredient, target string, mode os.FileMode) error {
	if err := approved(in); err != nil {
		return err
	}
	return withExclusiveFile(target, mode, func(out *os.File) (err error) {
		source, err := os.Open(in.Source)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, source.Close()) }()
		hash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(out, hash), source); err != nil {
			return err
		}
		if !equalDigest(hash.Sum(nil), in.SHA256) {
			return errors.New("recoveryboot: ingredient_changed")
		}
		return nil
	})
}

func writeExclusive(name string, data []byte, mode os.FileMode) error {
	return withExclusiveFile(name, mode, func(out *os.File) error {
		_, err := out.Write(data)
		return err
	})
}

func withExclusiveFile(name string, mode os.FileMode, write func(*os.File) error) (err error) {
	out, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	owned, statErr := out.Stat()
	defer func() { err = closeExclusive(out, owned, err) }()
	if statErr != nil {
		return statErr
	}
	if err := write(out); err != nil {
		return err
	}
	return out.Sync()
}

// closeExclusive removes a failed newly owned file, including sync/close failures,
// and durably records the removal. A failed O_EXCL open never reaches this helper.
func closeExclusive(out *os.File, owned os.FileInfo, err error) error {
	err = errors.Join(err, out.Close())
	if err == nil || owned == nil {
		return err
	}
	current, statErr := os.Lstat(out.Name())
	if errors.Is(statErr, os.ErrNotExist) {
		return errors.Join(err, syncDirectory(filepath.Dir(out.Name())))
	}
	if statErr != nil {
		return errors.Join(err, statErr)
	}
	if !os.SameFile(owned, current) {
		return errors.Join(err, errors.New("recoveryboot: exclusive_file_ownership_changed"))
	}
	if removeErr := os.Remove(out.Name()); removeErr != nil {
		return errors.Join(err, removeErr)
	}
	return errors.Join(err, syncDirectory(filepath.Dir(out.Name())))
}

// Output is bounded and deliberately excludes private-key contents and native
// stdout/stderr from errors. Standard tools authenticate their own formats.
func native(ctx context.Context, extraEnv []string, command string, args ...string) error {
	switch command {
	case "ukify", "sbsign", "bootctl", "systemctl":
	default:
		return errors.New("recoveryboot: unapproved_native_tool")
	}
	if _, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: "/usr/bin/" + command, Args: args, Env: extraEnv,
		Timeout: 90 * time.Second, StdoutLimit: 64 << 10, StderrLimit: 64 << 10,
	}); err != nil {
		return fmt.Errorf("recoveryboot: %s: %w", command, err)
	}
	return nil
}

func uuidText(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func writeInitramfs(name string, request BuildRequest) (_ string, err error) {
	files := []Ingredient{request.Agent, request.Config}
	files[0].Destination, files[0].Executable = "init", true
	files[1].Destination, files[1].Executable = "etc/lindm/recovery.json", false
	// A measured image is proven by TPM quote; it carries no UKI signer.
	if request.BootMode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		certificate := request.Certificate
		certificate.Destination, certificate.Executable = "etc/lindm/image-signing.pem", false
		files = append(files, certificate)
	}
	files = append(files, request.Files...)
	// The initramfs root may start with tmpfs's replaceable default mode.
	// Archive "." explicitly so every protected configuration ancestor is
	// root-owned mode 0755, including the root itself.
	dirs := map[string]bool{".": true, "dev": true, "proc": true, "sys": true, "run": true, "tmp": true, "etc": true, "etc/lindm": true}
	seen := map[string]bool{initParamsPath: true}
	for _, node := range recoveryDeviceNodes {
		seen[node.name] = true
	}
	for _, in := range files {
		if path.Clean(in.Destination) != in.Destination || strings.HasPrefix(in.Destination, "/") || in.Destination == "." || strings.HasPrefix(in.Destination, "../") || seen[in.Destination] {
			return "", errors.New("recoveryboot: invalid_closure_path")
		}
		seen[in.Destination] = true
		for p := path.Dir(in.Destination); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	for dir := range dirs {
		if seen[dir] {
			return "", errors.New("recoveryboot: closure_path_collision")
		}
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	owned, statErr := f.Stat()
	defer func() { err = closeExclusive(f, owned, err) }()
	if statErr != nil {
		return "", statErr
	}
	compressed, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	// The gzip header has no timestamp or filename; the archive epoch below
	// comes only from the approved build request, never the host wall clock.
	defer func() {
		err = errors.Join(err, compressed.Close())
		if err == nil {
			err = f.Sync()
		}
	}()
	names := make([]string, 0, len(dirs))
	for dir := range dirs {
		names = append(names, dir)
	}
	sort.Strings(names)
	var inode uint32
	for _, dir := range names {
		inode++
		if err := cpioEntry(compressed, inode, dir, 0040755, 0, request.SourceDateEpoch, strings.NewReader("")); err != nil {
			return "", err
		}
	}
	// The kernel opens /dev/console for PID 1's standard streams before init
	// runs; Go's runtime otherwise requires /dev/null for closed descriptors.
	// Both static nodes are hidden once init mounts devtmpfs over /dev.
	for _, node := range recoveryDeviceNodes {
		inode++
		if err := cpioHeader(compressed, inode, node.name, node.mode, 0, request.SourceDateEpoch, node.major, node.minor); err != nil {
			return "", err
		}
	}
	params := initParamsFor(request).render()
	inode++
	if err := cpioEntry(compressed, inode, initParamsPath, 0100600, int64(len(params)), request.SourceDateEpoch, strings.NewReader(params)); err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Destination < files[j].Destination })
	var closure strings.Builder
	fmt.Fprintf(&closure, "lindm-recovery-closure-v2\nepoch %d\nstate_uuid %s\nkernel %x\nstub %x\ncertificate %x\ninit_parameters %x\n", request.SourceDateEpoch, request.StateUUID, request.Kernel.SHA256, request.Stub.SHA256, request.Certificate.SHA256, sha256.Sum256([]byte(params)))
	fmt.Fprintf(&closure, "esp_uuid %s\nboot_mode %s\n", request.ESPUUID, request.BootMode)
	for _, node := range recoveryDeviceNodes {
		fmt.Fprintf(&closure, "device %s %o %d:%d\n", node.name, node.mode, node.major, node.minor)
	}
	for _, in := range files {
		if err := approved(in); err != nil {
			return "", err
		}
		input, err := os.Open(in.Source)
		if err != nil {
			return "", err
		}
		info, statErr := input.Stat()
		if statErr != nil {
			return "", errors.Join(statErr, input.Close())
		}
		mode := uint32(0100600)
		if in.Executable {
			mode = 0100700
		}
		inode++
		err = cpioEntry(compressed, inode, in.Destination, mode, info.Size(), request.SourceDateEpoch, input)
		if err = errors.Join(err, input.Close()); err != nil {
			return "", err
		}
		fmt.Fprintf(&closure, "%s %d %s\n", hex.EncodeToString(in.SHA256), info.Size(), in.Destination)
	}
	inode++
	if err := cpioEntry(compressed, inode, "TRAILER!!!", 0, 0, 0, strings.NewReader("")); err != nil {
		return "", err
	}
	return closure.String(), nil
}

// recoveryDeviceNodes are the only non-directory entries not taken from an
// approved ingredient: the kernel console and null character devices.
var recoveryDeviceNodes = []struct {
	name         string
	mode         uint32
	major, minor uint32
}{{"dev/console", 0020600, 5, 1}, {"dev/null", 0020666, 1, 3}}

func cpioEntry(out io.Writer, inode uint32, name string, mode uint32, size, epoch int64, data io.Reader) error {
	if err := cpioHeader(out, inode, name, mode, size, epoch, 0, 0); err != nil {
		return err
	}
	if _, err := io.CopyN(out, data, size); err != nil {
		return err
	}
	_, err := io.WriteString(out, strings.Repeat("\x00", int((4-size%4)%4)))
	return err
}

func cpioHeader(out io.Writer, inode uint32, name string, mode uint32, size, epoch int64, rdevMajor, rdevMinor uint32) error {
	if size < 0 || size > 0xffffffff || epoch < 0 || epoch > 0xffffffff {
		return errors.New("recoveryboot: cpio_size_overflow")
	}
	if _, err := fmt.Fprintf(out, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", inode, mode, 0, 0, 1, epoch, size, 0, 0, rdevMajor, rdevMinor, len(name)+1, 0); err != nil {
		return err
	}
	_, err := io.WriteString(out, name+"\x00"+strings.Repeat("\x00", (4-(110+len(name)+1)%4)%4))
	return err
}

func fatUUID(value string) bool {
	if len(value) != 9 || value[4] != '-' {
		return false
	}
	for i, c := range value {
		if i == 4 {
			continue
		}
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
