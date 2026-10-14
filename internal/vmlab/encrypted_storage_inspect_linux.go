// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// EncryptedStorageInspectOptions packages an already-built, version-stamped agent.
// Repository identifies the harness; BuildRepository identifies the agent sources.
// FixtureOutput must be a new child of an existing private, caller-owned directory.
type EncryptedStorageInspectOptions struct {
	VM              EncryptedVMOptions
	Repository      string
	BuildRepository string
	Agent           string
	PackageVersion  string
	FixtureOutput   string
}

// StorageSourceEvidence binds tracked changes and each untracked source file.
// It describes a working tree, not a reproducible release build attestation.
type StorageSourceEvidence struct {
	BaseCommit string            `json:"base_commit"`
	DiffSHA256 string            `json:"diff_sha256"`
	Untracked  map[string]string `json:"untracked_sha256"`
}

// EncryptedStorageEvidence contains public observations only, never raw headers.
type EncryptedStorageEvidence struct {
	Distribution       string                     `json:"distribution"`
	Version            string                     `json:"version"`
	CapturedAt         time.Time                  `json:"captured_at"`
	ImageID            string                     `json:"image_id"`
	ImageSHA256        string                     `json:"image_sha256"`
	GoldenDiskSHA256   string                     `json:"golden_disk_sha256"`
	Harness            *StorageSourceEvidence     `json:"harness_source"`
	AgentSource        *StorageSourceEvidence     `json:"agent_source"`
	AgentSHA256        string                     `json:"agent_sha256"`
	PackageSHA256      string                     `json:"package_sha256"`
	PackageVersion     string                     `json:"package_version"`
	PackageFormat      packaging.Format           `json:"package_format"`
	Firmware           *EncryptedFirmwareEvidence `json:"firmware"`
	NativeVersions     map[string]string          `json:"native_versions"`
	LUKSUUID           string                     `json:"luks_uuid"`
	PartitionSizeBytes uint64                     `json:"stopped_partition_size_bytes"`
	ControllerSerial   string                     `json:"controller_serial"`
	ControllerWWN      string                     `json:"controller_wwn"`
	StorageBus         string                     `json:"storage_bus"`
	IndependentMatch   bool                       `json:"independent_oracle_match"`
	HeadersUnchanged   bool                       `json:"stopped_headers_unchanged"`
	GuestCleaned       bool                       `json:"guest_cleaned"`
	Files              map[string]string          `json:"files_sha256"`
	Projection         map[string]string          `json:"projection"`
}

// InspectEncryptedStorage never accepts a host block pathname. The immutable
// golden is used only as the backing of NewEncryptedVM's disposable clone.
// Capture publication is deferred until every guest and packaging resource closes.
func InspectEncryptedStorage(ctx context.Context, manifest *labv1.ImageManifest, options EncryptedStorageInspectOptions) (result *EncryptedStorageEvidence, err error) {
	options.VM.RequireCachedGolden = true
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if err := platform.ForManifest(manifest.Distribution, manifest.Version).Gate(platform.Encryption); err != nil {
		return nil, fmt.Errorf("encrypted storage capture: %w", err)
	}
	if options.Repository == "" || options.Agent == "" || options.FixtureOutput == "" {
		return nil, errors.New("encrypted storage capture requires repository, versioned agent and new fixture output")
	}
	if options.BuildRepository == "" {
		options.BuildRepository = options.Repository
	}
	if options.PackageVersion == "" {
		options.PackageVersion = "0.1.0"
	}
	if err := validateStorageCaptureDestination(options.FixtureOutput); err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	defer func() {
		if err != nil || result == nil {
			result = nil
			return
		}
		result.GuestCleaned = true
		result.Files = make(map[string]string, len(files))
		for name, data := range files {
			result.Files[name] = storageCaptureDigest(data)
		}
		files["provenance.json"], err = json.MarshalIndent(result, "", "  ")
		if err == nil {
			err = publishStorageCapture(options.FixtureOutput, files)
		}
		if err != nil {
			result = nil
		}
	}()
	result = &EncryptedStorageEvidence{
		Distribution: manifest.Distribution, Version: manifest.Version, CapturedAt: time.Now().UTC(),
		ImageID: manifest.Id, ImageSHA256: manifest.Sha256, NativeVersions: make(map[string]string),
		Projection: map[string]string{
			"lsblk.json":         "raw native lsblk --bytes --json --output-all stdout",
			"udev.txt":           "udevadm info --export-db; block records only; P/N and allowlisted public E identity properties, native order retained",
			"luks.json":          "cryptsetup luksDump --dump-json-metadata; keyslots type and tokens type/keyslots only; all payloads, digests, salts and areas removed",
			"luks.txt":           "cryptsetup luksDump; Version/UUID and Keyslots/Tokens section plus direct numeric type lines only",
			"agent-storage.json": "installed packaged lindm-agent inspect as root; StorageDetails protobuf JSON only",
		},
	}
	result.Harness, err = storageSourceEvidence(ctx, options.Repository)
	if err != nil {
		return nil, err
	}
	result.AgentSource, err = storageSourceEvidence(ctx, options.BuildRepository)
	if err != nil {
		return nil, err
	}
	pack, binaryDigest, err := buildStorageInspectPackage(ctx, manifest, options)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, pack.Close()) }()
	result.AgentSHA256, result.PackageSHA256 = binaryDigest, pack.artifact.SHA256
	result.PackageVersion, result.PackageFormat = pack.artifact.Version, pack.artifact.Format
	vm, err := NewEncryptedVM(ctx, manifest, options.VM)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.Close()) }()
	result.Firmware = vm.firmware
	// Read only the checked overlay's own backing filename, never a guest path.
	overlay, err := openRegular(filepath.Join(vm.dir, "disk.qcow2"))
	if err != nil {
		return nil, err
	}
	backing, backingErr := encryptedQCOWBacking(overlay)
	if err := errors.Join(backingErr, overlay.Close()); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(backing) {
		backing = filepath.Join(vm.dir, backing)
	}
	result.GoldenDiskSHA256, err = encryptedFileDigest(backing)
	if err != nil {
		return nil, err
	}
	before, err := vm.Headers(ctx)
	if err != nil {
		return nil, err
	}
	if len(before) != 1 {
		return nil, errors.New("encrypted storage capture requires exactly one root LUKS2 container")
	}
	result.LUKSUUID = before[0].UUID
	if _, err := vm.ColdBoot(ctx, vm.InitialUnlockSecret()); err != nil {
		return nil, err
	}
	packages, err := newNativeGuestPackages(ctx, vm.guest, pack.artifact, pack.artifact, pack.apt, pack.publicKey, pack.fingerprint)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	if err := packages.InstallFirst(ctx); err != nil {
		return nil, err
	}
	run := func(command string) ([]byte, error) {
		data, runErr := vm.guest.run(ctx, "sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C sh -eu -c "+nativeQuote(command), nil, 4<<20, 2*time.Minute)
		if runErr != nil {
			return nil, errors.New("encrypted storage native command failed (guest output withheld)")
		}
		return data, nil
	}
	digest, err := run("sha256sum " + packaging.BinaryPath)
	if err != nil {
		return nil, err
	}
	if fields := strings.Fields(string(digest)); len(fields) != 2 || fields[0] != binaryDigest || fields[1] != packaging.BinaryPath {
		return nil, errors.New("installed agent digest differs from packaged binary")
	}
	for name, command := range map[string]string{"lsblk": "lsblk --version", "udevadm": "udevadm --version", "cryptsetup": "cryptsetup --version", "agent": packaging.BinaryPath + " version", "kernel": "uname -r"} {
		data, err := run(command)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > 4096 {
			return nil, errors.New("invalid native tool version output")
		}
		result.NativeVersions[name] = strings.TrimSpace(string(data))
	}
	for _, tool := range []string{"qemu-img", "guestfish"} {
		data, err := encryptedHostOutput(ctx, vm.dir, 15*time.Second, tool, "--version")
		if err != nil {
			return nil, err
		}
		result.NativeVersions["host-"+tool] = strings.TrimSpace(string(data))
	}
	pairs, err := run(storageTruthCommand)
	if err != nil {
		return nil, err
	}
	truth, err := parseTruthStorage(pairs, truthSuccess)
	if err != nil {
		return nil, err
	}
	actual, err := run(packaging.BinaryPath + " inspect")
	if err != nil {
		return nil, err
	}
	observation := new(inventoryv1.NativeObservation)
	if err := protojson.Unmarshal(actual, observation); err != nil {
		return nil, errors.New("packaged root inspection returned invalid protobuf JSON")
	}
	storage := observation.GetHost().GetDetails().GetStorage()
	device, err := compareEncryptedStorage(truth, storage, before[0].UUID)
	if err != nil {
		return nil, err
	}
	if err := compareStorageController(storage, vm.hardware.StorageBus, device); err != nil {
		return nil, err
	}
	result.StorageBus, result.ControllerSerial = vm.hardware.StorageBus, "lindm-lab-0"
	result.ControllerWWN = labControllerWWN(vm.hardware.StorageBus)
	files["agent-storage.json"], err = protojson.MarshalOptions{Indent: "  "}.Marshal(storage)
	if err != nil {
		return nil, err
	}
	files["lsblk.json"], err = run("lsblk --bytes --json --output-all")
	if err != nil {
		return nil, err
	}
	if !json.Valid(files["lsblk.json"]) {
		return nil, errors.New("lsblk did not emit complete JSON")
	}
	udev, err := run("udevadm info --export-db")
	if err != nil {
		return nil, err
	}
	files["udev.txt"], err = projectStorageUdev(udev)
	if err != nil {
		return nil, err
	}
	// Device was discovered independently inside the owned guest, not supplied by
	// the caller. Restrict it to one kernel basename before constructing /dev/.
	if device == "" || strings.ContainsAny(device, "/\x00\r\n") || device == "." || device == ".." {
		return nil, errors.New("invalid guest LUKS kernel basename")
	}
	jsonDump, err := run("cryptsetup luksDump --dump-json-metadata " + nativeQuote("/dev/"+device))
	if err != nil {
		return nil, err
	}
	files["luks.json"], err = projectStorageLUKS(jsonDump)
	if err != nil {
		return nil, err
	}
	publicBefore, err := projectStorageLUKS(before[0].JSON)
	if err != nil || string(publicBefore) != string(files["luks.json"]) {
		return nil, errors.Join(errors.New("guest LUKS metadata differs from stopped header oracle"), err)
	}
	if err := compareStoragePublicSummary(storage, before[0].UUID, publicBefore); err != nil {
		return nil, err
	}
	textDump, err := run("cryptsetup luksDump " + nativeQuote("/dev/"+device))
	if err != nil {
		return nil, err
	}
	files["luks.txt"], err = projectStorageLUKSText(textDump, before[0].UUID)
	if err != nil {
		return nil, err
	}
	if err := vm.PowerOff(ctx); err != nil {
		return nil, err
	}
	after, err := vm.Headers(ctx)
	if err != nil {
		return nil, err
	}
	equal, err := encryptedHeadersEqual(before, after)
	if err != nil || !equal {
		return nil, errors.Join(errors.New("read-only storage capture changed LUKS headers"), err)
	}
	result.PartitionSizeBytes, err = stoppedStoragePartitionSize(ctx, vm, before[0].Device)
	if err != nil {
		return nil, err
	}
	for _, target := range storage.Devices {
		if target.Name == device && target.GetSizeBytes().GetValue() != result.PartitionSizeBytes {
			return nil, errors.New("root encrypted partition size differs from stopped appliance")
		}
	}
	for _, source := range []struct {
		path   string
		before *StorageSourceEvidence
	}{{options.Repository, result.Harness}, {options.BuildRepository, result.AgentSource}} {
		after, err := storageSourceEvidence(ctx, source.path)
		if err != nil {
			return nil, err
		}
		a, err := json.Marshal(source.before)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(after)
		if err != nil || string(a) != string(b) {
			return nil, errors.Join(errors.New("source changed during encrypted storage capture"), err)
		}
	}
	result.IndependentMatch, result.HeadersUnchanged = true, true
	return result, nil
}

func buildStorageInspectPackage(ctx context.Context, manifest *labv1.ImageManifest, options EncryptedStorageInspectOptions) (_ *actionNativePackage, _ string, err error) {
	work, err := os.MkdirTemp(options.VM.WorkDir, "lindm-storage-packages-")
	if err != nil {
		return nil, "", err
	}
	p := &actionNativePackage{work: work}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	signer, err := packaging.GenerateDevelopmentSigner(ctx, work)
	if err != nil {
		return nil, "", err
	}
	format, err := NativePackageFormat(manifestRelease(manifest))
	if err != nil {
		return nil, "", err
	}
	architecture := manifest.Architecture
	switch architecture {
	case "x86_64":
		architecture = "amd64"
	case "aarch64":
		architecture = "arm64"
	}
	built, err := packaging.Build(ctx, packaging.BuildRequest{AgentBinary: options.Agent, Version: options.PackageVersion, TargetArchitecture: architecture, OutputDir: work, Formats: []packaging.Format{format}, Signer: *signer})
	if err != nil {
		return nil, "", err
	}
	if len(built.Artifacts) != 1 {
		return nil, "", errors.New("storage capture requires one native package")
	}
	p.artifact, p.publicKey, p.fingerprint = built.Artifacts[0], built.PublicKey, signer.Fingerprint
	if format == packaging.FormatDEB {
		output := filepath.Join(work, "apt")
		if err := os.Mkdir(output, 0700); err != nil {
			return nil, "", err
		}
		p.apt, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: output, DEBs: []string{p.artifact.Path}, Signer: *signer})
		if err != nil {
			return nil, "", err
		}
		p.publicKey = p.apt.PublicKeyArmor
	}
	return p, built.BinarySHA256, nil
}

func storageCaptureDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func storageSourceEvidence(ctx context.Context, repository string) (*StorageSourceEvidence, error) {
	if err := storageOwnedDirectory(repository, false); err != nil {
		return nil, err
	}
	base, err := encryptedHostOutput(ctx, repository, 15*time.Second, "git", "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	commit := strings.TrimSpace(string(base))
	if (len(commit) != 40 && len(commit) != 64) || strings.Trim(commit, "0123456789abcdef") != "" {
		return nil, errors.New("invalid source base commit")
	}
	diff, err := encryptedHostOutput(ctx, repository, 15*time.Second, "git", "diff", "--no-ext-diff", "--binary", "HEAD", "--")
	if err != nil {
		return nil, err
	}
	untracked, err := encryptedHostOutput(ctx, repository, 15*time.Second, "git", "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	result := &StorageSourceEvidence{BaseCommit: commit, DiffSHA256: storageCaptureDigest(diff), Untracked: make(map[string]string)}
	var total int
	for name := range strings.SplitSeq(string(untracked), "\x00") {
		if name == "" {
			continue
		}
		if !filepath.IsLocal(name) || len(result.Untracked) >= 4096 {
			return nil, errors.New("invalid or excessive untracked source paths")
		}
		data, err := readRegular(filepath.Join(repository, name), 16<<20)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > 64<<20 {
			return nil, errors.New("untracked source exceeds capture bound")
		}
		result.Untracked[name] = storageCaptureDigest(data)
	}
	return result, nil
}

func validateStorageCaptureDestination(path string) error {
	if path == "" || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return errors.New("fixture output must be a new directory")
	}
	if err := storageOwnedDirectory(filepath.Dir(path), true); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixture output already exists or cannot be inspected")
	}
	return nil
}

func publishStorageCapture(path string, files map[string][]byte) (err error) {
	if err := validateStorageCaptureDestination(path); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(path))
		}
	}()
	for name, data := range files {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return errors.New("invalid capture filename")
		}
		f, err := os.OpenFile(filepath.Join(path, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		n, writeErr := f.Write(data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = f.Sync()
		}
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return fmt.Errorf("publish public storage capture: %w", err)
		}
	}
	return nil
}
