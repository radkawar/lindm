//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	labv1 "lindm/gen/lindm/lab/v1"
)

// VMInspectOptions selects a built Linux guest agent and owned scratch parent.
// WorkDir must already exist; an empty value uses the OS temporary directory.
// Only the newly created private child is removed. CacheDir remains reusable.
type VMInspectOptions struct {
	Agent             string
	CacheDir          string
	WorkDir           string
	Hardware          *VMHardwareOptions
	EncryptionFixture string
	// Opt-in private NativeObservation JSON, including local accounts and network
	// identifiers. Created exclusively only after successful owned-VM cleanup.
	InventoryRecord string
	// Explicitly retains bounded failure status outside the disposable run.
	// Files are 0600 and are never printed; the caller owns their deletion.
	DiagnosticsDir string
}

// VMInspectResult is bounded, nonsensitive evidence of this exact inspection.
// It deliberately does not claim installation, enrollment or OS certification.
type VMInspectResult struct {
	Distribution           string
	Version                string
	RepositorySnapshotDate string
	ImageID                string
	ImageSHA256            string
	AgentSHA256            string
	MatchedPackages        int
	NativeDetailStatuses   map[string]string
	FirmwareSetupMode      *bool
	EncryptionFixture      string
	InventoryRecordPath    string
	InventoryRecordSHA256  string
	Runtime                *vmRuntimeEvidence
}

// InspectVM fetches/reverifies the pinned image, boots a disposable guest overlay,
// and compares real agent output against independent native tools. No success
// escapes until the guest has been reaped and all private run files removed.
func InspectVM(ctx context.Context, manifest *labv1.ImageManifest, options VMInspectOptions) (result *VMInspectResult, err error) {
	var actual []byte
	// Register first so all resource closes, guest reaping and private-directory
	// cleanup have completed before sensitive evidence can be published.
	defer func() {
		err = publishVMInventoryRecord(options.InventoryRecord, actual, result, err)
		if err != nil {
			result = nil
		}
	}()
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if _, err := NativePackageFormat(manifest.Distribution); err != nil {
		return nil, err
	}
	architecture, machine, err := inspectArchitecture(manifest.Architecture)
	if err != nil {
		return nil, err
	}
	hardware := VMHardwareOptions{Architecture: architecture}
	if options.Hardware != nil {
		hardware = *options.Hardware
		if hardware.Architecture == "" {
			hardware.Architecture = architecture
		}
	}
	hardware, err = defaultVMHardware(&hardware)
	if err != nil {
		return nil, err
	}
	if hardware.Architecture != architecture {
		return nil, errors.New("inspect hardware and manifest architectures differ")
	}
	fixture := options.EncryptionFixture
	if fixture == "" {
		fixture = "none"
	}
	switch fixture {
	case "none":
	case "luks1", "luks2", "lvm-luks2":
		if hardware.ExtraDisks == 0 {
			return nil, errors.New("encryption fixture requires at least one extra disposable disk")
		}
	default:
		return nil, errors.New("encryption fixture must be none, luks1, luks2 or lvm-luks2")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	agent, err := openRegular(options.Agent)
	if err != nil {
		return nil, fmt.Errorf("open agent binary: %w", err)
	}
	defer func() { err = errors.Join(err, agent.Close()) }()
	binary, err := elf.NewFile(agent)
	if err != nil {
		return nil, fmt.Errorf("agent must be a Linux ELF binary: %w", err)
	}
	if binary.Machine != machine || binary.Class != elf.ELFCLASS64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return nil, errors.New("agent must be an executable ELF binary matching the manifest architecture")
	}
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, &hardware)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()

	// Snapshot once: the digest describes exactly the bytes uploaded, even if
	// the caller replaces the original executable while the guest is booting.
	snapshot, err := os.OpenFile(filepath.Join(vm.dir, "agent"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, snapshot.Close()) }()
	if _, err := agent.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	hash := sha256.New()
	if _, err := copyVMBytes(ctx, io.MultiWriter(snapshot, hash), agent, 256<<20); err != nil {
		return nil, fmt.Errorf("snapshot agent: %w", err)
	}
	agentDigest := hex.EncodeToString(hash.Sum(nil))
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	runtimeEvidence, err := vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if status, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		if options.DiagnosticsDir != "" && len(status) != 0 {
			path, saveErr := saveGuestDiagnostics(options.DiagnosticsDir, status)
			if saveErr != nil {
				return nil, errors.Join(fmt.Errorf("cloud-init readiness: %w", err), saveErr)
			}
			return nil, fmt.Errorf("cloud-init readiness: %w; private status saved to %q", err, path)
		}
		return nil, fmt.Errorf("cloud-init readiness: %w; use -diagnostics DIR for private failure status", err)
	}
	if err := pinArchRepositories(ctx, vm, manifest); err != nil {
		return nil, err
	}
	if err := configureVMEncryptionFixture(ctx, vm, fixture); err != nil {
		return nil, err
	}
	if _, err := vm.run(ctx, "umask 077; cat > "+guestAgent+".upload && chmod 0500 "+guestAgent+".upload && mv "+guestAgent+".upload "+guestAgent, snapshot, 1024, time.Minute); err != nil {
		return nil, fmt.Errorf("upload agent over pinned SSH: %w", err)
	}
	uploadDigest, err := vm.run(ctx, "sha256sum "+guestAgent, nil, 1024, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("verify uploaded agent: %w", err)
	}
	if fields := strings.Fields(string(uploadDigest)); len(fields) != 2 || fields[0] != agentDigest || fields[1] != guestAgent {
		return nil, errors.New("uploaded agent digest mismatch")
	}

	before, err := collectVMTruth(ctx, vm, manifest.Distribution)
	if err != nil {
		return nil, err
	}
	inspected, inspectErr := vm.runResult(ctx, "env -i PATH=/usr/bin:/bin HOME=/home/"+labUser+" LANG=C LC_ALL=C "+guestAgent+" inspect", nil, maxGuestOutput, 90*time.Second)
	actual = inspected.Stdout
	after, err := collectVMTruth(ctx, vm, manifest.Distribution)
	if err != nil {
		return nil, err
	}
	if err := stableVMTruth(before, after); err != nil {
		return nil, err
	}
	if inspectErr != nil || inspected.ExitCode != 0 {
		failure := errors.Join(fmt.Errorf("agent inspection failed (exit %d)", inspected.ExitCode), inspectErr)
		if options.DiagnosticsDir != "" {
			path, saveErr := saveGuestDiagnostics(options.DiagnosticsDir, append(append(inspected.Stderr, '\n'), actual...))
			return nil, errors.Join(failure, saveErr, fmt.Errorf("private inspection diagnostics saved to %q", path))
		}
		return nil, failure
	}
	observation := new(inventoryv1.NativeObservation)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(actual, observation); err != nil {
		// Protojson errors can quote guest facts; report the failure without data.
		return nil, errors.New("agent inspection did not emit strict NativeObservation protobuf JSON")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(observation))
	if err != nil {
		return nil, err
	}
	if err := validator.Validate(observation); err != nil {
		return nil, errors.New("agent inspection failed NativeObservation validation")
	}
	if before.host[0] != manifest.Distribution || (manifest.Distribution != "arch" && before.host[1] != manifest.Version) || before.host[2] != architecture {
		return nil, errors.New("guest OS identity does not match the selected manifest")
	}
	if err := compareVMObservation(before, observation); err != nil {
		return nil, err
	}
	if err := compareVMDetails(before.details, after.details, observation.Host.Details); err != nil {
		return nil, err
	}
	if err := compareInspectHardware(&hardware, observation.Host.Details); err != nil {
		return nil, err
	}
	diskIdentities, err := (vmInventoryOracle{ctx: ctx, vm: vm}).command("lsblk --nodeps --pairs --output NAME,TYPE,SERIAL")
	if err != nil {
		return nil, err
	}
	if err := compareInspectDiskIdentities(diskIdentities, &hardware, observation.Host.Details); err != nil {
		return nil, err
	}
	if err := compareInspectEncryption(fixture, observation.Host.Details); err != nil {
		return nil, err
	}
	return &VMInspectResult{Distribution: manifest.Distribution, Version: manifest.Version, RepositorySnapshotDate: manifest.GetRepositorySnapshotDate(), ImageID: manifest.Id, ImageSHA256: verified.SHA256, AgentSHA256: agentDigest, MatchedPackages: len(observation.Packages.Packages), NativeDetailStatuses: vmDetailStatuses(observation.Host.Details), FirmwareSetupMode: runtimeEvidence.FirmwareSetupMode, EncryptionFixture: fixture, Runtime: runtimeEvidence}, nil
}

func publishVMInventoryRecord(path string, data []byte, result *VMInspectResult, prior error) error {
	if prior != nil || path == "" {
		return prior
	}
	if result == nil || len(data) == 0 || len(data) > maxGuestOutput {
		return errors.New("missing or oversized validated inventory record")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create private inventory record: %w", err)
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	writeErr = errors.Join(writeErr, file.Close())
	if writeErr != nil {
		return errors.Join(fmt.Errorf("persist private inventory record: %w", writeErr), os.Remove(absolute))
	}
	digest := sha256.Sum256(data)
	result.InventoryRecordPath = absolute
	result.InventoryRecordSHA256 = hex.EncodeToString(digest[:])
	return nil
}

func inspectArchitecture(architecture string) (string, elf.Machine, error) {
	switch architecture {
	case "amd64", "x86_64":
		return "x86_64", elf.EM_X86_64, nil
	case "arm64", "aarch64":
		return "aarch64", elf.EM_AARCH64, nil
	default:
		return "", 0, errors.New("vm inspect requires an x86_64 or aarch64 manifest")
	}
}

func compareInspectEncryption(fixture string, details *inventoryv1.NativeDetails) error {
	if fixture == "" || fixture == "none" {
		return nil
	}
	luks, crypt, inherited := false, false, false
	for _, disk := range details.GetStorage().GetDevices() {
		if disk.GetEncryption().GetStatus() != truthSuccess {
			continue
		}
		switch disk.GetEncryption().GetValue() {
		case "luks":
			luks = true
		case "dm-crypt":
			crypt = true
		case "inherited-dm-crypt":
			if disk.GetType().GetValue() == "lvm" {
				inherited = true
			}
		}
	}
	if !luks || !crypt || (fixture == "lvm-luks2" && !inherited) {
		return errors.New("requested encryption fixture layers were not observed")
	}
	return nil
}

func compareInspectHardware(hardware *VMHardwareOptions, details *inventoryv1.NativeDetails) error {
	if details == nil {
		return errors.New("missing requested hardware observations")
	}
	if err := compareVMFirmware(hardware, details.GetFirmware()); err != nil {
		return err
	}
	tpm := details.GetTpm()
	if tpm.GetPresent().GetStatus() != truthSuccess || tpm.GetPresent().GetValue() != hardware.TPM {
		return errors.New("observed TPM presence differs from selected emulation")
	}
	if hardware.TPM && (tpm.GetVersion().GetStatus() != truthSuccess || tpm.GetVersion().GetValue() != "2") {
		return errors.New("emulated TPM did not expose version 2")
	}
	if details.GetStorage().GetStatus() != truthSuccess {
		return errors.New("selected virtual disks were not observed")
	}
	return nil
}

// Match configured media by the serials assigned by the shared QEMU builder.
// Guest-created block devices (zram, loop, device mapper) remain fully covered
// by native inventory comparison, but are not QEMU-attached disk identities.
func compareInspectDiskIdentities(data []byte, hardware *VMHardwareOptions, details *inventoryv1.NativeDetails) error {
	lines, err := truthLines(data)
	if err != nil {
		return err
	}
	expected := make(map[string]string, hardware.ExtraDisks+1)
	for i := range hardware.ExtraDisks + 1 {
		expected[fmt.Sprintf("lindm-lab-%d", i)] = ""
	}
	for _, line := range lines {
		fields, err := parseTruthPairs(line)
		if err != nil {
			return err
		}
		if len(fields) != 3 || fields["NAME"] == "" || fields["TYPE"] == "" {
			return errors.New("incomplete native disk identity truth")
		}
		serial := strings.TrimSpace(fields["SERIAL"])
		if !strings.HasPrefix(serial, "lindm-lab-") {
			continue
		}
		name, exists := expected[serial]
		if !exists || name != "" || fields["TYPE"] != "disk" {
			return errors.New("unexpected or duplicate configured disk identity")
		}
		expected[serial] = fields["NAME"]
	}
	matched := 0
	for _, name := range expected {
		if name == "" {
			continue
		}
		observed := 0
		for _, disk := range details.GetStorage().GetDevices() {
			if disk.GetName() == name && disk.GetType().GetStatus() == truthSuccess && disk.GetType().GetValue() == "disk" {
				observed++
			}
		}
		if observed != 1 {
			return errors.New("configured native disk identity is missing or duplicated in inventory")
		}
		matched++
	}
	if matched != len(expected) {
		return fmt.Errorf("configured disk identity count differs: expected %d, observed %d", len(expected), matched)
	}
	return nil
}

func inspectFirmwareSetupMode(ctx context.Context, vm *guestVM, hardware *VMHardwareOptions) (*bool, error) {
	if hardware.Firmware == nil {
		return nil, nil
	}
	o := vmInventoryOracle{ctx: ctx, vm: vm}
	data, err := o.command("sudo -n od -An -j4 -N1 -tu1 /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		return nil, errors.New("cannot independently observe firmware SetupMode")
	}
	return parseFirmwareSetupMode(data, hardware.Firmware.SecureBoot)
}

func parseFirmwareSetupMode(data []byte, secureBoot bool) (*bool, error) {
	value, err := parseTruthUint(string(data))
	if err != nil || value > 1 {
		return nil, errors.New("invalid native firmware SetupMode")
	}
	setup := value == 1
	if secureBoot && setup {
		return nil, errors.New("secure boot requested but firmware remains in SetupMode")
	}
	return &setup, nil
}

func copyVMBytes(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 128<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buffer)
		if total+int64(n) > limit {
			return total, errors.New("file exceeds expected size limit")
		}
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// The truth commands deliberately use native presentation distinct from the
// agent's parser: dpkg's full state and RPM's conditional epoch/architecture.
// No helper or parser from internal/agent/inventory is used for expected data.
const dpkgTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /usr/bin/dpkg-query --show '--showformat=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'`
const rpmTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /usr/bin/rpm --query --all --queryformat '%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%|ARCH?{%{ARCH}}:{}|\t%{MODULARITYLABEL}\n'`
const hostTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c 'set -eu; if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; printf "%s\n" "$ID" "${VERSION_ID-}"; uname -m; uname -r; uname -n; cat /proc/sys/kernel/random/boot_id'`

type nativePackage struct {
	name, version, architecture, manager, sourceName, sourceVersion string
	module                                                          nativeModule
}

type nativeModule struct {
	status                         inventoryv1.CollectionStatus
	modular                        bool
	name, stream, version, context string
}

func nativeModuleIdentity(module *inventoryv1.ModuleObservation) nativeModule {
	return nativeModule{status: module.GetStatus(), modular: module.GetModular(), name: module.GetName(), stream: module.GetStream(), version: module.GetVersion(), context: module.GetContext()}
}

func parseTruthModule(label string) nativeModule {
	if label == "(none)" {
		return nativeModule{status: truthSuccess}
	}
	fields := strings.Split(label, ":")
	if len(fields) != 4 {
		return nativeModule{status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT}
	}
	module := &inventoryv1.ModuleObservation{Status: truthSuccess, Modular: true, Name: fields[0], Stream: fields[1], Version: fields[2], Context: fields[3]}
	if err := protovalidate.Validate(module); err != nil {
		return nativeModule{status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT}
	}
	return nativeModuleIdentity(module)
}

type vmTruth struct {
	packages map[nativePackage]int
	host     [6]string
	manager  string
	details  *inventoryv1.NativeDetails
}

func collectVMTruth(ctx context.Context, vm *guestVM, distribution string) (*vmTruth, error) {
	family, err := nativeDistributionFamily(distribution)
	if err != nil {
		return nil, err
	}
	command, manager := dpkgTruthCommand, "dpkg"
	if family != familyAPT {
		command, manager = rpmTruthCommand, "rpm"
	}
	if family == familyPacman {
		command, manager = pacmanTruthCommand, "pacman"
	}
	data, err := vm.run(ctx, command, nil, maxGuestOutput, time.Minute)
	if err != nil {
		return nil, fmt.Errorf("native package truth: %w", err)
	}
	packages, err := parseVMTruth(data, manager)
	if err != nil {
		return nil, err
	}
	host, err := vm.run(ctx, hostTruthCommand, nil, 64<<10, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("native host truth: %w", err)
	}
	lines := strings.Split(string(host), "\n")
	if len(lines) != 7 || lines[6] != "" {
		return nil, errors.New("unexpected native host truth shape")
	}
	truth := &vmTruth{packages: packages, manager: manager}
	for i := range truth.host {
		if (lines[i] == "" && (i != 1 || distribution != "arch")) || strings.ContainsAny(lines[i], "\x00\r") {
			return nil, errors.New("invalid native host truth")
		}
		truth.host[i] = lines[i]
	}
	truth.details, err = collectVMDetails(ctx, vm)
	if err != nil {
		return nil, err
	}
	return truth, nil
}

func parseVMTruth(data []byte, manager string) (map[nativePackage]int, error) {
	if manager == "pacman" {
		return parsePacmanTruth(data)
	}
	if manager != "dpkg" && manager != "rpm" {
		return nil, errors.New("unsupported native truth manager")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("empty or truncated native package truth")
	}
	result := make(map[nativePackage]int)
	rows := strings.Split(string(data[:len(data)-1]), "\n")
	if len(rows) > 100000 {
		return nil, errors.New("native package truth exceeds record bound")
	}
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if manager == "dpkg" {
			if len(fields) != 6 {
				return nil, errors.New("unexpected dpkg truth shape")
			}
			switch fields[0] {
			case "installed":
			case "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending":
				continue
			default:
				return nil, errors.New("unrecognized dpkg truth state")
			}
			fields = fields[1:]
		}
		expectedFields := 4
		if manager == "dpkg" {
			expectedFields = 5
		}
		if len(fields) != expectedFields || fields[0] == "" || fields[1] == "" || (manager == "dpkg" && (fields[2] == "" || fields[3] == "" || fields[4] == "")) || strings.ContainsAny(row, "\x00\r") {
			return nil, errors.New("invalid native package truth record")
		}
		pkg := nativePackage{name: fields[0], version: fields[1], architecture: fields[2], manager: manager}
		if manager == "dpkg" {
			pkg.sourceName, pkg.sourceVersion = fields[3], fields[4]
			pkg.module = nativeModule{status: truthUnavailable}
		} else {
			pkg.module = parseTruthModule(fields[3])
		}
		result[pkg]++
	}
	if len(result) == 0 {
		return nil, errors.New("native package truth contains no installed packages")
	}
	return result, nil
}

func sameVMPackages(a, b map[nativePackage]int) bool {
	if len(a) != len(b) {
		return false
	}
	for key, count := range a {
		if b[key] != count {
			return false
		}
	}
	return true
}

func stableVMTruth(before, after *vmTruth) error {
	if before.host != after.host {
		return errors.New("native host truth changed during inspection; no collector verdict")
	}
	if before.manager != after.manager || !sameVMPackages(before.packages, after.packages) {
		return errors.New("native package truth changed during inspection; no collector verdict")
	}
	return nil
}

func compareVMObservation(expected *vmTruth, actual *inventoryv1.NativeObservation) error {
	if actual.Host == nil || actual.Packages == nil {
		return errors.New("agent omitted host or package observation")
	}
	if actual.Packages.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || actual.Packages.Backend != expected.manager {
		return errors.New("agent package collection did not succeed with the native manager")
	}
	got := make(map[nativePackage]int, len(actual.Packages.Packages))
	for _, pkg := range actual.Packages.Packages {
		if pkg == nil {
			return errors.New("agent emitted an absent package record")
		}
		got[nativePackage{name: pkg.Name, version: pkg.Version, architecture: pkg.Architecture, manager: pkg.Manager, sourceName: pkg.SourceName, sourceVersion: pkg.SourceVersion, module: nativeModuleIdentity(pkg.Module)}]++
	}
	if !sameVMPackages(expected.packages, got) {
		missing, extra := 0, 0
		for key, count := range expected.packages {
			if n := count - got[key]; n > 0 {
				missing += n
			}
		}
		for key, count := range got {
			if n := count - expected.packages[key]; n > 0 {
				extra += n
			}
		}
		return fmt.Errorf("complete native package comparison failed: %d missing, %d unexpected records", missing, extra)
	}
	host := actual.Host
	fields := []*inventoryv1.ObservedString{host.OsId, host.OsVersion, host.Architecture, host.KernelRelease, host.Hostname, host.BootId}
	names := []string{"OS ID", "OS version", "architecture", "kernel release", "hostname", "boot ID"}
	for i, field := range fields {
		if i == 1 && expected.host[0] == "arch" && expected.host[i] == "" && field != nil && field.Status == inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE && field.Value == "" {
			continue
		}
		if field == nil || field.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || field.Value == "" || field.Value != expected.host[i] {
			return fmt.Errorf("native host comparison failed for %s (values withheld)", names[i])
		}
	}
	return nil
}

func saveGuestDiagnostics(directory string, data []byte) (string, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, "lindm-cloud-init-*.json")
	if err != nil {
		return "", fmt.Errorf("create private guest diagnostic: %w", err)
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return "", errors.Join(err, os.Remove(file.Name()))
	}
	return file.Name(), nil
}
