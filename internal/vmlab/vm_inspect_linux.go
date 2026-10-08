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

// VMInspectOptions selects a built Linux amd64 agent and owned scratch parent.
// WorkDir must already exist; an empty value uses the OS temporary directory.
// Only the newly created private child is removed. CacheDir remains reusable.
type VMInspectOptions struct {
	Agent    string
	CacheDir string
	WorkDir  string
	// Explicitly retains bounded failure status outside the disposable run.
	// Files are 0600 and are never printed; the caller owns their deletion.
	DiagnosticsDir string
}

// VMInspectResult is bounded, nonsensitive evidence of this exact inspection.
// It deliberately does not claim installation, enrollment or OS certification.
type VMInspectResult struct {
	Distribution    string
	Version         string
	ImageID         string
	ImageSHA256     string
	AgentSHA256     string
	MatchedPackages int
	Runtime         *vmRuntimeEvidence
}

// InspectVM fetches/reverifies the pinned image, boots a disposable KVM overlay,
// and compares real agent output against independent native tools. No success
// escapes until the guest has been reaped and all private run files removed.
func InspectVM(ctx context.Context, manifest *labv1.ImageManifest, options VMInspectOptions) (_ *VMInspectResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if (manifest.Distribution != "ubuntu" && manifest.Distribution != "fedora") || (manifest.Architecture != "amd64" && manifest.Architecture != "x86_64") {
		return nil, errors.New("vm inspect requires an Ubuntu or Fedora amd64/x86_64 manifest")
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
		return nil, fmt.Errorf("agent must be a Linux amd64 ELF binary: %w", err)
	}
	if binary.Machine != elf.EM_X86_64 || binary.Class != elf.ELFCLASS64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return nil, errors.New("agent must be an executable amd64 ELF binary")
	}
	vm, verified, err := newVerifiedGuest(ctx, manifest, options.CacheDir, options.WorkDir, false)
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
	actual, inspectErr := vm.run(ctx, "env -i PATH=/usr/bin:/bin HOME=/home/"+labUser+" LANG=C LC_ALL=C "+guestAgent+" inspect", nil, maxGuestOutput, 90*time.Second)
	after, err := collectVMTruth(ctx, vm, manifest.Distribution)
	if err != nil {
		return nil, err
	}
	if err := stableVMTruth(before, after); err != nil {
		return nil, err
	}
	if inspectErr != nil {
		return nil, fmt.Errorf("agent inspection: %w", inspectErr)
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
	if before.host[0] != manifest.Distribution || before.host[1] != manifest.Version || before.host[2] != "x86_64" {
		return nil, errors.New("guest OS identity does not match the selected manifest")
	}
	if err := compareVMObservation(before, observation); err != nil {
		return nil, err
	}
	return &VMInspectResult{Distribution: manifest.Distribution, Version: manifest.Version, ImageID: manifest.Id, ImageSHA256: verified.SHA256, AgentSHA256: agentDigest, MatchedPackages: len(observation.Packages.Packages), Runtime: runtimeEvidence}, nil
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
const dpkgTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /usr/bin/dpkg-query --show '--showformat=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n'`
const rpmTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /usr/bin/rpm --query --all --queryformat '%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%|ARCH?{%{ARCH}}:{}|\n'`
const hostTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c 'set -eu; if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; printf "%s\n" "$ID" "$VERSION_ID"; uname -m; uname -r; uname -n; cat /proc/sys/kernel/random/boot_id'`

type nativePackage struct{ name, version, architecture, manager string }
type vmTruth struct {
	packages map[nativePackage]int
	host     [6]string
	manager  string
}

func collectVMTruth(ctx context.Context, vm *guestVM, distribution string) (*vmTruth, error) {
	command, manager := dpkgTruthCommand, "dpkg"
	if distribution == "fedora" {
		command, manager = rpmTruthCommand, "rpm"
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
		if lines[i] == "" || strings.ContainsAny(lines[i], "\x00\r") {
			return nil, errors.New("invalid native host truth")
		}
		truth.host[i] = lines[i]
	}
	return truth, nil
}

func parseVMTruth(data []byte, manager string) (map[nativePackage]int, error) {
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
			if len(fields) != 4 {
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
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || (manager == "dpkg" && fields[2] == "") || strings.ContainsAny(row, "\x00\r") {
			return nil, errors.New("invalid native package truth record")
		}
		result[nativePackage{name: fields[0], version: fields[1], architecture: fields[2], manager: manager}]++
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
		got[nativePackage{name: pkg.Name, version: pkg.Version, architecture: pkg.Architecture, manager: pkg.Manager}]++
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
		if field == nil || field.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || field.Value != expected.host[i] {
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
