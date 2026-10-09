//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
)

// VMServicesOptions only accepts the laboratory executable, never service
// definitions or commands. Every mutation takes place in a fresh owned guest.
type VMServicesOptions struct {
	LabBinary      string
	CacheDir       string
	WorkDir        string
	DiagnosticsDir string
}

type VMServiceNativeState struct {
	Unit          string `json:"unit"`
	ID            string `json:"id"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
}

// Provider messages retain complete native observations, including definition
// hashes and fingerprints. Native states come from independent systemctl calls.
type VMServiceStep struct {
	Name         string                       `json:"name"`
	Target       string                       `json:"target"`
	Plan         *agentv1.ServicePlan         `json:"plan,omitempty"`
	Before       *agentv1.ServiceObservation  `json:"before,omitempty"`
	After        *agentv1.ServiceObservation  `json:"after"`
	Verification *agentv1.ServiceVerification `json:"verification,omitempty"`
	NativeBefore *VMServiceNativeState        `json:"native_before"`
	NativeAfter  *VMServiceNativeState        `json:"native_after"`
	Rejection    string                       `json:"rejection,omitempty"`
}

type VMServicesEvidence struct {
	Capability string          `json:"capability"`
	Steps      []VMServiceStep `json:"steps"`
}

type VMServicesResult struct {
	Distribution  string              `json:"distribution"`
	Version       string              `json:"version"`
	ImageID       string              `json:"image_id"`
	ImageSHA256   string              `json:"image_sha256"`
	LabSHA256     string              `json:"lab_sha256"`
	Runtime       *vmRuntimeEvidence  `json:"runtime"`
	SELinuxBefore string              `json:"selinux_before,omitempty"`
	SELinuxAfter  string              `json:"selinux_after,omitempty"`
	Services      *VMServicesEvidence `json:"services"`
}

// ServicesVM qualifies the native provider, not remote execution authority.
// Success is returned only after the owned VM and all private state are gone.
func ServicesVM(ctx context.Context, manifest *labv1.ImageManifest, options VMServicesOptions) (result *VMServicesResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if (manifest.Distribution != "ubuntu" && manifest.Distribution != "fedora") || (manifest.Architecture != "amd64" && manifest.Architecture != "x86_64") {
		return nil, errors.New("vm services requires an Ubuntu or Fedora amd64/x86_64 manifest")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	vm, verified, err := newVerifiedGuest(ctx, manifest, options.CacheDir, options.WorkDir, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, vm.close())
		if err != nil {
			result = nil
		}
	}()
	vm.captureDiagnostics = options.DiagnosticsDir != ""
	defer func() {
		if err != nil && options.DiagnosticsDir != "" {
			err = errors.Join(err, saveLifecycleFailure(ctx, vm, options.DiagnosticsDir))
		}
	}()
	// Hash and validate the private snapshot, not a pathname which could be
	// replaced between ELF inspection and upload.
	snapshot, digest, err := snapshotServicesProbe(ctx, vm.dir, options.LabBinary)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, snapshot.Close()) }()
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	runtimeEvidence, err := vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("service guest cloud-init: %w", err)
	}
	host, err := vm.run(ctx, hostTruthCommand, nil, 4096, 15*time.Second)
	if err != nil {
		return nil, err
	}
	identity := strings.Split(string(host), "\n")
	if len(identity) != 7 || identity[0] != manifest.Distribution || identity[1] != manifest.Version || identity[2] != "x86_64" {
		return nil, errors.New("service guest OS identity differs from manifest")
	}
	result = &VMServicesResult{Distribution: manifest.Distribution, Version: manifest.Version, ImageID: manifest.Id, ImageSHA256: verified.SHA256, LabSHA256: digest, Runtime: runtimeEvidence}
	if manifest.Distribution == "fedora" {
		result.SELinuxBefore, err = serviceGuestEnforcing(ctx, vm)
		if err != nil {
			return nil, err
		}
	}
	const probe = "/home/lindm-lab/lab-services-probe"
	command := "umask 077; cat > " + probe + ".upload && chmod 0500 " + probe + ".upload && mv " + probe + ".upload " + probe + " && printf '%s  %s\\n' " + digest + " " + probe + " | sha256sum --check --status"
	if _, err := vm.run(ctx, command, snapshot, 1024, time.Minute); err != nil {
		return nil, fmt.Errorf("upload service laboratory snapshot: %w", err)
	}
	data, err := vm.run(ctx, "sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C "+probe+" guest services", nil, 256<<10, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("native service qualification: %w", err)
	}
	evidence := new(VMServicesEvidence)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(evidence); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid native service evidence encoding")
	}
	if err := validateServiceEvidence(evidence); err != nil {
		return nil, err
	}
	result.Services = evidence
	if manifest.Distribution == "fedora" {
		result.SELinuxAfter, err = serviceGuestEnforcing(ctx, vm)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// This validates the required qualification scenarios, not the authenticity of
// an arbitrary executable. The caller still selects and trusts the lab binary.
func validateServiceEvidence(evidence *VMServicesEvidence) error {
	const primary = "lab-native-service-proof.service"
	expected := [...]struct{ name, target, rejection string }{
		{"converge-active", primary, ""},
		{"repeat-active", primary, ""},
		{"stale-plan", primary, "conflict"},
		{"reconverge-active", primary, ""},
		{"converge-inactive", primary, ""},
		{"canceled-before-start", primary, "canceled"},
		{"missing-rejected", "lab-native-service-proof-missing.service", "unsupported"},
		{"alias-rejected", "lab-native-service-proof-alias.service", "unsupported"},
		{"oneshot-rejected", "lab-native-service-proof-oneshot.service", "unsupported"},
		{"legacy-include-rejected", "lab-native-service-proof-legacy-include.service", "unsupported"},
	}
	if evidence == nil || evidence.Capability != "systemd.service.v1" || len(evidence.Steps) != len(expected) {
		return errors.New("incomplete native service evidence")
	}
	for index, want := range expected {
		step := &evidence.Steps[index]
		if step.Name != want.name || step.Target != want.target || step.Rejection != want.rejection ||
			step.NativeBefore == nil || step.NativeAfter == nil || step.After == nil ||
			step.NativeBefore.Unit != want.target || step.NativeAfter.Unit != want.target || step.After.Unit != primary {
			return fmt.Errorf("incomplete native service scenario %s", want.name)
		}
		id := want.target
		if want.name == "alias-rejected" {
			id = primary
		}
		if step.NativeBefore.ID != id || step.NativeAfter.ID != id {
			return fmt.Errorf("incorrect canonical identity in native service scenario %s", want.name)
		}
		if want.rejection != "" && *step.NativeBefore != *step.NativeAfter {
			return fmt.Errorf("rejected native service scenario changed state: %s", want.name)
		}
		if want.name == "legacy-include-rejected" &&
			(step.NativeBefore.LoadState != "loaded" || step.NativeBefore.ActiveState != "inactive" || step.NativeBefore.UnitFileState != "disabled") {
			return errors.New("legacy include refusal lacks loaded inactive disabled native evidence")
		}
	}
	return nil
}

func serviceGuestEnforcing(ctx context.Context, vm *guestVM) (string, error) {
	data, err := vm.run(ctx, "sudo -n /usr/sbin/getenforce", nil, 1024, 10*time.Second)
	if err != nil {
		return "", err
	}
	if string(data) != "Enforcing\n" {
		return "", errors.New("fedora service qualification requires SELinux Enforcing throughout")
	}
	return "Enforcing", nil
}

func snapshotServicesProbe(ctx context.Context, dir, path string) (_ *os.File, digest string, err error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, "", err
	}
	snapshot, err := os.OpenFile(filepath.Join(dir, "lab-services-probe"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, "", errors.Join(err, file.Close())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, snapshot.Close())
		}
	}()
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := copyVMBytes(ctx, io.MultiWriter(snapshot, hash), file, 256<<20); err != nil {
		return nil, "", err
	}
	binary, err := elf.NewFile(snapshot)
	if err != nil || binary.Machine != elf.EM_X86_64 || binary.Class != elf.ELFCLASS64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return nil, "", errors.New("service laboratory probe must be an executable amd64 ELF binary")
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	return snapshot, hex.EncodeToString(hash.Sum(nil)), nil
}
