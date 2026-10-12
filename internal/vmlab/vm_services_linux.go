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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// VMServicesOptions only accepts the laboratory executable, never service
// definitions or commands. Every mutation takes place in a fresh owned guest.
type VMServicesOptions struct {
	LabBinary      string
	CacheDir       string
	WorkDir        string
	DiagnosticsDir string
	Hardware       *VMHardwareOptions
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
	Name                 string                           `json:"name"`
	Target               string                           `json:"target"`
	Plan                 *resourcev1.ResourcePlan         `json:"plan,omitempty"`
	Before               *resourcev1.ResourceObservation  `json:"before,omitempty"`
	After                *resourcev1.ResourceObservation  `json:"after"`
	Verification         *resourcev1.ResourceVerification `json:"verification,omitempty"`
	NativeBefore         *VMServiceNativeState            `json:"native_before"`
	NativeAfter          *VMServiceNativeState            `json:"native_after"`
	Rejection            string                           `json:"rejection,omitempty"`
	UnreportedDefinition *VMServiceDefinitionLength       `json:"unreported_definition,omitempty"`
}

// vmServiceStepJSON carries the provider messages as protojson: encoding/json
// writes a oneof as its Go wrapper and cannot decode it back, so the guest's
// evidence would never reach validation.
type vmServiceStepJSON struct {
	Name                 string                     `json:"name"`
	Target               string                     `json:"target"`
	Plan                 json.RawMessage            `json:"plan,omitempty"`
	Before               json.RawMessage            `json:"before,omitempty"`
	After                json.RawMessage            `json:"after"`
	Verification         json.RawMessage            `json:"verification,omitempty"`
	NativeBefore         *VMServiceNativeState      `json:"native_before"`
	NativeAfter          *VMServiceNativeState      `json:"native_after"`
	Rejection            string                     `json:"rejection,omitempty"`
	UnreportedDefinition *VMServiceDefinitionLength `json:"unreported_definition,omitempty"`
}

func (s VMServiceStep) MarshalJSON() ([]byte, error) {
	out := vmServiceStepJSON{Name: s.Name, Target: s.Target, NativeBefore: s.NativeBefore, NativeAfter: s.NativeAfter, Rejection: s.Rejection, UnreportedDefinition: s.UnreportedDefinition}
	for _, field := range []struct {
		message proto.Message
		present bool
		into    *json.RawMessage
	}{{s.Plan, s.Plan != nil, &out.Plan}, {s.Before, s.Before != nil, &out.Before}, {s.After, s.After != nil, &out.After}, {s.Verification, s.Verification != nil, &out.Verification}} {
		if !field.present {
			continue
		}
		data, err := protojson.Marshal(field.message)
		if err != nil {
			return nil, err
		}
		*field.into = data
	}
	if out.After == nil {
		out.After = json.RawMessage("null")
	}
	return json.Marshal(out)
}

func (s *VMServiceStep) UnmarshalJSON(data []byte) error {
	var in vmServiceStepJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	*s = VMServiceStep{Name: in.Name, Target: in.Target, NativeBefore: in.NativeBefore, NativeAfter: in.NativeAfter, Rejection: in.Rejection, UnreportedDefinition: in.UnreportedDefinition}
	decode := func(raw json.RawMessage, message proto.Message) (bool, error) {
		if len(raw) == 0 || string(raw) == "null" {
			return false, nil
		}
		return true, protojson.Unmarshal(raw, message)
	}
	plan, before, after, verification := new(resourcev1.ResourcePlan), new(resourcev1.ResourceObservation), new(resourcev1.ResourceObservation), new(resourcev1.ResourceVerification)
	for _, field := range []struct {
		raw     json.RawMessage
		message proto.Message
		assign  func()
	}{
		{in.Plan, plan, func() { s.Plan = plan }},
		{in.Before, before, func() { s.Before = before }},
		{in.After, after, func() { s.After = after }},
		{in.Verification, verification, func() { s.Verification = verification }},
	} {
		present, err := decode(field.raw, field.message)
		if err != nil {
			return err
		}
		if present {
			field.assign()
		}
	}
	return nil
}

type VMServiceDefinitionLength struct {
	ReportedSize      int64  `json:"reported_size"`
	ObservedSize      int64  `json:"observed_size"`
	NativeDescription string `json:"native_description"`
}

type VMServicesEvidence struct {
	Capability string          `json:"capability"`
	Steps      []VMServiceStep `json:"steps"`
}

type VMServicesResult struct {
	Distribution                     string              `json:"distribution"`
	Version                          string              `json:"version"`
	RepositorySnapshotDate           string              `json:"repository_snapshot_date,omitempty"`
	RepositorySnapshotManifestSHA256 string              `json:"repository_snapshot_manifest_sha256,omitempty"`
	RepositorySnapshotRepomdSHA256   string              `json:"repository_snapshot_repomd_sha256,omitempty"`
	ImageID                          string              `json:"image_id"`
	ImageSHA256                      string              `json:"image_sha256"`
	LabSHA256                        string              `json:"lab_sha256"`
	Runtime                          *vmRuntimeEvidence  `json:"runtime"`
	SELinuxBefore                    string              `json:"selinux_before,omitempty"`
	SELinuxAfter                     string              `json:"selinux_after,omitempty"`
	Services                         *VMServicesEvidence `json:"services"`
}

// ServicesVM qualifies the native provider, not remote execution authority.
// Success is returned only after the owned VM and all private state are gone.
func ServicesVM(ctx context.Context, manifest *labv1.ImageManifest, options VMServicesOptions) (result *VMServicesResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	release := manifestRelease(manifest)
	if err := release.LabLaneOn(platform.LaneServices, manifest.GetArchitecture()); err != nil {
		return nil, err
	}
	architecture, machine, err := inspectArchitecture(manifest.GetArchitecture())
	if err != nil {
		return nil, err
	}
	selinux := release.Native().Packages.Backend.DNF()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, options.Hardware)
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
	snapshot, digest, err := snapshotServicesProbe(ctx, vm.dir, options.LabBinary, machine)
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
	repositorySnapshot, err := prepareGuestRollingSnapshot(ctx, vm, manifest, options.CacheDir)
	if err != nil {
		return nil, err
	}
	if repositorySnapshot != nil {
		defer func() { err = errors.Join(err, repositorySnapshot.Close()) }()
	}
	host, err := vm.run(ctx, hostTruthCommand, nil, 4096, 15*time.Second)
	if err != nil {
		return nil, err
	}
	identity := strings.Split(string(host), "\n")
	if len(identity) != 7 || identity[0] != manifest.Distribution || (release.Version.Rule != platform.VersionAbsent && identity[1] != manifest.Version) || identity[2] != architecture {
		return nil, errors.New("service guest OS identity differs from manifest")
	}
	result = &VMServicesResult{Distribution: manifest.Distribution, Version: manifest.Version, ImageID: manifest.Id, ImageSHA256: verified.SHA256, LabSHA256: digest, Runtime: runtimeEvidence}
	result.RepositorySnapshotDate = manifest.GetRepositorySnapshotDate()
	result.RepositorySnapshotManifestSHA256 = manifest.GetRepositorySnapshotManifestSha256()
	result.RepositorySnapshotRepomdSHA256 = manifest.GetRepositorySnapshotRepomdSha256()
	if selinux {
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
	if selinux {
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
		{"unreported-bytes-rejected", primary, "conflict"},
	}
	if evidence == nil || evidence.Capability != "systemd.service.v1" || len(evidence.Steps) != len(expected) {
		return errors.New("incomplete native service evidence")
	}
	for index, want := range expected {
		step := &evidence.Steps[index]
		if step.Name != want.name || step.Target != want.target || step.Rejection != want.rejection ||
			step.NativeBefore == nil || step.NativeAfter == nil || step.After == nil ||
			step.NativeBefore.Unit != want.target || step.NativeAfter.Unit != want.target || step.After.GetSystemdService().GetUnit() != primary {
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
		if want.name == "unreported-bytes-rejected" {
			length := step.UnreportedDefinition
			if length == nil || length.ReportedSize != 0 || length.ObservedSize <= 0 || length.ObservedSize >= 4096 ||
				length.NativeDescription != "Disposable native unreported definition bytes proof\n" ||
				step.NativeBefore.LoadState != "loaded" || step.NativeBefore.ActiveState != "inactive" || step.NativeBefore.UnitFileState != "indirect" ||
				step.Before == nil || step.Before.GetSystemdService().GetUnit() != primary ||
				len(step.Before.GetSystemdService().GetFingerprintSha256()) != sha256.Size || len(step.After.GetSystemdService().GetFingerprintSha256()) != sha256.Size ||
				!bytes.Equal(step.Before.GetSystemdService().GetFingerprintSha256(), step.After.GetSystemdService().GetFingerprintSha256()) {
				return errors.New("unreported definition refusal lacks loaded native bytes or restored definition evidence")
			}
		} else if step.UnreportedDefinition != nil {
			return errors.New("unexpected unreported definition evidence in another scenario")
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

func snapshotServicesProbe(ctx context.Context, dir, path string, machine elf.Machine) (_ *os.File, digest string, err error) {
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
	if err != nil || binary.Machine != machine || binary.Class != elf.ELFCLASS64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
		return nil, "", errors.New("service laboratory probe must be a 64-bit executable ELF for the selected guest architecture")
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	return snapshot, hex.EncodeToString(hash.Sum(nil)), nil
}
