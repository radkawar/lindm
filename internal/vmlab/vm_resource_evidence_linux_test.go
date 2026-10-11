//go:build linux

package vmlab

import (
	"bytes"
	"os/exec"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// These are report-integrity and desired-contract tests, not native provider
// qualification. They cannot open the launch gate or substitute for VM runs.
func TestResourceEvidenceFailsClosedWithoutNativeRecords(t *testing.T) {
	now := time.Now()
	kind := &VMResourceKindEvidence{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, Scenarios: []VMResourceScenario{{Name: "install", StartedAt: now, FinishedAt: now, Passed: true, Action: &adminv1.ResourceActionSummary{}}}}
	if err := qualifyResourceEvidence(kind, []string{"install"}); err == nil {
		t.Fatal("server-only report was qualified")
	}
	if kind.NativeQualified {
		t.Fatal("missing native evidence opened kind gate")
	}
	kind.Scenarios[0].Native = []VMResourceNativeRecord{resourceNativeRecord("dpkg", []byte("independent bytes\n"))}
	if err := qualifyResourceEvidence(kind, []string{"install"}); err == nil {
		t.Fatal("native bytes without authenticated execution were accepted")
	}
	kind.Scenarios[0].Action = nil
	kind.Scenarios[0].Release = &adminv1.ResourceRelease{State: "released"}
	kind.Scenarios[0].Native[0].Bytes[0] ^= 1
	if err := qualifyResourceEvidence(kind, []string{"install"}); err == nil {
		t.Fatal("altered native record was accepted")
	}
}

func TestResourceEvidencePreservesUnprovenFields(t *testing.T) {
	evidence := newVMResourceEvidence()
	if evidence.LaunchGateOpen {
		t.Fatal("new resource report opened launch gate")
	}
	for _, kind := range evidence.Kinds {
		if kind.NativeQualified || len(kind.Unproven) == 0 {
			t.Fatalf("unexercised kind marked qualified: %s", kind.Kind)
		}
	}
	now := time.Now()
	kind := &VMResourceKindEvidence{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, Unproven: []string{"native interrupted release"}, Scenarios: []VMResourceScenario{{Name: "release", StartedAt: now, FinishedAt: now, Passed: true, Release: &adminv1.ResourceRelease{State: "released"}, Native: []VMResourceNativeRecord{resourceNativeRecord("file", []byte("absent\n"))}}}}
	if err := qualifyResourceEvidence(kind, []string{"release"}); err != nil {
		t.Fatal(err)
	}
	if kind.NativeQualified {
		t.Fatal("unproven field ignored")
	}
	if err := qualifyResourceEvidence(kind, []string{"release", "adopt"}); err == nil {
		t.Fatal("missing required scenario accepted")
	}
}

func TestModuleDriftEvidenceRequiresObservedDriftAndAnEffect(t *testing.T) {
	for _, test := range []struct {
		name                               string
		bootOnly, sameFile, stale, granted bool
		want                               bool
	}{
		{"file-repaired", false, false, false, true, true},
		{"image-repaired", true, true, true, true, true},
		{"file-noop", false, true, false, true, false},
		{"image-noop", true, true, false, true, false},
		{"no-grant", true, true, true, false, false},
		{"file-not-image-drift", true, false, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			hash := bytes.Repeat([]byte{1}, 32)
			before := &resourcev1.ManagedFileObservation{Exists: true, File: &resourcev1.FileIdentity{Sha256: hash}}
			after := &resourcev1.ManagedFileObservation{Exists: true, File: &resourcev1.FileIdentity{Sha256: hash}}
			if !test.sameFile {
				before.File.Sha256 = bytes.Repeat([]byte{2}, 32)
			}
			image := &resourcev1.ModuleInitramfsObservation{BlocklistSha256: before.File.Sha256}
			if test.stale {
				image.BlocklistSha256 = nil
			}
			before.KernelModuleBlocklist = &resourcev1.KernelModuleBlocklistObservation{Initramfs: []*resourcev1.ModuleInitramfsObservation{image}}
			s := &VMResourceScenario{Passed: true, Action: &adminv1.ResourceActionSummary{Status: &agentv1.ResourceExecutionStatus{
				Before:       &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: before}},
				Verification: &resourcev1.ResourceVerification{After: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: after}}},
			}}}
			if test.granted {
				s.Action.StartAuthorizedAt = timestamppb.Now()
			}
			if err := moduleDriftEvidence(s, test.bootOnly); (err == nil) != test.want || s.Passed != test.want {
				t.Fatalf("want qualified=%v, got passed=%v err=%v", test.want, s.Passed, err)
			}
		})
	}
}

func TestModuleNativeOracleChecksCommandsNotEmptyOptionSpacing(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{"install /bin/false ", true},
		{"install /bin/false \ninstall /bin/false ", true},
		{"", false},
		{"install /bin/false\n\ninstall /bin/false", false},
		{"insmod /lib/modules/driver.ko\ninstall /bin/false", false},
		{"install /bin/true", false},
		{"install /bin/false ; true", false},
		{"builtin driver", false},
	} {
		command := exec.CommandContext(t.Context(), "/bin/sh", "-eu", "-c", "dependencies=$1; "+moduleDependencyOracle, "oracle", test.output)
		if err := command.Run(); (err == nil) != test.want {
			t.Errorf("output=%q want accepted=%v, err=%v", test.output, test.want, err)
		}
	}
}

func TestModuleBuiltinFixtureUsesObservedCanonicalEntry(t *testing.T) {
	desired, entry, err := moduleBuiltinDesired([]byte("not-a-module\nkernel/9p.ko\nkernel/drivers/real-builtin.ko\n"))
	if err != nil || entry != "kernel/drivers/real-builtin.ko" || desired.GetManagedFile().GetKernelModuleBlocklist().GetModules()[0] != "real_builtin" {
		t.Fatalf("built-in selection must use real validated entry: desired=%v entry=%q err=%v", desired, entry, err)
	}
	if _, _, err := moduleBuiltinDesired([]byte("")); err == nil {
		t.Fatal("missing native built-in evidence invented a driver")
	}
}

func TestResourceLaneDesiredIdentities(t *testing.T) {
	for _, rpm := range []resourcePackaging{{}, {rpm: true}, {arm: true}, {rpm: true, arm: true}, {pacman: true}, {rpm: true, zypper: true}, {rpm: true, zypper: true, arm: true}} {
		for _, present := range []bool{false, true} {
			desired := resourcePackageDesired(rpm, "1.0", present)
			if err := protovalidate.Validate(desired); err != nil {
				t.Fatal(err)
			}
			if err := resource.ValidateDesired(desired); err != nil {
				t.Fatal(err)
			}
			packageState := desired.GetNativePackage()
			if present && packageState.GetExact() == nil {
				t.Fatal("exact package fixture lost native version")
			}
			if !present && packageState.GetAny() == nil {
				t.Fatal("absence carries installation pin")
			}
			if packageState.GetRemoval() != resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA {
				t.Fatal("release can purge data")
			}
		}
	}
	desired := resourceFileDesired("proof", "public fixture\n")
	if err := protovalidate.Validate(desired); err != nil {
		t.Fatal(err)
	}
	if err := resource.ValidateDesired(desired); err != nil {
		t.Fatal(err)
	}
	if desired.GetManagedFile().GetMode() != 0640 || desired.GetManagedFile().Uid == nil || desired.GetManagedFile().Gid == nil {
		t.Fatal("native file oracle dimensions are not explicit")
	}
}
