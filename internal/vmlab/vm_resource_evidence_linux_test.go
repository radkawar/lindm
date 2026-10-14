// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"os/exec"
	"strings"
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

func TestRebootEvidenceBindsFollowOnObservationsToSignedPolicy(t *testing.T) {
	now := time.Now()
	signed := &adminv1.ResourceActionSummary{
		ActionId: "installed-policy-action", ClosedReason: "result",
		AttestedAt: timestamppb.New(now), ReceivedAt: timestamppb.New(now),
		Status: &agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED},
	}
	proof := &VMRebootPolicyResult{Policy: VMResourceKindEvidence{
		Kind:      resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY,
		Unproven:  []string{"unit evidence structure is not native qualification"},
		Scenarios: []VMResourceScenario{{Name: "signed-independent-reboot-window", StartedAt: now, FinishedAt: now, Passed: true, Action: signed, Native: []VMResourceNativeRecord{resourceNativeRecord("installed", []byte("test fixture"))}}},
	}}
	required := []string{"signed-independent-reboot-window", "native-update-and-reboot-window", "employee-deferral-and-executor-restart", "deferred-native-reboot-executes"}
	for _, name := range required[1:] {
		scenario, _ := proof.scenario(t.Context(), &resourceDispatch{}, name)
		if scenario.Action != signed {
			t.Fatal("follow-on observation lost its actual policy execution")
		}
		passScenario(scenario, resourceNativeRecord("observed", []byte("test fixture")))
	}
	if err := qualifyResourceEvidence(&proof.Policy, required); err != nil {
		t.Fatal(err)
	}
	if proof.Policy.NativeQualified {
		t.Fatal("report-integrity test pretended native qualification")
	}
	proof.Policy.Scenarios[2].Action = nil
	if err := qualifyResourceEvidence(&proof.Policy, required); err == nil {
		t.Fatal("native-only deferral evidence accepted without signed policy")
	}
}

func TestRebootKernelPrerequisiteUsesVerifiedNativeTransactions(t *testing.T) {
	for _, rpm := range []resourcePackaging{{}, {rpm: true}, {rpm: true, dnf4: true}} {
		script := rebootKernelReinstallScript(rpm)
		for _, forbidden := range []string{"/run/reboot-required", "--nogpgcheck", "AllowUnauthenticated=true", "gpgcheck=0"} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("fixture bypasses native authority with %q", forbidden)
			}
		}
		required := []string{"uname -r", "reinstall", "before", "after", "sha256sum"}
		if rpm.rpm {
			required = append(required, "rpmkeys --checksig --verbose", "--setopt=gpgcheck=1", "--setopt=localpkg_gpgcheck=1", `reinstall "$private"/*.rpm`)
		} else {
			required = append(required, "Debug::Acquire::gpgv=true", "Debug::pkgAcquire::Auth=true", "APT::Get::AllowUnauthenticated=false", `--reinstall install "$package=$version"`)
		}
		for _, value := range required {
			if !strings.Contains(script, value) {
				t.Fatalf("missing native provenance/verification %q", value)
			}
		}
		// Syntax only: this test never executes the package transaction.
		command := exec.CommandContext(t.Context(), "/bin/sh", "-n")
		command.Stdin = strings.NewReader(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("invalid fixture shell: %v: %s", err, output)
		}
	}
}

func TestRebootRPMPrerequisiteRetainsEveryRunningKernelProvider(t *testing.T) {
	for _, dnf4 := range []bool{false, true} {
		script, _, found := strings.Cut(rebootKernelReinstallScript(resourcePackaging{rpm: true, dnf4: dnf4}), "printf 'selinux '")
		if !found {
			t.Fatal("missing native package-selection boundary")
		}
		for _, packages := range [][]string{
			{},
			{"kernel-core-6.19.10-300.fc44.aarch64"},
			{"kernel-6.19.10-300.fc44.aarch64", "kernel-core-6.19.10-300.fc44.aarch64"},
		} {
			// Only substitute the package query. Stop before posture, signatures,
			// download or reinstallation; no package manager effect runs in this test.
			manager, format := "dnf5", "%s\\n"
			if dnf4 {
				manager, format = "dnf", "%s\\n\\n"
			}
			query := manager + "() { test \"$3\" = --installed && test \"$4\" = --whatprovides && test \"$5\" = \"kernel-uname-r = $kernel\" || return 9; printf " + nativeQuote(format)
			for _, name := range packages {
				query += " " + nativeQuote(name)
			}
			query += "; }\n"
			command := exec.CommandContext(t.Context(), "/bin/sh", "-eu")
			command.Stdin = strings.NewReader(query + script + "\nprintf 'selected-package %s\\n' \"$@\"\n")
			output, err := command.CombinedOutput()
			if len(packages) == 0 {
				if err == nil {
					t.Fatal("empty native package query accepted")
				}
				continue
			}
			if err != nil {
				t.Fatalf("native provider set rejected: %v: %s", err, output)
			}
			if strings.Count(string(output), "selected-package ") != len(packages) {
				t.Fatalf("running-kernel providers lost: %s", output)
			}
			for _, name := range packages {
				if !strings.Contains(string(output), "selected-package "+name+"\n") {
					t.Fatalf("exact installed package identity changed: %s", output)
				}
			}
		}
	}
}
