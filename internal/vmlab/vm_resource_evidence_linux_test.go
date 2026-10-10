//go:build linux

package vmlab

import (
	"testing"
	"time"

	"buf.build/go/protovalidate"

	adminv1 "lindm/gen/lindm/admin/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// These are report-integrity and desired-contract tests, not native provider
// qualification. They cannot open the launch gate or substitute for VM runs.
func TestResourceEvidenceFailsClosedWithoutNativeRecords(t *testing.T) {
	now := time.Now()
	kind := &VMResourceKindEvidence{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, Scenarios: []VMResourceScenario{{Name: "install", StartedAt: now, FinishedAt: now, Passed: true, Action: &adminv1.ServiceActionSummary{}}}}
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

func TestResourceLaneDesiredIdentities(t *testing.T) {
	for _, rpm := range []resourcePackaging{{}, {rpm: true}, {arm: true}, {rpm: true, arm: true}} {
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
