package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/demolab"
	"lindm/internal/devlab"
	"lindm/internal/orgapply"
	"lindm/internal/vmlab"
)

func TestDemoPrerequisitesPreserveDeclaredRolloutGates(t *testing.T) {
	declared := &orgv1.Organization{
		Groups:      []*orgv1.StaticGroup{{Name: "Engineering"}},
		Rollouts:    []*policyv1.RolloutSpec{{Rings: []*policyv1.RolloutRing{{MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 86400}}}},
		Assignments: []*orgv1.Assignment{{}},
	}
	original := proto.CloneOf(declared)
	prerequisites := demoPrerequisiteOrganization(declared)
	if len(prerequisites.Rollouts) != 0 || len(prerequisites.Assignments) != 0 || len(prerequisites.Groups) != 1 {
		t.Fatal("initial apply did not isolate enrollment prerequisites")
	}
	prerequisites.Groups[0].Name = "changed clone"
	if !proto.Equal(declared, original) {
		t.Fatal("staging changed the full declaration or its rollout gates")
	}
}

func TestDemoStateRejectsIdentityDrift(t *testing.T) {
	device := &labv1.DemoDevice{Key: "laptop", Hostname: "engineering-01", Manifest: "../images/example.json", Role: labv1.DemoRole_DEMO_ROLE_DESKTOP, Group: "26d5407e-0035-5ae1-b4c9-83d105e13915", ProvisioningToken: "engineering", Host: proto.String("spark")}
	manifest := &labv1.ImageManifest{Sha256: strings.Repeat("a", 64)}
	spec := &demolab.Spec{Devices: []demolab.Device{{Config: device, Manifest: manifest}}}
	state := &labv1.DemoState{Bindings: []*labv1.DemoBinding{{Key: device.Key, Device: proto.CloneOf(device), ManifestSha256: manifest.Sha256}}}
	if err := matchDemoState(state, spec); err != nil {
		t.Fatalf("unchanged spec: %v", err)
	}
	for name, mutate := range map[string]func(*labv1.DemoDevice){
		"host":     func(d *labv1.DemoDevice) { d.Host = proto.String("other") },
		"hostname": func(d *labv1.DemoDevice) { d.Hostname = "replacement" },
		"group":    func(d *labv1.DemoDevice) { d.Group = "9b1eb9f4-dee7-54b3-839d-4e0938f5a579" },
		"token":    func(d *labv1.DemoDevice) { d.ProvisioningToken = "finance" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(device)
			mutate(changed)
			other := &demolab.Spec{Devices: []demolab.Device{{Config: changed, Manifest: manifest}}}
			if err := matchDemoState(state, other); err == nil {
				t.Fatal("accepted changed persistent identity")
			}
		})
	}
	manifest.Sha256 = strings.Repeat("b", 64)
	if err := matchDemoState(state, spec); err == nil {
		t.Fatal("accepted replaced image bytes")
	}
	if err := matchDemoState(state, &demolab.Spec{}); err == nil {
		t.Fatal("accepted removed device and orphaned its disk")
	}
}

func TestDemoOwnerCheckpointRemainsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-access")
	access := &demoOwnerAccess{Username: "console-owner", EnrollmentSecret: "human-once", Secrets: []orgapply.Secret{{Kind: "provisioning_token", Name: "engineering", Value: "token-once"}}}
	if err := publishDemoJSON(path, access, 0400); err != nil {
		t.Fatal(err)
	}
	access.Secrets = append(access.Secrets, orgapply.Secret{Kind: "account", Name: "auditor", Value: "auditor-once"})
	if err := publishDemoJSON(path, access, 0400); err != nil {
		t.Fatal(err)
	}
	data, err := readDemoPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if !strings.Contains(string(data), "human-once") || !strings.Contains(string(data), "auditor-once") {
		t.Fatal("checkpoint lost original or newly issued secrets")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("owner access mode %o", info.Mode().Perm())
	}
	if got := demoToken(access, "engineering"); got != "token-once" {
		t.Fatalf("provisioning secret not found: %q", got)
	}
	if got := demoToken(access, "auditor"); got != "" {
		t.Fatal("account enrollment used as a provisioning token")
	}
}

func TestDemoOwnerEnrollmentCustody(t *testing.T) {
	run := &demoRun{root: t.TempDir(), controller: &vmlab.AssistanceController{Fixture: &devlab.AuthorityFixture{ConsoleOrigin: "http://127.0.0.1:1234"}}}
	if err := run.openOwnerAccess(); err != nil {
		t.Fatal(err)
	}
	if run.access.EnrollmentStarted || run.access.Username != "" || run.access.EnrollmentSecret != "" {
		t.Fatal("owner enrollment issued before devices are ready")
	}
	if err := run.openOwnerAccess(); err != nil {
		t.Fatalf("interrupted device preparation cannot resume: %v", err)
	}
	run.access.EnrollmentStarted = true
	if err := run.saveOwnerAccess(); err != nil {
		t.Fatal(err)
	}
	if err := run.openOwnerAccess(); err == nil {
		t.Fatal("ambiguous one-time issuance was silently retried")
	}
	run.access.Username, run.access.EnrollmentSecret = "console-owner", "original-once"
	if err := run.saveOwnerAccess(); err != nil {
		t.Fatal(err)
	}
	if err := run.openOwnerAccess(); err != nil {
		t.Fatal(err)
	}
	if err := run.enrollOwner(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.access.EnrollmentSecret != "original-once" {
		t.Fatal("resume changed original owner enrollment")
	}
}

func TestDemoPrivateReadRejectsSymlinksAndPublicFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDemoPrivate(path); err == nil {
		t.Fatal("accepted public secret file")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readDemoPrivate(link); err == nil {
		t.Fatal("followed secret symlink")
	}
}

func TestOrganizationDeviceRootDoesNotAdoptOtherDemos(t *testing.T) {
	root := filepath.Join(t.TempDir(), "org-laptop")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "desktop"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := bindOrganizationDeviceRoot(root, "org", true); err == nil {
		t.Fatal("adopted existing assistance VM without organization ownership")
	}
	if err := bindOrganizationDeviceRoot(root, "org", false); err == nil {
		t.Fatal("allowed deletion of an unowned device")
	}
	owned := filepath.Join(t.TempDir(), "org-laptop")
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	if err := bindOrganizationDeviceRoot(owned, "org", true); err != nil {
		t.Fatal(err)
	}
	if err := bindOrganizationDeviceRoot(owned, "org", false); err != nil {
		t.Fatal(err)
	}
	if err := bindOrganizationDeviceRoot(owned, "other", false); err == nil {
		t.Fatal("accepted another organization's device root")
	}
}

// A device the product cannot classify is shown with its reason, never as zero
// findings; pending or stale evaluations are not terminal.
func TestDemoFindingsTextShowsUnknownReason(t *testing.T) {
	unknown := &devlab.DeviceFindingCounts{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN, Reason: "rhel_platform_stream_unavailable"}}
	if got := demoFindingsText(unknown); got != "findings unknown (rhel_platform_stream_unavailable)" {
		t.Fatalf("unknown text = %q", got)
	}
	affected := &devlab.DeviceFindingCounts{Affected: 3, Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}}
	if got := demoFindingsText(affected); got != "findings affected=3 accepted=0 unknown=0 clear=0" {
		t.Fatalf("affected text = %q", got)
	}
	for _, reason := range []string{"evaluation_pending", "inventory_stale", "feed_stale", ""} {
		if demoTerminalUnknown(reason) {
			t.Fatalf("%q accepted as terminal", reason)
		}
	}
}
