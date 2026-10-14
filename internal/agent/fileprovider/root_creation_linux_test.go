// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fileprovider

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestCreatableRootOnlyForDirectChildOfApprovedRoot(t *testing.T) {
	config := &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/motd.d", "/srv/lindm"}}
	for _, test := range []struct {
		desired *resourcev1.ManagedFileDesired
		root    string
		ok      bool
	}{
		{&resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company"}, "/etc/motd.d", true},
		{&resourcev1.ManagedFileDesired{Path: "/srv/lindm/deeper/file"}, "", false},
		{&resourcev1.ManagedFileDesired{Path: "/etc/issue.d/50-company"}, "", false},
		{&resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company", KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{}}, "", false},
	} {
		root, ok := creatableRoot(config, test.desired)
		if ok != test.ok || (ok && root != test.root) {
			t.Fatalf("creatableRoot(%s) = %q %v", test.desired.GetPath(), root, ok)
		}
	}
}

func releaseLedger(recorded string, release resourcev1.ReleaseBehavior) *agentv1.ResourceOwnershipLedger {
	last := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: &resourcev1.ManagedFileObservation{Path: "/etc/motd.d/50-company", Exists: true}}}}
	if recorded != "" {
		last.CreatedDirectory = proto.String(recorded)
	}
	return &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, LastApplied: last, Owner: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Release: release}}}
}

func absentTarget() *agentv1.ResourceOwnershipSnapshot {
	return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: &resourcev1.ManagedFileObservation{Path: "/etc/motd.d/50-company"}}}}
}

func TestReleaseRemovesOnlyRecordedRestoreOwnedRoot(t *testing.T) {
	desired := &resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company"}
	config := &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/motd.d"}}
	release := resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	if root, ok := releasedCreatedRoot(config, desired, releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), absentTarget(), release); !ok || root != "/etc/motd.d" {
		t.Fatal("recorded created root not released")
	}
	for name, test := range map[string]struct {
		ledger    *agentv1.ResourceOwnershipLedger
		target    *agentv1.ResourceOwnershipSnapshot
		operation resourcev1.ResourceOperation
		config    *agentv1.NativeFileProviderConfig
	}{
		"not recorded": {releaseLedger("", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), absentTarget(), release, config},
		"retain":       {releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN), absentTarget(), release, config},
		"reconcile":    {releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), absentTarget(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, config},
		"file restored": {releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), func() *agentv1.ResourceOwnershipSnapshot {
			s := absentTarget()
			s.Observation.GetManagedFile().Exists = true
			return s
		}(), release, config},
		"foreign recorded":  {releaseLedger("/etc", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), absentTarget(), release, config},
		"no longer allowed": {releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED), absentTarget(), release, &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/issue.d"}}},
	} {
		if _, ok := releasedCreatedRoot(test.config, desired, test.ledger, test.target, test.operation); ok {
			t.Fatalf("%s: root removal admitted", name)
		}
	}
}

func TestEffectWritePathsGrantParentOnlyForRootCreationOrRelease(t *testing.T) {
	absentRoot := "/etc/lindm-absent-" + uuid.NewString()
	desired := &resourcev1.ManagedFileDesired{Path: filepath.Join(absentRoot, "50-company")}
	before := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: &resourcev1.ManagedFileObservation{Path: desired.GetPath()}}}}
	target := proto.CloneOf(before)
	target.Observation.GetManagedFile().Exists = true
	plan := &resourcev1.ResourcePlan{Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE}
	request := &agentv1.NativeResourceTransactionRequest{Plan: plan, Before: before, Target: target}
	if paths, err := EffectWritePaths(request, desired); err != nil || !slices.Equal(paths, []string{absentRoot}) {
		t.Fatalf("ordinary write = %v %v", paths, err)
	}
	target.CreatedDirectory = proto.String(absentRoot)
	if paths, err := EffectWritePaths(request, desired); err != nil || !slices.Equal(paths, []string{"/etc"}) {
		t.Fatalf("root creation = %v %v", paths, err)
	}
	target.CreatedDirectory = proto.String("/etc")
	if _, err := EffectWritePaths(request, desired); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign created directory = %v", err)
	}
	// An existing recorded root on re-creation keeps the narrow grant.
	existing := &resourcev1.ManagedFileDesired{Path: "/etc/50-company"}
	target.CreatedDirectory = proto.String("/etc")
	if paths, err := EffectWritePaths(request, existing); err != nil || !slices.Equal(paths, []string{"/etc"}) {
		t.Fatalf("existing root = %v %v", paths, err)
	}
	release := &agentv1.NativeResourceTransactionRequest{Plan: &resourcev1.ResourcePlan{Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE}, Target: absentTarget(), Ownership: releaseLedger("/etc/motd.d", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED)}
	if paths, err := EffectWritePaths(release, &resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company"}); err != nil || !slices.Equal(paths, []string{"/etc"}) {
		t.Fatalf("release = %v %v", paths, err)
	}
	release.Ownership = releaseLedger("", resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED)
	if paths, err := EffectWritePaths(release, &resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company"}); err != nil || !slices.Equal(paths, []string{"/etc/motd.d"}) {
		t.Fatalf("unrecorded release = %v %v", paths, err)
	}
}

func requireDirectory(t *testing.T, path string) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0755 || st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("created root mode=%o uid=%d gid=%d", st.Mode&07777, st.Uid, st.Gid)
	}
}

func TestAbsentApprovedRootCreatedOwnedAndReleased(t *testing.T) {
	p, m, path := fileFixture(t)
	root := filepath.Join(filepath.Dir(path), "motd.d")
	p.config.Native.AllowedRoots = []string{root}
	file := filepath.Join(root, "50-company")
	d := fileDesired(t, file, []byte("company notice\n"))
	observed, err := p.Observe(t.Context(), d)
	if err != nil || observed.GetManagedFile().GetExists() {
		t.Fatalf("absent root not observed as absent file: %v", err)
	}
	plan := applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if plan.GetManagedFile().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE {
		t.Fatal("root creation not planned as creation")
	}
	requireDirectory(t, root)
	requireFile(t, file, "company notice\n", 0600, 0, 0)
	if m.ledger.GetLastApplied().GetCreatedDirectory() != root {
		t.Fatal("ownership did not record the created root")
	}
	again := applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if again.GetManagedFile().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE || m.ledger.GetLastApplied().GetCreatedDirectory() != root {
		t.Fatal("idempotent reconcile lost the created root record")
	}
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("RESTORE_OWNED release left the created empty root")
	}
}

func TestReleaseKeepsCreatedRootWithForeignEntries(t *testing.T) {
	p, m, path := fileFixture(t)
	root := filepath.Join(filepath.Dir(path), "motd.d")
	p.config.Native.AllowedRoots = []string{root}
	d := fileDesired(t, filepath.Join(root, "50-company"), []byte("company notice\n"))
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err := os.WriteFile(filepath.Join(root, "60-other"), []byte("other\n"), 0644); err != nil {
		t.Fatal(err)
	}
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	requireFile(t, filepath.Join(root, "60-other"), "other\n", 0644, 0, 0)
}

func TestAbsentAncestorAboveApprovedRootStaysPrecondition(t *testing.T) {
	p, _, path := fileFixture(t)
	root := filepath.Join(filepath.Dir(path), "absent", "motd.d")
	p.config.Native.AllowedRoots = []string{root}
	d := fileDesired(t, filepath.Join(root, "50-company"), []byte("notice\n"))
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err == nil {
		t.Fatal("absent ancestor above the approved root was created")
	}
	if _, err := os.Lstat(filepath.Dir(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("planning created a directory")
	}
}
