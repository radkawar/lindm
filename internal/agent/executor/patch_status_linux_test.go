//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

const patchStatusTestBoot = "25eec0a2-bb9f-42bc-b6cc-0508320c960e"

type patchStatusFixture struct {
	t        *testing.T
	dir      string
	now      time.Time
	boot     string
	refresh  int
	reader   *patchStatusReader
	database string
}

func newPatchStatusFixture(t *testing.T) *patchStatusFixture {
	t.Helper()
	f := &patchStatusFixture{t: t, dir: t.TempDir(), now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), boot: patchStatusTestBoot}
	f.database = filepath.Join(f.dir, "dpkg-status")
	if err := os.WriteFile(f.database, []byte("Package: base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.setMtime(f.database, f.now.Add(-2*time.Hour))
	lists := filepath.Join(f.dir, "lists")
	if err := os.Mkdir(lists, 0o755); err != nil {
		t.Fatal(err)
	}
	f.setMtime(lists, f.now.Add(-2*time.Hour))
	f.reader = &patchStatusReader{
		path: filepath.Join(f.dir, "status.binpb"), owner: uint32(os.Getuid()),
		fingerprints: []string{f.database, filepath.Join(f.dir, "absent-rpmdb"), lists, filepath.Join(lists, "*Release")},
		wall:         func() time.Time { return f.now }, monotonic: func() time.Time { return f.now },
		bootID:   func() (string, error) { return f.boot, nil },
		validate: func(m proto.Message) error { return protovalidate.Validate(m) },
		refresh: func(context.Context) error {
			f.refresh++
			return nil
		},
	}
	return f
}

func (f *patchStatusFixture) setMtime(path string, at time.Time) {
	f.t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		f.t.Fatal(err)
	}
}

func (f *patchStatusFixture) available(observedAt time.Time) *agentv1.PatchStatusObservation {
	return &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(observedAt), BootId: f.boot, Available: true,
		Backend:                resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES,
		PendingSecurityUpdates: 2, PendingUpdates: 5, DeferredUpdates: 1, RebootRequired: true,
		MetadataRefreshedAt: timestamppb.New(observedAt.Add(-time.Hour)), PolicyInstalled: true,
		LastRun: &agentv1.PatchRunSummary{
			Trigger:   agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_MAINTENANCE_WINDOW,
			StartedAt: timestamppb.New(observedAt.Add(-time.Hour)), FinishedAt: timestamppb.New(observedAt.Add(-50 * time.Minute)),
			Result: agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED, Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY,
			Diagnostic: &agentv1.PatchRunDiagnostic{
				Tool: agentv1.PatchRunTool_PATCH_RUN_TOOL_UNATTENDED_UPGRADE, Phase: agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL,
				ExitCode: 1, ErrorLines: []string{"dpkg was interrupted"},
			},
		},
	}
}

func (f *patchStatusFixture) store(observation *agentv1.PatchStatusObservation, mode os.FileMode) {
	f.t.Helper()
	data, err := proto.Marshal(observation)
	if err != nil {
		f.t.Fatal(err)
	}
	f.storeBytes(data, mode)
}

func (f *patchStatusFixture) storeBytes(data []byte, mode os.FileMode) {
	f.t.Helper()
	if err := os.WriteFile(f.reader.path, data, mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.reader.path, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *patchStatusFixture) unavailable(got *agentv1.PatchStatusObservation, reason string) {
	f.t.Helper()
	if got.GetAvailable() || got.GetReason() != reason || !got.GetObservedAt().AsTime().Equal(f.now) || got.GetPendingUpdates() != 0 {
		f.t.Fatalf("observation = %v, want unavailable %s at %v", got, reason, f.now)
	}
	if err := protovalidate.Validate(got); err != nil {
		f.t.Fatalf("unavailable observation cannot be published: %v", err)
	}
}

func TestPatchStatusPublishesFreshStatusUnmodified(t *testing.T) {
	f := newPatchStatusFixture(t)
	stored := f.available(f.now.Add(-10 * time.Minute))
	f.store(stored, 0o600)
	got := f.reader.observe(t.Context())
	if !proto.Equal(got, stored) {
		t.Fatalf("status was altered: %v", got)
	}
	if f.refresh != 0 {
		t.Fatal("fresh status started a refresh")
	}
}

func TestPatchStatusStaleTriggersThrottledRefresh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*patchStatusFixture)
		reason  string
	}{
		{name: "missing", reason: "patch_status_not_computed", prepare: func(*patchStatusFixture) {}},
		{name: "old", prepare: func(f *patchStatusFixture) { f.store(f.available(f.now.Add(-61*time.Minute)), 0o600) }},
		{name: "previous_boot", reason: "patch_status_previous_boot", prepare: func(f *patchStatusFixture) {
			observation := f.available(f.now.Add(-time.Minute))
			observation.BootId = "4a1a87b5-2f37-4f43-8d1b-7c0e3d0b5b52"
			f.store(observation, 0o600)
		}},
		{name: "package_database_changed", prepare: func(f *patchStatusFixture) {
			f.store(f.available(f.now.Add(-10*time.Minute)), 0o600)
			f.setMtime(f.database, f.now.Add(-time.Minute))
		}},
		{name: "metadata_changed", prepare: func(f *patchStatusFixture) {
			f.store(f.available(f.now.Add(-10*time.Minute)), 0o600)
			release := filepath.Join(f.dir, "lists", "archive.ubuntu.com_dists_noble-security_InRelease")
			if err := os.WriteFile(release, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			f.setMtime(release, f.now.Add(-time.Minute))
			f.setMtime(filepath.Dir(release), f.now.Add(-2*time.Hour))
		}},
		{name: "invalid_encoding", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) { f.storeBytes([]byte{0xff, 0xff}, 0o600) }},
		{name: "group_writable", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) { f.store(f.available(f.now), 0o620) }},
		{name: "validation", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) {
			observation := f.available(f.now)
			observation.PendingSecurityUpdates = 6
			f.store(observation, 0o600)
		}},
		{name: "future", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) { f.store(f.available(f.now.Add(time.Hour)), 0o600) }},
		{name: "symlink", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) {
			target := filepath.Join(f.dir, "target.binpb")
			data, err := proto.Marshal(f.available(f.now))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, f.reader.path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized", reason: "patch_status_invalid", prepare: func(f *patchStatusFixture) {
			f.storeBytes(make([]byte, patchStatusLimit+1), 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPatchStatusFixture(t)
			tc.prepare(f)
			got := f.reader.observe(t.Context())
			if tc.reason != "" {
				f.unavailable(got, tc.reason)
			} else if !got.GetAvailable() {
				t.Fatalf("stale but valid status was withheld: %v", got)
			}
			if f.refresh != 1 {
				t.Fatalf("refresh starts = %d, want 1", f.refresh)
			}
			f.now = f.now.Add(patchStatusRefreshInterval - time.Second)
			f.reader.observe(t.Context())
			if f.refresh != 1 {
				t.Fatal("refresh was started twice inside the throttle interval")
			}
			f.now = f.now.Add(time.Second)
			f.reader.observe(t.Context())
			if f.refresh != 2 {
				t.Fatal("refresh was not retried after the throttle interval")
			}
		})
	}
}

func TestPatchStatusRefreshFailureIsNotFatal(t *testing.T) {
	f := newPatchStatusFixture(t)
	f.reader.refresh = func(context.Context) error {
		f.refresh++
		return errors.New("systemd unavailable")
	}
	f.unavailable(f.reader.observe(t.Context()), "patch_status_not_computed")
	f.reader.observe(t.Context())
	if f.refresh != 1 {
		t.Fatal("failed refresh bypassed the throttle")
	}
}

func TestPatchStatusWithoutBootIdentityIsUnavailable(t *testing.T) {
	f := newPatchStatusFixture(t)
	f.store(f.available(f.now), 0o600)
	f.reader.bootID = func() (string, error) { return "", errors.New("no boot id") }
	f.boot = ""
	f.unavailable(f.reader.observe(t.Context()), "patch_status_boot_id_unavailable")
}

func TestPatchStatusUnavailableRunnerStatusIsPublished(t *testing.T) {
	f := newPatchStatusFixture(t)
	stored := &agentv1.PatchStatusObservation{ObservedAt: timestamppb.New(f.now.Add(-time.Minute)), BootId: f.boot, Reason: "os_update_backend_unsupported"}
	f.store(stored, 0o600)
	if got := f.reader.observe(t.Context()); !proto.Equal(got, stored) || f.refresh != 0 {
		t.Fatalf("runner reason was replaced: %v (refresh %d)", got, f.refresh)
	}
}
