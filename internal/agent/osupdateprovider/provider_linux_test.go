//go:build linux

package osupdateprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

// These tests cover planning and ownership decisions over captured evidence.
// They never fake systemd or a native file transaction: those are qualified on
// real Ubuntu, Fedora and RHEL guests only.

// fixtureZoneinfo is a tzdata tree with the zones the fixtures use; the host
// tzdata is not part of these tests.
func fixtureZoneinfo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, zone := range []string{"UTC", "Europe/Berlin"} {
		path := filepath.Join(root, zone)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("TZif2"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fixtureProvider(t *testing.T) *Provider {
	owner := &agentv1.ResourceOwnershipBinding{
		AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(),
		Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}},
		Policy:  &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
	}
	product := &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "amd64"}
	return &Provider{
		config:  Config{Ownership: owner, Platform: product, ExecutorIncarnation: uuid.NewString()},
		backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_APT, NativeVersion: "unattended-upgrades 2.9.1+nmu4ubuntu1", ProviderVersion: "1", Product: product},
		update:  resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES,
		// Hosts without SELinux derive no creation label.
		creation: func(_ context.Context, image *agentv1.ResourceOwnershipSnapshot) error {
			image.ManagedFileXattrs = nil
			image.Observation.GetManagedFile().SecurityMetadataSha256 = nativefile.XattrDigest(nil)
			return nil
		},
		// The native APT prediction is a seam here; this fixture predicts the
		// override wins. apt_candidate_linux_test.go covers the scratch tree.
		aptPeriodic: func(context.Context, []byte) (string, error) { return "0", nil },
		boot:        uuid.NewString(),
		zoneinfo:    fixtureZoneinfo(t),
	}
}

func fixtureState(desired *resourcev1.OSUpdateDesired) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: osUpdateRef(), State: &resourcev1.ResourceDesiredState_OsUpdate{OsUpdate: desired}}
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// fixtureSnapshot is captured evidence in the exact shape the native
// observation produces: nil content means the owned path is absent.
func fixtureSnapshot(t *testing.T, p *Provider, contents map[resourcev1.OSUpdateNativeFile][]byte, active bool, calendar string) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	observed := &resourcev1.ResourceObservation{Ref: osUpdateRef(), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: digest("revision"), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	private := &agentv1.OSUpdateOwnership{TimerActive: active}
	for i, kind := range ownedKinds(p.update) {
		path := resource.OSUpdateNativePath(kind)
		state := &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: digest("ancestry " + path), NativeIdentitySha256: absentIdentity(), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
		file := &agentv1.OSUpdateNativeFileSnapshot{Kind: kind, State: state}
		if content, ok := contents[kind]; ok {
			sum := sha256.Sum256(content)
			state.Exists = true
			state.NativeIdentitySha256 = digest("inode " + path)
			state.File = &resourcev1.FileIdentity{Path: path, Device: 2049, Inode: uint64(100 + i), Mode: fileMode(kind), Sha256: sum[:]}
			file.Content = slices.Clone(content)
			if file.Content == nil {
				file.Content = []byte{}
			}
		}
		private.Files = append(private.Files, file)
	}
	observation := &resourcev1.OSUpdateObservation{Backend: p.update, NativeVersion: p.backend.GetNativeVersion(), Files: publicFiles(private), TimerActive: active, TimerCalendar: calendar, RebootOracleAvailable: true}
	if policy := contents[resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY]; policy != nil {
		observation.Effective = decodePolicy(policy)
	}
	observed.Observed = &resourcev1.ResourceObservation_OsUpdate{OsUpdate: observation}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: observed, OsUpdate: private}
	if err := validateMessage(snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func convergedSnapshot(t *testing.T, p *Provider, desired *resourcev1.OSUpdateDesired) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	files, specs, err := renderFiles(p.zoneinfo, desired, p.update)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureSnapshot(t, p, files, true, joinCalendar(specs))
}

func appliedLedger(p *Provider, baseline, last *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipLedger {
	return &agentv1.ResourceOwnershipLedger{
		FormatVersion: 1, Revision: 2, Ref: osUpdateRef(), Owner: proto.CloneOf(p.config.Ownership), State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED,
		Baseline: baseline, LastApplied: last, OwnedDimensions: ownedDimensions(),
	}
}

func TestUnownedPresentFileIsNeverAdopted(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	for _, kind := range ownedKinds(p.update) {
		before := fixtureSnapshot(t, p, map[resourcev1.OSUpdateNativeFile][]byte{kind: []byte("foreign\n")}, false, "")
		if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); !errors.Is(err, ErrConflict) {
			t.Fatalf("unowned %v was planned for replacement: %v", kind, err)
		}
	}
	// Even an approved adoption never takes over an existing native object.
	p.config.Ownership.Policy = &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, AdoptionApprovalId: proto.String(uuid.NewString()), Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
	before := fixtureSnapshot(t, p, map[resourcev1.OSUpdateNativeFile][]byte{resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER: []byte("[Timer]\n")}, false, "")
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("adoption mode adopted a foreign timer: %v", err)
	}
	loaded := fixtureSnapshot(t, p, nil, false, "Mon *-*-* 02:00:00 UTC")
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, loaded, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("already loaded timer was acquired: %v", err)
	}
}

func TestCreationPlansEveryOwnedFileAndTimerStart(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	before := fixtureSnapshot(t, p, nil, false, "")
	plan, target, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil)
	if err != nil {
		t.Fatal(err)
	}
	update := plan.GetOsUpdate()
	if !slices.Equal(update.GetChangedFiles(), ownedKinds(p.update)) || !update.GetTimerChange() || !resource.PlanRequiresEffect(plan) {
		t.Fatalf("creation plan = %v", update)
	}
	if update.GetTimerCalendar() != "Wed *-*-* 02:05:00 UTC; Sun *-*-* 02:05:00 UTC" || update.GetInverse() != nil {
		t.Fatalf("creation plan calendar/inverse = %q %v", update.GetTimerCalendar(), update.GetInverse())
	}
	policy := nativeFile(target, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY)
	if policy.GetState().GetFile().GetMode() != 0600 || policy.GetState().GetFile().GetUid() != 0 || !proto.Equal(decodePolicy(policy.GetContent()), desired) {
		t.Fatal("target runner policy is not the root-only desired policy")
	}
	// The private target binds the candidate digest the helper recomputes.
	candidate, err := digestMessage(target.GetOsUpdate())
	if err != nil || !slices.Equal(candidate, update.GetCandidateSha256()) {
		t.Fatal("candidate digest does not bind the target image")
	}
}

func TestConvergedPolicyNeedsNoEffect(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	before := convergedSnapshot(t, p, desired)
	ledger := appliedLedger(p, fixtureSnapshot(t, p, nil, false, ""), before)
	plan, target, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.GetOsUpdate().GetChangedFiles()) != 0 || plan.GetOsUpdate().GetTimerChange() || resource.PlanRequiresEffect(plan) {
		t.Fatalf("converged plan requested an effect: %v", plan.GetOsUpdate())
	}
	result, err := verification(plan, before, target, p.update)
	if err != nil {
		t.Fatal(err)
	}
	if !result.GetOsUpdate().GetConverged() || result.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		t.Fatalf("converged evidence verified as %v", result.GetOsUpdate())
	}
	// A stopped timer with unchanged files is still an effect.
	stopped := proto.CloneOf(before)
	stopped.OsUpdate.TimerActive = false
	stopped.Observation.GetOsUpdate().TimerActive = false
	plan, _, err = p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, stopped, ledger)
	if err != nil || len(plan.GetOsUpdate().GetChangedFiles()) != 0 || !plan.GetOsUpdate().GetTimerChange() {
		t.Fatalf("stopped timer plan = %v, %v", plan.GetOsUpdate(), err)
	}
	// A new window rewrites only policy and timer and restarts the timer.
	moved := fixtureDesired()
	moved.Maintenance.LocalStartMinute = 180
	plan, _, err = p.plan(t.Context(), fixtureState(moved), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, ledger)
	if err != nil || !slices.Equal(plan.GetOsUpdate().GetChangedFiles(), []resourcev1.OSUpdateNativeFile{resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER}) || !plan.GetOsUpdate().GetTimerChange() {
		t.Fatalf("window change plan = %v, %v", plan.GetOsUpdate(), err)
	}
}

func TestCompetingSchedulerIsRefusedBeforeAnyEffect(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	predicted, value := []byte(nil), "0"
	p.aptPeriodic = func(_ context.Context, candidate []byte) (string, error) {
		predicted = candidate
		return value, nil
	}
	// The current native setting (APT periodic upgrades on) is what the
	// candidate override replaces; only the predicted result decides.
	before := fixtureSnapshot(t, p, nil, false, "")
	before.Observation.GetOsUpdate().ConflictingUnits = []string{"apt-daily-upgrade.timer"}
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); err != nil {
		t.Fatalf("installing the APT override was refused: %v", err)
	}
	if string(predicted) != string(renderAPTPeriodic()) {
		t.Fatalf("prediction did not use the candidate override: %q", predicted)
	}
	// A later part or /etc/apt/apt.conf re-enabling periodic upgrades.
	value = "1"
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("APT setting overriding the candidate was not refused: %v", err)
	}
	// Release hands scheduling back to the native defaults.
	converged := convergedSnapshot(t, p, desired)
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, converged, appliedLedger(p, fixtureSnapshot(t, p, nil, false, ""), converged)); err != nil {
		t.Fatalf("release was refused by the native periodic setting: %v", err)
	}
	p.update = resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC
	p.backend.Backend = resourcev1.Backend_BACKEND_DNF4
	p.backend.NativeVersion = "dnf-automatic 4.14.0-25.el9"
	rpm := fixtureSnapshot(t, p, nil, false, "")
	rpm.Observation.GetOsUpdate().ConflictingUnits = []string{"dnf-automatic-install.timer"}
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, rpm, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("enabled dnf-automatic timer was not refused: %v", err)
	}
}

func TestReleaseRemovesOnlyOwnedObjectsWithBoundInverse(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	baseline := fixtureSnapshot(t, p, nil, false, "")
	applied := convergedSnapshot(t, p, desired)
	ledger := appliedLedger(p, baseline, applied)
	plan, target, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, applied, ledger)
	if err != nil {
		t.Fatal(err)
	}
	update := plan.GetOsUpdate()
	if !slices.Equal(update.GetChangedFiles(), ownedKinds(p.update)) || !update.GetTimerChange() || update.GetTimerCalendar() != "" || update.GetInverse() == nil {
		t.Fatalf("release plan = %v", update)
	}
	if !slices.Equal(update.GetInverse().GetInverseSha256(), update.GetCandidateSha256()) || !slices.Equal(update.GetInverse().GetLedgerRevisionSha256(), plan.GetOwnershipRevisionSha256()) {
		t.Fatal("release inverse does not bind the ledger and the restored image")
	}
	for _, file := range target.GetOsUpdate().GetFiles() {
		if file.GetState().GetExists() || file.Content != nil || len(file.GetXattrs()) != 0 {
			t.Fatalf("release target retains %v", file.GetKind())
		}
	}
	if target.GetOsUpdate().GetTimerActive() || target.GetObservation().GetOsUpdate().GetEffective() != nil {
		t.Fatal("release target keeps the schedule or policy")
	}
	result, err := verification(plan, baseline, target, p.update)
	if err != nil || !result.GetOsUpdate().GetConverged() {
		t.Fatalf("restored baseline did not verify the release: %v %v", result.GetOsUpdate(), err)
	}
	// A foreign replacement of an owned file since the last effect (a new
	// inode with the same bytes) blocks release; a boot-only device-number
	// change does not (journal TestOSUpdateDimensionsIgnoreBootDeviceNumbers).
	drifted := proto.CloneOf(applied)
	drifted.OsUpdate.Files[1].State.File.Inode++
	drifted.OsUpdate.Files[1].State.NativeIdentitySha256 = digest("replaced inode")
	drifted.Observation.GetOsUpdate().Files = publicFiles(drifted.GetOsUpdate())
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, drifted, ledger); !errors.Is(err, ErrConflict) {
		t.Fatalf("drifted owned file was released: %v", err)
	}
	// Without an applied ledger there is nothing this provider may remove.
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, applied, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unowned release was planned: %v", err)
	}
}

func TestOtherOwnerCannotPlanOverActiveLedger(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	before := convergedSnapshot(t, p, desired)
	ledger := appliedLedger(p, fixtureSnapshot(t, p, nil, false, ""), before)
	ledger.Owner.Sources[0].ResourceId = uuid.NewString()
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, ledger); !errors.Is(err, ErrConflict) {
		t.Fatalf("another owner replanned the update policy: %v", err)
	}
	ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, ledger); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown prior effect was replanned: %v", err)
	}
}
