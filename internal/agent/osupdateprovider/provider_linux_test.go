// SPDX-License-Identifier: Apache-2.0

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
	"lindm/internal/agent/admissiondetail"
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
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, loaded, nil); !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_update_timer" {
		t.Fatalf("already loaded timer was acquired: %v", err)
	}
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); admissiondetail.Of(err) != "existing_update_timer" {
		t.Fatalf("existing timer file detail: %v", err)
	}
}
func TestMissingNativeToolNamesDetail(t *testing.T) {
	err := missingPackage(&resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "amd64"}, "unattended-upgrades", errNotInstalled)
	var prerequisite *PrerequisiteError
	if !errors.As(err, &prerequisite) || !errors.Is(err, ErrMissingPrerequisite) || prerequisite.Package.GetNativeName() != "unattended-upgrades" || admissiondetail.Of(err) != "native_tool_missing" {
		t.Fatalf("missing tool = %v", err)
	}
}

// dpkgStatus answers `dpkg-query -W -f=${db:Status-Abbrev}\t${Version}\n NAME`
// for the listed installed packages; any other name gets dpkg-query's exit 1
// ("no packages found matching"), which runNative maps to errNotInstalled.
func dpkgStatus(installed map[string]string, queried *[]string) commandRunner {
	return func(_ context.Context, path string, args ...string) ([]byte, error) {
		name := args[len(args)-1]
		*queried = append(*queried, name)
		if path != "/usr/bin/dpkg-query" {
			return nil, errors.New("unexpected native command " + path)
		}
		if version, ok := installed[name]; ok {
			return []byte("ii \t" + version + "\n"), nil
		}
		return nil, errNotInstalled
	}
}

// The stock Ubuntu 24.04 desktop (ubuntu-24.04.5.1-desktop-amd64.manifest)
// has unattended-upgrades 2.9.1+nmu4ubuntu1 and update-notifier-common
// 3.192.68.2 but no needrestart: the registry's reboot signal is the oracle.
func TestStockUbuntuDesktopUsesRebootSignal(t *testing.T) {
	ubuntu := &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "amd64"}
	for _, tc := range []struct {
		name      string
		installed map[string]string
		queried   []string
	}{
		{"stock desktop", map[string]string{"unattended-upgrades": "2.9.1+nmu4ubuntu1", "update-notifier-common": "3.192.68.2"}, []string{"unattended-upgrades", "needrestart", "update-notifier-common"}},
		{"needrestart installed", map[string]string{"unattended-upgrades": "2.9.1+nmu4ubuntu1", "needrestart": "3.6-7ubuntu4.5"}, []string{"unattended-upgrades", "needrestart"}},
	} {
		var queried []string
		version, oracle, err := nativeTools(t.Context(), ubuntu, dpkgStatus(tc.installed, &queried))
		if err != nil || version != "unattended-upgrades 2.9.1+nmu4ubuntu1" || !oracle || !slices.Equal(queried, tc.queried) {
			t.Fatalf("%s: nativeTools = %q, %v, %v (queried %q)", tc.name, version, oracle, err, queried)
		}
	}
	// Neither oracle: the refusal names the registry's native signal package.
	var queried []string
	_, _, err := nativeTools(t.Context(), ubuntu, dpkgStatus(map[string]string{"unattended-upgrades": "2.9.1+nmu4ubuntu1"}, &queried))
	var prerequisite *PrerequisiteError
	if !errors.As(err, &prerequisite) || admissiondetail.Of(err) != "native_tool_missing" || prerequisite.Package.GetNativeName() != "update-notifier-common" ||
		prerequisite.Package.GetEcosystem() != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB || prerequisite.Package.GetArchitecture() != "all" {
		t.Fatalf("no oracle = %v", err)
	}
	// Other releases never query Ubuntu's signal package (Fedora's stock
	// oracle is covered by TestStockFedoraPolicyNeedsOnlyDNF5).
	fedora := &resourcev1.PlatformProduct{OsId: "fedora", Product: "Fedora Linux", Version: "44", Architecture: "x86_64"}
	rpm := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "dnf5-plugin-automatic" {
			return []byte("5.4.6.0-1.fc44\n"), nil
		}
		return nil, errNotInstalled
	}
	if _, err := packageVersion(t.Context(), fedora, "update-notifier-common", rpm); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("fedora queried Ubuntu's signal package: %v", err)
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

// A stock Fedora 44 Workstation has dnf5 5.4.1.0 and neither
// dnf5-plugin-automatic nor dnf5-plugins. The policy must still converge
// there (its window runs are what upgrade dnf5 past the package provider's
// floor), while a native dnf5-automatic timer stays refused.
func TestStockFedoraPolicyNeedsOnlyDNF5(t *testing.T) {
	fedora := &resourcev1.PlatformProduct{OsId: "fedora", Product: "Fedora Linux", Version: "44", Architecture: "x86_64"}
	rpm := func(installed map[string]string) commandRunner {
		return func(_ context.Context, path string, args ...string) ([]byte, error) {
			if path != "/usr/bin/rpm" || len(args) != 4 || args[0] != "-q" {
				t.Fatalf("unexpected native query %s %q", path, args)
			}
			if version, ok := installed[args[3]]; ok {
				return []byte(version + "\n"), nil
			}
			return nil, errNotInstalled
		}
	}
	for _, tc := range []struct {
		name      string
		installed map[string]string
		want      string
	}{
		{"stock workstation", map[string]string{"dnf5": "5.4.1.0-1.fc44"}, "dnf5 5.4.1.0-1.fc44"},
		{"automatic plugin installed", map[string]string{"dnf5": "5.4.6.0-1.fc44", "dnf5-plugin-automatic": "5.4.6.0-1.fc44", "dnf5-plugins": "5.4.6.0-1.fc44"}, "dnf5-plugin-automatic 5.4.6.0-1.fc44"},
	} {
		version, oracle, err := nativeTools(t.Context(), fedora, rpm(tc.installed))
		if err != nil || version != tc.want || !oracle {
			t.Errorf("%s: native tools = %q oracle=%v %v; want %q", tc.name, version, oracle, err, tc.want)
		}
	}
	var prerequisite *PrerequisiteError
	if _, _, err := nativeTools(t.Context(), fedora, rpm(nil)); !errors.As(err, &prerequisite) || prerequisite.Package.GetNativeName() != "dnf5" || admissiondetail.Of(err) != "native_tool_missing" {
		t.Fatalf("missing dnf5 = %v", err)
	}

	p := fixtureProvider(t)
	p.config.Platform, p.update = fedora, resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC
	p.backend = &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_DNF5, NativeVersion: "dnf5 5.4.1.0-1.fc44", ProviderVersion: "1", Product: fedora}
	desired := fixtureDesired()
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(t, p, nil, false, ""), nil); err != nil {
		t.Fatalf("stock Fedora policy refused: %v", err)
	}
	timer := fixtureSnapshot(t, p, nil, false, "")
	timer.Observation.GetOsUpdate().ConflictingUnits = []string{"dnf5-automatic.timer"}
	if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, timer, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("enabled dnf5-automatic timer was not refused: %v", err)
	}
}

// A security-only or unpinned policy on a rolling backend is a typed terminal
// refusal. The bare validation error was classified as an internal executor
// failure and retried every 20 s until the lane deadline (Tumbleweed aarch64).
func TestRollingModelRefusalIsTypedUnsupported(t *testing.T) {
	p := fixtureProvider(t)
	p.update = resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER
	p.backend.Backend = resourcev1.Backend_BACKEND_ZYPPER
	p.backend.NativeVersion = "zypper 1.14.94"
	before := fixtureSnapshot(t, p, nil, false, "")
	for _, desired := range []*resourcev1.OSUpdateDesired{fixtureDesired(), {Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, Maintenance: fixtureDesired().GetMaintenance(), RebootPolicy: fixtureDesired().GetRebootPolicy()}} {
		if _, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("rolling backend did not refuse %v as unsupported: %v", desired, err)
		}
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
