//go:build linux

package osupdate

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Shape of `apt-get -s -o Debug::NoLocking=1 dist-upgrade` on Ubuntu 24.04.
const aptSimulation = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following NEW packages will be installed:
  linux-image-6.8.0-45-generic
The following packages will be upgraded:
  libc6 libssl3t64 openssl tzdata ubuntu-pro-client
5 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst libssl3t64 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.8.0-45-generic (6.8.0-45.45 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst libc6:i386 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates [i386]) []
Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Inst libgtk-3-0t64 [3.24.41-4ubuntu1.1] (3.24.41-4ubuntu1.3 UbuntuESMApps:24.04/noble-apps-security [amd64])
Inst lindm-agent [0.1.0] (0.2.0 lindm:stable [amd64])
Conf libssl3t64 (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf openssl (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`

func TestParseAptSimulation(t *testing.T) {
	pending, err := parseAptSimulation([]byte(aptSimulation))
	if err != nil {
		t.Fatal(err)
	}
	want := []pendingPackage{
		{packageKey{"libc6", "i386"}, false},
		{packageKey{"libgtk-3-0t64", "amd64"}, true},
		{packageKey{"libssl3t64", "amd64"}, true},
		{packageKey{"lindm-agent", "amd64"}, false},
		{packageKey{"openssl", "amd64"}, true},
		{packageKey{"tzdata", "all"}, false},
	}
	if !slices.Equal(pending, want) {
		t.Fatalf("pending = %+v, want %+v", pending, want)
	}
	for _, malformed := range []string{
		"Inst openssl [3.0.13] (3.0.14 Ubuntu:24.04/noble-security)\n",
		"Inst open$ssl [3.0.13] (3.0.14 Ubuntu:24.04/noble-security [amd64])\n",
		"Inst openssl [3.0.13] 3.0.14\n",
	} {
		if _, err := parseAptSimulation([]byte(malformed)); !errors.Is(err, errNativeOutput) {
			t.Errorf("parseAptSimulation(%q) = %v, want malformed", malformed, err)
		}
	}
	if pending, err := parseAptSimulation([]byte("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")); err != nil || len(pending) != 0 {
		t.Fatalf("empty simulation = %v, %v", pending, err)
	}
}

func TestParseRepoqueryAndMerge(t *testing.T) {
	// dnf 4 on RHEL may print plugin chatter without a tab on stdout.
	all, err := parseRepoquery([]byte("Updating Subscription Management repositories.\nkernel\tx86_64\nopenssl-libs\tx86_64\ntzdata\tnoarch\nkernel\tx86_64\n"))
	if err != nil {
		t.Fatal(err)
	}
	security, err := parseRepoquery([]byte("openssl-libs\tx86_64\n"))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := mergeRepoquery(all, security)
	if err != nil {
		t.Fatal(err)
	}
	want := []pendingPackage{{packageKey{"kernel", "x86_64"}, false}, {packageKey{"openssl-libs", "x86_64"}, true}, {packageKey{"tzdata", "noarch"}, false}}
	if !slices.Equal(pending, want) {
		t.Fatalf("pending = %+v, want %+v", pending, want)
	}
	if _, err := mergeRepoquery(all, []packageKey{{"glibc", "x86_64"}}); !errors.Is(err, errNativeOutput) {
		t.Fatalf("security outside the upgrade list = %v", err)
	}
	if _, err := parseRepoquery([]byte("bad name\tx86_64\n")); !errors.Is(err, errNativeOutput) {
		t.Fatalf("invalid package = %v", err)
	}
}

func TestParseNeedrestartKernel(t *testing.T) {
	status, err := parseNeedrestartKernel([]byte("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-31-generic\nNEEDRESTART-KEXP: 6.8.0-45-generic\nNEEDRESTART-KSTA: 3\n"))
	if err != nil || status != 3 {
		t.Fatalf("status = %d, %v", status, err)
	}
	for _, bad := range []string{"NEEDRESTART-VER: 3.6\n", "NEEDRESTART-KSTA: 7\n", "NEEDRESTART-KSTA: 1\nNEEDRESTART-KSTA: 3\n"} {
		if _, err := parseNeedrestartKernel([]byte(bad)); err == nil {
			t.Errorf("parseNeedrestartKernel(%q) accepted", bad)
		}
	}
}

func TestNeedsRestartingResult(t *testing.T) {
	required := "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n"
	notRequired := "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
	if got, err := needsRestartingResult(1, []byte(required)); err != nil || !got {
		t.Fatalf("required = %v, %v", got, err)
	}
	if got, err := needsRestartingResult(0, []byte(notRequired)); err != nil || got {
		t.Fatalf("not required = %v, %v", got, err)
	}
	// Exit 1 is also every dnf error; without the verdict it is not a reboot.
	for _, tc := range []struct {
		code int
		out  string
	}{{1, ""}, {1, notRequired}, {0, required}, {2, required}} {
		if _, err := needsRestartingResult(tc.code, []byte(tc.out)); err == nil {
			t.Errorf("needsRestartingResult(%d, %q) accepted", tc.code, tc.out)
		}
	}
}

func TestInstalledSnapshotDiff(t *testing.T) {
	before, err := parseInstalled([]byte("openssl\tamd64\t3.0.13-0ubuntu3.1\tii \nrc-only\tamd64\t1.0\trc \nlinux-image-6.8.0-31-generic\tamd64\t6.8.0-31.31\tii \n"), true)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseInstalled([]byte("openssl\tamd64\t3.0.13-0ubuntu3.4\tii \nlinux-image-6.8.0-31-generic\tamd64\t6.8.0-31.31\tii \nlinux-image-6.8.0-45-generic\tamd64\t6.8.0-45.45\tii \n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := before[packageKey{"rc-only", "amd64"}]; ok {
		t.Fatal("config-files-only package counted as installed")
	}
	if got := changedPackages(before, after); got != 2 {
		t.Fatalf("changed = %d, want 2", got)
	}
	rpmBefore, err := parseInstalled([]byte("kernel-core\tx86_64\t0:6.11.4-301.fc44\nopenssl-libs\tx86_64\t1:3.2.2-9.fc44\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	rpmAfter, err := parseInstalled([]byte("kernel-core\tx86_64\t0:6.11.4-301.fc44\nkernel-core\tx86_64\t0:6.11.9-300.fc44\nopenssl-libs\tx86_64\t1:3.2.2-9.fc44\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := changedPackages(rpmBefore, rpmAfter); got != 1 {
		t.Fatalf("installonly change = %d, want 1", got)
	}
	for _, bad := range []string{"", "openssl\tamd64\n", "openssl\tamd64\t3.0\n"} {
		if _, err := parseInstalled([]byte(bad), true); err == nil {
			t.Errorf("parseInstalled(%q) accepted", bad)
		}
	}
}

func TestDetectBackend(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    resourcev1.OSUpdateBackend
	}{
		{"NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES},
		{"NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC},
		{"NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"9.6\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"10.2\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"ID=arch\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN},
		{"ID=opensuse-tumbleweed\nVERSION_ID=20261007\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER},
		{"ID=ubuntu\nVERSION_ID=\"22.04\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES},
		{"ID=almalinux\nVERSION_ID=\"9.6\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"ID=rocky\nVERSION_ID=\"10.2\"\n", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
	} {
		native, err := detectBackend([]byte(tc.release))
		if err != nil || native.kind() != tc.want {
			t.Errorf("detectBackend(%q) = %v, %v", tc.release, native, err)
		}
	}
	// Debian's suites need Origins-Pattern selection the runner does not render.
	for _, release := range []string{"ID=fedora\nVERSION_ID=43\n", "ID=rhel\nVERSION_ID=\"8.10\"\n", "ID=rhel\nVERSION_ID=\"11.0\"\n", "ID=debian\nVERSION_ID=\"13\"\n", "ID=debian\nVERSION_ID=\"12\"\n", "ID=almalinux\nVERSION_ID=\"8.10\"\n"} {
		if _, err := detectBackend([]byte(release)); err == nil {
			t.Errorf("detectBackend(%q) accepted an unqualified platform", release)
		}
	}
}

func TestDeferralLedger(t *testing.T) {
	day := 24 * time.Hour
	t0 := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	openssl, kernel, tzdata := packageKey{"openssl", "amd64"}, packageKey{"linux-image-generic", "amd64"}, packageKey{"tzdata", "all"}
	previous := []*agentv1.OSUpdateDeferralEntry{
		{Name: "openssl", Architecture: "amd64", FirstSeen: timestamppb.New(t0)},
		{Name: "gone", Architecture: "amd64", FirstSeen: timestamppb.New(t0)},
	}
	now := t0.Add(3 * day)
	pending := []pendingPackage{{tzdata, false}, {openssl, true}, {kernel, true}, {openssl, true}}
	ledger, err := updateLedger(previous, pending, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger) != 3 {
		t.Fatalf("ledger = %v", ledger)
	}
	for _, entry := range ledger {
		want := now
		if entry.GetName() == "openssl" {
			want = t0
		}
		if !entry.GetFirstSeen().AsTime().Equal(want) || entry.GetName() == "gone" {
			t.Errorf("entry %v first seen %v, want %v", entry.GetName(), entry.GetFirstSeen().AsTime(), want)
		}
	}
	if ledger[0].GetName() != "linux-image-generic" || ledger[2].GetName() != "tzdata" {
		t.Fatalf("ledger not sorted: %v", ledger)
	}

	rule := func(days uint32) *deferral { return &deferral{days: days, zone: time.UTC} }
	plan := planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, pending, ledger, rule(3), now)
	if plan.selected != 2 || plan.eligible != 1 || !slices.Equal(plan.deferred, []packageKey{kernel}) {
		t.Fatalf("security plan = %+v", plan)
	}
	plan = planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, pending, ledger, rule(3), now)
	if plan.selected != 3 || plan.eligible != 1 || !slices.Equal(plan.deferred, []packageKey{kernel, tzdata}) {
		t.Fatalf("all plan = %+v", plan)
	}
	// Exactly at first_seen + days the update is eligible.
	plan = planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, pending, ledger, rule(3), now.Add(3*day))
	if plan.eligible != 3 || len(plan.deferred) != 0 {
		t.Fatalf("elapsed plan = %+v", plan)
	}
	plan = planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, pending, ledger, rule(0), now)
	if plan.eligible != 3 {
		t.Fatalf("zero-day plan = %+v", plan)
	}
	// Patch now skips deferral.
	plan = planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, pending, ledger, nil, now)
	if plan.eligible != 3 || len(plan.deferred) != 0 {
		t.Fatalf("patch-now plan = %+v", plan)
	}
	// A first observation in the future (clock stepped back) stays deferred.
	plan = planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, pending, ledger, rule(1), t0.Add(-day))
	if plan.eligible != 0 {
		t.Fatalf("future first_seen plan = %+v", plan)
	}
	if _, err := updateLedger(nil, make([]pendingPackage, maxLedger+1), now); !errors.Is(err, errLedgerCapacity) {
		t.Fatalf("capacity = %v", err)
	}
}

// A weekly window with deferral_days = 7: an update first seen in one
// window is installed in the next one, wherever inside its window each run
// started, and across a spring-forward week (167 elapsed hours).
func TestDeferralIsAnchoredToWindowStarts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		zone  string
		first time.Time // a time inside the first window (Monday 02:00 local)
		next  time.Time // a time inside the next week's window
	}{
		{"plain week", "Europe/Berlin", time.Date(2026, 10, 12, 0, 40, 0, 0, time.UTC), time.Date(2026, 10, 19, 0, 5, 0, 0, time.UTC)},
		// 2026-03-29 02:00 CET -> 03:00 CEST lies between both Mondays.
		{"spring forward week", "Europe/Berlin", time.Date(2026, 3, 23, 1, 50, 0, 0, time.UTC), time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)},
		// 2026-11-01 02:00 EDT -> 01:00 EST: 169 elapsed hours.
		{"fall back week", "America/New_York", time.Date(2026, 10, 26, 6, 10, 0, 0, time.UTC), time.Date(2026, 11, 2, 7, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := mustZone(t, tc.zone)
			w := window(tc.zone, 120, 60, resourcev1.Weekday_WEEKDAY_MONDAY)
			start1, open, err := openWindow(w, zone, tc.first)
			if err != nil || !open {
				t.Fatalf("first run outside its window: %v %v", open, err)
			}
			start2, open, err := openWindow(w, zone, tc.next)
			if err != nil || !open {
				t.Fatalf("next run outside its window: %v %v", open, err)
			}
			pending := []pendingPackage{{packageKey{"openssl", "amd64"}, true}}
			ledger, err := updateLedger(nil, pending, start1)
			if err != nil {
				t.Fatal(err)
			}
			rule := &deferral{days: 7, zone: zone}
			if plan := planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, pending, ledger, rule, start1); plan.eligible != 0 {
				t.Fatalf("first window installed a new update: %+v", plan)
			}
			ledger, err = updateLedger(ledger, pending, start2)
			if err != nil {
				t.Fatal(err)
			}
			if !ledger[0].GetFirstSeen().AsTime().Equal(start1) {
				t.Fatalf("first seen moved to %v", ledger[0].GetFirstSeen().AsTime())
			}
			if plan := planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, pending, ledger, rule, start2); plan.eligible != 1 {
				t.Fatalf("next window still deferred: %+v", plan)
			}
			// One day more of deferral than the window period waits another week.
			if plan := planRun(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, pending, ledger, &deferral{days: 8, zone: zone}, start2); plan.eligible != 0 {
				t.Fatalf("8-day deferral installed after one week: %+v", plan)
			}
		})
	}
}

// The reboot oracle never loads repository metadata: on Fedora 44 a cache-only
// needs-restarting failed on a repository without cached filelists although
// the cache-only repoquery of the same run succeeded.
func TestDNFRebootOracleDisablesEveryRepository(t *testing.T) {
	if got := (dnfBackend{dnf5: true}).oracleArgs(); !slices.Equal(got, []string{"-q", "--disable-repo=*", "needs-restarting", "-r"}) {
		t.Fatalf("dnf5 oracle args = %q", got)
	}
	if got := (dnfBackend{}).oracleArgs(); !slices.Equal(got, []string{"-q", "--disablerepo=*", "needs-restarting", "-r"}) {
		t.Fatalf("dnf4 oracle args = %q", got)
	}
	for _, args := range [][]string{(dnfBackend{dnf5: true}).oracleArgs(), (dnfBackend{}).oracleArgs()} {
		if slices.Contains(args, "--cacheonly") {
			t.Fatalf("oracle still depends on repository cache: %q", args)
		}
	}
	// dnf5 may print its repository-loading header before the verdict.
	header := "Updating and loading repositories:\nRepositories loaded.\n"
	if got, err := needsRestartingResult(1, []byte(header+"Core libraries or services have been updated since boot-up:\n  * kernel-core\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n")); err != nil || !got {
		t.Fatalf("required with header = %v, %v", got, err)
	}
	if got, err := needsRestartingResult(0, []byte(header+"No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n")); err != nil || got {
		t.Fatalf("not required with header = %v, %v", got, err)
	}
	// The observed failure: exit 1 without a verdict is an oracle error.
	if _, err := needsRestartingResult(1, []byte("Updating and loading repositories:\n")); err == nil {
		t.Fatal("missing-cache failure read as a required reboot")
	}
}

func TestDNFListMissingCacheIsMetadataUnavailable(t *testing.T) {
	for _, message := range []string{
		"Updating and loading repositories:\nCache-only enabled but no cache for repository \"fedora\"\n",
		"Error: Cache-only enabled but no cache for 'rhel-9-for-x86_64-baseos-rpms'\n",
	} {
		stderr := newOutputCapture()
		_, _ = stderr.Write([]byte(message))
		if got := dnfListReason(commandResult{stdoutTail: newOutputCapture(), stderrTail: stderr, exitCode: 1}); got != reasonMetadata {
			t.Errorf("dnfListReason(%q) = %q", message, got)
		}
	}
	stderr := newOutputCapture()
	_, _ = stderr.Write([]byte("Error: Failed to load expired repos cache\n"))
	if got := dnfListReason(commandResult{stdoutTail: newOutputCapture(), stderrTail: stderr, exitCode: 1}); got != reasonListFailed {
		t.Fatalf("other listing failure = %q", got)
	}
	if got := failureReason(&nativeFailure{reason: reasonMetadata}, reasonListFailed); got != reasonMetadata {
		t.Fatalf("failureReason = %q", got)
	}
	if got := failureReason(errors.New("plain"), reasonOracleFailed); got != reasonOracleFailed {
		t.Fatalf("failureReason fallback = %q", got)
	}
}
