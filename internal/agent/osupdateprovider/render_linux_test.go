//go:build linux

package osupdateprovider

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func fixtureDesired() *resourcev1.OSUpdateDesired {
	return &resourcev1.OSUpdateDesired{
		Selection:    resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY,
		Maintenance:  &resourcev1.MaintenanceWindow{TimeZone: "UTC", Weekdays: []resourcev1.Weekday{resourcev1.Weekday_WEEKDAY_SUNDAY, resourcev1.Weekday_WEEKDAY_WEDNESDAY}, LocalStartMinute: 125, DurationMinutes: 120},
		RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, MaxDelayMinutes: 60, Notice: "Updates were installed."},
		DeferralDays: 3,
	}
}

func TestTimerHasOneCalendarPerWeekdayInCanonicalOrder(t *testing.T) {
	specs, err := calendarSpecs(fixtureZoneinfo(t), fixtureDesired().GetMaintenance())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(specs, []string{"Wed *-*-* 02:05:00 UTC", "Sun *-*-* 02:05:00 UTC"}) {
		t.Fatalf("calendar specs = %q", specs)
	}
	want := "# Managed by lindm os.update.v1. Changes are drift.\n[Unit]\nDescription=lindm OS update maintenance window\n[Timer]\nOnCalendar=Wed *-*-* 02:05:00 UTC\nOnCalendar=Sun *-*-* 02:05:00 UTC\nPersistent=true\nAccuracySec=1min\nUnit=lindm-os-update.service\n"
	if got := string(renderTimer(specs)); got != want {
		t.Fatalf("timer =\n%s", got)
	}
	// systemd may report the loaded calendars in another order.
	if !sameCalendar("Sun *-*-* 02:05:00 UTC; Wed *-*-* 02:05:00 UTC", joinCalendar(specs)) || sameCalendar("Wed *-*-* 02:05:00 UTC", joinCalendar(specs)) {
		t.Fatal("calendar comparison is order-sensitive or ignores a missing window")
	}
}

func TestZoneMustExistInHostTzdata(t *testing.T) {
	root := fixtureZoneinfo(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "Zone"), []byte("TZif2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "Zone"), filepath.Join(root, "Escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("UTC", filepath.Join(root, "Alias")); err != nil {
		t.Fatal(err)
	}
	window := fixtureDesired().GetMaintenance()
	// Debian ships many zones as links inside the tzdata tree.
	window.TimeZone = "Alias"
	if _, err := calendarSpecs(root, window); err != nil {
		t.Fatalf("tzdata alias refused: %v", err)
	}
	for _, zone := range []string{"Mars/Olympus_Mons", "Local", "Europe", "Escape", "../UTC", "/UTC"} {
		window.TimeZone = zone
		if _, err := calendarSpecs(root, window); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("zone %q accepted: %v", zone, err)
		}
	}
}

func TestPolicyBytesAreDeterministicAndDecodeExactly(t *testing.T) {
	first, err := renderPolicy(fixtureDesired())
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		again, err := renderPolicy(fixtureDesired())
		if err != nil || !bytes.Equal(first, again) {
			t.Fatal("runner policy encoding is not deterministic")
		}
	}
	if !proto.Equal(decodePolicy(first), fixtureDesired()) {
		t.Fatal("rendered policy does not decode to the desired policy")
	}
	// Valid protobuf with an unknown trailing field is not the owned policy.
	if decodePolicy(append(bytes.Clone(first), 0xf8, 0x01, 0x01)) != nil {
		t.Fatal("noncanonical policy bytes decoded as effective")
	}
	invalid := fixtureDesired()
	invalid.RebootPolicy.MaxDelayMinutes = 0
	if _, err := renderPolicy(invalid); err == nil {
		t.Fatal("invalid scheduled reboot delay rendered")
	}
}

func TestBackendOwnsOnlyItsNativeConfiguration(t *testing.T) {
	for _, test := range []struct {
		backend resourcev1.OSUpdateBackend
		native  resourcev1.OSUpdateNativeFile
		content string
	}{
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC, "APT::Periodic::Unattended-Upgrade \"0\";\n"},
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC, "upgrade_type = security\n"},
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_UNSPECIFIED, ""},
	} {
		files, _, err := renderFiles(fixtureZoneinfo(t), fixtureDesired(), test.backend)
		if err != nil {
			t.Fatal(err)
		}
		kinds := ownedKinds(test.backend)
		if len(files) != len(kinds) || nativeConfigurationKind(test.backend) != test.native {
			t.Fatalf("%v renders %d files for %d owned kinds", test.backend, len(files), len(kinds))
		}
		for _, kind := range kinds {
			if files[kind] == nil {
				t.Fatalf("%v owns unrendered %v", test.backend, kind)
			}
		}
		if test.content != "" && !strings.Contains(string(files[test.native]), test.content) {
			t.Fatalf("%v native configuration =\n%s", test.backend, files[test.native])
		}
	}
	all := fixtureDesired()
	all.Selection = resourcev1.UpdateSelection_UPDATE_SELECTION_ALL
	automatic, err := renderDNF5Automatic(all.GetSelection())
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by lindm os.update.v1. Changes are drift.\n[commands]\nupgrade_type = default\nrandom_sleep = 0\nnetwork_online_timeout = 60\ndownload_updates = yes\napply_updates = yes\nreboot = never\n\n[emitters]\nemit_via = stdio\n"
	if string(automatic) != want {
		t.Fatalf("dnf5 automatic.conf =\n%s", automatic)
	}
}

func TestAPTPeriodicValueParsing(t *testing.T) {
	for output, want := range map[string]string{"": "", "Value='0'\n": "0", "Value='1'\n": "1", "Value='always'\n": "always"} {
		got, err := parseAPTShell([]byte(output))
		if err != nil || got != want {
			t.Fatalf("parse %q = %q, %v", output, got, err)
		}
	}
	for _, output := range []string{"Other='1'\n", "Value='1'\nValue='0'\n", "Value='$(x)'\n"} {
		if _, err := parseAPTShell([]byte(output)); err == nil {
			t.Fatalf("unexpected apt-config output accepted: %q", output)
		}
	}
}
