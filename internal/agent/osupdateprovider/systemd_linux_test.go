//go:build linux

package osupdateprovider

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/osupdate"
	"lindm/internal/resource"
)

// These tests run the host's real systemd-analyze over the rendered units and
// calendars. They never start a unit: installation on a booted system is
// qualified on native guests.

func systemdAnalyze(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not installed on this host")
	}
	return path
}

func runAnalyze(t *testing.T, path string, env []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "TZ=UTC"}, env...)
	cmd.Dir = "/"
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}

func packagedService(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source location unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "packaging", "assets", resource.OSUpdateServiceUnit))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestWantsDropInIsExact(t *testing.T) {
	want := "# Managed by lindm os.update.v1. Changes are drift.\n[Unit]\nWants=lindm-os-update.timer\n"
	if got := string(renderWants()); got != want {
		t.Fatalf("timers.target drop-in =\n%s", got)
	}
}

// The rendered timer, its pull-in from timers.target and the packaged window
// service are valid systemd units together.
func TestRenderedUnitsPassSystemdVerify(t *testing.T) {
	analyze := systemdAnalyze(t)
	units := t.TempDir()
	specs, err := calendarSpecs(zoneinfoRoot, &resourcev1.MaintenanceWindow{TimeZone: "Europe/Berlin", Weekdays: []resourcev1.Weekday{1, 7}, LocalStartMinute: 1410, DurationMinutes: 120})
	if err != nil {
		t.Fatal(err)
	}
	timer := renderTimer(specs)
	if !bytes.Contains(timer, []byte("\nUnit="+resource.OSUpdateServiceUnit+"\n")) {
		t.Fatal("timer does not trigger the packaged window service")
	}
	// The packaged binary is not installed on the test host; only its path is
	// replaced so verify can check the rest of the unit as shipped.
	stub := filepath.Join(units, "lindm-agent")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	service := packagedService(t)
	const exec = "ExecStart=/usr/libexec/lindm/lindm-agent os-update run\n"
	if !bytes.Contains(service, []byte(exec)) {
		t.Fatal("packaged window service no longer runs the os-update runner")
	}
	service = bytes.Replace(service, []byte(exec), []byte("ExecStart="+stub+" os-update run\n"), 1)
	files := map[string][]byte{
		resource.OSUpdateTimerUnit:   timer,
		resource.OSUpdateServiceUnit: service,
		filepath.Join("timers.target.d", filepath.Base(resource.OSUpdateWantsPath)): renderWants(),
	}
	for name, content := range files {
		path := filepath.Join(units, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"SYSTEMD_UNIT_PATH=" + units + ":"}
	for _, target := range []string{filepath.Join(units, resource.OSUpdateTimerUnit), filepath.Join(units, resource.OSUpdateServiceUnit), "timers.target"} {
		if output, err := runAnalyze(t, analyze, env, "verify", "--man=no", "--recursive-errors=no", "--", target); err != nil {
			t.Fatalf("systemd-analyze verify %s: %v\n%s", filepath.Base(target), err, output)
		}
	}
	// verify is meaningful: an unparsable calendar is refused.
	broken := bytes.ReplaceAll(timer, []byte("Europe/Berlin"), []byte("Bogus/Zone"))
	if err := os.WriteFile(filepath.Join(units, resource.OSUpdateTimerUnit), broken, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := runAnalyze(t, analyze, env, "verify", "--man=no", "--recursive-errors=no", "--", filepath.Join(units, resource.OSUpdateTimerUnit)); err == nil {
		t.Fatalf("systemd-analyze accepted an unparsable calendar:\n%s", output)
	}
}

// parseElapses reads systemd-analyze calendar output (TZ=UTC) per spec.
func parseElapses(t *testing.T, output string) [][]time.Time {
	t.Helper()
	var all [][]time.Time
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Normalized form:"):
			all = append(all, nil)
		case strings.HasPrefix(line, "Next elapse:"), strings.HasPrefix(line, "Iteration #"):
			_, value, _ := strings.Cut(line, ": ")
			elapse, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(value))
			if err != nil || len(all) == 0 {
				t.Fatalf("unexpected calendar line %q: %v", line, err)
			}
			all[len(all)-1] = append(all[len(all)-1], elapse.UTC())
		}
	}
	return all
}

// systemd's next elapses of the rendered calendars are exactly the window
// starts the runner's gate admits, including DST gaps (skipped by both),
// fall-back repeats (first occurrence) and windows crossing midnight.
func TestTimerElapsesAreTheRunnerWindowStarts(t *testing.T) {
	analyze := systemdAnalyze(t)
	help, _ := runAnalyze(t, analyze, nil, "calendar", "--help")
	baseSupported := strings.Contains(help, "--base-time")
	for _, test := range []struct {
		name   string
		window *resourcev1.MaintenanceWindow
		base   string
	}{
		{"utc", &resourcev1.MaintenanceWindow{TimeZone: "UTC", Weekdays: []resourcev1.Weekday{1}, LocalStartMinute: 120, DurationMinutes: 120}, "2026-10-11T12:00:00Z"},
		{"berlin spring gap", &resourcev1.MaintenanceWindow{TimeZone: "Europe/Berlin", Weekdays: []resourcev1.Weekday{7}, LocalStartMinute: 150, DurationMinutes: 60}, "2026-03-28T12:00:00Z"},
		{"berlin fall back", &resourcev1.MaintenanceWindow{TimeZone: "Europe/Berlin", Weekdays: []resourcev1.Weekday{7}, LocalStartMinute: 150, DurationMinutes: 60}, "2026-10-24T12:00:00Z"},
		{"new york multi weekday", &resourcev1.MaintenanceWindow{TimeZone: "America/New_York", Weekdays: []resourcev1.Weekday{5, 1, 3}, LocalStartMinute: 240, DurationMinutes: 90}, "2026-10-28T12:00:00Z"},
		{"new york crossing midnight", &resourcev1.MaintenanceWindow{TimeZone: "America/New_York", Weekdays: []resourcev1.Weekday{6, 7}, LocalStartMinute: 1410, DurationMinutes: 120}, "2026-10-30T12:00:00Z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, err := time.Parse(time.RFC3339, test.base)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"calendar", "--iterations=3"}
			if baseSupported {
				args = append(args, "--base-time="+base.Format("2006-01-02 15:04:05")+" UTC")
			} else {
				// Older systemd computes from now; compare against the gate from now.
				base = time.Now().UTC().Truncate(time.Second)
			}
			specs, err := calendarSpecs(zoneinfoRoot, test.window)
			if err != nil {
				t.Fatal(err)
			}
			output, err := runAnalyze(t, analyze, nil, append(args, specs...)...)
			if err != nil {
				t.Fatalf("systemd-analyze calendar: %v\n%s", err, output)
			}
			perSpec := parseElapses(t, output)
			if len(perSpec) != len(specs) {
				t.Fatalf("systemd parsed %d of %d calendars:\n%s", len(perSpec), len(specs), output)
			}
			// Every spec contributes all its starts up to the earliest third
			// iteration, so the union is complete within that horizon.
			var horizon time.Time
			var elapses []time.Time
			for _, spec := range perSpec {
				if len(spec) != 3 {
					t.Fatalf("calendar has %d iterations:\n%s", len(spec), output)
				}
				if horizon.IsZero() || spec[2].Before(horizon) {
					horizon = spec[2]
				}
				elapses = append(elapses, spec...)
			}
			elapses = slices.DeleteFunc(elapses, func(e time.Time) bool { return e.After(horizon) })
			slices.SortFunc(elapses, func(a, b time.Time) int { return a.Compare(b) })
			var starts []time.Time
			for now := base.Truncate(time.Minute); !now.After(horizon); now = now.Add(time.Minute) {
				start, open, err := osupdate.OpenWindow(test.window, now)
				if err != nil {
					t.Fatal(err)
				}
				if open && start.After(base) && !start.After(horizon) && !slices.ContainsFunc(starts, start.Equal) {
					starts = append(starts, start.UTC())
				}
			}
			if len(elapses) < 3 || !slices.EqualFunc(elapses, starts, time.Time.Equal) {
				t.Fatalf("systemd elapses %v\nrunner window starts %v", elapses, starts)
			}
		})
	}
}
