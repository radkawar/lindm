// SPDX-License-Identifier: Apache-2.0

//go:build linux

package definitionprovider

import (
	"bytes"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestRenderClosedDefinitions(t *testing.T) {
	d := timerDesired()
	actual, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	expected := "# Managed by lindm. Changes are ownership conflicts.\n[Unit]\nDescription=lindm managed timer\n\n[Timer]\nUnit=example.service\nOnActiveSec=60s\nOnUnitActiveSec=60s\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=no\nWakeSystem=no\n\n[Install]\nWantedBy=timers.target\n"
	if string(actual) != expected {
		t.Fatalf("interval render = %q", actual)
	}
	d.GetSystemdDefinition().GetTimer().Schedule = &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_Daily{Daily: &resourcev1.DailyTimerSchedule{Hour: 2, Minute: 7}}}
	actual, err = Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(actual, []byte("OnCalendar=*-*-* 02:07:00 UTC\n")) || bytes.Contains(actual, []byte("OnActiveSec")) {
		t.Fatalf("daily schedule = %q", actual)
	}
	d = dropDesired()
	actual, err = Render(d)
	if err != nil {
		t.Fatal(err)
	}
	expected = "# Managed by lindm. Changes are ownership conflicts.\n[Service]\nCPUWeight=100\nMemoryMax=1048576\nTasksMax=32\nNoNewPrivileges=yes\n"
	if string(actual) != expected {
		t.Fatalf("drop-in render = %q", actual)
	}
	d.GetSystemdDefinition().GetDropIn().NoNewPrivileges = proto.Bool(false)
	actual, err = Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(actual, []byte("NoNewPrivileges=no\n")) {
		t.Fatal("managed false option was lost")
	}
	d.GetSystemdDefinition().Presence = resourcev1.Presence_PRESENCE_ABSENT
	actual, err = Render(d)
	if err != nil || actual != nil {
		t.Fatalf("absent render = %q, %v", actual, err)
	}
}
func TestProtectedAndCanonicalDefinitions(t *testing.T) {
	for _, unit := range []string{"lindm.service", "lindm-executor.service", "lindm-agent.service", "../bad.service", "example@.service", "example.service\nExecStart=/bin/sh"} {
		d := dropDesired()
		d.GetSystemdDefinition().GetDropIn().Unit = unit
		d.Ref.CanonicalKey = "drop-in/" + unit
		if _, err := Render(d); err == nil {
			t.Errorf("unsafe drop-in accepted: %q", unit)
		}
	}
	for _, unit := range []string{"lindm.timer", "lindm-update.timer", "../example.timer", "example.timer\n"} {
		d := timerDesired()
		d.GetSystemdDefinition().GetTimer().Unit = unit
		d.Ref.CanonicalKey = "timer/" + unit
		if _, err := DefinitionPath(d); err == nil {
			t.Errorf("unsafe timer accepted: %q", unit)
		}
	}
	d := timerDesired()
	d.GetSystemdDefinition().GetTimer().Service.CanonicalKey = "lindm-executor.service"
	if _, err := Render(d); err == nil {
		t.Fatal("protected service target accepted")
	}
	d = dropDesired()
	d.Ref.CanonicalKey = "drop-in/another.service"
	if _, err := DefinitionPath(d); err == nil {
		t.Fatal("ref identity substitution accepted")
	}
	path, err := DefinitionPath(dropDesired())
	if err != nil || path != "/etc/systemd/system/example.service.d/50-lindm.conf" {
		t.Fatalf("derived path = %q, %v", path, err)
	}
}
func TestAdoptionCannotCaptureExecutableDirectives(t *testing.T) {
	d := dropDesired()
	data, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseOwnedDropIn(d, data)
	if err != nil || !proto.Equal(parsed, d.GetSystemdDefinition()) {
		t.Fatalf("supported baseline = %v, %v", parsed, err)
	}
	for _, text := range []string{string(data) + "ExecStart=/bin/sh\n", strings.ReplaceAll(string(data), "CPUWeight=100", "CPUWeight=100\nCPUWeight=200"), string(data) + ".include /etc/other\n", strings.ReplaceAll(string(data), "MemoryMax=1048576", "MemoryMax=infinity")} {
		if _, err := parseOwnedDropIn(d, []byte(text)); err == nil {
			t.Fatal("unrepresentable adoption baseline accepted")
		}
	}
}
func TestEffectivePropertiesExposeDrift(t *testing.T) {
	d := dropDesired()
	desired := d.GetSystemdDefinition().GetDropIn()
	base := &resourcev1.SystemdEffectiveOptions{CpuWeight: 100, MemoryMax: 1048576, TasksMax: 32, NoNewPrivileges: true}
	if !optionsMatch(desired, base) {
		t.Fatal("matching properties not accepted")
	}
	for _, mutate := range []func(*resourcev1.SystemdEffectiveOptions){func(o *resourcev1.SystemdEffectiveOptions) { o.CpuWeight++ }, func(o *resourcev1.SystemdEffectiveOptions) { o.MemoryMax = ^uint64(0) }, func(o *resourcev1.SystemdEffectiveOptions) { o.TasksMax++ }, func(o *resourcev1.SystemdEffectiveOptions) { o.NoNewPrivileges = false }} {
		other := proto.CloneOf(base)
		mutate(other)
		if optionsMatch(desired, other) {
			t.Fatal("native effective drift hidden")
		}
	}
	desired.MemoryMaxBytes = nil
	other := proto.CloneOf(base)
	other.MemoryMax = ^uint64(0)
	if !optionsMatch(desired, other) {
		t.Fatal("unmanaged infinity was mistaken for drift")
	}
	view := &unitView{properties: map[string]dbus.Variant{"CPUWeight": dbus.MakeVariant(uint64(100))}}
	if _, err := effectiveOptions(view); err == nil {
		t.Fatal("missing native evidence looked converged")
	}
}
func TestTimerNativeScheduleExcludesVolatileNextElapse(t *testing.T) {
	view := timerView()
	effective, first, err := timerSchedule(view)
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetSchedule().GetIntervalSeconds() != 60 {
		t.Fatalf("interval = %v", effective)
	}
	view.properties["TimersMonotonic"] = dbus.MakeVariant([]monotonicTimer{{Base: "OnUnitActiveUSec", Value: 60000000, Next: 999999999}, {Base: "OnActiveUSec", Value: 60000000, Next: 888888888}})
	_, second, err := timerSchedule(view)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("volatile deadlines changed stable schedule fingerprint")
	}
	view.properties["TimersMonotonic"] = dbus.MakeVariant([]monotonicTimer{{Base: "OnBootUSec", Value: 60000000}, {Base: "OnUnitActiveUSec", Value: 60000000}})
	if _, _, err := timerSchedule(view); err == nil {
		t.Fatal("different initial activation semantics accepted")
	}
	view = timerView()
	view.properties["Persistent"] = dbus.MakeVariant(true)
	if _, _, err := timerSchedule(view); err == nil {
		t.Fatal("catch-up behavior silently adopted")
	}
	view = timerView()
	view.properties["TimersMonotonic"] = dbus.MakeVariant([]monotonicTimer{})
	view.properties["TimersCalendar"] = dbus.MakeVariant([]calendarTimer{{Base: "OnCalendar", Spec: "*-*-* 02:07:00 UTC", Next: 99}})
	if got, _, err := timerSchedule(view); err != nil || got.GetSchedule().GetDaily().GetHour() != 2 || got.GetSchedule().GetDaily().GetMinute() != 7 {
		t.Fatalf("UTC native schedule = %v, %v", got, err)
	}
	view.properties["TimersCalendar"] = dbus.MakeVariant([]calendarTimer{{Base: "OnCalendar", Spec: "*-*-* 02:07:00 Europe/Paris", Next: 99}})
	if _, _, err := timerSchedule(view); err == nil {
		t.Fatal("non-UTC schedule accepted")
	}
}

func TestNativeCanonicalIdentityRejectsAliasesAndProtectedNames(t *testing.T) {
	if err := canonicalUnit("alias.service", "example.service", []string{"alias.service", "example.service"}); err == nil {
		t.Fatal("alias used as canonical authority")
	}
	if err := canonicalUnit("example.service", "example.service", []string{"example.service", "lindm-executor.service"}); err == nil {
		t.Fatal("protected alias hidden behind ordinary canonical name")
	}
	if err := canonicalUnit("example.service", "example.service", []string{"example.service", "another-name.service"}); err != nil {
		t.Fatalf("canonical ordinary service refused: %v", err)
	}
}
