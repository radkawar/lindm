// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// This seam exercises native protocol, authority ordering and outcome semantics;
// it is not evidence of an actual reboot or logind integration qualification.
type powerCall struct {
	method string
	args   []any
}

type powerFixture struct {
	p          *Provider
	boot       string
	capability string
	missing    string
	scheduled  string
	preparing  bool
	inhibitors []powerInhibitor
	fail       string
	calls      []powerCall
	rechecks   int
	gates      int
}

func newPowerFixture(t *testing.T) *powerFixture {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	f := &powerFixture{boot: "b57567b4-873a-451e-b948-946212a1e2fc", capability: "yes"}
	f.p = &Provider{
		config: &agentv1.DeviceActionProviderConfig{AllowPowerActions: true}, validate: validator,
		gate: make(chan struct{}, 1), clock: func() time.Time { return time.Unix(1800000000, 123000000) },
		bootID:    func() (string, error) { return f.boot, nil },
		openPower: func(context.Context) (powerBus, func() error, error) { return f, func() error { return nil }, nil },
	}
	return f
}

func (f *powerFixture) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
	if flags != dbus.FlagNoAutoStart {
		return &dbus.Call{Err: errors.New("unsafe bus flags")}
	}
	name := method[strings.LastIndex(method, ".")+1:]
	f.calls = append(f.calls, powerCall{name, args})
	if f.fail == name {
		return &dbus.Call{Err: errors.New("native failure")}
	}
	switch name {
	case "Introspect":
		description := `<node><interface name="org.freedesktop.login1.Manager">`
		for _, name := range []string{"RebootWithFlags", "PowerOffWithFlags", "CanReboot", "CanPowerOff", "ListInhibitors", "ScheduleShutdown", "SetWallMessage"} {
			if name != f.missing {
				description += `<method name="` + name + `"/>`
			}
		}
		return &dbus.Call{Body: []any{description + `</interface></node>`}}
	case "CanReboot", "CanPowerOff":
		return &dbus.Call{Body: []any{f.capability}}
	case "GetAll":
		return &dbus.Call{Body: []any{map[string]dbus.Variant{
			"PreparingForShutdown": dbus.MakeVariant(f.preparing),
			"ScheduledShutdown": dbus.MakeVariant(struct {
				Kind string
				Usec uint64
			}{f.scheduled, ^uint64(0)}),
		}}}
	case "ListInhibitors":
		return &dbus.Call{Body: []any{f.inhibitors}}
	case "RebootWithFlags", "PowerOffWithFlags", "ScheduleShutdown", "SetWallMessage":
		if f.gates != 1 {
			return &dbus.Call{Err: errors.New("mutation without durable gate")}
		}
		return &dbus.Call{}
	default:
		return &dbus.Call{Err: errors.New("unexpected native method")}
	}
}

func (f *powerFixture) plan(t *testing.T, spec *agentv1.DeviceActionSpec) *agentv1.DeviceActionPlan {
	t.Helper()
	before, err := f.p.Observe(t.Context(), spec)
	if err != nil || !before.GetSupported() || before.GetBootId() != f.boot {
		t.Fatalf("observe: %v, %v", before, err)
	}
	plan, err := f.p.Plan(t.Context(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	f.calls = nil
	return plan
}

func (f *powerFixture) gate(context.Context) error {
	if f.gates == 0 {
		f.gates++
	} else {
		f.rechecks++
	}
	return nil
}

func (f *powerFixture) mutations() []powerCall {
	var calls []powerCall
	for _, call := range f.calls {
		switch call.method {
		case "RebootWithFlags", "PowerOffWithFlags", "ScheduleShutdown", "SetWallMessage":
			calls = append(calls, call)
		}
	}
	return calls
}

func restartSpec(delay uint32, message string) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{DelaySeconds: proto.Uint32(delay), Message: proto.String(message)}}}
}

func shutdownSpec(delay uint32, message string) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{DelaySeconds: proto.Uint32(delay), Message: proto.String(message)}}}
}

func TestPowerNativeArgumentsAndAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    *agentv1.DeviceActionSpec
		missing string
		want    []powerCall
	}{
		{"restart", restartSpec(0, ""), "", []powerCall{{"RebootWithFlags", []any{uint64(1)}}}},
		{"shutdown", shutdownSpec(0, ""), "", []powerCall{{"PowerOffWithFlags", []any{uint64(1)}}}},
		{"scheduled_restart", restartSpec(60, "Maintenance"), "", []powerCall{{"SetWallMessage", []any{"Maintenance", true}}, {"ScheduleShutdown", []any{"reboot", uint64(1800000060123000)}}}},
		{"scheduled_shutdown", shutdownSpec(3600, ""), "", []powerCall{{"ScheduleShutdown", []any{"poweroff", uint64(1800003600123000)}}}},
		{"unsupported_wall", restartSpec(0, "Maintenance"), "SetWallMessage", []powerCall{{"RebootWithFlags", []any{uint64(1)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPowerFixture(t)
			f.missing = tc.missing
			// Native delay locks must not be replaced by our own sleep/force path.
			f.inhibitors = []powerInhibitor{{What: "shutdown", Mode: "delay"}}
			plan := f.plan(t, tc.spec)
			result, err := f.p.Apply(t.Context(), plan, nil, f.gate)
			if err != nil || !result.GetPowerRequestAccepted() || result.GetVerified() || result.GetBootId() != f.boot || result.GetEvidence() != "outcome_unknown_until_contact" {
				t.Fatalf("apply: %v, %v", result, err)
			}
			if f.gates != 1 || f.rechecks != len(tc.want)-1 || !reflect.DeepEqual(f.mutations(), tc.want) {
				t.Fatalf("gates=%d rechecks=%d mutations=%v want=%v", f.gates, f.rechecks, f.mutations(), tc.want)
			}
			if _, err := f.p.Verify(t.Context(), plan, result); !errors.Is(err, ErrNotVerified) {
				t.Fatalf("native acceptance verified completion: %v", err)
			}
		})
	}
}

func TestPowerRequiresDurableAuthorityBeforeAnyMutation(t *testing.T) {
	for _, absent := range []bool{false, true} {
		f := newPowerFixture(t)
		plan := f.plan(t, restartSpec(30, "Maintenance"))
		denied := errors.New("authority revoked")
		var gate func(context.Context) error
		if !absent {
			gate = func(context.Context) error { return denied }
		}
		_, err := f.p.Apply(t.Context(), plan, nil, gate)
		if err == nil || (!absent && !errors.Is(err, denied)) || len(f.mutations()) != 0 {
			t.Fatalf("absent=%v err=%v mutations=%v", absent, err, f.mutations())
		}
	}
}

func TestPowerReobservesBeforeGate(t *testing.T) {
	for _, condition := range []string{"schedule", "preparing", "block", "block-weak", "boot", "capability", "method", "observation_error", "disabled"} {
		t.Run(condition, func(t *testing.T) {
			f := newPowerFixture(t)
			plan := f.plan(t, shutdownSpec(60, "Maintenance"))
			switch condition {
			case "schedule":
				f.scheduled = "poweroff" // Even an identical operation has another owner.
			case "preparing":
				f.preparing = true
			case "block", "block-weak":
				f.inhibitors = []powerInhibitor{{What: "sleep:shutdown", Mode: condition}}
			case "boot":
				f.boot = "dc68a4dc-f100-485c-aab1-fbc6145a297d"
			case "capability":
				f.capability = "challenge"
			case "method":
				f.missing = "ScheduleShutdown"
			case "observation_error":
				f.fail = "GetAll"
			case "disabled":
				f.p.config.AllowPowerActions = false
			}
			if _, err := f.p.Apply(t.Context(), plan, nil, f.gate); err == nil || f.gates != 0 || len(f.mutations()) != 0 {
				t.Fatalf("err=%v gates=%d mutations=%v", err, f.gates, f.mutations())
			}
		})
	}
}

func TestPowerUnsupportedAndObservationFailures(t *testing.T) {
	for _, capability := range []string{"no", "na", "challenge", "inhibited", "inhibitor-blocked", "unknown"} {
		f := newPowerFixture(t)
		f.capability = capability
		before, err := f.p.Observe(t.Context(), restartSpec(0, ""))
		if err != nil || before.GetSupported() || before.GetBootId() != f.boot || len(f.mutations()) != 0 {
			t.Fatalf("capability=%s observation=%v err=%v", capability, before, err)
		}
	}
	for _, method := range []string{"Introspect", "CanReboot", "GetAll", "ListInhibitors"} {
		f := newPowerFixture(t)
		f.fail = method
		if _, err := f.p.Observe(t.Context(), restartSpec(0, "")); err == nil {
			t.Fatalf("%s failure swallowed", method)
		}
	}
	f := newPowerFixture(t)
	f.missing = "RebootWithFlags"
	before, err := f.p.Observe(t.Context(), restartSpec(0, ""))
	if err != nil || before.GetSupported() {
		t.Fatalf("unsafe legacy fallback: %v, %v", before, err)
	}
}

func TestPowerNativeFailuresNeverRetryOrClaimAcceptance(t *testing.T) {
	for _, method := range []string{"SetWallMessage", "ScheduleShutdown", "RebootWithFlags", "PowerOffWithFlags"} {
		t.Run(method, func(t *testing.T) {
			f := newPowerFixture(t)
			spec := restartSpec(60, "Maintenance")
			switch method {
			case "RebootWithFlags":
				spec = restartSpec(0, "")
			case "PowerOffWithFlags":
				spec = shutdownSpec(0, "")
			}
			plan := f.plan(t, spec)
			f.fail = method
			result, err := f.p.Apply(t.Context(), plan, nil, f.gate)
			if !errors.Is(err, ErrOutcomeUnknown) || result.GetPowerRequestAccepted() || f.gates != 1 {
				t.Fatalf("result=%v err=%v gates=%d", result, err, f.gates)
			}
			count := 0
			for _, call := range f.mutations() {
				if call.method == method {
					count++
				}
			}
			if count != 1 || f.mutations()[len(f.mutations())-1].method != method {
				t.Fatalf("retried or continued after failure: %v", f.mutations())
			}
		})
	}
}

func TestPowerInputBoundsRejectBeforeNativeAccess(t *testing.T) {
	for _, spec := range []*agentv1.DeviceActionSpec{restartSpec(3601, ""), shutdownSpec(0, "line\nbreak"), restartSpec(0, strings.Repeat("x", 513))} {
		f := newPowerFixture(t)
		if _, err := f.p.Observe(t.Context(), spec); err == nil || len(f.calls) != 0 {
			t.Fatalf("invalid input reached native bus: %v, %v", err, f.calls)
		}
	}
}

func TestRefreshObservationDoesNotClaimNativeCompletion(t *testing.T) {
	f := newPowerFixture(t)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}
	before, err := f.p.Observe(t.Context(), spec)
	if err != nil || !before.GetSupported() || len(f.calls) != 0 {
		t.Fatalf("observe: %v, %v", before, err)
	}
	plan, err := f.p.Plan(t.Context(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	if _, err := f.p.Apply(t.Context(), plan, nil, f.gate); !errors.Is(err, ErrUnsupported) || f.gates != 0 {
		t.Fatalf("provider pretended to collect: %v gates=%d", err, f.gates)
	}
}

func TestPowerRechecksAuthorityAfterWallMessage(t *testing.T) {
	for _, delay := range []uint32{0, 60} {
		f := newPowerFixture(t)
		plan := f.plan(t, restartSpec(delay, "Maintenance"))
		expired := errors.New("challenge expired during wall request")
		gate := func(ctx context.Context) error {
			if f.gates != 0 {
				f.rechecks++
				return expired
			}
			return f.gate(ctx)
		}
		result, err := f.p.Apply(t.Context(), plan, nil, gate)
		if !errors.Is(err, expired) || !errors.Is(err, ErrOutcomeUnknown) || result.GetPowerRequestAccepted() {
			t.Fatalf("delay=%d result=%v err=%v", delay, result, err)
		}
		want := []powerCall{{"SetWallMessage", []any{"Maintenance", true}}}
		if f.gates != 1 || f.rechecks != 1 || !reflect.DeepEqual(f.mutations(), want) {
			t.Fatalf("power after expired wall authority: gates=%d rechecks=%d mutations=%v", f.gates, f.rechecks, f.mutations())
		}
	}
}
