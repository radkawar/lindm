//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// This seam exercises the systemd D-Bus protocol, authority ordering and the
// request handoff; it is not evidence of a native patch run or VM qualification.
type patchFixture struct {
	p      *Provider
	dir    string
	boot   string
	units  map[string][2]string // name -> load, active
	fail   string
	calls  []string
	starts []any
	gates  int
}

type patchObject struct {
	f    *patchFixture
	path dbus.ObjectPath
}

func newPatchFixture(t *testing.T) *patchFixture {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	f := &patchFixture{dir: filepath.Join(t.TempDir(), "os-update"), boot: "b57567b4-873a-451e-b948-946212a1e2fc", units: map[string][2]string{
		resource.OSUpdateNowUnit:     {"loaded", "inactive"},
		resource.OSUpdateServiceUnit: {"loaded", "inactive"},
	}}
	f.p = &Provider{
		config: &agentv1.DeviceActionProviderConfig{AllowPatchNow: true}, validate: validator,
		gate: make(chan struct{}, 1), clock: func() time.Time { return time.Unix(1800000000, 0) },
		bootID:      func() (string, error) { return f.boot, nil },
		openSystemd: func(context.Context) (systemdBus, func() error, error) { return f, func() error { return nil }, nil },
		patchNowDir: f.dir,
	}
	return f
}

func (f *patchFixture) Object(path dbus.ObjectPath) powerBus { return patchObject{f, path} }

func (o patchObject) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
	f := o.f
	if flags != dbus.FlagNoAutoStart {
		return &dbus.Call{Err: errors.New("unsafe bus flags")}
	}
	name := method[strings.LastIndex(method, ".")+1:]
	f.calls = append(f.calls, name)
	if f.fail == name {
		return &dbus.Call{Err: errors.New("native failure")}
	}
	switch {
	case o.path == systemdPath && name == "LoadUnit":
		unit, ok := args[0].(string)
		if !ok {
			return &dbus.Call{Err: errors.New("unit name is not a string")}
		}
		return &dbus.Call{Body: []any{dbus.ObjectPath("/org/freedesktop/systemd1/unit/" + strings.NewReplacer("-", "_2d", ".", "_2e").Replace(unit))}}
	case o.path == systemdPath && name == "StartUnit":
		if f.gates != 1 {
			return &dbus.Call{Err: errors.New("start without durable gate")}
		}
		if _, err := os.Stat(filepath.Join(f.dir, "patch-now.binpb")); err != nil {
			return &dbus.Call{Err: errors.New("start before request")}
		}
		f.starts = append(f.starts, args...)
		return &dbus.Call{Body: []any{dbus.ObjectPath("/org/freedesktop/systemd1/job/1")}}
	case name == "Get":
		for unit, state := range f.units {
			if strings.HasSuffix(string(o.path), strings.NewReplacer("-", "_2d", ".", "_2e").Replace(unit)) {
				value := state[0]
				if args[1] == "ActiveState" {
					value = state[1]
				}
				return &dbus.Call{Body: []any{dbus.MakeVariant(value)}}
			}
		}
		return &dbus.Call{Body: []any{dbus.MakeVariant("not-found")}}
	}
	return &dbus.Call{Err: errors.New("unexpected native method")}
}

func (f *patchFixture) gate(context.Context) error {
	f.gates++
	return nil
}

func patchSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{
		Selection:    resourcev1.UpdateSelection_UPDATE_SELECTION_ALL,
		RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, MaxDelayMinutes: 30, Notice: "Maintenance"},
	}}}
}

func (f *patchFixture) plan(t *testing.T) *agentv1.DeviceActionPlan {
	t.Helper()
	before, err := f.p.Observe(t.Context(), patchSpec())
	if err != nil || !before.GetSupported() || before.GetBootId() != f.boot {
		t.Fatalf("observe: %v, %v", before, err)
	}
	plan, err := f.p.Plan(t.Context(), patchSpec(), before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	f.calls = nil
	return plan
}

func TestPatchNowWritesRequestAfterGateAndStartsUnit(t *testing.T) {
	f := newPatchFixture(t)
	plan := f.plan(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	result, err := f.p.Apply(ctx, plan, nil, f.gate)
	if err != nil || !result.GetVerified() || !result.GetPatchRunStarted() || result.GetPowerRequestAccepted() || result.GetEvidence() != "native_patch_run_started" || result.GetAfter().GetBootId() != f.boot {
		t.Fatalf("apply: %v, %v", result, err)
	}
	if f.gates != 1 || len(f.starts) != 2 || f.starts[0] != resource.OSUpdateNowUnit || f.starts[1] != "fail" {
		t.Fatalf("gates=%d starts=%v", f.gates, f.starts)
	}
	path := filepath.Join(f.dir, "patch-now.binpb")
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("request mode: %v %v", info, err)
	}
	if dir, err := os.Lstat(f.dir); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("request directory: %v %v", dir, err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request := new(agentv1.OSUpdatePatchNowRequest)
	if err := proto.Unmarshal(encoded, request); err != nil {
		t.Fatal(err)
	}
	now := f.p.clock()
	want := &agentv1.OSUpdatePatchNowRequest{ActionId: fixtureAction, Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, RebootPolicy: patchSpec().GetPatchNow().GetRebootPolicy()}
	if notAfter := request.GetNotAfter().AsTime(); request.GetActionId() != want.GetActionId() || request.GetSelection() != want.GetSelection() || !proto.Equal(request.GetRebootPolicy(), want.GetRebootPolicy()) || !request.GetRequestedAt().AsTime().Equal(now) || notAfter.After(now.Add(4*time.Minute)) || notAfter.Before(now.Add(3*time.Minute)) {
		t.Fatalf("request = %v", request)
	}
	deterministic, _ := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if string(deterministic) != string(encoded) {
		t.Fatal("request is not deterministic protobuf")
	}
	if err := f.p.validate.Validate(request); err != nil {
		t.Fatal(err)
	}
	// Verification cannot re-establish a start from later observation.
	if _, err := f.p.Verify(t.Context(), plan, result); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("verify: %v", err)
	}
}

func TestPatchNowRequestLifetimeIsBounded(t *testing.T) {
	f := newPatchFixture(t)
	plan := f.plan(t)
	if _, err := f.p.Apply(t.Context(), plan, nil, f.gate); err != nil {
		t.Fatal(err)
	}
	encoded, _ := os.ReadFile(filepath.Join(f.dir, "patch-now.binpb"))
	request := new(agentv1.OSUpdatePatchNowRequest)
	if err := proto.Unmarshal(encoded, request); err != nil || !request.GetNotAfter().AsTime().Equal(f.p.clock().Add(10*time.Minute)) {
		t.Fatalf("not_after = %v, %v", request.GetNotAfter(), err)
	}
}

func TestPatchNowObservationRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*patchFixture)
		reason string
	}{
		{"not configured", func(f *patchFixture) { f.p.config.AllowPatchNow = false }, "patch_now_not_qualified"},
		{"unit missing", func(f *patchFixture) { f.units[resource.OSUpdateNowUnit] = [2]string{"not-found", "inactive"} }, "patch_run_unit_missing"},
		{"now unit running", func(f *patchFixture) { f.units[resource.OSUpdateNowUnit] = [2]string{"loaded", "activating"} }, "patch_run_in_progress"},
		{"window run active", func(f *patchFixture) { f.units[resource.OSUpdateServiceUnit] = [2]string{"loaded", "active"} }, "patch_run_in_progress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPatchFixture(t)
			tc.change(f)
			observation, err := f.p.Observe(t.Context(), patchSpec())
			if err != nil || observation.GetSupported() || !strings.HasSuffix(observation.GetReason(), tc.reason) {
				t.Fatalf("observation = %v, %v", observation, err)
			}
		})
	}
}

func TestPatchNowRefusesBeforeGateAndUnknownAfter(t *testing.T) {
	t.Run("run started after plan", func(t *testing.T) {
		f := newPatchFixture(t)
		plan := f.plan(t)
		f.units[resource.OSUpdateServiceUnit] = [2]string{"loaded", "active"}
		if _, err := f.p.Apply(t.Context(), plan, nil, f.gate); !errors.Is(err, ErrConflict) || errors.Is(err, ErrOutcomeUnknown) || f.gates != 0 {
			t.Fatalf("err=%v gates=%d", err, f.gates)
		}
	})
	t.Run("changed boot", func(t *testing.T) {
		f := newPatchFixture(t)
		plan := f.plan(t)
		f.boot = "0f3b8c69-3d0e-4c58-9a57-1d1f3b3c2b11"
		if _, err := f.p.Apply(t.Context(), plan, nil, f.gate); !errors.Is(err, ErrConflict) || f.gates != 0 {
			t.Fatalf("err=%v gates=%d", err, f.gates)
		}
	})
	t.Run("start failure", func(t *testing.T) {
		f := newPatchFixture(t)
		plan := f.plan(t)
		f.fail = "StartUnit"
		result, err := f.p.Apply(t.Context(), plan, nil, f.gate)
		if !errors.Is(err, ErrOutcomeUnknown) || result.GetPatchRunStarted() || f.gates != 1 {
			t.Fatalf("result=%v err=%v gates=%d", result, err, f.gates)
		}
	})
	t.Run("untrusted request directory", func(t *testing.T) {
		f := newPatchFixture(t)
		plan := f.plan(t)
		if err := os.Mkdir(f.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := f.p.Apply(t.Context(), plan, nil, f.gate)
		if !errors.Is(err, ErrOutcomeUnknown) || f.gates != 1 || len(f.starts) != 0 {
			t.Fatalf("err=%v gates=%d starts=%v", err, f.gates, f.starts)
		}
	})
}
