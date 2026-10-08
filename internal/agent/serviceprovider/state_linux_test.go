//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func testDesired() *agentv1.ServiceDesiredState {
	return &agentv1.ServiceDesiredState{
		Unit:       "example.service",
		Runtime:    agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE,
		Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED,
	}
}

func testObservation() *agentv1.ServiceObservation {
	o := &agentv1.ServiceObservation{
		Unit: "example.service", BootId: "11111111-2222-4333-8444-555555555555",
		ObservedAt: timestamppb.New(time.Unix(1700000000, 0)),
		LoadState:  "loaded", ActiveState: "inactive", SubState: "dead",
		UnitFileState: "disabled", ServiceType: "simple", DefinitionSha256: bytes.Repeat([]byte{1}, 32),
	}
	o.FingerprintSha256 = fingerprint(o)
	return o
}

func testPlan(t *testing.T) *agentv1.ServicePlan {
	t.Helper()
	plan, err := planFor(testDesired(), testObservation())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// Exercise the production input boundary with an unopened Provider. Invalid
// messages must be rejected before connection access, not echoed by a fake bus.
func TestInvalidDesiredBeforeNativeAccess(t *testing.T) {
	cases := map[string]func(*agentv1.ServiceDesiredState){
		"empty unit":          func(d *agentv1.ServiceDesiredState) { d.Unit = "" },
		"path":                func(d *agentv1.ServiceDesiredState) { d.Unit = "../example.service" },
		"template":            func(d *agentv1.ServiceDesiredState) { d.Unit = "example@.service" },
		"escaped unit":        func(d *agentv1.ServiceDesiredState) { d.Unit = `example\x2dother.service` },
		"protected agent":     func(d *agentv1.ServiceDesiredState) { d.Unit = "lindm-agent.service" },
		"protected authority": func(d *agentv1.ServiceDesiredState) { d.Unit = "lindm.service" },
		"unknown runtime":     func(d *agentv1.ServiceDesiredState) { d.Runtime = 99 },
		"unspecified runtime": func(d *agentv1.ServiceDesiredState) { d.Runtime = 0 },
		"unknown enablement":  func(d *agentv1.ServiceDesiredState) { d.Enablement = 99 },
		"both unmanaged":      func(d *agentv1.ServiceDesiredState) { d.Runtime = 1; d.Enablement = 1 },
		"unknown wire field":  func(d *agentv1.ServiceDesiredState) { d.ProtoReflect().SetUnknown([]byte{0x78, 0x01}) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			desired := testDesired()
			change(desired)
			if _, err := (&Provider{}).Plan(context.Background(), desired); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("invalid desired reached native boundary: %v", err)
			}
		})
	}
	if _, err := (&Provider{}).Plan(context.Background(), nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil desired: %v", err)
	}
}

func TestFabricatedPlansBeforeNativeAccess(t *testing.T) {
	cases := map[string]func(*agentv1.ServicePlan){
		"runtime drift":           func(p *agentv1.ServicePlan) { p.ChangeRuntime = false },
		"enablement drift":        func(p *agentv1.ServicePlan) { p.ChangeEnablement = false },
		"observation fingerprint": func(p *agentv1.ServicePlan) { p.Before.RefuseManualStart = true },
		"unit mismatch":           func(p *agentv1.ServicePlan) { p.Desired.Unit = "other.service" },
		"nested unknown":          func(p *agentv1.ServicePlan) { p.Before.ObservedAt.ProtoReflect().SetUnknown([]byte{0x78, 0x01}) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			plan := testPlan(t)
			change(plan)
			_, err := (&Provider{}).Apply(context.Background(), plan)
			if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("fabricated plan reached native boundary: %v", err)
			}
		})
	}
}

func TestCanceledBeforeNativeAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Provider{}).Apply(ctx, testPlan(t)); !errors.Is(err, context.Canceled) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("canceled pre-start apply: %v", err)
	}
}

func TestFingerprintBindsEveryPreconditionExceptTime(t *testing.T) {
	before := testObservation()
	later := proto.CloneOf(before)
	later.ObservedAt = timestamppb.New(time.Unix(1800000000, 0))
	later.FingerprintSha256 = bytes.Repeat([]byte{9}, 32)
	if !bytes.Equal(fingerprint(before), fingerprint(later)) {
		t.Fatal("observation time or stored digest changed fingerprint")
	}
	cases := map[string]func(*agentv1.ServiceObservation){
		"unit":         func(o *agentv1.ServiceObservation) { o.Unit = "other.service" },
		"boot":         func(o *agentv1.ServiceObservation) { o.BootId = "22222222-2222-4333-8444-555555555555" },
		"load":         func(o *agentv1.ServiceObservation) { o.LoadState = "masked" },
		"active":       func(o *agentv1.ServiceObservation) { o.ActiveState = "active" },
		"substate":     func(o *agentv1.ServiceObservation) { o.SubState = "running" },
		"enablement":   func(o *agentv1.ServiceObservation) { o.UnitFileState = "enabled" },
		"type":         func(o *agentv1.ServiceObservation) { o.ServiceType = "oneshot" },
		"remain":       func(o *agentv1.ServiceObservation) { o.RemainAfterExit = true },
		"refuse start": func(o *agentv1.ServiceObservation) { o.RefuseManualStart = true },
		"refuse stop":  func(o *agentv1.ServiceObservation) { o.RefuseManualStop = true },
		"reload":       func(o *agentv1.ServiceObservation) { o.NeedDaemonReload = true },
		"transient":    func(o *agentv1.ServiceObservation) { o.Transient = true },
		"definition":   func(o *agentv1.ServiceObservation) { o.DefinitionSha256[0] ^= 1 },
		"job":          func(o *agentv1.ServiceObservation) { o.JobPending = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			current := proto.CloneOf(before)
			change(current)
			current.FingerprintSha256 = fingerprint(current)
			if bytes.Equal(before.GetFingerprintSha256(), current.GetFingerprintSha256()) {
				t.Fatal("native precondition is not fingerprinted")
			}
			if err := checkFresh(testPlan(t), current); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale fingerprint accepted: %v", err)
			}
		})
	}
}

func TestUnsupportedAndConflictingNativeStates(t *testing.T) {
	cases := map[string]struct {
		change func(*agentv1.ServiceDesiredState, *agentv1.ServiceObservation)
		want   error
	}{
		"pending":      {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.JobPending = true }, ErrConflict},
		"transition":   {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.ActiveState = "activating" }, ErrConflict},
		"oneshot":      {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.ServiceType = "oneshot" }, ErrUnsupported},
		"reload":       {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.NeedDaemonReload = true }, ErrUnsupported},
		"transient":    {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.Transient = true }, ErrUnsupported},
		"refuse start": {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.RefuseManualStart = true }, ErrUnsupported},
		"refuse stop": {func(d *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) {
			d.Runtime = 3
			o.ActiveState = "active"
			o.SubState = "running"
			o.RefuseManualStop = true
		}, ErrUnsupported},
		"static managed": {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.UnitFileState = "static" }, ErrUnsupported},
		"runtime enabled": {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) {
			o.UnitFileState = "enabled-runtime"
		}, ErrUnsupported},
		"unknown active": {func(_ *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) { o.ActiveState = "future-state" }, ErrUnsupported},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			desired, before := testDesired(), testObservation()
			test.change(desired, before)
			if _, _, err := drift(desired, before); !errors.Is(err, test.want) {
				t.Fatalf("unexpected admission: %v", err)
			}
		})
	}
	desired, before := testDesired(), testObservation()
	desired.Enablement = agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED
	before.UnitFileState = "static"
	if runtime, enablement, err := drift(desired, before); err != nil || !runtime || enablement {
		t.Fatalf("ordinary static unit with unmanaged enablement: %t %t %v", runtime, enablement, err)
	}
}

func TestVerificationDefinitionAndUnmanagedInvariants(t *testing.T) {
	plan := testPlan(t)
	after := proto.CloneOf(plan.GetBefore())
	after.ActiveState, after.SubState, after.UnitFileState = "active", "running", "enabled"
	after.FingerprintSha256 = fingerprint(after)
	result := verification(plan, after)
	if !result.GetConverged() || !result.GetDefinitionMatches() {
		t.Fatal("runtime/enablement drift incorrectly treated as definition drift")
	}
	for _, change := range []func(*agentv1.ServiceObservation){
		func(o *agentv1.ServiceObservation) { o.DefinitionSha256[0] ^= 1 },
		func(o *agentv1.ServiceObservation) { o.JobPending = true },
		func(o *agentv1.ServiceObservation) { o.NeedDaemonReload = true },
		func(o *agentv1.ServiceObservation) { o.Transient = true },
		func(o *agentv1.ServiceObservation) { o.ActiveState = "future-state" },
		func(o *agentv1.ServiceObservation) { o.SubState = "future-state" },
		func(o *agentv1.ServiceObservation) { o.BootId = "22222222-2222-4333-8444-555555555555" },
	} {
		changed := proto.CloneOf(after)
		change(changed)
		if verification(plan, changed).GetConverged() {
			t.Fatal("unsafe state reported converged")
		}
	}
	plan.Desired.Runtime = agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED
	after.ActiveState, after.SubState = "inactive", "dead"
	if !verification(plan, after).GetRuntimeMatches() {
		t.Fatal("unmanaged runtime reported drift")
	}
	plan.Desired.Enablement = agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED
	after.UnitFileState = "static"
	if !verification(plan, after).GetEnablementMatches() {
		t.Fatal("unmanaged enablement reported drift")
	}
}

func TestExactNativeJobCompletion(t *testing.T) {
	owner, unit := ":1.42", "example.service"
	job := dbus.ObjectPath("/org/freedesktop/systemd1/job/123")
	newSignal := func() *dbus.Signal {
		return &dbus.Signal{Sender: owner, Path: managerPath, Name: managerInterface + ".JobRemoved", Body: []any{uint32(123), job, unit, "done"}}
	}
	if result, matches := jobResult(newSignal(), owner, job, unit); !matches || result != "done" {
		t.Fatal("exact native completion rejected")
	}
	for _, change := range []func(*dbus.Signal){
		func(s *dbus.Signal) { s.Sender = ":1.43" },
		func(s *dbus.Signal) { s.Path = "/other" },
		func(s *dbus.Signal) { s.Name = managerInterface + ".JobNew" },
		func(s *dbus.Signal) { s.Body[0] = uint32(124) },
		func(s *dbus.Signal) { s.Body[1] = dbus.ObjectPath("/org/freedesktop/systemd1/job/124") },
		func(s *dbus.Signal) { s.Body[2] = "other.service" },
		func(s *dbus.Signal) { s.Body[3] = true },
	} {
		signal := newSignal()
		change(signal)
		if _, matches := jobResult(signal, owner, job, unit); matches {
			t.Fatal("unrelated or malformed job completion accepted")
		}
	}
	signal := newSignal()
	signal.Body[3] = "failed"
	if result, matches := jobResult(signal, owner, job, unit); !matches || result != "failed" {
		t.Fatal("failed job result was lost")
	}
}
