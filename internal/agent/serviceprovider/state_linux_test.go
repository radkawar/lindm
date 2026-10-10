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

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func testDesired() *resourcev1.SystemdServiceDesired {
	return &resourcev1.SystemdServiceDesired{
		Unit:       "example.service",
		Runtime:    resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE,
		Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED,
	}
}

func testObservation() *resourcev1.SystemdServiceObservation {
	o := &resourcev1.SystemdServiceObservation{
		Unit: "example.service", BootId: "11111111-2222-4333-8444-555555555555",
		ObservedAt: timestamppb.New(time.Unix(1700000000, 0)),
		LoadState:  "loaded", ActiveState: "inactive", SubState: "dead",
		UnitFileState: "disabled", ServiceType: "simple", DefinitionSha256: bytes.Repeat([]byte{1}, 32),
	}
	o.FingerprintSha256 = fingerprint(o)
	return o
}

func testPlan(t *testing.T) *resourcev1.ResourcePlan {
	t.Helper()
	plan, err := planFor(testResourceDesired(testDesired()), testResourceObservation(testObservation()), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testResourceDesired(native *resourcev1.SystemdServiceDesired) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: native.GetUnit()},
		State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: native},
	}
}

func testResourceObservation(native *resourcev1.SystemdServiceObservation) *resourcev1.ResourceObservation {
	return observationEnvelope(native, "33333333-2222-4333-8444-555555555555", &resourcev1.BackendSelection{
		Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "257", ProviderVersion: "systemd.service.v1",
		Product: &resourcev1.PlatformProduct{OsId: "debian", Product: "Debian GNU/Linux", Version: "13", Architecture: "x86_64"},
	})
}

func testVerification(t *testing.T, plan *resourcev1.ResourcePlan, after *resourcev1.SystemdServiceObservation) *resourcev1.ResourceVerification {
	t.Helper()
	result, err := verification(plan, after, plan.GetBefore().GetMetadata().GetExecutorIncarnation())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Exercise the production input boundary with an unopened Provider. Invalid
// messages must be rejected before connection access, not echoed by a fake bus.
func TestInvalidDesiredBeforeNativeAccess(t *testing.T) {
	cases := map[string]func(*resourcev1.SystemdServiceDesired){
		"empty unit":          func(d *resourcev1.SystemdServiceDesired) { d.Unit = "" },
		"path":                func(d *resourcev1.SystemdServiceDesired) { d.Unit = "../example.service" },
		"template":            func(d *resourcev1.SystemdServiceDesired) { d.Unit = "example@.service" },
		"escaped unit":        func(d *resourcev1.SystemdServiceDesired) { d.Unit = `example\x2dother.service` },
		"protected agent":     func(d *resourcev1.SystemdServiceDesired) { d.Unit = "lindm-agent.service" },
		"protected authority": func(d *resourcev1.SystemdServiceDesired) { d.Unit = "lindm.service" },
		"unknown runtime":     func(d *resourcev1.SystemdServiceDesired) { d.Runtime = 99 },
		"unspecified runtime": func(d *resourcev1.SystemdServiceDesired) { d.Runtime = 0 },
		"unknown enablement":  func(d *resourcev1.SystemdServiceDesired) { d.Enablement = 99 },
		"both unmanaged":      func(d *resourcev1.SystemdServiceDesired) { d.Runtime = 1; d.Enablement = 1 },
		"unknown wire field":  func(d *resourcev1.SystemdServiceDesired) { d.ProtoReflect().SetUnknown([]byte{0x78, 0x01}) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			desired := testDesired()
			change(desired)
			if _, err := (&Provider{}).Plan(context.Background(), testResourceDesired(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("invalid desired reached native boundary: %v", err)
			}
		})
	}
	if _, err := (&Provider{}).Plan(context.Background(), nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil desired: %v", err)
	}
}

func TestFabricatedPlansBeforeNativeAccess(t *testing.T) {
	cases := map[string]func(*resourcev1.ResourcePlan){
		"runtime drift":           func(p *resourcev1.ResourcePlan) { p.GetSystemdService().ChangeRuntime = false },
		"enablement drift":        func(p *resourcev1.ResourcePlan) { p.GetSystemdService().ChangeEnablement = false },
		"observation fingerprint": func(p *resourcev1.ResourcePlan) { p.GetSystemdService().Before.RefuseManualStart = true },
		"unit mismatch":           func(p *resourcev1.ResourcePlan) { p.GetSystemdService().Desired.Unit = "other.service" },
		"nested unknown": func(p *resourcev1.ResourcePlan) {
			p.GetSystemdService().Before.ObservedAt.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
		},
		"resource kind":      func(p *resourcev1.ResourcePlan) { p.Ref.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP },
		"resource key":       func(p *resourcev1.ResourcePlan) { p.Ref.CanonicalKey = "other.service" },
		"desired digest":     func(p *resourcev1.ResourcePlan) { p.DesiredSha256[0] ^= 1 },
		"observation digest": func(p *resourcev1.ResourcePlan) { p.ObservationSha256[0] ^= 1 },
		"native envelope": func(p *resourcev1.ResourcePlan) {
			p.Before = testResourceObservation(testObservation())
			p.Before.Metadata.NativeRevision[0] ^= 1
		},
		"claims": func(p *resourcev1.ResourcePlan) { p.Claims = nil },
		"rollback claim": func(p *resourcev1.ResourcePlan) {
			p.Safety.RollbackScope = resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS
		},
		"release": func(p *resourcev1.ResourcePlan) {
			p.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			plan := testPlan(t)
			change(plan)
			_, err := (&Provider{}).Apply(context.Background(), plan, nil)
			if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("fabricated plan reached native boundary: %v", err)
			}
		})
	}
}

func TestCanceledBeforeNativeAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Provider{}).Apply(ctx, testPlan(t), func(ctx context.Context) error { return ctx.Err() }); !errors.Is(err, context.Canceled) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("canceled pre-start apply: %v", err)
	}
}

func TestDriftingPlanCannotApplyWithoutStartAuthority(t *testing.T) {
	if _, err := (&Provider{}).Apply(t.Context(), testPlan(t), nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("drifting plan reached native access without start authority: %v", err)
	}
}

func TestRetainedVerificationRejectsFabricatedCompliance(t *testing.T) {
	plan := testPlan(t)
	after := testObservation()
	after.ActiveState, after.SubState, after.UnitFileState = "active", "running", "enabled"
	after.FingerprintSha256 = fingerprint(after)
	result := testVerification(t, plan, after)
	if err := ValidateVerification(plan, result); err != nil {
		t.Fatalf("consistent convergence rejected: %v", err)
	}
	for name, mutate := range map[string]func(*resourcev1.ResourceVerification){
		"unbound observation": func(v *resourcev1.ResourceVerification) { v.GetAfter().GetSystemdService().ActiveState = "inactive" },
		"false runtime": func(v *resourcev1.ResourceVerification) {
			o := v.GetAfter().GetSystemdService()
			o.ActiveState, o.SubState = "inactive", "dead"
			o.FingerprintSha256 = fingerprint(o)
		},
		"foreign unit": func(v *resourcev1.ResourceVerification) {
			o := v.GetAfter().GetSystemdService()
			o.Unit = "other.service"
			o.FingerprintSha256 = fingerprint(o)
		},
		"false definition": func(v *resourcev1.ResourceVerification) {
			o := v.GetAfter().GetSystemdService()
			o.DefinitionSha256[0] ^= 1
			o.FingerprintSha256 = fingerprint(o)
		},
		"false boot": func(v *resourcev1.ResourceVerification) {
			o := v.GetAfter().GetSystemdService()
			o.BootId = "22222222-2222-4333-8444-555555555555"
			o.FingerprintSha256 = fingerprint(o)
		},
		"desired digest":      func(v *resourcev1.ResourceVerification) { v.DesiredSha256[0] ^= 1 },
		"plan digest":         func(v *resourcev1.ResourceVerification) { v.PlanSha256[0] ^= 1 },
		"invalid incarnation": func(v *resourcev1.ResourceVerification) { v.After.Metadata.ExecutorIncarnation = "invalid" },
		"disposition": func(v *resourcev1.ResourceVerification) {
			v.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proto.CloneOf(result)
			mutate(candidate)
			if err := ValidateVerification(plan, candidate); !errors.Is(err, ErrConflict) {
				t.Fatalf("fabricated retained compliance accepted: %v", err)
			}
		})
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
	cases := map[string]func(*resourcev1.SystemdServiceObservation){
		"unit":         func(o *resourcev1.SystemdServiceObservation) { o.Unit = "other.service" },
		"boot":         func(o *resourcev1.SystemdServiceObservation) { o.BootId = "22222222-2222-4333-8444-555555555555" },
		"load":         func(o *resourcev1.SystemdServiceObservation) { o.LoadState = "masked" },
		"active":       func(o *resourcev1.SystemdServiceObservation) { o.ActiveState = "active" },
		"substate":     func(o *resourcev1.SystemdServiceObservation) { o.SubState = "running" },
		"enablement":   func(o *resourcev1.SystemdServiceObservation) { o.UnitFileState = "enabled" },
		"type":         func(o *resourcev1.SystemdServiceObservation) { o.ServiceType = "oneshot" },
		"remain":       func(o *resourcev1.SystemdServiceObservation) { o.RemainAfterExit = true },
		"refuse start": func(o *resourcev1.SystemdServiceObservation) { o.RefuseManualStart = true },
		"refuse stop":  func(o *resourcev1.SystemdServiceObservation) { o.RefuseManualStop = true },
		"reload":       func(o *resourcev1.SystemdServiceObservation) { o.NeedDaemonReload = true },
		"transient":    func(o *resourcev1.SystemdServiceObservation) { o.Transient = true },
		"definition":   func(o *resourcev1.SystemdServiceObservation) { o.DefinitionSha256[0] ^= 1 },
		"job":          func(o *resourcev1.SystemdServiceObservation) { o.JobPending = true },
		"invocation":   func(o *resourcev1.SystemdServiceObservation) { o.InvocationId = bytes.Repeat([]byte{3}, 16) },
		"projection":   func(o *resourcev1.SystemdServiceObservation) { o.InstallProjectionComplete = true },
		"install links": func(o *resourcev1.SystemdServiceObservation) {
			o.InstallLinks = []*resourcev1.InstallLink{{Path: "/etc/systemd/system/multi-user.target.wants/example.service", Target: "/usr/lib/systemd/system/example.service", Device: 1, Inode: 2, AncestrySha256: bytes.Repeat([]byte{4}, 32)}}
		},
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
		change func(*resourcev1.SystemdServiceDesired, *resourcev1.SystemdServiceObservation)
		want   error
	}{
		"pending": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.JobPending = true
		}, ErrConflict},
		"transition": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.ActiveState = "activating"
		}, ErrConflict},
		"oneshot": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.ServiceType = "oneshot"
		}, ErrUnsupported},
		"reload": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.NeedDaemonReload = true
		}, ErrUnsupported},
		"transient": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) { o.Transient = true }, ErrUnsupported},
		"refuse start": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.RefuseManualStart = true
		}, ErrUnsupported},
		"refuse stop": {func(d *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			d.Runtime = 3
			o.ActiveState = "active"
			o.SubState = "running"
			o.RefuseManualStop = true
		}, ErrUnsupported},
		"static managed": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.UnitFileState = "static"
		}, ErrUnsupported},
		"runtime enabled": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.UnitFileState = "enabled-runtime"
		}, ErrUnsupported},
		"unknown active": {func(_ *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) {
			o.ActiveState = "future-state"
		}, ErrUnsupported},
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
	desired.Enablement = resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED
	before.UnitFileState = "static"
	if runtime, enablement, err := drift(desired, before); err != nil || !runtime || enablement {
		t.Fatalf("ordinary static unit with unmanaged enablement: %t %t %v", runtime, enablement, err)
	}
}

func TestVerificationDefinitionAndUnmanagedInvariants(t *testing.T) {
	plan := testPlan(t)
	after := proto.CloneOf(plan.GetSystemdService().GetBefore())
	after.ActiveState, after.SubState, after.UnitFileState = "active", "running", "enabled"
	after.FingerprintSha256 = fingerprint(after)
	result := testVerification(t, plan, after)
	if !result.GetSystemdService().GetConverged() || !result.GetSystemdService().GetDefinitionMatches() {
		t.Fatal("runtime/enablement drift incorrectly treated as definition drift")
	}
	for _, change := range []func(*resourcev1.SystemdServiceObservation){
		func(o *resourcev1.SystemdServiceObservation) { o.DefinitionSha256[0] ^= 1 },
		func(o *resourcev1.SystemdServiceObservation) { o.JobPending = true },
		func(o *resourcev1.SystemdServiceObservation) { o.NeedDaemonReload = true },
		func(o *resourcev1.SystemdServiceObservation) { o.Transient = true },
		func(o *resourcev1.SystemdServiceObservation) { o.ActiveState = "future-state" },
		func(o *resourcev1.SystemdServiceObservation) { o.SubState = "future-state" },
		func(o *resourcev1.SystemdServiceObservation) { o.BootId = "22222222-2222-4333-8444-555555555555" },
	} {
		changed := proto.CloneOf(after)
		change(changed)
		if testVerification(t, plan, changed).GetSystemdService().GetConverged() {
			t.Fatal("unsafe state reported converged")
		}
	}
	desired := testDesired()
	desired.Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED
	plan, err := planFor(testResourceDesired(desired), testResourceObservation(testObservation()), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	after.ActiveState, after.SubState = "inactive", "dead"
	if !testVerification(t, plan, after).GetSystemdService().GetRuntimeMatches() {
		t.Fatal("unmanaged runtime reported drift")
	}
	desired.Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE
	desired.Enablement = resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED
	plan, err = planFor(testResourceDesired(desired), testResourceObservation(testObservation()), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	after.UnitFileState = "static"
	if !testVerification(t, plan, after).GetSystemdService().GetEnablementMatches() {
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

func TestResourceEnvelopeBindings(t *testing.T) {
	plan := testPlan(t)
	desired := testResourceDesired(testDesired())
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	observationDigest, err := resource.ObservationDigest(plan.GetBefore())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plan.GetDesiredSha256(), desiredDigest[:]) || !bytes.Equal(plan.GetObservationSha256(), observationDigest[:]) {
		t.Fatal("plan did not bind exact resource envelope digests")
	}
	if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || !resource.RefEqual(plan.GetRef(), desired.GetRef()) {
		t.Fatal("plan lost canonical resource identity or operation")
	}
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	result := testVerification(t, plan, testObservation())
	if result.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED {
		t.Fatal("unchanged native drift reported convergence")
	}
	if err := ValidateVerification(plan, result); err != nil {
		t.Fatal(err)
	}
	planDigest, err := resource.PlanDigest(plan)
	if err != nil || !bytes.Equal(result.GetPlanSha256(), planDigest[:]) {
		t.Fatalf("verification did not bind exact plan: %v", err)
	}
}

func TestResourceAdmissionAndUnknownOwnershipRelease(t *testing.T) {
	for _, operation := range []resourcev1.ResourceOperation{
		resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE,
		resourcev1.ResourceOperation_RESOURCE_OPERATION_UNSPECIFIED,
		resourcev1.ResourceOperation(99),
	} {
		plan, err := (&Provider{}).Plan(t.Context(), testResourceDesired(testDesired()), operation)
		if !errors.Is(err, ErrUnsupported) || plan != nil {
			t.Fatalf("unsupported operation %v reached native access or fabricated restoration: %v", operation, err)
		}
		if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && !errors.Is(err, ErrBaselineUnknown) {
			t.Fatalf("release hid unknown ownership: %v", err)
		}
		if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && errors.Is(err, ErrBaselineUnknown) {
			t.Fatalf("invalid operation misclassified as unknown baseline: %v", err)
		}
	}
	for name, mutate := range map[string]func(*resourcev1.ResourceDesiredState){
		"missing ref": func(d *resourcev1.ResourceDesiredState) { d.Ref = nil },
		"foreign key": func(d *resourcev1.ResourceDesiredState) { d.Ref.CanonicalKey = "other.service" },
		"foreign kind": func(d *resourcev1.ResourceDesiredState) {
			d.Ref.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
		},
		"unknown field": func(d *resourcev1.ResourceDesiredState) { d.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01}) },
		"other resource": func(d *resourcev1.ResourceDesiredState) {
			d.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "example"}
			d.State = &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{
				Name: "example", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			desired := testResourceDesired(testDesired())
			mutate(desired)
			if _, err := (&Provider{}).Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("invalid resource reached native access: %v", err)
			}
		})
	}
}

func TestExecutorAndOwnershipBinding(t *testing.T) {
	plan := testPlan(t)
	provider := &Provider{
		incarnation:       plan.GetBefore().GetMetadata().GetExecutorIncarnation(),
		backend:           proto.CloneOf(plan.GetBackend()),
		ownershipRevision: bytes.Clone(plan.GetOwnershipRevisionSha256()),
	}
	if err := provider.checkBinding(plan, true); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*resourcev1.ResourcePlan){
		"incarnation": func(p *resourcev1.ResourcePlan) {
			p.Before.Metadata.ExecutorIncarnation = "44444444-2222-4333-8444-555555555555"
		},
		"native backend": func(p *resourcev1.ResourcePlan) { p.Backend.NativeVersion = "258" },
		"ownership":      func(p *resourcev1.ResourcePlan) { p.OwnershipRevisionSha256[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(plan)
			mutate(changed)
			if err := provider.checkBinding(changed, true); !errors.Is(err, ErrConflict) {
				t.Fatalf("foreign executor/ownership context accepted: %v", err)
			}
		})
	}
}

func TestReadOnlyVerificationAcrossExecutorRestart(t *testing.T) {
	plan := testPlan(t)
	const restarted = "44444444-2222-4333-8444-555555555555"
	provider := &Provider{
		incarnation:       restarted,
		backend:           proto.CloneOf(plan.GetBackend()),
		ownershipRevision: bytes.Clone(plan.GetOwnershipRevisionSha256()),
	}
	if err := provider.checkBinding(plan, false); err != nil {
		t.Fatalf("read-only restart reconciliation rejected: %v", err)
	}
	if err := provider.checkBinding(plan, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("previous incarnation authorized another effect: %v", err)
	}
	after := testObservation()
	after.ActiveState, after.SubState, after.UnitFileState = "active", "running", "enabled"
	after.FingerprintSha256 = fingerprint(after)
	result, err := verification(plan, after, provider.incarnation)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetAfter().GetMetadata().GetExecutorIncarnation() != restarted ||
		result.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		t.Fatal("restart verification lost current observer or native convergence")
	}
	if err := ValidateVerification(plan, result); err != nil {
		t.Fatalf("retained restart evidence rejected: %v", err)
	}
	after.BootId = "55555555-2222-4333-8444-555555555555"
	after.FingerprintSha256 = fingerprint(after)
	result, err = verification(plan, after, provider.incarnation)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		t.Fatal("restart verification bypassed boot fence")
	}
}
