//go:build linux

package definitionprovider

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
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

const fixtureID = "11111111-1111-4111-8111-111111111111"

func timerDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "timer/example.timer"}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_Timer{Timer: &resourcev1.TimerDefinition{Unit: "example.timer", Service: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"}, Enabled: true, Schedule: &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_IntervalSeconds{IntervalSeconds: 60}}}}}}}
}
func dropDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "drop-in/example.service"}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_DropIn{DropIn: &resourcev1.ServiceDropIn{Unit: "example.service", CpuWeight: proto.Uint32(100), MemoryMaxBytes: proto.Uint64(1048576), TasksMax: proto.Uint32(32), NoNewPrivileges: proto.Bool(true)}}}}}
}
func fixtureOwner() *agentv1.ResourceOwnershipBinding {
	return &agentv1.ResourceOwnershipBinding{AssignmentId: fixtureID, ResourceId: fixtureID, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}, Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: fixtureID, ProfileRevision: fixtureID, ResourceId: fixtureID}}}
}
func fixtureProvider() *Provider {
	return &Provider{config: Config{ExecutorIncarnation: fixtureID, Ownership: fixtureOwner()}, backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "255", ProviderVersion: Capability, Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "ubuntu", Version: "24.04", Architecture: "amd64"}}, boot: fixtureID}
}
func fixtureSnapshot(t *testing.T, desired *resourcev1.ResourceDesiredState, exists bool) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	path, err := DefinitionPath(desired)
	if err != nil {
		t.Fatal(err)
	}
	file := &resourcev1.ManagedFileObservation{Path: path, Exists: exists, AncestrySha256: bytes.Repeat([]byte{1}, 32), NativeIdentitySha256: bytes.Repeat([]byte{2}, 32), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
	private := &agentv1.DefinitionFileSnapshot{State: file, ParentIdentitySha256: bytes.Repeat([]byte{3}, 32), NativeRevisionSha256: bytes.Repeat([]byte{9}, 32)}
	o := &resourcev1.SystemdDefinitionObservation{CanonicalKey: desired.GetRef().GetCanonicalKey(), Exists: exists, FileState: proto.CloneOf(file), DefinitionSha256: bytes.Repeat([]byte{4}, 32), TargetDefinitionSha256: bytes.Repeat([]byte{5}, 32), TimerScheduleSha256: emptyDigest(), TargetServiceExists: true}
	if exists {
		private.Content, err = Render(desired)
		if err != nil {
			t.Fatal(err)
		}
		file.File = &resourcev1.FileIdentity{Path: path, Device: 1, Inode: 7, Uid: 0, Gid: 0, Mode: 0644, Sha256: sha256Bytes(private.Content)}
		o.OwnedFile = proto.CloneOf(file.File)
		o.FileState = proto.CloneOf(file)
		o.Effective = proto.CloneOf(desired.GetSystemdDefinition())
	}
	if timer := desired.GetSystemdDefinition().GetTimer(); timer != nil {
		o.TimerEnabled = proto.Bool(exists && timer.GetEnabled())
		o.TimerActive = proto.Bool(exists && timer.GetEnabled())
		o.TimerInstallProjectionComplete = true
		o.TimerUnitFileState = "absent"
		if exists {
			o.TimerUnitFileState = "disabled"
		}
		if o.GetTimerEnabled() {
			o.TimerUnitFileState = "enabled"
			o.TimerInvocationId = bytes.Repeat([]byte{6}, 16)
			o.TimerInstallLinks = []*resourcev1.InstallLink{{Path: unitRoot + "/timers.target.wants/example.timer", Target: path, Device: 1, Inode: 8, AncestrySha256: bytes.Repeat([]byte{7}, 32)}}
		}
	} else {
		o.EffectiveOptions = &resourcev1.SystemdEffectiveOptions{CpuWeight: 100, MemoryMax: 1048576, TasksMax: 32, NoNewPrivileges: true}
	}
	p := fixtureProvider()
	obs := p.observationTemplate(desired.GetRef())
	obs.Metadata.ObservedAt = timestamppb.New(time.Unix(1700000000, 0))
	obs.Metadata.NativeRevision = bytes.Repeat([]byte{8}, 32)
	obs.Observed = &resourcev1.ResourceObservation_SystemdDefinition{SystemdDefinition: o}
	return &agentv1.ResourceOwnershipSnapshot{Observation: obs, DefinitionFile: private}
}
func fixtureLedger(t *testing.T, d *resourcev1.ResourceDesiredState, before, after *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipLedger {
	t.Helper()
	return &agentv1.ResourceOwnershipLedger{FormatVersion: 1, InstallationId: fixtureID, DeploymentId: fixtureID, DeviceId: fixtureID, EnrollmentGeneration: fixtureID, Ref: proto.CloneOf(d.GetRef()), Owner: fixtureOwner(), Revision: 3, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Baseline: proto.CloneOf(before), LastApplied: proto.CloneOf(after), BeforeEffect: proto.CloneOf(before), EffectActionId: proto.String(fixtureID), OwnedDimensions: dimensions(d.GetSystemdDefinition()), OwnerIntentEnvelope: []byte("test-owner-binding"), ClaimActionId: fixtureID}
}

type fakeManager struct {
	calls  []string
	fail   string
	cancel context.CancelFunc
}

func (f *fakeManager) record(call string) error {
	f.calls = append(f.calls, call)
	if f.cancel != nil {
		f.cancel()
	}
	if f.fail == call {
		return errors.New("native call failed")
	}
	return nil
}
func (*fakeManager) Version() string { return "255" }
func (*fakeManager) Unit(context.Context, string, string) (*unitView, error) {
	return nil, errors.New("unexpected observation")
}
func (*fakeManager) Links(context.Context, string) ([]*resourcev1.InstallLink, error) {
	return nil, errors.New("unexpected links")
}
func (f *fakeManager) Reload(context.Context) error { return f.record("reload") }
func (f *fakeManager) Enable(_ context.Context, _ string, enabled bool) error {
	if enabled {
		return f.record("enable")
	}
	return f.record("disable")
}
func (f *fakeManager) Runtime(_ context.Context, _ string, active bool) error {
	if active {
		return f.record("start")
	}
	return f.record("stop")
}
func (*fakeManager) Close() error { return nil }

var _ nativeManager = (*fakeManager)(nil)

func timerView() *unitView {
	return &unitView{id: "example.timer", fileState: "enabled", properties: map[string]dbus.Variant{"Unit": dbus.MakeVariant("example.service"), "TimersMonotonic": dbus.MakeVariant([]monotonicTimer{{Base: "OnActiveUSec", Value: 60000000, Next: 90000000}, {Base: "OnUnitActiveUSec", Value: 60000000, Next: 100000000}}), "TimersCalendar": dbus.MakeVariant([]calendarTimer{}), "AccuracyUSec": dbus.MakeVariant(uint64(1000000)), "RandomizedDelayUSec": dbus.MakeVariant(uint64(0)), "Persistent": dbus.MakeVariant(false), "WakeSystem": dbus.MakeVariant(false), "OnClockChange": dbus.MakeVariant(false), "OnTimezoneChange": dbus.MakeVariant(false)}}
}
