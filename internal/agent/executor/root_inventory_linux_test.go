//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const rootInventoryTestBoot = "25eec0a2-bb9f-42bc-b6cc-0508320c960e"

func rootInventoryTestObservation(now time.Time) *inventoryv1.RootObservation {
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	return &inventoryv1.RootObservation{
		StartedAt: timestamppb.New(now), FinishedAt: timestamppb.New(now), BootId: rootInventoryTestBoot,
		HardwareSerial: &inventoryv1.ObservedString{Status: unavailable},
		Firmware: &inventoryv1.FirmwareDetails{
			Mode:       &inventoryv1.ObservedString{Status: unavailable},
			SecureBoot: &inventoryv1.ObservedString{Status: unavailable},
		},
		Storage: &inventoryv1.StorageDetails{Status: unavailable},
		Cpu: &inventoryv1.CpuDetails{
			Model:         &inventoryv1.ObservedString{Status: unavailable},
			ModelSource:   &inventoryv1.ObservedString{Status: unavailable},
			LogicalCores:  &inventoryv1.ObservedUint64{Status: unavailable},
			PhysicalCores: &inventoryv1.ObservedUint64{Status: unavailable},
			X86_64Level:   &inventoryv1.ObservedString{Status: unavailable},
		},
	}
}

func rootInventoryTestJSON(t *testing.T, root *inventoryv1.RootObservation) []byte {
	t.Helper()
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rootInventoryTestService(t *testing.T, now time.Time) *Service {
	t.Helper()
	return openExecutor(t, now, WithBootID(func() (string, error) { return rootInventoryTestBoot, nil }))
}

// fakeUnits replaces only PID 1: observeRootInventory's admission, deadlines,
// cleanup and logging run unchanged around it.
type fakeUnits struct {
	t       *testing.T
	unit    string
	runUnit func(context.Context, []systemdProperty) ([]byte, error)
	stopped func(context.Context) error
	stops   int
	closed  bool
}

func (f *fakeUnits) run(ctx context.Context, properties []systemdProperty) ([]byte, error) {
	return f.runUnit(ctx, properties)
}

func (f *fakeUnits) stop(ctx context.Context) error {
	f.stops++
	if f.stopped == nil {
		f.t.Fatal("successful observation stopped its unit")
	}
	return f.stopped(ctx)
}

func (f *fakeUnits) close() error {
	f.closed = true
	return nil
}

func fakeRootInventory(t *testing.T, run func(context.Context, []systemdProperty) ([]byte, error), stop func(context.Context) error) func(context.Context, string) (rootInventoryUnits, error) {
	return func(_ context.Context, unit string) (rootInventoryUnits, error) {
		return &fakeUnits{t: t, unit: unit, runUnit: run, stopped: stop}, nil
	}
}

func rootInventoryProperty(t *testing.T, properties []systemdProperty, name string) any {
	t.Helper()
	found := -1
	for i, property := range properties {
		if property.Name == name {
			if found >= 0 {
				t.Fatalf("duplicate unit property %s", name)
			}
			found = i
		}
	}
	if found < 0 {
		t.Fatalf("missing fixed unit property %s", name)
	}
	return properties[found].Value.Value()
}

func TestRootInventoryTransientUnitContractAndFreshness(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := rootInventoryTestService(t, now)
	units := make(map[string]bool)
	calls := 0
	var opened []*fakeUnits
	s.rootInventorySystemd = func(ctx context.Context, unit string) (rootInventoryUnits, error) {
		id := strings.TrimSuffix(strings.TrimPrefix(unit, "lindm-inventory-"), ".service")
		if _, err := uuid.Parse(id); err != nil || units[unit] || unit != "lindm-inventory-"+id+".service" {
			t.Fatalf("helper reused or failed to isolate unit %q", unit)
		}
		units[unit] = true
		fake := &fakeUnits{t: t, unit: unit, runUnit: func(ctx context.Context, properties []systemdProperty) ([]byte, error) {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 12*time.Second || time.Until(deadline) <= 0 {
				t.Fatal("helper start has no bounded runtime")
			}
			for name, want := range map[string]any{
				"Type": "exec", "User": "root", "Group": "root",
				"ExecStart":      []systemdExec{{Path: "/usr/libexec/lindm/lindm-agent", Arguments: []string{"/usr/libexec/lindm/lindm-agent", "inventory-observe"}}},
				"PrivateDevices": false, "DevicePolicy": "closed", "DeviceAllow": []struct{ Path, Access string }{{"block-*", "r"}},
				"CapabilityBoundingSet": uint64(0), "AmbientCapabilities": uint64(0), "NoNewPrivileges": true,
				"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": true, "PrivateNetwork": true,
				"RestrictAddressFamilies": systemdList{AllowList: true, Values: []string{"AF_UNIX"}},
				"ProtectKernelTunables":   true, "ProtectKernelModules": true, "ProtectKernelLogs": true,
				"ProtectClock": true, "ProtectHostname": true, "ProtectProc": "invisible",
				"ProtectControlGroups": true, "RestrictNamespaces": uint64(0), "RestrictRealtime": true,
				"RestrictSUIDSGID": true, "LockPersonality": true, "MemoryDenyWriteExecute": true,
				"SystemCallArchitectures": []string{"native"},
				"SystemCallFilter":        systemdList{AllowList: true, Values: []string{"@system-service"}},
				"InaccessiblePaths":       []string{"-/etc/lindm", "-/var/lib/lindm", "-/run/lindm"},
				"UMask":                   uint32(0o077), "WorkingDirectory": "/",
				"RuntimeMaxUSec": uint64(10_000_000), "TimeoutStartUSec": uint64(10_000_000), "TimeoutStopUSec": uint64(500_000),
				"KillMode": "control-group", "SendSIGKILL": true, "TasksMax": uint64(64), "MemoryMax": uint64(256 << 20),
				"LimitCORE": uint64(0), "LimitCORESoft": uint64(0), "LimitNOFILE": uint64(256), "LimitNOFILESoft": uint64(256),
				"Environment": []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"},
				"Restart":     "no", "CollectMode": "inactive-or-failed", "StandardInput": "null",
			} {
				if got := rootInventoryProperty(t, properties, name); !reflect.DeepEqual(got, want) {
					t.Fatalf("unit property %s = %#v, want %#v", name, got, want)
				}
			}
			root := rootInventoryTestObservation(now)
			root.HardwareSerial = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: fmt.Sprintf("serial-%d", calls)}
			root.Cpu.Model = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: fmt.Sprintf("root-cpu-%d", calls)}
			root.Cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "smbios_type4"}
			return rootInventoryTestJSON(t, root), nil
		}}
		opened = append(opened, fake)
		return fake, nil
	}
	for i := 1; i <= 2; i++ {
		response, err := s.GetRecoveryReadiness(t.Context(), connect.NewRequest(&agentv1.GetRecoveryReadinessRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		root := new(inventoryv1.RootObservation)
		if err := proto.Unmarshal(response.Msg.GetRootObservation(), root); err != nil {
			t.Fatal(err)
		}
		if root.GetHardwareSerial().GetValue() != fmt.Sprintf("serial-%d", i) || response.Msg.GetObservation().GetBootId() != root.GetBootId() {
			t.Fatal("RPC cached evidence or lost boot binding")
		}
		if root.GetCpu().GetModel().GetValue() != fmt.Sprintf("root-cpu-%d", i) || root.GetCpu().GetModelSource().GetValue() != "smbios_type4" {
			t.Fatal("RPC cached or omitted root CPU provenance")
		}
	}
	if calls != 2 || len(opened) != 2 || !opened[0].closed || !opened[1].closed {
		t.Fatal("RPC did not perform a fresh native helper observation on its own closed connection")
	}
}

func TestRootInventoryRejectsInvalidHelperPayload(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	valid := rootInventoryTestJSON(t, rootInventoryTestObservation(now))
	for name, payload := range map[string][]byte{
		"empty":              nil,
		"malformed":          []byte("{"),
		"unknown_field":      append(append([]byte(nil), valid[:len(valid)-1]...), []byte(",\"unknown\":true}")...),
		"duplicate_field":    append(append([]byte(nil), valid[:len(valid)-1]...), []byte(",\"boot_id\":\""+rootInventoryTestBoot+"\"}")...),
		"trailing_json":      append(append([]byte(nil), valid...), []byte("{}")...),
		"oversized":          bytes.Repeat([]byte(" "), rootInventoryOutputLimit+1),
		"missing_projection": []byte("{}"),
	} {
		t.Run(name, func(t *testing.T) {
			s := rootInventoryTestService(t, now)
			s.rootInventorySystemd = fakeRootInventory(t, func(context.Context, []systemdProperty) ([]byte, error) { return payload, nil }, nil)
			if root, err := s.observeRootInventory(t.Context()); err == nil || root != nil {
				t.Fatal("invalid helper payload became evidence")
			}
		})
	}
	for name, mutate := range map[string]func(*inventoryv1.RootObservation){
		"missing_serial":  func(r *inventoryv1.RootObservation) { r.HardwareSerial = nil },
		"missing_storage": func(r *inventoryv1.RootObservation) { r.Storage = nil },
		"missing_cpu":     func(r *inventoryv1.RootObservation) { r.Cpu = nil },
		"missing_model":   func(r *inventoryv1.RootObservation) { r.Cpu.Model = nil },
		"invalid_source": func(r *inventoryv1.RootObservation) {
			r.Cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "smbios_type4"}
		},
		"wrong_boot":     func(r *inventoryv1.RootObservation) { r.BootId = "794aa3f7-f271-4489-ad95-cd5954ad3426" },
		"stale_start":    func(r *inventoryv1.RootObservation) { r.StartedAt = timestamppb.New(now.Add(-time.Second)) },
		"future_finish":  func(r *inventoryv1.RootObservation) { r.FinishedAt = timestamppb.New(now.Add(time.Second)) },
		"reversed_times": func(r *inventoryv1.RootObservation) { r.FinishedAt = timestamppb.New(now.Add(-time.Second)) },
		"unknown_enum":   func(r *inventoryv1.RootObservation) { r.Storage.Status = inventoryv1.CollectionStatus(999) },
	} {
		t.Run(name, func(t *testing.T) {
			s := rootInventoryTestService(t, now)
			root := rootInventoryTestObservation(now)
			mutate(root)
			s.rootInventorySystemd = fakeRootInventory(t, func(context.Context, []systemdProperty) ([]byte, error) { return rootInventoryTestJSON(t, root), nil }, nil)
			if result, err := s.observeRootInventory(t.Context()); err == nil || result != nil {
				t.Fatal("invalid native projection became evidence")
			}
		})
	}
}

func TestRootInventoryFailureAndCancellationStopAndJoinUnit(t *testing.T) {
	for _, mode := range []string{"start_ambiguous", "native_nonzero", "canceled_with_payload", "cleanup_failure"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			s := rootInventoryTestService(t, now)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var fake *fakeUnits
			s.rootInventorySystemd = func(_ context.Context, unit string) (rootInventoryUnits, error) {
				fake = &fakeUnits{t: t, unit: unit, runUnit: func(context.Context, []systemdProperty) ([]byte, error) {
					if mode == "canceled_with_payload" {
						cancel()
						return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), nil
					}
					return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), errors.New("native start or exit failed")
				}, stopped: func(call context.Context) error {
					deadline, ok := call.Deadline()
					if call.Err() != nil || !ok || time.Until(deadline) > rootInventoryCleanupTimeout {
						t.Fatal("cleanup inherited canceled context or lacked a deadline")
					}
					if mode == "cleanup_failure" {
						return errors.New("PID 1 unavailable")
					}
					return nil
				}}
				return fake, nil
			}
			root, err := s.observeRootInventory(ctx)
			if err == nil || root != nil || fake == nil || fake.stops != 1 || !fake.closed {
				t.Fatal("native failure accepted or cleanup escaped the call lifecycle")
			}
			var stage *rootInventoryError
			if !errors.As(err, &stage) || stage.stage != "run" || stage.unit != fake.unit || (mode == "cleanup_failure") != (stage.cleanup != nil) {
				t.Fatalf("failure lost its stage, unit or cleanup outcome: %v", err)
			}
		})
	}
}

func TestRootInventoryConnectFailureSubmitsNothing(t *testing.T) {
	s := rootInventoryTestService(t, time.Now())
	s.rootInventorySystemd = func(context.Context, string) (rootInventoryUnits, error) {
		return nil, errors.New("private socket refused")
	}
	var stage *rootInventoryError
	if root, err := s.observeRootInventory(t.Context()); root != nil || !errors.As(err, &stage) || stage.stage != "connect" {
		t.Fatalf("connection failure was not classified: %v", err)
	}
}

func TestRootInventoryRejectsBootChangeAndUnavailableBoot(t *testing.T) {
	for _, mode := range []string{"unavailable", "invalid", "changed_during_helper", "changed_after_helper"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			s := rootInventoryTestService(t, now)
			boots, commands := 0, 0
			s.bootID = func() (string, error) {
				boots++
				switch {
				case mode == "unavailable":
					return "", errors.New("boot unavailable")
				case mode == "invalid":
					return "not-a-boot", nil
				case mode == "changed_during_helper" && boots >= 3, mode == "changed_after_helper" && boots >= 4:
					return "794aa3f7-f271-4489-ad95-cd5954ad3426", nil
				default:
					return rootInventoryTestBoot, nil
				}
			}
			s.rootInventorySystemd = fakeRootInventory(t, func(context.Context, []systemdProperty) ([]byte, error) {
				commands++
				return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), nil
			}, nil)
			if response, err := s.GetRecoveryReadiness(t.Context(), connect.NewRequest(&agentv1.GetRecoveryReadinessRequest{})); err == nil || response != nil {
				t.Fatal("boot change became published evidence")
			}
			if (mode == "unavailable" || mode == "invalid") && commands != 0 {
				t.Fatal("missing boot identity spawned helper")
			}
		})
	}
}

func TestRootInventoryNoLaunchAfterCancellationOrExhaustedBudget(t *testing.T) {
	s := rootInventoryTestService(t, time.Now())
	s.rootInventorySystemd = func(context.Context, string) (rootInventoryUnits, error) {
		t.Fatal("canceled or exhausted request connected to PID 1")
		return nil, nil
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	short, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	for _, ctx := range []context.Context{canceled, short} {
		if root, err := s.observeRootInventory(ctx); err == nil || root != nil {
			t.Fatal("exhausted request accepted")
		}
	}
}

func TestRootInventoryBoundedOutput(t *testing.T) {
	for _, limit := range []int{rootInventoryOutputLimit, rootInventoryDiagnosticLimit} {
		out := rootInventoryOutput{limit: limit}
		if n, err := out.Write(bytes.Repeat([]byte("x"), limit)); err != nil || n != limit || out.overflow {
			t.Fatal("exact output bound rejected")
		}
		if n, err := out.Write([]byte("overflow")); err != nil || n != 8 || !out.overflow || out.buffer.Len() != limit {
			t.Fatal("output overflow was retained, blocked, or not classified")
		}
	}
}

func TestRootInventoryReservesRPCCleanupBudget(t *testing.T) {
	now := time.Now()
	s := rootInventoryTestService(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second+50*time.Millisecond)
	defer cancel()
	outer, _ := ctx.Deadline()
	stopped := false
	s.rootInventorySystemd = fakeRootInventory(t, func(call context.Context, _ []systemdProperty) ([]byte, error) {
		deadline, ok := call.Deadline()
		if !ok || !deadline.Equal(outer.Add(-2*time.Second)) {
			t.Fatal("helper consumed the cleanup reserve")
		}
		<-call.Done()
		return nil, call.Err()
	}, func(call context.Context) error {
		deadline, ok := call.Deadline()
		if !ok || !deadline.Before(outer) || call.Err() != nil {
			t.Fatal("cleanup did not fit inside the original RPC deadline")
		}
		stopped = true
		return nil
	})
	if root, err := s.observeRootInventory(ctx); root != nil || !errors.Is(err, context.DeadlineExceeded) || !stopped {
		t.Fatal("helper deadline did not trigger joined cleanup")
	}
	if ctx.Err() != nil {
		t.Fatal("cleanup exceeded the enclosing RPC deadline")
	}
}

// The executor journal is the only place a native readiness failure is
// diagnosable; the RPC itself carries only "internal".
func TestRecoveryReadinessLogsNativeFailureWithoutPayload(t *testing.T) {
	now := time.Now()
	s := rootInventoryTestService(t, now)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	s.rootInventorySystemd = fakeRootInventory(t, func(context.Context, []systemdProperty) ([]byte, error) {
		return nil, &rootInventoryFailure{
			cause: errors.New("start transient unit: Connection reset by peer"), jobResult: "done", unitResult: "exit-code",
			exitCode: cldExited, exitStatus: 7, diagnostic: rootInventoryDiagnostic([]byte("helper failed\x1b[31m\n")),
		}
	}, func(context.Context) error { return nil })
	_, err := s.GetRecoveryReadiness(t.Context(), connect.NewRequest(&agentv1.GetRecoveryReadinessRequest{}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("native failure changed the RPC contract: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("expected one structured log entry: %v: %s", err, logs.Bytes())
	}
	for key, want := range map[string]any{
		"msg": "recovery readiness observation failed", "stage": "run", "unit_result": "exit-code",
		"job_result": "done", "exit_status": float64(7), "diagnostic": "helper failed?[31m",
	} {
		if entry[key] != want {
			t.Fatalf("log %s = %#v, want %#v", key, entry[key], want)
		}
	}
	unit, _ := entry["unit"].(string)
	cause, _ := entry["error"].(string)
	if !strings.HasPrefix(unit, "lindm-inventory-") || !strings.Contains(cause, "Connection reset by peer") {
		t.Fatalf("log omitted the unit or native cause: %v", entry)
	}

	// A decodable-but-invalid payload is logged by size only, never by content.
	logs.Reset()
	s.rootInventorySystemd = fakeRootInventory(t, func(context.Context, []systemdProperty) ([]byte, error) {
		return []byte(`{"hardware_serial":"SECRET-SERIAL"`), nil
	}, nil)
	if _, err := s.GetRecoveryReadiness(t.Context(), connect.NewRequest(&agentv1.GetRecoveryReadinessRequest{})); err == nil {
		t.Fatal("malformed payload accepted")
	}
	if strings.Contains(logs.String(), "SECRET-SERIAL") || !strings.Contains(logs.String(), `"stage":"decode"`) || !strings.Contains(logs.String(), `"payload_bytes":34`) {
		t.Fatalf("decode failure log leaked or omitted payload metadata: %s", logs.String())
	}
}

func TestSystemdUnitPathEscapesLikeSdBus(t *testing.T) {
	got := systemdUnitPath("lindm-inventory-1e6cec1c-c5ae-4957-804d-a157cf15ed43.service")
	want := dbus.ObjectPath("/org/freedesktop/systemd1/unit/lindm_2dinventory_2d1e6cec1c_2dc5ae_2d4957_2d804d_2da157cf15ed43_2eservice")
	if got != want {
		t.Fatalf("unit path %s, want %s", got, want)
	}
}

func TestSystemdUnitSignalsFilterAndFailClosed(t *testing.T) {
	const unit = "lindm-inventory-1e6cec1c-c5ae-4957-804d-a157cf15ed43.service"
	h := &systemdUnitSignals{unit: unit, path: systemdUnitPath(unit), queue: make(chan *dbus.Signal, 1)}
	h.DeliverSignal("", "", &dbus.Signal{Path: systemdUnitPath("other.service"), Name: systemdProperties, Body: []any{systemdUnitInterface, map[string]dbus.Variant{}, []string{}}})
	h.DeliverSignal("", "", &dbus.Signal{Path: systemdManagerPath, Name: systemdManager + ".JobRemoved", Body: []any{uint32(1), dbus.ObjectPath("/org/freedesktop/systemd1/job/1"), "other.service", "done"}})
	if len(h.queue) != 0 || h.overflow.Load() {
		t.Fatal("another unit's signals reached this observation")
	}
	removed := &dbus.Signal{Path: systemdManagerPath, Name: systemdManager + ".JobRemoved", Body: []any{uint32(2), dbus.ObjectPath("/org/freedesktop/systemd1/job/2"), unit, "done"}}
	h.DeliverSignal("", "", removed)
	h.DeliverSignal("", "", removed)
	if len(h.queue) != 1 || !h.overflow.Load() {
		t.Fatal("full signal queue blocked or silently dropped evidence")
	}
	if _, err := awaitSystemdUnit(t.Context(), t.Context(), h, "/org/freedesktop/systemd1/job/2"); err == nil {
		t.Fatal("overflowed signal stream produced a unit result")
	}
}

func TestAwaitSystemdUnitReportsTerminalMainProcess(t *testing.T) {
	const unit = "lindm-inventory-1e6cec1c-c5ae-4957-804d-a157cf15ed43.service"
	const job = dbus.ObjectPath("/org/freedesktop/systemd1/job/42")
	state := func(value string) *dbus.Signal {
		return &dbus.Signal{Path: systemdUnitPath(unit), Name: systemdProperties, Body: []any{systemdUnitInterface, map[string]dbus.Variant{"ActiveState": dbus.MakeVariant(value)}, []string{}}}
	}
	service := func(result string, code, status int32) *dbus.Signal {
		return &dbus.Signal{Path: systemdUnitPath(unit), Name: systemdProperties, Body: []any{systemdServiceInterface, map[string]dbus.Variant{
			"Result": dbus.MakeVariant(result), "ExecMainCode": dbus.MakeVariant(code), "ExecMainStatus": dbus.MakeVariant(status),
		}, []string{}}}
	}
	jobRemoved := func(path dbus.ObjectPath, result string) *dbus.Signal {
		return &dbus.Signal{Path: systemdManagerPath, Name: systemdManager + ".JobRemoved", Body: []any{uint32(42), path, unit, result}}
	}
	for name, tc := range map[string]struct {
		signals []*dbus.Signal
		want    systemdUnitExit
	}{
		// The inactive state reported while the job is queued is not an exit.
		"success": {[]*dbus.Signal{state("inactive"), jobRemoved("/org/freedesktop/systemd1/job/7", "done"), jobRemoved(job, "done"), state("active"), service("success", cldExited, 0), state("inactive")},
			systemdUnitExit{jobResult: "done", unitResult: "success", code: cldExited, status: 0}},
		"exec_failure": {[]*dbus.Signal{jobRemoved(job, "failed"), service("exit-code", cldExited, 203), state("failed")},
			systemdUnitExit{jobResult: "failed", unitResult: "exit-code", code: cldExited, status: 203}},
		"killed": {[]*dbus.Signal{jobRemoved(job, "done"), service("signal", cldKilled, 9), state("failed")},
			systemdUnitExit{jobResult: "done", unitResult: "signal", code: cldKilled, status: 9}},
		// daemon-reload emits UnitRemoved for a live unit and suppresses
		// JobRemoved; neither may end or fail the wait.
		"reload_during_run": {[]*dbus.Signal{{Path: systemdManagerPath, Name: systemdManager + ".UnitRemoved", Body: []any{unit, systemdUnitPath(unit)}}, state("active"), service("success", cldExited, 0), state("inactive")},
			systemdUnitExit{unitResult: "success", code: cldExited, status: 0}},
		"start_failed_without_exit": {[]*dbus.Signal{jobRemoved(job, "resources")},
			systemdUnitExit{jobResult: "resources"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := &systemdUnitSignals{unit: unit, path: systemdUnitPath(unit), queue: make(chan *dbus.Signal, len(tc.signals))}
			for _, signal := range tc.signals {
				h.DeliverSignal("", "", signal)
			}
			got, err := awaitSystemdUnit(t.Context(), t.Context(), h, job)
			if err != nil || got != tc.want {
				t.Fatalf("exit = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	h := &systemdUnitSignals{unit: unit, path: systemdUnitPath(unit), queue: make(chan *dbus.Signal, 1)}
	h.DeliverSignal("", "", state("active"))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := awaitSystemdUnit(ctx, t.Context(), h, job); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished unit was not bounded by the call deadline: %v", err)
	}
}
