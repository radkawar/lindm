//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func (e *refreshTransportExecutor) GetRecoveryReadiness(context.Context, *connect.Request[agentv1.GetRecoveryReadinessRequest]) (*connect.Response[agentv1.GetRecoveryReadinessResponse], error) {
	e.f.readinessCalls++
	if e.f.readinessErr != nil {
		return nil, e.f.readinessErr
	}
	observation := proto.CloneOf(e.f.readiness)
	observation.ObservedAt = timestamppb.Now()
	root, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&inventoryv1.RootObservation{
		StartedAt: timestamppb.Now(), FinishedAt: timestamppb.Now(), BootId: e.f.boot,
		HardwareSerial: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "root-serial"},
		Firmware: &inventoryv1.FirmwareDetails{
			Mode:       &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "uefi"},
			SecureBoot: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "enabled"},
		},
		Storage: &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS},
		Cpu:     protectedCPUFixture("root-arm-cpu", "smbios_type4"),
	})
	if err != nil {
		e.f.t.Fatal(err)
	}
	return connect.NewResponse(&agentv1.GetRecoveryReadinessResponse{Observation: observation, RootObservation: root}), nil
}

func protectedCPUFixture(model, source string) *inventoryv1.CpuDetails {
	const success = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	return &inventoryv1.CpuDetails{
		Model:         &inventoryv1.ObservedString{Status: success, Value: model},
		ModelSource:   &inventoryv1.ObservedString{Status: success, Value: source},
		LogicalCores:  &inventoryv1.ObservedUint64{Status: success, Value: 4},
		PhysicalCores: &inventoryv1.ObservedUint64{Status: success, Value: 2},
		X86_64Level:   &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
	}
}

func unavailableNativeDetails() *inventoryv1.NativeDetails {
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	boolean := func() *inventoryv1.ObservedBool { return &inventoryv1.ObservedBool{Status: unavailable} }
	return &inventoryv1.NativeDetails{
		Cpu:     &inventoryv1.CpuDetails{Model: text(), ModelSource: text(), LogicalCores: number(), PhysicalCores: number(), X86_64Level: text()},
		Memory:  &inventoryv1.MemoryDetails{TotalBytes: number(), AvailableBytes: number(), SwapTotalBytes: number()},
		Storage: &inventoryv1.StorageDetails{Status: unavailable}, Network: &inventoryv1.NetworkDetails{Status: unavailable},
		Firmware: &inventoryv1.FirmwareDetails{Mode: text(), SecureBoot: text()}, Tpm: &inventoryv1.TpmDetails{Present: boolean(), Version: text()},
		Power:    &inventoryv1.PowerDetails{Chassis: text(), Batteries: &inventoryv1.BatteryDetails{Status: unavailable}},
		Sessions: &inventoryv1.SessionCounts{Users: number(), Sessions: number()}, LocalUsers: &inventoryv1.LocalUsers{Status: unavailable},
		KernelModuleCount: number(), UptimeSeconds: number(), BootTimeUnixSeconds: number(),
		Backends: &inventoryv1.BackendDetails{Dpkg: boolean(), Rpm: boolean(), Pacman: boolean(), Zypper: boolean(), RpmOstree: boolean(), Nix: boolean(), Flatpak: boolean(), Snap: boolean()},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: unavailable}, Snap: &inventoryv1.ApplicationDetails{Status: unavailable},
	}
}

func TestPeriodicInventoryQueuesImmutableProtectedReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	if err := f.r.bind(t.Context(), f.connection); err != nil {
		t.Fatal(err)
	}
	if err := f.r.store.Synchronize(t.Context(), f.host, f.packages); err != nil {
		t.Fatal(err)
	}
	if err := f.r.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	upload, err := f.r.store.PromoteHost(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := upload.Observation.GetDetails().GetRecoveryReadiness()
	if !got.GetAvailable() || got.GetEspUuid() != "1234-5678" || got.GetFreeBytes() != 16384 || got.GetBootId() != f.boot || f.readinessCalls != 1 {
		t.Fatalf("periodic spool omitted protected readiness: %v", got)
	}
	if upload.Observation.GetDetails().GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		t.Fatal("root storage observation did not replace unprivileged unavailable storage")
	}
	if upload.Observation.GetHardwareSerial().GetValue() != "root-serial" || upload.Observation.GetDetails().GetFirmware().GetSecureBoot().GetValue() != "enabled" {
		t.Fatal("periodic spool omitted root serial or Secure Boot")
	}
	if !proto.Equal(upload.Observation.GetDetails().GetCpu(), protectedCPUFixture("root-arm-cpu", "smbios_type4")) {
		t.Fatal("periodic spool omitted complete root CPU evidence")
	}
	f.readiness.FreeBytes = 0
	if err := f.r.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, ok, err := f.r.store.PendingHost(t.Context())
	if err != nil || !ok || !proto.Equal(pending.Observation, upload.Observation) {
		t.Fatalf("new observation changed immutable pending evidence: %v", err)
	}
	if f.readinessCalls != 2 {
		t.Fatal("second collection reused readiness")
	}
}

func TestExplicitRefreshPublishesProtectedReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	got := f.publishedHost.GetDetails().GetRecoveryReadiness()
	if !got.GetAvailable() || got.GetFreeBytes() != 16384 || got.GetBootId() != f.boot || f.readinessCalls != 1 || f.confirmations != 1 {
		t.Fatalf("refresh completion omitted root observation: %v", got)
	}
	if f.publishedHost.GetHardwareSerial().GetValue() != "root-serial" || f.publishedHost.GetDetails().GetFirmware().GetSecureBoot().GetValue() != "enabled" {
		t.Fatal("refresh publication omitted root serial or Secure Boot")
	}
	if !proto.Equal(f.publishedHost.GetDetails().GetCpu(), protectedCPUFixture("root-arm-cpu", "smbios_type4")) {
		t.Fatal("refresh publication omitted complete root CPU evidence")
	}
}

func TestReadinessFailureDoesNotFailInventoryPublication(t *testing.T) {
	for _, reason := range []string{"recovery_readiness_not_configured", "recovery_readiness_esp_unreadable", "recovery_readiness_esp_unsupported", "recovery_readiness_executor_unavailable"} {
		t.Run(reason, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.readiness.Available = false
			f.readiness.Reason = reason
			if reason == "recovery_readiness_executor_unavailable" {
				f.readinessErr = errors.New("root RPC unavailable")
			}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			got := f.publishedHost.GetDetails().GetRecoveryReadiness()
			if got.GetAvailable() || got.GetReason() != reason || f.confirmations != 1 {
				t.Fatalf("failed observation blocked inventory or implied readiness: %v", got)
			}
			if f.readinessErr != nil {
				assertRootUnavailable(t, f.publishedHost)
			} else if f.publishedHost.GetHardwareSerial().GetValue() != "root-serial" {
				t.Fatal("unconfigured or unsupported recovery suppressed independent root inventory")
			}
		})
	}
}

func TestDirectCollectorDoesNotInventReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	observation, err := f.r.collectInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.GetHost().GetDetails().GetRecoveryReadiness() != nil || f.readinessCalls != 0 {
		t.Fatal("direct unprivileged collection claimed protected readiness")
	}
}

type invalidReadinessExecutor struct {
	*refreshTransportExecutor
	mutate func(*agentv1.GetRecoveryReadinessResponse)
}

func (e invalidReadinessExecutor) GetRecoveryReadiness(ctx context.Context, req *connect.Request[agentv1.GetRecoveryReadinessRequest]) (*connect.Response[agentv1.GetRecoveryReadinessResponse], error) {
	response, err := e.refreshTransportExecutor.GetRecoveryReadiness(ctx, req)
	if err == nil {
		e.mutate(response.Msg)
	}
	return response, err
}

func TestProtectedObservationRejectsMalformedOrStaleRootResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*agentv1.GetRecoveryReadinessResponse)
	}{
		{name: "malformed_projection", mutate: func(r *agentv1.GetRecoveryReadinessResponse) { r.RootObservation = []byte{0xff} }},
		{name: "unknown_projection_fields", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.RootObservation = append(r.RootObservation, 0x98, 0x06, 0x01)
		}},
		{name: "missing_projection", mutate: func(r *agentv1.GetRecoveryReadinessResponse) { r.RootObservation = nil }},
		{name: "oversized_projection", mutate: func(r *agentv1.GetRecoveryReadinessResponse) { r.RootObservation = make([]byte, 81921) }},
		{name: "changed_boot", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.Observation.BootId = "794aa3f7-f271-4489-ad95-cd5954ad3426"
		}},
		{name: "stale_readiness", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.Observation.ObservedAt = timestamppb.New(time.Now().Add(-time.Hour))
		}},
		{name: "future_readiness", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.Observation.ObservedAt = timestamppb.New(time.Now().Add(time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: tc.mutate}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			details := f.publishedHost.GetDetails()
			if details.GetRecoveryReadiness().GetAvailable() || details.GetRecoveryReadiness().GetReason() == "" || details.GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE {
				t.Fatal("malformed root response became available native evidence")
			}
			assertRootUnavailable(t, f.publishedHost)
		})
	}
}

func assertRootUnavailable(t *testing.T, host *inventoryv1.HostObservation) {
	t.Helper()
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if host.GetHardwareSerial().GetStatus() != unavailable ||
		host.GetDetails().GetFirmware().GetMode().GetStatus() != unavailable ||
		host.GetDetails().GetFirmware().GetSecureBoot().GetStatus() != unavailable ||
		host.GetDetails().GetStorage().GetStatus() != unavailable ||
		host.GetDetails().GetCpu().GetModel().GetStatus() != unavailable ||
		host.GetDetails().GetCpu().GetModelSource().GetStatus() != unavailable ||
		host.GetDetails().GetCpu().GetModel().GetValue() != "" ||
		host.GetDetails().GetCpu().GetModelSource().GetValue() != "" {
		t.Fatal("rejected root projection retained partial or unprivileged evidence")
	}
}

func mutateRootObservation(t *testing.T, mutate func(*inventoryv1.RootObservation)) func(*agentv1.GetRecoveryReadinessResponse) {
	t.Helper()
	return func(response *agentv1.GetRecoveryReadinessResponse) {
		root := new(inventoryv1.RootObservation)
		if err := proto.Unmarshal(response.RootObservation, root); err != nil {
			t.Fatal(err)
		}
		mutate(root)
		encoded, err := proto.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		response.RootObservation = encoded
	}
}

func TestProtectedInventoryValidatesEntireProjection(t *testing.T) {
	for name, mutate := range map[string]func(*inventoryv1.RootObservation){
		"missing_start":  func(r *inventoryv1.RootObservation) { r.StartedAt = nil },
		"missing_finish": func(r *inventoryv1.RootObservation) { r.FinishedAt = nil },
		"missing_boot":   func(r *inventoryv1.RootObservation) { r.BootId = "" },
		"wrong_boot":     func(r *inventoryv1.RootObservation) { r.BootId = "794aa3f7-f271-4489-ad95-cd5954ad3426" },
		"stale_start":    func(r *inventoryv1.RootObservation) { r.StartedAt = timestamppb.New(time.Now().Add(-time.Hour)) },
		"future_finish":  func(r *inventoryv1.RootObservation) { r.FinishedAt = timestamppb.New(time.Now().Add(time.Hour)) },
		"reversed_times": func(r *inventoryv1.RootObservation) {
			r.FinishedAt = timestamppb.New(r.StartedAt.AsTime().Add(-time.Second))
		},
		"invalid_timestamp": func(r *inventoryv1.RootObservation) { r.StartedAt.Nanos = -1 },
		"missing_serial":    func(r *inventoryv1.RootObservation) { r.HardwareSerial = nil },
		"invalid_serial": func(r *inventoryv1.RootObservation) {
			r.HardwareSerial.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
		},
		"missing_firmware":    func(r *inventoryv1.RootObservation) { r.Firmware = nil },
		"missing_secure_boot": func(r *inventoryv1.RootObservation) { r.Firmware.SecureBoot = nil },
		"invalid_secure_boot": func(r *inventoryv1.RootObservation) {
			r.Firmware.SecureBoot.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNSPECIFIED
		},
		"unknown_nested_field": func(r *inventoryv1.RootObservation) { r.Firmware.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) },
		"missing_storage":      func(r *inventoryv1.RootObservation) { r.Storage = nil },
		"invalid_storage": func(r *inventoryv1.RootObservation) {
			r.Storage.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNSPECIFIED
		},
		"missing_cpu":        func(r *inventoryv1.RootObservation) { r.Cpu = nil },
		"missing_cpu_model":  func(r *inventoryv1.RootObservation) { r.Cpu.Model = nil },
		"missing_cpu_count":  func(r *inventoryv1.RootObservation) { r.Cpu.LogicalCores = nil },
		"invalid_cpu_source": func(r *inventoryv1.RootObservation) { r.Cpu.ModelSource.Value = "guessed_cpu" },
		"mismatched_cpu_source": func(r *inventoryv1.RootObservation) {
			r.Cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		},
		"unknown_cpu_field": func(r *inventoryv1.RootObservation) { r.Cpu.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: mutateRootObservation(t, mutate)}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			assertRootUnavailable(t, f.publishedHost)
			if f.publishedHost.GetDetails().GetRecoveryReadiness().GetAvailable() {
				t.Fatal("invalid projection retained recovery readiness")
			}
		})
	}
}

func TestProtectedInventoryPreservesBlankSerialAndBIOS(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: mutateRootObservation(t, func(r *inventoryv1.RootObservation) {
		r.HardwareSerial = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		r.Firmware.Mode.Value = "bios"
		r.Firmware.SecureBoot = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
	})}
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.publishedHost.GetHardwareSerial().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE ||
		f.publishedHost.GetDetails().GetFirmware().GetMode().GetValue() != "bios" ||
		f.publishedHost.GetDetails().GetFirmware().GetSecureBoot().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE ||
		f.publishedHost.GetDetails().GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		t.Fatal("truthful missing hardware facts were replaced or discarded")
	}
}

func TestProtectedInventoryReplacesTransientPublicCPU(t *testing.T) {
	for _, source := range []string{"arm_midr_procfs", "arm_midr_sysfs", "proc_cpuinfo"} {
		t.Run(source, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			collect := f.r.collectInventory
			f.r.collectInventory = func(ctx context.Context) (*inventoryv1.NativeObservation, error) {
				observation, err := collect(ctx)
				observation.Host.Details.Cpu = protectedCPUFixture("transient public model", source)
				observation.Host.Details.Cpu.LogicalCores.Value = 8
				return observation, err
			}
			observation, err := f.r.collectNativeObservation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(observation.GetHost().GetDetails().GetCpu(), protectedCPUFixture("root-arm-cpu", "smbios_type4")) {
				t.Fatal("fresh root CPU did not replace the complete public CPU observation")
			}
		})
	}
}

func TestProtectedInventoryFailurePreservesIndependentCPU(t *testing.T) {
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	for _, source := range []string{"proc_cpuinfo", "arm_midr_procfs", "arm_midr_sysfs", "smbios_type4", "historical", "deferred", "invalid", "denied"} {
		t.Run(source, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.readinessErr = errors.New("root RPC unavailable")
			cpu := protectedCPUFixture("independently collected model", source)
			switch source {
			case "historical":
				cpu.ModelSource = nil
			case "deferred", "invalid", "denied":
				status := map[string]inventoryv1.CollectionStatus{
					"deferred": unavailable,
					"invalid":  inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT,
					"denied":   inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED,
				}[source]
				cpu.Model = &inventoryv1.ObservedString{Status: status}
				cpu.ModelSource = &inventoryv1.ObservedString{Status: status}
			}
			cpu.X86_64Level = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "x86-64-v3"}
			want := proto.CloneOf(cpu)
			if source == "smbios_type4" {
				want.Model = &inventoryv1.ObservedString{Status: unavailable}
				want.ModelSource = &inventoryv1.ObservedString{Status: unavailable}
			}
			collect := f.r.collectInventory
			f.r.collectInventory = func(ctx context.Context) (*inventoryv1.NativeObservation, error) {
				observation, err := collect(ctx)
				observation.Host.Details.Cpu = cpu
				return observation, err
			}
			observation, err := f.r.collectNativeObservation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(observation.GetHost().GetDetails().GetCpu(), want) {
				t.Fatal("failed root observation retained privileged CPU model or changed independent CPU evidence")
			}
		})
	}
}

func TestProtectedInventoryRejectsStaleRootCPU(t *testing.T) {
	for name, mutate := range map[string]func(*inventoryv1.RootObservation){
		"stale":      func(r *inventoryv1.RootObservation) { r.StartedAt = timestamppb.New(time.Now().Add(-time.Hour)) },
		"cross_boot": func(r *inventoryv1.RootObservation) { r.BootId = "794aa3f7-f271-4489-ad95-cd5954ad3426" },
		"malformed":  func(r *inventoryv1.RootObservation) { r.Cpu.ModelSource.Value = "not-native" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			collect := f.r.collectInventory
			f.r.collectInventory = func(ctx context.Context) (*inventoryv1.NativeObservation, error) {
				observation, err := collect(ctx)
				observation.Host.Details.Cpu = protectedCPUFixture("previous root model", "smbios_type4")
				return observation, err
			}
			f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: mutateRootObservation(t, mutate)}
			observation, err := f.r.collectNativeObservation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			assertRootUnavailable(t, observation.GetHost())
			cpu := observation.GetHost().GetDetails().GetCpu()
			if cpu.GetLogicalCores().GetValue() != 4 || cpu.GetPhysicalCores().GetValue() != 2 {
				t.Fatal("rejected root CPU discarded independently collected counts")
			}
		})
	}
}

func TestProtectedInventoryPreservesCurrentCPUFailure(t *testing.T) {
	for _, status := range []inventoryv1.CollectionStatus{
		inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED,
		inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT,
	} {
		t.Run(status.String(), func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			want := protectedCPUFixture("root-arm-cpu", "smbios_type4")
			want.Model = &inventoryv1.ObservedString{Status: status}
			want.ModelSource = &inventoryv1.ObservedString{Status: status}
			f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: mutateRootObservation(t, func(r *inventoryv1.RootObservation) {
				r.Cpu = proto.CloneOf(want)
			})}
			observation, err := f.r.collectNativeObservation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(observation.GetHost().GetDetails().GetCpu(), want) || !observation.GetHost().GetDetails().GetRecoveryReadiness().GetAvailable() {
				t.Fatal("current native CPU failure was hidden or rejected with independent root evidence")
			}
		})
	}
}
