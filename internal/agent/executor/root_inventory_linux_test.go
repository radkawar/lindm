//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
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

func TestRootInventoryTransientCommandContractAndFreshness(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := rootInventoryTestService(t, now)
	units := make(map[string]bool)
	calls := 0
	s.rootInventoryCommand = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		calls++
		if executable != "/usr/bin/systemd-run" {
			t.Fatalf("unexpected command: %s", executable)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 12*time.Second || time.Until(deadline) <= 0 {
			t.Fatal("helper start has no bounded runtime")
		}
		for _, required := range []string{
			"--quiet", "--no-ask-password", "--pipe", "--wait", "--collect",
			"--property=Type=exec", "--property=User=root", "--property=Group=root",
			"--property=PrivateDevices=no", "--property=DevicePolicy=closed", "--property=DeviceAllow=block-* r",
			"--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=", "--property=NoNewPrivileges=yes",
			"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
			"--property=PrivateNetwork=yes", "--property=RestrictAddressFamilies=AF_UNIX",
			"--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectKernelLogs=yes",
			"--property=ProtectClock=yes", "--property=ProtectHostname=yes", "--property=ProtectProc=invisible",
			"--property=ProtectControlGroups=yes", "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
			"--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes", "--property=MemoryDenyWriteExecute=yes",
			"--property=SystemCallArchitectures=native", "--property=SystemCallFilter=@system-service",
			"--property=InaccessiblePaths=-/etc/lindm -/var/lib/lindm -/run/lindm",
			"--property=UMask=0077", "--property=WorkingDirectory=/",
			"--property=RuntimeMaxSec=10s", "--property=TimeoutStartSec=10s", "--property=TimeoutStopSec=500ms",
			"--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=TasksMax=64",
			"--property=MemoryMax=256M", "--property=LimitCORE=0", "--property=LimitNOFILE=256",
			"--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
		} {
			if !slices.Contains(args, required) {
				t.Fatalf("missing fixed helper argument %q", required)
			}
		}
		separator := slices.Index(args, "--")
		if separator < 0 || !slices.Equal(args[separator:], []string{"--", "/usr/libexec/lindm/lindm-agent", "inventory-observe"}) {
			t.Fatalf("helper accepted paths, configuration or caller arguments: %v", args)
		}
		unit := strings.TrimPrefix(args[5], "--unit=")
		id := strings.TrimSuffix(strings.TrimPrefix(unit, "lindm-inventory-"), ".service")
		if _, err := uuid.Parse(id); err != nil || units[unit] {
			t.Fatalf("helper reused or failed to isolate unit %q", unit)
		}
		units[unit] = true
		root := rootInventoryTestObservation(now)
		root.HardwareSerial = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: fmt.Sprintf("serial-%d", calls)}
		root.Cpu.Model = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: fmt.Sprintf("root-cpu-%d", calls)}
		root.Cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "smbios_type4"}
		return rootInventoryTestJSON(t, root), nil
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
	if calls != 2 {
		t.Fatal("RPC did not perform a fresh native helper observation")
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
			s.rootInventoryCommand = func(context.Context, string, ...string) ([]byte, error) { return payload, nil }
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
			s.rootInventoryCommand = func(context.Context, string, ...string) ([]byte, error) { return rootInventoryTestJSON(t, root), nil }
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
			calls, joined := 0, false
			var unit string
			s.rootInventoryCommand = func(call context.Context, executable string, args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					unit = strings.TrimPrefix(args[5], "--unit=")
					if mode == "canceled_with_payload" {
						cancel()
						return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), nil
					}
					return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), errors.New("native start or exit failed")
				}
				if calls != 2 || executable != "/usr/bin/systemctl" || !slices.Equal(args, []string{"--no-ask-password", "stop", unit}) {
					t.Fatal("uncertain start did not stop exactly its unique unit")
				}
				deadline, ok := call.Deadline()
				if call.Err() != nil || !ok || time.Until(deadline) > rootInventoryCleanupTimeout {
					t.Fatal("cleanup inherited canceled context or lacked a deadline")
				}
				joined = true
				if mode == "cleanup_failure" {
					return nil, errors.New("PID 1 unavailable")
				}
				return nil, nil
			}
			if root, err := s.observeRootInventory(ctx); err == nil || root != nil || !joined || calls != 2 {
				t.Fatal("native failure accepted or cleanup escaped the call lifecycle")
			}
		})
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
			s.rootInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
				commands++
				return rootInventoryTestJSON(t, rootInventoryTestObservation(now)), nil
			}
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
	s.rootInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("canceled or exhausted request spawned a command")
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

// These subprocess fixtures exercise os/exec output draining and cancellation,
// never systemd or the host's PID 1. The runner deliberately clears parent env.
func TestRootInventoryCommandProcess(t *testing.T) {
	index := slices.Index(os.Args, "--root-inventory-command-fixture")
	if index < 0 {
		return
	}
	write := func(file *os.File, data []byte) {
		t.Helper()
		if _, err := file.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	switch os.Args[index+1] {
	case "success":
		write(os.Stdout, []byte("payload"))
	case "failure":
		write(os.Stdout, []byte("payload"))
		write(os.Stderr, []byte("private diagnostic"))
		os.Exit(7)
	case "stdout_overflow":
		write(os.Stdout, bytes.Repeat([]byte("x"), rootInventoryOutputLimit+1))
	case "stderr_overflow":
		write(os.Stderr, bytes.Repeat([]byte("x"), rootInventoryDiagnosticLimit+1))
	case "cancel":
		time.Sleep(time.Hour)
	default:
		os.Exit(8)
	}
	os.Exit(0)
}

func TestRootInventoryNativeRunnerBoundsAndExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failure", "stdout_overflow", "stderr_overflow", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if mode == "cancel" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			started := time.Now()
			output, err := runRootInventoryCommand(ctx, executable, "-test.run=^TestRootInventoryCommandProcess$", "--", "--root-inventory-command-fixture", mode)
			if mode == "success" {
				if err != nil || string(output) != "payload" {
					t.Fatalf("successful native output lost: %q, %v", output, err)
				}
				return
			}
			if err == nil || output != nil {
				t.Fatal("failed or overflowing native command produced evidence")
			}
			var failure *rootInventoryFailure
			if !errors.As(err, &failure) || len(failure.diagnostic) > rootInventoryDiagnosticLimit || strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("native diagnostics unbounded or publicly exposed")
			}
			if mode == "cancel" && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second) {
				t.Fatal("canceled native process was not bounded and joined")
			}
		})
	}
}

func TestRootInventoryReservesRPCCleanupBudget(t *testing.T) {
	now := time.Now()
	s := rootInventoryTestService(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second+50*time.Millisecond)
	defer cancel()
	outer, _ := ctx.Deadline()
	calls := 0
	s.rootInventoryCommand = func(call context.Context, executable string, args ...string) ([]byte, error) {
		calls++
		deadline, ok := call.Deadline()
		if !ok {
			t.Fatal("native command lacks deadline")
		}
		if calls == 1 {
			if !deadline.Equal(outer.Add(-2 * time.Second)) {
				t.Fatal("helper consumed the cleanup reserve")
			}
			<-call.Done()
			return nil, call.Err()
		}
		if executable != "/usr/bin/systemctl" || !deadline.Before(outer) || call.Err() != nil {
			t.Fatal("cleanup did not fit inside the original RPC deadline")
		}
		return nil, nil
	}
	if root, err := s.observeRootInventory(ctx); root != nil || !errors.Is(err, context.DeadlineExceeded) || calls != 2 {
		t.Fatal("helper deadline did not trigger joined cleanup")
	}
	if ctx.Err() != nil {
		t.Fatal("cleanup exceeded the enclosing RPC deadline")
	}
}
