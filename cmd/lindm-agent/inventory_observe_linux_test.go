// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/protodata"
)

const inventoryObservationTestBoot = "25eec0a2-bb9f-42bc-b6cc-0508320c960e"
const inventoryObservationOtherBoot = "794aa3f7-f271-4489-ad95-cd5954ad3426"

func inventoryObservationFixture() *inventoryv1.RootObservation {
	const success = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func(value string) *inventoryv1.ObservedString {
		status := success
		if value == "" {
			status = unavailable
		}
		return &inventoryv1.ObservedString{Status: status, Value: value}
	}
	now := time.Now()
	return &inventoryv1.RootObservation{
		StartedAt: timestamppb.New(now), FinishedAt: timestamppb.New(now), BootId: inventoryObservationTestBoot,
		HardwareSerial: text("hardware-serial"),
		Firmware:       &inventoryv1.FirmwareDetails{Mode: text("uefi"), SecureBoot: text("enabled")},
		Cpu: &inventoryv1.CpuDetails{
			Model: text("ARM native model"), ModelSource: text("smbios_type4"), X86_64Level: text(""),
			LogicalCores:  &inventoryv1.ObservedUint64{Status: success, Value: 4},
			PhysicalCores: &inventoryv1.ObservedUint64{Status: success, Value: 2},
		},
		Storage: &inventoryv1.StorageDetails{Status: success, Devices: []*inventoryv1.BlockDevice{{
			Name: "dm-0", Type: text("crypt"), Parent: text("vda3"),
			SizeBytes:  &inventoryv1.ObservedUint64{Status: success, Value: 4096},
			Filesystem: text("LVM2_member"), Mountpoint: text(""), Encryption: text("dm-crypt"),
			Identity: &inventoryv1.StorageIdentity{
				Transport: text(""), Model: text(""), Serial: text(""), Firmware: text(""),
				Wwn: text(""), Eui: text(""), PartitionUuid: text(""), PartitionType: text(""),
				FilesystemUuid: text(""), LuksUuid: text(""), LuksVersion: text("2"),
				LuksKeyslotCount: &inventoryv1.ObservedUint64{Status: success, Value: 2},
				LuksTokenCount:   &inventoryv1.ObservedUint64{Status: success, Value: 1},
				LuksTokenTypes:   text("systemd-tpm2"), BackingDisk: text("vda"),
				RootBacking: &inventoryv1.ObservedBool{Status: success, Value: true},
				Nvme:        &inventoryv1.ObservedNVMeScope{Status: unavailable},
			},
		}}},
	}
}

func inventoryObservationTestSources(observation *inventoryv1.RootObservation) inventoryObservationSources {
	return inventoryObservationSources{
		euid:    func() int { return 0 },
		bootID:  func() (string, error) { return inventoryObservationTestBoot, nil },
		collect: func(context.Context, string) *inventoryv1.RootObservation { return observation },
	}
}

type inventoryObservationWriter struct {
	bytes.Buffer
	calls int
}

func (w *inventoryObservationWriter) Write(data []byte) (int, error) {
	w.calls++
	return w.Buffer.Write(data)
}

func TestInventoryObserveRequiresRootAndNoArguments(t *testing.T) {
	for _, test := range []struct {
		name string
		uid  int
		args []string
	}{
		{name: "unprivileged", uid: 1000},
		{name: "flag", args: []string{"--boot-id", inventoryObservationTestBoot}},
		{name: "path", args: []string{"/etc/lindm/executor.json"}},
		{name: "help", args: []string{"--help"}},
		{name: "separator", args: []string{"--"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources := inventoryObservationTestSources(nil)
			sources.euid = func() int { return test.uid }
			sources.bootID = func() (string, error) {
				t.Fatal("inadmissible command read boot identity")
				return "", nil
			}
			sources.collect = func(context.Context, string) *inventoryv1.RootObservation {
				t.Fatal("inadmissible command collected inventory")
				return nil
			}
			var output inventoryObservationWriter
			if err := inventoryObserve(t.Context(), test.args, &output, sources); err == nil || output.calls != 0 {
				t.Fatalf("admission error=%v writes=%d", err, output.calls)
			}
		})
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"inventory-observe", "/caller-path"}, &output); err == nil || !strings.Contains(err.Error(), "accepts no flags or paths") || output.Len() != 0 {
		t.Fatalf("dispatch did not enforce helper argument boundary: %v", err)
	}
}

func TestInventoryObserveWritesWholeValidatedBoundedProjection(t *testing.T) {
	for _, failedNative := range []bool{false, true} {
		t.Run(fmt.Sprintf("native-failed-%t", failedNative), func(t *testing.T) {
			want := inventoryObservationFixture()
			if failedNative {
				want.Storage = &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
			}
			sources := inventoryObservationTestSources(want)
			boots, collects := 0, 0
			var output inventoryObservationWriter
			sources.bootID = func() (string, error) {
				boots++
				if output.calls != 0 {
					t.Fatal("output escaped before boot recheck")
				}
				return inventoryObservationTestBoot, nil
			}
			sources.collect = func(ctx context.Context, boot string) *inventoryv1.RootObservation {
				collects++
				if boot != inventoryObservationTestBoot || ctx.Err() != nil || boots != 1 {
					t.Fatal("collector did not receive live locally-read boot identity")
				}
				return want
			}
			if err := inventoryObserve(t.Context(), nil, &output, sources); err != nil {
				t.Fatal(err)
			}
			if collects != 1 || boots != 2 || output.calls != 1 || output.Len() > maxRootObservationJSON || !bytes.HasSuffix(output.Bytes(), []byte{'\n'}) {
				t.Fatalf("collects=%d boots=%d writes=%d bytes=%d", collects, boots, output.calls, output.Len())
			}
			got := new(inventoryv1.RootObservation)
			if err := protojson.Unmarshal(output.Bytes(), got); err != nil {
				t.Fatalf("stdout is not exclusively one protobuf JSON document: %v", err)
			}
			if err := protodata.ValidateClosed(got.ProtoReflect()); err != nil {
				t.Fatal(err)
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) || !strings.Contains(output.String(), `"boot_id"`) || !strings.Contains(output.String(), `"COLLECTION_STATUS_SUCCESS"`) {
				t.Fatal("output lost full native evidence or canonical protobuf names")
			}
		})
	}
}

func TestInventoryObserveRejectsInvalidProjectionBeforeOutput(t *testing.T) {
	for name, mutate := range map[string]func(*inventoryv1.RootObservation){
		"missing_start":     func(r *inventoryv1.RootObservation) { r.StartedAt = nil },
		"missing_finish":    func(r *inventoryv1.RootObservation) { r.FinishedAt = nil },
		"invalid_timestamp": func(r *inventoryv1.RootObservation) { r.StartedAt.Nanos = -1 },
		"reversed_times": func(r *inventoryv1.RootObservation) {
			r.FinishedAt = timestamppb.New(r.StartedAt.AsTime().Add(-time.Second))
		},
		"missing_serial":     func(r *inventoryv1.RootObservation) { r.HardwareSerial = nil },
		"invalid_serial":     func(r *inventoryv1.RootObservation) { r.HardwareSerial.Value = "" },
		"missing_firmware":   func(r *inventoryv1.RootObservation) { r.Firmware = nil },
		"invalid_firmware":   func(r *inventoryv1.RootObservation) { r.Firmware.SecureBoot.Status = 0 },
		"missing_storage":    func(r *inventoryv1.RootObservation) { r.Storage = nil },
		"missing_cpu":        func(r *inventoryv1.RootObservation) { r.Cpu = nil },
		"missing_cpu_model":  func(r *inventoryv1.RootObservation) { r.Cpu.Model = nil },
		"invalid_cpu_source": func(r *inventoryv1.RootObservation) { r.Cpu.ModelSource.Value = "guessed_cpu" },
		"mismatched_cpu_source": func(r *inventoryv1.RootObservation) {
			r.Cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		},
		"invalid_native_row": func(r *inventoryv1.RootObservation) { r.Storage.Devices[0].Identity.LuksTokenCount.Status = 0 },
		"failed_partial_storage": func(r *inventoryv1.RootObservation) {
			r.Storage.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
		},
		"invalid_boot":         func(r *inventoryv1.RootObservation) { r.BootId = "invalid" },
		"foreign_boot":         func(r *inventoryv1.RootObservation) { r.BootId = inventoryObservationOtherBoot },
		"unknown_field":        func(r *inventoryv1.RootObservation) { r.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) },
		"nested_unknown_field": func(r *inventoryv1.RootObservation) { r.Firmware.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) },
	} {
		t.Run(name, func(t *testing.T) {
			observation := inventoryObservationFixture()
			mutate(observation)
			var output inventoryObservationWriter
			if err := inventoryObserve(t.Context(), nil, &output, inventoryObservationTestSources(observation)); err == nil || output.calls != 0 {
				t.Fatalf("invalid observation error=%v writes=%d", err, output.calls)
			}
		})
	}
}

func TestInventoryObserveRejectsOversizeAndMissingProjection(t *testing.T) {
	oversize := inventoryObservationFixture()
	device := oversize.Storage.Devices[0]
	device.Filesystem.Value = strings.Repeat("x", 4096)
	oversize.Storage.Devices = nil
	for i := range 24 {
		row := proto.CloneOf(device)
		row.Name = fmt.Sprintf("dm-%d", i)
		oversize.Storage.Devices = append(oversize.Storage.Devices, row)
	}
	if err := protovalidate.Validate(oversize); err != nil {
		t.Fatalf("oversize fixture must otherwise be valid: %v", err)
	}
	for _, observation := range []*inventoryv1.RootObservation{nil, oversize} {
		var output inventoryObservationWriter
		err := inventoryObserve(t.Context(), nil, &output, inventoryObservationTestSources(observation))
		if err == nil || output.calls != 0 {
			t.Fatalf("invalid size error=%v writes=%d", err, output.calls)
		}
		if observation != nil && !strings.Contains(err.Error(), "exceeds output limit") {
			t.Fatalf("oversize rejected for wrong reason: %v", err)
		}
	}
}

func TestInventoryObserveBootAndCancellationFailuresPublishNothing(t *testing.T) {
	bootErr := errors.New("boot read failed")
	for _, mode := range []string{"first_boot_error", "second_boot_error", "boot_changed", "canceled_before_start", "canceled_during_collect", "canceled_during_recheck"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "canceled_before_start" {
				cancel()
			}
			observation := inventoryObservationFixture()
			sources := inventoryObservationTestSources(observation)
			boots, collects := 0, 0
			sources.bootID = func() (string, error) {
				boots++
				if mode == "first_boot_error" || (mode == "second_boot_error" && boots == 2) {
					return "", bootErr
				}
				if boots == 2 && mode == "boot_changed" {
					return inventoryObservationOtherBoot, nil
				}
				if boots == 2 && mode == "canceled_during_recheck" {
					cancel()
				}
				return inventoryObservationTestBoot, nil
			}
			sources.collect = func(ctx context.Context, boot string) *inventoryv1.RootObservation {
				collects++
				if mode == "canceled_during_collect" {
					cancel()
					if !errors.Is(ctx.Err(), context.Canceled) {
						t.Fatal("collector did not share command cancellation")
					}
				}
				return observation
			}
			var output inventoryObservationWriter
			err := inventoryObserve(ctx, nil, &output, sources)
			if err == nil || output.calls != 0 {
				t.Fatalf("failure error=%v writes=%d", err, output.calls)
			}
			if strings.HasPrefix(mode, "canceled_") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation error: %v", err)
			}
			if strings.HasSuffix(mode, "boot_error") && !errors.Is(err, bootErr) {
				t.Fatalf("lost boot read error: %v", err)
			}
			if (mode == "first_boot_error" || mode == "canceled_before_start") && collects != 0 {
				t.Fatal("collection ran after early failure")
			}
			if mode == "canceled_before_start" && boots != 0 {
				t.Fatal("boot read ran after cancellation")
			}
		})
	}
}

type inventoryObservationFailedWriter struct {
	err error
}

func (w inventoryObservationFailedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestInventoryObservePropagatesOutputErrors(t *testing.T) {
	writeErr := errors.New("output failed")
	for _, err := range []error{nil, writeErr} {
		want := err
		if want == nil {
			want = io.ErrShortWrite
		}
		got := inventoryObserve(t.Context(), nil, inventoryObservationFailedWriter{err: err}, inventoryObservationTestSources(inventoryObservationFixture()))
		if !errors.Is(got, want) {
			t.Fatalf("output error=%v want=%v", got, want)
		}
	}
}
