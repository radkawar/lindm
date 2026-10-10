package loadlab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func historicalTestHost() *inventoryv1.HostObservation {
	when := timestamppb.New(time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC))
	return &inventoryv1.HostObservation{
		StartedAt: when, FinishedAt: when, BootId: observed("original-captured-boot"),
		Hostname: observed("captured-ubuntu"), OsId: observed("ubuntu"), OsVersion: observed("24.04"),
		Architecture: observed("x86_64"), KernelRelease: observed("6.8.0"),
		HardwareVendor: observed("captured vendor"), HardwareModel: observed("captured model"),
		HardwareSerial: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
	}
}

func TestReadHistoricalHostValidatesBoundedCapturedInput(t *testing.T) {
	host := historicalTestHost()
	valid, err := protojson.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	invalid := proto.CloneOf(host)
	invalid.HardwareSerial.Value = "cannot carry a value on a failed collection"
	badStatus, err := protojson.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, data string
		valid      bool
	}{
		{"captured", string(valid), true},
		{"empty", "", false},
		{"missing fields", "{}", false},
		{"unknown field", strings.TrimSuffix(string(valid), "}") + `,"notAHostField":true}`, false},
		{"failed field carries value", string(badStatus), false},
		{"oversized", strings.Repeat(" ", maxHistoricalHostBytes+1), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "host.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readHistoricalHost(path)
			if !test.valid {
				if err == nil {
					t.Fatal("invalid capture was accepted")
				}
				return
			}
			if err != nil || !proto.Equal(got, host) {
				t.Fatalf("capture changed or was rejected: %v", err)
			}
		})
	}
	if _, err := readHistoricalHost(t.TempDir()); err == nil {
		t.Fatal("directory accepted as a host capture")
	}
}

// This records the publication boundary only, not native device or server behavior.
type historicalReportClient struct {
	inventoryReplayClient
	request      *devicev1.ReportHostObservationRequest
	err          error
	wrongReceipt bool
}

func (client *historicalReportClient) ReportHostObservation(_ context.Context, request *connect.Request[devicev1.ReportHostObservationRequest]) (*connect.Response[devicev1.ReportHostObservationResponse], error) {
	client.request = proto.CloneOf(request.Msg)
	if client.err != nil {
		return nil, client.err
	}
	sequence := request.Msg.Sequence
	if client.wrongReceipt {
		sequence++
	}
	return connect.NewResponse(&devicev1.ReportHostObservationResponse{AcceptedSequence: sequence}), nil
}

func TestHistoricalHostPublicationPreservesEvidenceAndSessionFence(t *testing.T) {
	for _, failure := range []string{"", "transport", "receipt"} {
		t.Run(failure, func(t *testing.T) {
			host := historicalTestHost()
			before := proto.CloneOf(host)
			client := &historicalReportClient{inventoryReplayClient: inventoryReplayClient{t: t}, wrongReceipt: failure == "receipt"}
			if failure == "transport" {
				client.err = errors.New("publication failed")
			}
			data, err := packages(1)
			if err != nil {
				t.Fatal(err)
			}
			r := &runner{historicalHost: host, packages: data}
			device := &simulatedDevice{client: client, generation: "isolated-generation", epoch: 9, hostSequence: 4}
			err = r.inventory(t.Context(), device, 0)
			if (err != nil) != (failure != "") {
				t.Fatalf("publication outcome: %v", err)
			}
			if !proto.Equal(host, before) || !proto.Equal(client.request.Observation, before) {
				t.Fatal("historical fields, statuses, boot ID or collection timestamps changed")
			}
			if client.request.EnrollmentGeneration != device.generation || client.request.SessionEpoch != 9 || client.request.Sequence != 5 {
				t.Fatal("publication lost simulator generation/session/monotonic sequence")
			}
			if failure != "" {
				original := proto.CloneOf(client.request)
				client.err, client.wrongReceipt = nil, false
				if err := r.inventory(t.Context(), device, 0); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(client.request, original) {
					t.Fatal("retry changed captured publication")
				}
			}
			other := &simulatedDevice{client: client, generation: "another-generation", epoch: 1}
			if err := r.inventory(t.Context(), other, 1); err != nil {
				t.Fatal(err)
			}
			if proto.Equal(client.request.Observation, host) || client.request.Observation.GetHostname().GetValue() != label(1) {
				t.Fatal("historical capture replaced more than the first device")
			}
		})
	}
}
