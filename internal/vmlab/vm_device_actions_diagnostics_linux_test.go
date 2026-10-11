//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestActionStatusDiagnosticExcludesEscrow(t *testing.T) {
	status := &agentv1.GetDeviceActionResponse{Status: &agentv1.DeviceActionStatus{
		ActionId:     "641466e8-07b1-4a91-88c4-32b559b33adf",
		State:        agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN,
		Failure:      agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED,
		StartedAt:    timestamppb.Now(),
		Verification: &agentv1.DeviceActionVerification{Evidence: "native failure", Escrow: &agentv1.DeviceActionEscrow{Ciphertext: []byte("not diagnostic material"), RecoveryKeySha256: make([]byte, 32)}},
	}}
	encoded, err := protojson.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := actionStatusDiagnostic(encoded)
	if err != nil {
		t.Fatal(err)
	}
	observed := new(agentv1.GetDeviceActionResponse)
	if err := protojson.Unmarshal(retained, observed); err != nil {
		t.Fatal(err)
	}
	status.Status.Verification.Escrow = nil
	if !proto.Equal(status, observed) {
		t.Fatal("diagnostic retained escrow material or lost outcome/timing")
	}
	if _, err := actionStatusDiagnostic([]byte(`{"unknownSecret":"must not survive"}`)); err == nil {
		t.Fatal("unknown status field accepted")
	}
}

func TestLiveRootDiagnosticRetainsPoweredOffFailure(t *testing.T) {
	done := make(chan struct{})
	close(done)
	vm := &guestVM{done: done, log: new(vmLog)}
	finish := monitorLiveRoot(t.Context(), vm, "641466e8-07b1-4a91-88c4-32b559b33adf")
	result := finish()
	if result.Status != nil || !strings.Contains(result.Failure, "QEMU exited unexpectedly") {
		t.Fatalf("missing explicit powered-off observation failure: %+v", result)
	}
}

func TestNativeActionFailureRetainsExplicitDiagnostics(t *testing.T) {
	directory := t.TempDir()
	done := make(chan struct{})
	close(done)
	vm := &guestVM{done: done, log: new(vmLog), diagnosticsDir: directory}
	cause := errors.New("native action failed")
	err := diagnoseNativeAction(t.Context(), vm, "641466e8-07b1-4a91-88c4-32b559b33adf", cause)
	if !errors.Is(err, cause) {
		t.Fatalf("lost original failure: %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("diagnostics not retained in requested directory: %v, %v", entries, readErr)
	}
	path := filepath.Join(directory, entries[0].Name())
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("diagnostic permissions = %o, want 0600", info.Mode().Perm())
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var record struct {
		ActionID      string `json:"action_id"`
		StatusFailure string `json:"executor_status_failure"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.ActionID != "641466e8-07b1-4a91-88c4-32b559b33adf" || !strings.Contains(record.StatusFailure, "QEMU exited unexpectedly") || !strings.Contains(err.Error(), path) {
		t.Fatalf("lost action identity, failure, or retained path: %+v; %v", record, err)
	}
}
