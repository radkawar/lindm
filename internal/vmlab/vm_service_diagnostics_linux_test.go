//go:build linux

package vmlab

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestServiceFailureRetainsPublicTerminalEvidence(t *testing.T) {
	status := &agentv1.ServiceExecutionStatus{
		ActionId:     "e7fb3f03-56b3-453b-89cb-07b709ea865d",
		State:        agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED,
		Failure:      agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NATIVE,
		AcceptedAt:   timestamppb.New(time.Unix(100, 0)),
		StartedAt:    timestamppb.New(time.Unix(101, 0)),
		CompletedAt:  timestamppb.New(time.Unix(102, 0)),
		Before:       &agentv1.ServiceObservation{},
		Verification: &agentv1.ServiceVerification{Converged: false},
	}
	err := vmServiceSucceeded(status, true)
	if err == nil {
		t.Fatal("failed native action reported success")
	}
	status.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE
	for _, want := range []string{"SERVICE_EXECUTION_STATE_FAILED", "SERVICE_EXECUTION_FAILURE_NATIVE", "before", "verification", "acceptedAt", "startedAt", "completedAt", "expected_started=true"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic lost %q: %v", want, err)
		}
	}
}

func TestServiceJournalProjectionExcludesUnrelatedAndSensitiveFields(t *testing.T) {
	action := "e7fb3f03-56b3-453b-89cb-07b709ea865d"
	data := []byte(`{"_SYSTEMD_UNIT":"lindm-executor.service","MESSAGE":"native failure action ` + action + `","__REALTIME_TIMESTAMP":"102000000","_CMDLINE":"private-argument","PRIVATE":"secret-value"}` + "\n" +
		`{"_SYSTEMD_UNIT":"other.service","MESSAGE":"` + action + ` unrelated"}` + "\n" +
		`{"_SYSTEMD_UNIT":"lindm-agent.service","MESSAGE":"unrelated"}` + "\n" +
		`{"_SYSTEMD_UNIT":"lindm-agent.service","MESSAGE":"` + action + ` token=do-not-publish"}` + "\n" +
		`{"_SYSTEMD_UNIT":"lindm-agent.service","MESSAGE":"` + action + ` error=postgres://alice:hunter2@db/app"}` + "\n" +
		`{"_SYSTEMD_UNIT":"lindm-agent.service","MESSAGE":"` + action + ` api_key=opaque-value service_result_conflict"}` + "\n")
	encoded, err := serviceJournalProjection(data, action)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]string
	if err := json.Unmarshal(encoded, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 || entries[0]["__REALTIME_TIMESTAMP"] != "102000000" || entries[3]["message_classification"] != "service_result_conflict" {
		t.Fatalf("lost action journal: %s", encoded)
	}
	for _, forbidden := range []string{"private-argument", "secret-value", "unrelated", "do-not-publish", "_CMDLINE", "PRIVATE", "hunter2", "opaque-value", "postgres://", "api_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("leaked %q: %s", forbidden, encoded)
		}
	}
	if _, err := serviceJournalProjection([]byte(`{"MESSAGE":42}`), action); err == nil {
		t.Fatal("accepted malformed journal message")
	}
}
