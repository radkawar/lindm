package update

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestActiveMetadataWorkerCannotReturnAnIdlePollingPhase(t *testing.T) {
	for _, phase := range []string{"idle", "installed", "rejected"} {
		e := &Engine{running: true, status: &agentv1.AgentUpdateStatus{Enabled: true, Phase: phase, Version: "0.1.0"}}
		status := e.Status()
		if status.GetPhase() != "checking" {
			t.Fatalf("active worker returned %q, allowing transport to sleep through its fetch deadline", status.GetPhase())
		}
		status.Version = "9.9.9"
		if e.Status().GetVersion() != "0.1.0" {
			t.Fatal("status caller mutated protected update state")
		}
		e.running = false
		if e.Status().GetPhase() != phase {
			t.Fatal("completed worker lost its durable outcome")
		}
	}
}
