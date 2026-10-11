//go:build linux

package vmlab

import (
	"context"
	"debug/elf"
	"os"
	"testing"
)

func TestServiceEvidenceRejectsEmptyScenarioRecords(t *testing.T) {
	// A successful guest exit and the expected record count do not establish
	// that the required native scenarios ran.
	evidence := &VMServicesEvidence{Capability: "systemd.service.v1", Steps: make([]VMServiceStep, 11)}
	if err := validateServiceEvidence(evidence); err == nil {
		t.Fatal("empty native scenario records accepted as qualification evidence")
	}
}

func TestServiceProbeRequiresSelectedGuestArchitecture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	machine := binary.Machine
	if err := binary.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []elf.Machine{machine, elf.EM_NONE} {
		snapshot, _, err := snapshotServicesProbe(context.Background(), t.TempDir(), executable, want)
		if want == machine {
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			_ = snapshot.Close()
			t.Fatal("service probe for another guest architecture was accepted")
		}
	}
}
