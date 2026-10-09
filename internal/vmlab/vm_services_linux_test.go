//go:build linux

package vmlab

import "testing"

func TestServiceEvidenceRejectsEmptyScenarioRecords(t *testing.T) {
	// A successful guest exit and the expected record count do not establish
	// that the required native scenarios ran.
	evidence := &VMServicesEvidence{Capability: "systemd.service.v1", Steps: make([]VMServiceStep, 11)}
	if err := validateServiceEvidence(evidence); err == nil {
		t.Fatal("empty native scenario records accepted as qualification evidence")
	}
}
