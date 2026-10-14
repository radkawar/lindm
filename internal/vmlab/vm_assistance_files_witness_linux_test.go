// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestCompleteAssistanceFilesRequiresEveryNamedBoundProof(t *testing.T) {
	complete := func() *VMAssistanceResult {
		result := new(VMAssistanceResult)
		for _, name := range assistanceFileScenarios {
			path := "file-transfer-" + name + ".json"
			result.Scenarios = append(result.Scenarios, &assistanceScenarioEvidence{Name: name, FileWitness: path})
			result.FileWitnesses = append(result.FileWitnesses, assistanceEvidenceFile{Name: "file-transfer-" + name, Path: path})
		}
		return result
	}
	if !completeAssistanceFiles(complete()) {
		t.Fatal("complete named ledger rejected")
	}
	for _, name := range assistanceFileScenarios {
		t.Run(name, func(t *testing.T) {
			result := complete()
			for _, scenario := range result.Scenarios {
				if scenario.Name == name {
					scenario.FileWitness = ""
				}
			}
			if completeAssistanceFiles(result) {
				t.Fatal("missing scenario proof counted as files pass")
			}
		})
	}
	result := complete()
	result.FileWitnesses = result.FileWitnesses[1:]
	result.FileWitnesses = append(result.FileWitnesses, assistanceEvidenceFile{Name: "operator file fixture", Path: result.Scenarios[0].FileWitness})
	if completeAssistanceFiles(result) {
		t.Fatal("payload artifact substituted for structured proof")
	}
	result = complete()
	result.Scenarios = result.Scenarios[1:]
	if completeAssistanceFiles(result) {
		t.Fatal("subset run counted as complete files qualification")
	}
}

// files-cancel needs Cancel (response 1) and Escape (response 2 on GNOME 46,
// 1 on GNOME 50) to each refuse only their request (layers-ubuntu24-files-17).
func TestChooserRefusalsRequireCancelAndEscapeOutcomes(t *testing.T) {
	attempt := func(chooser chooserAction, reason string) *assistanceFileAttempt {
		return &assistanceFileAttempt{LocalChooser: string(chooser), Report: &agentv1.AssistanceFileReport{Reason: reason}}
	}
	for _, escape := range []string{"file_dialog_closed", "file_dialog_dismissed"} {
		if err := verifyChooserRefusals(attempt(chooserCancel, "file_dialog_dismissed"), attempt(chooserEscape, escape)); err != nil {
			t.Fatalf("escape %s: %v", escape, err)
		}
	}
	// GNOME 50's Nautilus chooser has no Cancel button; Escape answers 1.
	if err := verifyChooserRefusals(attempt(chooserEscape, "file_dialog_dismissed"), attempt(chooserEscape, "file_dialog_dismissed")); err != nil {
		t.Fatalf("Nautilus escape cancel: %v", err)
	}
	for name, pair := range map[string][2]*assistanceFileAttempt{
		"cancel closed":        {attempt(chooserCancel, "file_dialog_closed"), attempt(chooserEscape, "file_dialog_closed")},
		"escape declined":      {attempt(chooserCancel, "file_dialog_dismissed"), attempt(chooserEscape, "file_declined")},
		"escape not pressed":   {attempt(chooserCancel, "file_dialog_dismissed"), attempt(chooserCancel, "file_dialog_dismissed")},
		"chosen not cancelled": {attempt(chooserSelect, "file_dialog_dismissed"), attempt(chooserEscape, "file_dialog_closed")},
	} {
		if verifyChooserRefusals(pair[0], pair[1]) == nil {
			t.Fatalf("%s qualified", name)
		}
	}
}
