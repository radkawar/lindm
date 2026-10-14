// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

var assistanceFileScenarios = []string{"files", "files-cancel", "files-limited", "files-filesystem", "files-limits", "files-interrupted", "files-policy", "files-permission"}

type assistanceFilesWitness struct {
	SessionID  string                        `json:"session_id"`
	Scenario   string                        `json:"scenario"`
	ObservedAt time.Time                     `json:"observed_at"`
	Attempts   []*assistanceFileAttempt      `json:"attempts,omitempty"`
	Authority  *assistanceFileAuthorityProof `json:"authority,omitempty"`
	Safety     *assistanceFileSafetyProof    `json:"safety,omitempty"`
	Isolation  *assistanceFileIsolationProof `json:"isolation,omitempty"`
}

func (r *assistanceRun) fileScenario(ctx context.Context, scenario *assistanceScenarioEvidence, session *adminv1.AssistanceSession) error {
	witness := &assistanceFilesWitness{SessionID: scenario.SessionID, Scenario: scenario.Name}
	switch scenario.Name {
	case "files", "files-cancel", "files-limited":
		fixture, err := r.fileFixture(32768, false)
		if err != nil {
			return err
		}
		allow, state := true, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED
		if scenario.Name == "files-cancel" {
			allow, state = false, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED
		}
		upload, err := r.fileUpload(ctx, scenario, fixture, allow, state)
		if err != nil {
			return err
		}
		witness.Attempts = append(witness.Attempts, upload)
		if scenario.Name == "files-limited" {
			witness.Authority, err = r.fileAuthorityScenario(ctx, scenario, session)
			if err != nil {
				return err
			}
		} else {
			fixture, err := r.fileFixture(49152, false)
			if err != nil {
				return err
			}
			action := chooserSelect
			if scenario.Name == "files-cancel" {
				action = chooserCancel
			}
			download, err := r.fileDownload(ctx, scenario, fixture, action)
			if err != nil {
				return err
			}
			witness.Attempts = append(witness.Attempts, download)
			if scenario.Name == "files-cancel" {
				// The real keyboard path: Escape closes the chooser (response 2
				// on GNOME 46) and must refuse only this request, resume input
				// and keep the session (layers-ubuntu24-files-17/-19).
				fixture, err := r.fileFixture(49152, false)
				if err != nil {
					return err
				}
				escape, err := r.fileDownload(ctx, scenario, fixture, chooserEscape)
				if err != nil {
					return err
				}
				witness.Attempts = append(witness.Attempts, escape)
			}
		}
	case "files-filesystem", "files-limits":
		safety, err := r.fileSafetyScenario(ctx, scenario)
		if err != nil {
			return err
		}
		witness.Safety = safety
	case "files-interrupted":
		isolation, err := r.fileInterruptedScenario(ctx, scenario)
		if err != nil {
			return err
		}
		witness.Isolation = isolation
	case "files-policy", "files-permission":
		authority, err := r.fileAuthorityScenario(ctx, scenario, session)
		if err != nil {
			return err
		}
		witness.Authority = authority
	default:
		return errors.New("unknown native file scenario")
	}
	witness.ObservedAt = time.Now().UTC()
	if err := verifyFilesWitness(scenario, witness); err != nil {
		return err
	}
	data, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return err
	}
	bound, err := r.evidence.write("file-transfer-"+scenario.Name, "file-transfer-"+scenario.Name+".json", data)
	if err != nil {
		return err
	}
	r.result.FileWitnesses = append(r.result.FileWitnesses, bound)
	scenario.FileWitness = bound.Path
	return nil
}

func verifyFilesWitness(scenario *assistanceScenarioEvidence, witness *assistanceFilesWitness) error {
	if witness == nil || witness.SessionID != scenario.SessionID || !vmValidID(witness.SessionID) || witness.Scenario != scenario.Name || witness.ObservedAt.IsZero() || !slices.Contains(assistanceFileScenarios, scenario.Name) {
		return errors.New("file witness does not identify its actual session and scenario")
	}
	for _, attempt := range witness.Attempts {
		if err := verifyFileAttempt(scenario, attempt); err != nil {
			return err
		}
	}
	switch scenario.Name {
	case "files", "files-cancel", "files-limited":
		count, expected := 2, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED
		if scenario.Name == "files-cancel" {
			count, expected = 3, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED
		}
		if scenario.Name == "files-limited" {
			count = 1
		}
		if len(witness.Attempts) != count {
			return errors.New("file scenario lacks its required directions")
		}
		for index, attempt := range witness.Attempts {
			direction := agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER
			if index > 0 {
				direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
			}
			if attempt.Report.GetDirection() != direction || attempt.Report.GetState() != expected {
				return errors.New("file scenario witnessed a different direction or outcome")
			}
		}
		if scenario.Name == "files-cancel" {
			if err := verifyChooserRefusals(witness.Attempts[1], witness.Attempts[2]); err != nil {
				return err
			}
		}
		if scenario.Name == "files-limited" {
			return verifyFileAuthority(scenario, witness.Authority)
		}
	case "files-policy", "files-permission":
		return verifyFileAuthority(scenario, witness.Authority)
	case "files-filesystem", "files-limits":
		return verifyFileSafety(scenario, witness.Safety)
	case "files-interrupted":
		return verifyFileIsolation(scenario, witness.Isolation)
	}
	return nil
}

// verifyChooserRefusals requires a cancel answered response 1 — the Cancel
// button, or Escape where the chooser has none (GNOME 50's Nautilus) — and an
// Escape answered response 2 (GNOME 46's delete-event) or 1 (GNOME 50). Both
// refuse only the request.
func verifyChooserRefusals(cancel, escape *assistanceFileAttempt) error {
	if (cancel.LocalChooser != string(chooserCancel) && cancel.LocalChooser != string(chooserEscape)) || cancel.Report.GetReason() != "file_dialog_dismissed" ||
		escape.LocalChooser != string(chooserEscape) || (escape.Report.GetReason() != "file_dialog_closed" && escape.Report.GetReason() != "file_dialog_dismissed") {
		return errors.New("local chooser refusals lack their Cancel and Escape outcomes")
	}
	return nil
}

func completeAssistanceFiles(result *VMAssistanceResult) bool {
	for _, name := range assistanceFileScenarios {
		index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == name })
		if index < 0 {
			return false
		}
		scenario := result.Scenarios[index]
		if scenario.FileWitness == "" || !slices.ContainsFunc(result.FileWitnesses, func(file assistanceEvidenceFile) bool {
			return file.Name == "file-transfer-"+name && file.Path == scenario.FileWitness
		}) {
			return false
		}
	}
	return true
}

func verifyFilesWitnessRecord(dir string, result *VMAssistanceResult, scenario *assistanceScenarioEvidence) error {
	index := slices.IndexFunc(result.FileWitnesses, func(file assistanceEvidenceFile) bool {
		return file.Name == "file-transfer-"+scenario.Name && file.Path == scenario.FileWitness
	})
	if index < 0 || result.FileWitnesses[index].Bytes <= 0 || result.FileWitnesses[index].Bytes > 4<<20 {
		return errors.New("file scenario lacks a bounded SHA-bound structured witness")
	}
	data, err := os.ReadFile(filepath.Join(dir, scenario.FileWitness))
	if err != nil {
		return err
	}
	var witness assistanceFilesWitness
	if err := json.Unmarshal(data, &witness); err != nil {
		return err
	}
	if err := verifyFilesWitness(scenario, &witness); err != nil {
		return err
	}
	for _, attempt := range witness.Attempts {
		if !slices.Contains(result.FileWitnesses, attempt.Source) || (attempt.Destination != nil && !slices.Contains(result.FileWitnesses, *attempt.Destination)) {
			return errors.New("file proof source or destination is not an independently rebound artifact")
		}
		for _, path := range []string{attempt.ConsentScreenshot, attempt.ReceivedScreenshot, attempt.HostPickerScreenshot, attempt.GuestPickerScreenshot} {
			if path != "" && (!slices.Contains(scenario.Screenshots, path) || !slices.ContainsFunc(result.Screenshots, func(file assistanceEvidenceFile) bool { return file.Path == path })) {
				return errors.New("file proof references an unbound native screenshot")
			}
		}
	}
	var nestedFiles []assistanceEvidenceFile
	var nestedScreenshots []string
	if witness.Safety != nil {
		nestedFiles = append(nestedFiles, witness.Safety.fileArtifacts()...)
		nestedScreenshots = append(nestedScreenshots, witness.Safety.screenshotPaths()...)
	}
	if witness.Isolation != nil {
		nestedFiles = append(nestedFiles, witness.Isolation.fileArtifacts()...)
		nestedScreenshots = append(nestedScreenshots, witness.Isolation.screenshotPaths()...)
		if err := witness.Isolation.verifySourcePrefixes(dir); err != nil {
			return err
		}
	}
	for _, file := range nestedFiles {
		if !slices.Contains(result.FileWitnesses, file) {
			return errors.New("nested file safety proof references an unbound artifact")
		}
	}
	for _, path := range nestedScreenshots {
		if path == "" || !slices.Contains(scenario.Screenshots, path) || !slices.ContainsFunc(result.Screenshots, func(file assistanceEvidenceFile) bool { return file.Path == path }) {
			return errors.New("nested file safety proof references an unbound screenshot")
		}
	}
	return nil
}
