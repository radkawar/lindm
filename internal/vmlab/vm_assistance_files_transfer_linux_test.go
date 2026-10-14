// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func fileAttemptTestProof() (*assistanceScenarioEvidence, *assistanceFileAttempt) {
	hash := sha256.Sum256([]byte("native-witness-unit-fixture"))
	digest := hex.EncodeToString(hash[:])
	scenario := &assistanceScenarioEvidence{Name: "files", SessionID: uuid.NewString(), DeviceID: uuid.NewString(), OperatorID: uuid.NewString(), OperatorDisplay: "Local operator", LocalSession: &assistanceLocalEvidence{UID: 1000}}
	id := uuid.NewString()
	attempt := &assistanceFileAttempt{
		Source: assistanceEvidenceFile{Name: "fixture", Path: "lindm-file-unit.txt", SHA256: digest, Bytes: 25},
		Before: &assistanceFileObservation{}, After: &assistanceFileObservation{Exists: true, Regular: true, UID: 1000, Mode: 0600, Bytes: 25, SHA256: digest},
		Report: &agentv1.AssistanceFileReport{RequestId: id, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, BytesTransferred: 25, File: &agentv1.AssistanceFileMetadata{Name: "lindm-file-unit.txt", Size: 25, Sha256: hash[:], MimeType: "text/plain"}, CompletedAt: timestamppb.New(time.Now()), Reason: "receiver_verified"},
		Paused: &agentv1.AssistanceInputState{Paused: true, Epoch: 2}, Resumed: &agentv1.AssistanceInputState{Epoch: 3},
		ConsentScreenshot: "consent.png", ConsentOCR: "Receive a file from your support operator Local operator lindm-file-unit.txt Downloads",
		ReceivedScreenshot: "received.png", ReceivedOCR: "Lindm file received Local operator lindm-file-unit.txt Downloads",
		Audit: &assistanceAuditEvidence{ID: uuid.NewString(), ActorID: scenario.OperatorID, ResourceID: scenario.SessionID, TargetDeviceID: scenario.DeviceID, Action: "assistance.file.complete", Details: map[string]string{"request": id, "sha256": digest, "sha256_origin": "receiver_verified"}},
	}
	return scenario, attempt
}

func TestFileReceiptProofRequiresNativePublicationAndNewAuthority(t *testing.T) {
	scenario, attempt := fileAttemptTestProof()
	if err := verifyFileAttempt(scenario, attempt); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*assistanceFileAttempt){
		"source_mismatch":              func(a *assistanceFileAttempt) { a.Source.SHA256 = "bad" },
		"wrong_request_audit":          func(a *assistanceFileAttempt) { a.Audit.Details["request"] = uuid.NewString() },
		"authorized_not_verified_hash": func(a *assistanceFileAttempt) { a.Audit.Details["sha256_origin"] = "authorized_sha256" },
		"missing_consent":              func(a *assistanceFileAttempt) { a.ConsentScreenshot = "" },
		"wrong_operator_pixels": func(a *assistanceFileAttempt) {
			a.ReceivedOCR = "Lindm file received other operator lindm-file-unit.txt Downloads"
		},
		"wrong_nonce_pixels": func(a *assistanceFileAttempt) {
			a.ReceivedOCR = "Lindm file received Local operator other.txt Downloads"
		},
		"wrong_uid":    func(a *assistanceFileAttempt) { a.After.UID = 1001 },
		"not_private":  func(a *assistanceFileAttempt) { a.After.Mode = 0644 },
		"symlink":      func(a *assistanceFileAttempt) { a.After.Symlink = true },
		"overwrite":    func(a *assistanceFileAttempt) { a.Before.Exists = true },
		"staging":      func(a *assistanceFileAttempt) { a.After.Staging = []string{".lindm-transfer-left"} },
		"old_epoch":    func(a *assistanceFileAttempt) { a.Resumed.Epoch = a.Paused.Epoch },
		"still_paused": func(a *assistanceFileAttempt) { a.Resumed.Paused = true },
		"no_pause":     func(a *assistanceFileAttempt) { a.Paused.Paused = false },
	} {
		t.Run(name, func(t *testing.T) {
			scenario, attempt := fileAttemptTestProof()
			mutate(attempt)
			if verifyFileAttempt(scenario, attempt) == nil {
				t.Fatal("incomplete receipt proof accepted")
			}
		})
	}
}

func TestRefusedFileProofRejectsPublicationAndDisclosure(t *testing.T) {
	refused := func() (*assistanceScenarioEvidence, *assistanceFileAttempt) {
		scenario, a := fileAttemptTestProof()
		a.Report.State = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED
		a.Report.File = nil
		a.Report.BytesTransferred = 0
		a.After = &assistanceFileObservation{}
		a.Audit.Action = "assistance.file.deny"
		delete(a.Audit.Details, "sha256_origin")
		delete(a.Audit.Details, "sha256")
		return scenario, a
	}
	scenario, attempt := refused()
	if err := verifyFileAttempt(scenario, attempt); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*assistanceFileAttempt){
		"published": func(a *assistanceFileAttempt) { a.After.Exists = true },
		"verified": func(a *assistanceFileAttempt) {
			a.Report.File = &agentv1.AssistanceFileMetadata{Name: "unexpected.txt"}
		},
		"success_audit": func(a *assistanceFileAttempt) { a.Audit.Action = "assistance.file.complete" },
		"nonterminal": func(a *assistanceFileAttempt) {
			a.Report.State = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING
		},
		"unknown_direction": func(a *assistanceFileAttempt) {
			a.Report.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_UNSPECIFIED
		},
	} {
		t.Run(name, func(t *testing.T) {
			scenario, attempt := refused()
			mutate(attempt)
			if verifyFileAttempt(scenario, attempt) == nil {
				t.Fatal("refused-transfer side effect accepted")
			}
		})
	}
}
