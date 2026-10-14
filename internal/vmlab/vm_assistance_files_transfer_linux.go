// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type assistanceFileAttempt struct {
	Source               assistanceEvidenceFile        `json:"source_artifact"`
	Destination          *assistanceEvidenceFile       `json:"destination_artifact,omitempty"`
	DestinationAbsent    bool                          `json:"destination_absent,omitempty"`
	Before               *assistanceFileObservation    `json:"guest_before"`
	After                *assistanceFileObservation    `json:"guest_after"`
	Report               *agentv1.AssistanceFileReport `json:"report"`
	Paused               *agentv1.AssistanceInputState `json:"paused"`
	Resumed              *agentv1.AssistanceInputState `json:"resumed,omitempty"`
	ConsentScreenshot    string                        `json:"consent_screenshot,omitempty"`
	ConsentOCR           string                        `json:"consent_ocr,omitempty"`
	ReceivedScreenshot   string                        `json:"received_screenshot,omitempty"`
	ReceivedOCR          string                        `json:"received_ocr,omitempty"`
	HostPickerScreenshot string                        `json:"operator_picker_screenshot,omitempty"`
	// LocalChooser is how the local user answered the outgoing chooser.
	LocalChooser          string                   `json:"local_chooser,omitempty"`
	HostPickerTitle       string                   `json:"operator_picker_title,omitempty"`
	GuestPickerScreenshot string                   `json:"guest_picker_screenshot,omitempty"`
	Audit                 *assistanceAuditEvidence `json:"audit,omitempty"`
}

func (r *assistanceRun) bindFileFixture(fixture *assistanceFileFixture) (assistanceEvidenceFile, error) {
	bound, err := r.evidence.bind("operator file fixture", fixture.Name)
	if err != nil {
		return assistanceEvidenceFile{}, err
	}
	if bound.SHA256 != fixture.SHA256 || bound.Bytes != int64(fixture.Bytes) {
		return assistanceEvidenceFile{}, errors.New("file fixture differs from its independent streaming hash")
	}
	r.result.FileWitnesses = append(r.result.FileWitnesses, bound)
	return bound, nil
}

func (r *assistanceRun) fileUpload(ctx context.Context, scenario *assistanceScenarioEvidence, fixture *assistanceFileFixture, allow bool, terminal agentv1.AssistanceFileState) (_ *assistanceFileAttempt, err error) {
	attempt := new(assistanceFileAttempt)
	attempt.Source, err = r.bindFileFixture(fixture)
	if err != nil {
		return nil, err
	}
	attempt.Before, err = r.observeGuestFile(ctx, fixture.Name, true)
	if err != nil {
		return nil, err
	}
	requested, err := r.fileReport(ctx, "fileSend", map[string]any{"file": fixture.Name})
	if err != nil {
		return nil, err
	}
	request := requested.GetRequestId()
	attempt.Paused, err = r.filePaused(ctx, scenario, request)
	if err != nil {
		return nil, err
	}
	attempt.ConsentScreenshot, attempt.ConsentOCR, err = r.fileIncomingDecision(ctx, scenario, request, fixture.Name, allow)
	if err != nil {
		return nil, err
	}
	if terminal == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		attempt.ReceivedScreenshot, attempt.ReceivedOCR, err = r.fileReceivedNotice(ctx, scenario, request, fixture.Name)
		if err != nil {
			return nil, err
		}
	}
	attempt.Report, err = r.waitFile(ctx, request, terminal)
	if err != nil {
		return nil, err
	}
	attempt.After, err = r.observeGuestFile(ctx, fixture.Name, true)
	if err != nil {
		return nil, err
	}
	attempt.Resumed, err = r.fileResumed(ctx, scenario, attempt.Paused)
	if err != nil {
		return nil, err
	}
	action := "assistance.file.deny"
	if terminal == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		action = "assistance.file.complete"
	}
	if terminal == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED {
		action = "assistance.file.cancel"
	}
	attempt.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, action, request)
	if err != nil {
		return nil, err
	}
	return attempt, nil
}

// chooserAction is the local user's answer to the outgoing file chooser.
type chooserAction string

const (
	chooserSelect chooserAction = "select"
	// chooserCancel presses the chooser's Cancel button (portal response 1).
	chooserCancel chooserAction = "cancel-button"
	// chooserEscape presses Escape: GNOME 46 answers its delete-event with
	// response 2, GNOME 50's delegated chooser with response 1.
	chooserEscape chooserAction = "escape-key"
)

// chooserButtonRegion is the desktop below GNOME's top bar, where the chooser
// draws its header buttons.
func chooserButtonRegion(display image.Rectangle) image.Rectangle {
	return image.Rect(display.Min.X, display.Min.Y+gnomeTopBarHeight, display.Max.X, display.Max.Y)
}

func (r *assistanceRun) fileDownload(ctx context.Context, scenario *assistanceScenarioEvidence, fixture *assistanceFileFixture, action chooserAction) (*assistanceFileAttempt, error) {
	terminal := agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED
	if action != chooserSelect {
		terminal = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED
	}
	return r.fileDownloadExpected(ctx, scenario, fixture, action, terminal)
}

func (r *assistanceRun) fileDownloadExpected(ctx context.Context, scenario *assistanceScenarioEvidence, fixture *assistanceFileFixture, choice chooserAction, terminal agentv1.AssistanceFileState) (_ *assistanceFileAttempt, err error) {
	attempt := new(assistanceFileAttempt)
	attempt.Source, err = r.bindFileFixture(fixture)
	if err != nil {
		return nil, err
	}
	if err := r.installGuestFile(ctx, fixture, false); err != nil {
		return nil, err
	}
	attempt.Before, err = r.observeGuestFile(ctx, fixture.Name, false)
	if err != nil {
		return nil, err
	}
	if !attempt.Before.Regular || attempt.Before.SHA256 != fixture.SHA256 || attempt.Before.Bytes != fixture.Bytes {
		return nil, errors.New("native chooser fixture was not independently installed")
	}
	var pending struct {
		Previous string `json:"previous"`
	}
	if err := r.browser.call(ctx, "fileRequest", nil, &pending, 15*time.Second); err != nil {
		return nil, err
	}
	if r.browser.hostDisplay == nil {
		return nil, errors.New("real operator save picker is not available")
	}
	name := "saved-" + fixture.Name
	screenshot := "operator-save-" + fixture.Name + ".png"
	// Chromium's File System Access blocklist refuses a destination under
	// ~/.cache, where evidence directories usually live (layers-fedora44-
	// files-06 closed the picker without creating the file), so the picker
	// saves into the display's private directory and the result is moved
	// into the evidence directory once the transfer ends.
	staged := filepath.Join(r.browser.hostDisplay.dir, name)
	attempt.HostPickerTitle, err = r.browser.hostDisplay.saveFile(ctx, staged, filepath.Join(r.evidence.dir, screenshot))
	if err != nil {
		return nil, err
	}
	shot, err := r.evidence.bind("real operator save picker", screenshot)
	if err != nil {
		return nil, err
	}
	r.result.Screenshots = append(r.result.Screenshots, shot)
	scenario.Screenshots = append(scenario.Screenshots, shot.Path)
	attempt.HostPickerScreenshot = shot.Path
	requested, err := r.fileReport(ctx, "fileCreated", map[string]any{"previous": pending.Previous})
	if err != nil {
		return nil, err
	}
	request := requested.GetRequestId()
	attempt.Paused, err = r.filePaused(ctx, scenario, request)
	if err != nil {
		return nil, err
	}
	chooser, err := r.screen.waitCentreWindow(ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	attempt.GuestPickerScreenshot, err = r.screen.save(scenario.Name+"-"+request+"-native-file-chooser", chooser)
	if err != nil {
		return nil, err
	}
	scenario.Screenshots = append(scenario.Screenshots, attempt.GuestPickerScreenshot)
	action := "assistance.file.deny"
	if terminal == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		action = "assistance.file.complete"
	}
	switch choice {
	case chooserSelect:
		if err := r.chooseGuestFile(ctx, fixture, request); err != nil {
			return nil, err
		}
		attempt.LocalChooser = string(chooserSelect)
	case chooserCancel:
		// GNOME 46's GTK chooser has a Cancel button (response 1). GNOME 50
		// delegates to Nautilus, whose chooser has none; Escape is its
		// cancel and answers response 1 (layers-fedora44-files-21).
		img, found, findErr := r.screen.waitText(ctx, chooserButtonRegion, 8*time.Second, "chooser Cancel", "Cancel")
		if findErr != nil {
			if err := r.screen.pressKey(ctx, "local-file-cancel-escape", scenario, "esc"); err != nil {
				return nil, err
			}
			attempt.LocalChooser = string(chooserEscape)
			break
		}
		// The modal chooser does not move, and the hovering pointer covers the
		// label's own glyphs, so a hover re-read never matched "Cancel"
		// (layers-ubuntu24-files-21); the button found is clicked directly and
		// the file report is the oracle.
		box := found["Cancel"]
		point := image.Pt(box.Min.X+box.Dx()/2, box.Min.Y+box.Dy()/2)
		display, local := r.screen.localPoint(img.Bounds(), point)
		if err := r.vm.guest.pointerClick(ctx, display, local, "left"); err != nil {
			return nil, err
		}
		scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: "local-file-cancel", X: point.X, Y: point.Y})
		attempt.LocalChooser = string(chooserCancel)
	case chooserEscape:
		if err := r.screen.pressKey(ctx, "local-file-escape", scenario, "esc"); err != nil {
			return nil, err
		}
		attempt.LocalChooser = string(chooserEscape)
	default:
		return nil, errors.New("unknown local chooser action")
	}
	attempt.Report, err = r.waitFile(ctx, request, terminal)
	if err != nil {
		return nil, err
	}
	if err := moveOperatorDestination(staged, filepath.Join(r.evidence.dir, name)); err != nil {
		return nil, err
	}
	attempt.After, err = r.observeGuestFile(ctx, fixture.Name, false)
	if err != nil {
		return nil, err
	}
	if terminal == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		bound, err := r.evidence.bind("independently reread operator destination", name)
		if err != nil {
			return nil, err
		}
		r.result.FileWitnesses = append(r.result.FileWitnesses, bound)
		attempt.Destination = &bound
	} else {
		// A refused native chooser or rejected source type may leave a new empty
		// browser placeholder. It must never contain source bytes; do not claim deletion.
		digest, size, err := assistanceEvidenceDigest(filepath.Join(r.evidence.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			attempt.DestinationAbsent = true
		} else {
			if err != nil {
				return nil, err
			}
			if size != 0 {
				return nil, fmt.Errorf("cancelled chooser disclosed %d bytes (%s)", size, digest)
			}
			bound, err := r.evidence.bind("cancelled operator destination placeholder", name)
			if err != nil {
				return nil, err
			}
			r.result.FileWitnesses = append(r.result.FileWitnesses, bound)
			attempt.Destination = &bound
		}
	}
	attempt.Resumed, err = r.fileResumed(ctx, scenario, attempt.Paused)
	if err != nil {
		return nil, err
	}
	attempt.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, action, request)
	if err != nil {
		return nil, err
	}
	return attempt, nil
}

func verifyFileAttempt(scenario *assistanceScenarioEvidence, attempt *assistanceFileAttempt) error {
	if attempt == nil || attempt.Report == nil || !vmValidID(attempt.Report.GetRequestId()) || attempt.Source.SHA256 == "" || attempt.Source.Bytes <= 0 {
		return errors.New("file attempt lacks independent source and authoritative identity")
	}
	if attempt.Paused == nil || !attempt.Paused.GetPaused() || attempt.Paused.GetEpoch() <= 1 || attempt.Resumed == nil || attempt.Resumed.GetPaused() || attempt.Resumed.GetEpoch() <= attempt.Paused.GetEpoch() {
		return errors.New("file attempt lacks isolated and renewed input epochs")
	}
	report, audit := attempt.Report, attempt.Audit
	if report.GetCompletedAt() == nil || report.GetCompletedAt().AsTime().IsZero() || audit == nil || !vmValidID(audit.ID) || audit.ActorID != scenario.OperatorID || audit.ResourceID != scenario.SessionID || audit.TargetDeviceID != scenario.DeviceID || audit.Details["request"] != report.GetRequestId() {
		return errors.New("file terminal result lacks matching typed audit attribution")
	}
	if attempt.Before == nil || attempt.After == nil || len(attempt.Before.Staging) != 0 || len(attempt.After.Staging) != 0 {
		return errors.New("file transfer left staging files or lacks independent filesystem observations")
	}
	if report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		if report.GetFile() != nil || audit.Action == "assistance.file.complete" || audit.Details["sha256_origin"] == "receiver_verified" {
			return errors.New("refused file claims verified publication")
		}
		if !sameGuestFile(attempt.Before, attempt.After) {
			return errors.New("refused file changed the independently observed guest path")
		}
		switch report.GetState() {
		case agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED:
			if audit.Action != "assistance.file.deny" {
				return errors.New("file refusal lacks its denial audit")
			}
		case agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED:
			if audit.Action != "assistance.file.cancel" {
				return errors.New("file cancellation lacks its cancellation audit")
			}
		default:
			return errors.New("file attempt is not terminal")
		}
		if report.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
			if attempt.HostPickerScreenshot == "" || attempt.GuestPickerScreenshot == "" || (!attempt.DestinationAbsent && (attempt.Destination == nil || attempt.Destination.Bytes != 0)) {
				return errors.New("outgoing refusal disclosed bytes or lacks genuine local pickers")
			}
		} else if report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
			return errors.New("refused file direction is missing")
		}
		return nil
	}
	file := report.GetFile()
	if file.GetSize() != uint64(attempt.Source.Bytes) || report.GetBytesTransferred() != file.GetSize() || hex.EncodeToString(file.GetSha256()) != attempt.Source.SHA256 || file.GetMimeType() != "text/plain" || audit.Action != "assistance.file.complete" || audit.Details["sha256"] != attempt.Source.SHA256 || audit.Details["sha256_origin"] != "receiver_verified" {
		return errors.New("file success lacks matching independent hash, size, type and receiver-verified audit")
	}
	if report.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
		if attempt.Before.Exists || !attempt.After.Regular || attempt.After.Symlink || attempt.After.Mode != 0600 || scenario.LocalSession == nil || attempt.After.UID != scenario.LocalSession.UID || attempt.After.SHA256 != attempt.Source.SHA256 || attempt.After.Bytes != uint64(attempt.Source.Bytes) || attempt.ConsentScreenshot == "" || attempt.ReceivedScreenshot == "" || !fileNoticeVisible(attempt.ConsentOCR, scenario.OperatorDisplay, file.GetName(), false) || !fileNoticeVisible(attempt.ReceivedOCR, scenario.OperatorDisplay, file.GetName(), true) {
			return errors.New("incoming file was not independently observed as privately saved and visibly notified")
		}
	} else if report.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		if attempt.HostPickerTitle == "" || attempt.HostPickerScreenshot == "" || attempt.GuestPickerScreenshot == "" || attempt.Destination == nil || attempt.Destination.Bytes != attempt.Source.Bytes || attempt.Destination.SHA256 != attempt.Source.SHA256 || attempt.Before.SHA256 != attempt.Source.SHA256 || attempt.After.SHA256 != attempt.Source.SHA256 {
			return errors.New("outgoing file lacks real local pickers and independently reread destination")
		}
	} else {
		return errors.New("file attempt direction is missing")
	}
	return nil
}

func sameGuestFile(before, after *assistanceFileObservation) bool {
	return before != nil && after != nil && before.Exists == after.Exists && before.Regular == after.Regular && before.Symlink == after.Symlink && before.UID == after.UID && before.Mode == after.Mode && before.Bytes == after.Bytes && before.SHA256 == after.SHA256
}
