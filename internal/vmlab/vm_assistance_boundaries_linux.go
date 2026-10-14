// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

type assistanceNativeBoundary struct {
	Boundary        string                      `json:"boundary"`
	SessionID       string                      `json:"session_id"`
	RequestID       string                      `json:"requestId,omitempty"`
	Code            string                      `json:"code,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	HTTPStatus      int                         `json:"httpStatus,omitempty"`
	ObservedAt      time.Time                   `json:"observed_at"`
	ClipboardBefore string                      `json:"clipboard_before,omitempty"`
	ClipboardAfter  string                      `json:"clipboard_after,omitempty"`
	Guest           *assistanceFixtureState     `json:"guest,omitempty"`
	GuestBefore     *assistanceFixtureState     `json:"guest_before,omitempty"`
	Actor           *assistanceActor            `json:"actor,omitempty"`
	Authority       *assistanceAuthorityWitness `json:"authority,omitempty"`
	HardwareEventAt time.Time                   `json:"hardware_event_at,omitempty"`
	EndCause        string                      `json:"end_cause,omitempty"`
	EndDetail       string                      `json:"end_detail,omitempty"`
	MediaBefore     *browserMedia               `json:"media_before,omitempty"`
	MediaAfter      *browserMedia               `json:"media_after,omitempty"`
}

func (r *assistanceRun) saveNativeBoundary(scenario *assistanceScenarioEvidence, boundary *assistanceNativeBoundary) error {
	boundary.SessionID, boundary.ObservedAt = scenario.SessionID, time.Now().UTC()
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err != nil {
		return err
	}
	data, err := json.MarshalIndent(boundary, "", "  ")
	if err != nil {
		return err
	}
	bound, err := r.evidence.write(boundary.Boundary, "boundary-"+scenario.Name+"-"+boundary.Boundary+".json", data)
	if err != nil {
		return err
	}
	r.result.BoundaryWitnesses = append(r.result.BoundaryWitnesses, bound)
	scenario.BoundaryWitnesses = append(scenario.BoundaryWitnesses, bound.Path)
	return nil
}

// localClipboardPaste is independent local-seat input, still usable after the
// product's session ends. A new native paste callback, not an old matching
// state file, proves the current clipboard content.
func (r *assistanceRun) localClipboardPaste(ctx context.Context) (*assistanceFixtureState, error) {
	before, err := r.waitFixture(ctx, "local clipboard baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return nil, err
	}
	if err := r.vm.guest.qmpCommand(ctx, map[string]any{"execute": "send-key", "id": "local-clipboard-paste", "arguments": map[string]any{"keys": []map[string]any{{"type": "qcode", "data": "ctrl"}, {"type": "qcode", "data": "v"}}}}); err != nil {
		return nil, err
	}
	return r.waitFixture(ctx, "fresh native local clipboard paste", func(state *assistanceFixtureState) bool { return state.PasteSerial > before.PasteSerial })
}

func (r *assistanceRun) clipboardRefusal(ctx context.Context, scenario *assistanceScenarioEvidence, kind string) error {
	before, err := r.localClipboardPaste(ctx)
	if err != nil {
		return err
	}
	var refusal assistanceNativeBoundary
	if err := r.browser.call(ctx, "refuse", map[string]any{"boundary": kind}, &refusal, 45*time.Second); err != nil {
		return err
	}
	after, err := r.localClipboardPaste(ctx)
	if err != nil {
		return err
	}
	if before.Pasted == "" || after.Pasted != before.Pasted {
		return errors.New("refused clipboard request changed the native clipboard")
	}
	refusal.Boundary = map[string]string{"oversized": "clipboard-oversized-refused", "read-denied": "clipboard-denied-direction", "ended": "clipboard-session-end-refused"}[kind]
	refusal.ClipboardBefore, refusal.ClipboardAfter, refusal.Guest = before.Pasted, after.Pasted, after
	refusal.GuestBefore = before
	return r.saveNativeBoundary(scenario, &refusal)
}

func (r *assistanceRun) modifierRelease(ctx context.Context, scenario *assistanceScenarioEvidence) error {
	baseline, err := r.waitFixture(ctx, "modifier release baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return err
	}
	if err := r.browser.call(ctx, "holdShift", nil, nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "held remote Shift", func(state *assistanceFixtureState) bool {
		return len(state.Keys) > 0 && state.Keys[len(state.Keys)-1].Symbol == "Shift_L"
	}); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "releaseControl", nil, nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "native remote Shift release", func(state *assistanceFixtureState) bool {
		return len(state.Releases) > len(baseline.Releases) && slices.Contains(state.Releases[len(baseline.Releases):], "Shift_L")
	}); err != nil {
		return err
	}
	before, err := r.waitFixture(ctx, "released-control key baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return err
	}
	// Guest layout remains German: physical Y must produce lowercase z when
	// the remote Shift has truly been released. Browser keyup cannot deliver
	// it after Release control; this key is from the independent local seat.
	if err := r.vm.guest.sendKey(ctx, "y"); err != nil {
		return err
	}
	after, err := r.waitFixture(ctx, "local key after remote control loss", func(state *assistanceFixtureState) bool { return len(state.Keys) > len(before.Keys) })
	if err != nil {
		return err
	}
	if got := after.Keys[len(after.Keys)-1].Symbol; got != "z" {
		return fmt.Errorf("modifier remained held after control loss: local key produced %s", got)
	}
	return r.saveNativeBoundary(scenario, &assistanceNativeBoundary{Boundary: "keyboard-control-loss-releases-modifiers", Guest: after})
}

func requiredAssistanceBoundaries(scenario string) []string {
	switch scenario {
	case "clipboard":
		return []string{"clipboard-oversized-refused", "clipboard-session-end-refused"}
	case "clipboard-limited":
		return []string{"clipboard-denied-direction"}
	case "clipboard-policy":
		return []string{"clipboard-policy-revoked"}
	case "clipboard-permission":
		return []string{"clipboard-permission-refused"}
	case "keyboard":
		return []string{"keyboard-control-loss-releases-modifiers"}
	case "monitors":
		return []string{"monitors-hot-unplug-no-fallback"}
	default:
		return nil
	}
}

func completeAssistanceNativeBoundaries(result *VMAssistanceResult) bool {
	for _, name := range []string{"clipboard", "clipboard-limited", "clipboard-policy", "clipboard-permission", "keyboard", "monitors"} {
		index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == name })
		if index < 0 {
			return false
		}
		scenario := result.Scenarios[index]
		for _, boundary := range requiredAssistanceBoundaries(name) {
			if !slices.ContainsFunc(result.BoundaryWitnesses, func(file assistanceEvidenceFile) bool {
				return file.Name == boundary && slices.Contains(scenario.BoundaryWitnesses, file.Path)
			}) {
				return false
			}
		}
	}
	return true
}

func verifyAssistanceNativeBoundary(scenario *assistanceScenarioEvidence, boundary *assistanceNativeBoundary) error {
	if boundary.SessionID != scenario.SessionID || boundary.ObservedAt.IsZero() || !slices.Contains(requiredAssistanceBoundaries(scenario.Name), boundary.Boundary) {
		return errors.New("native boundary belongs to another session or capability")
	}
	if err := verifyAssistanceFixtureIdentity(boundary.Guest, scenario.LocalSession); err != nil {
		return err
	}
	switch boundary.Boundary {
	case "clipboard-oversized-refused", "clipboard-denied-direction", "clipboard-session-end-refused":
		if err := verifyAssistanceClipboardUnchanged(scenario, boundary); err != nil {
			return err
		}
		if boundary.Boundary == "clipboard-oversized-refused" {
			if boundary.Code != "invalid_argument" || boundary.HTTPStatus != 400 {
				return errors.New("oversized clipboard request was not authoritatively refused")
			}
		} else {
			reason := "assistance_capability_not_granted"
			if boundary.Boundary == "clipboard-session-end-refused" {
				reason = "assistance_ended"
			}
			if boundary.Code != "failed_precondition" || boundary.HTTPStatus != 400 && boundary.HTTPStatus != 412 || boundary.Reason != reason {
				return errors.New("clipboard authority refusal was not observed")
			}
		}
	case "clipboard-policy-revoked", "clipboard-permission-refused":
		if err := verifyAssistanceClipboardUnchanged(scenario, boundary); err != nil {
			return err
		}
		if err := verifyAssistanceAuthorityBoundary(scenario, boundary); err != nil {
			return err
		}
	case "keyboard-control-loss-releases-modifiers":
		if !slices.Contains(boundary.Guest.Releases, "Shift_L") || fixtureSymbols(boundary.Guest) != "yzzyz" {
			return errors.New("modifier release lacked its independent local-key effect")
		}
	case "monitors-hot-unplug-no-fallback":
		if boundary.HardwareEventAt.IsZero() || boundary.ObservedAt.Before(boundary.HardwareEventAt) || boundary.ObservedAt.Sub(boundary.HardwareEventAt) > time.Minute || boundary.Guest.ActiveMonitors != 1 || !slices.Contains(boundary.Guest.RemovedHeads, 1) || boundary.MediaBefore == nil || boundary.MediaBefore.MarkerHead != 1 || boundary.MediaAfter == nil || boundary.MediaAfter.OpenInputChannels != 0 || boundary.MediaAfter.MarkerHead == 0 {
			return errors.New("hot-unplug lacks real hardware removal and terminated media/input authority")
		}
		portalClosed := boundary.EndCause == "portal_closed" && boundary.EndDetail == "portal_session_closed"
		captureUnavailable := boundary.EndCause == "unavailable" && slices.Contains([]string{"capture_exited", "display_disappeared", "capture_switch_failed"}, boundary.EndDetail)
		if !portalClosed && !captureUnavailable {
			return errors.New("hot-unplug was attributed to an unrelated session end")
		}
	}
	return nil
}

func verifyAssistanceClipboardUnchanged(scenario *assistanceScenarioEvidence, boundary *assistanceNativeBoundary) error {
	if err := verifyAssistanceFixtureIdentity(boundary.GuestBefore, scenario.LocalSession); err != nil {
		return err
	}
	if !vmValidID(boundary.RequestID) || len(boundary.ClipboardBefore) != 24 || boundary.ClipboardAfter != boundary.ClipboardBefore || boundary.Guest.Pasted != boundary.ClipboardAfter || boundary.GuestBefore.Pasted != boundary.ClipboardBefore || boundary.GuestBefore.PasteSerial <= 0 || boundary.Guest.PasteSerial <= boundary.GuestBefore.PasteSerial || boundary.Guest.PID != boundary.GuestBefore.PID {
		return errors.New("clipboard refusal lacks independent fresh unchanged native clipboard observations")
	}
	return nil
}
