//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// QEMU virtio_gpu_ui_info clears the scanout's enabled bit on a zero-sized
// display. This is a real connector removal, not a hidden fixture window.
func (r *assistanceRun) unplugSelectedMonitor(ctx context.Context, scenario *assistanceScenarioEvidence) (*adminv1.AssistanceSession, error) {
	if r.headConnection == nil || r.headOneLabel == "" {
		return nil, errors.New("missing real head-one activation")
	}
	beforeSession, err := r.waitSession(ctx, scenario, 10*time.Second, "active before hot-unplug", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE))
	if err != nil {
		return nil, err
	}
	var before browserMedia
	if err := r.browser.call(ctx, "observe", nil, &before, 10*time.Second); err != nil {
		return nil, err
	}
	if before.MarkerHead != 1 || before.FramesDecoded == 0 {
		return nil, errors.New("hot-unplug target is not the selected live native head one")
	}
	boundary := &assistanceNativeBoundary{Boundary: "monitors-hot-unplug-no-fallback", HardwareEventAt: time.Now().UTC(), MediaBefore: &before}
	if err := r.headConnection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	packet := [24]byte{251, 0, 0, 0, 0, 0, 1, 0} // one zero-sized RFB screen
	written, err := r.headConnection.Write(packet[:])
	if err != nil {
		return nil, err
	}
	if written != len(packet) {
		return nil, io.ErrShortWrite
	}
	var observationErr error
	session, err := r.waitSession(ctx, scenario, 20*time.Second, "fail-closed selected-head removal", func(current *adminv1.AssistanceSession) bool {
		var media browserMedia
		observationErr = r.browser.call(ctx, "observe", nil, &media, 5*time.Second)
		if observationErr != nil {
			return true
		}
		if media.MarkerHead == 0 || current.GetSelectedDisplayId() != "" && current.GetSelectedDisplayId() != beforeSession.GetSelectedDisplayId() {
			observationErr = errors.New("removed selected monitor silently fell back to another granted head")
			return true
		}
		return ended(current)
	})
	if err != nil || observationErr != nil {
		return nil, errors.Join(err, observationErr)
	}
	if !acceptedAssistanceUnplugEnd(session.GetEndCause(), session.GetEndDetail()) {
		return nil, fmt.Errorf("hot-unplug ended with unrelated cause %s/%s", assistanceCauseText(session.GetEndCause()), session.GetEndDetail())
	}
	boundary.EndCause, boundary.EndDetail = assistanceCauseText(session.GetEndCause()), session.GetEndDetail()
	boundary.Guest, err = r.waitFixture(ctx, "native head-one removal", func(state *assistanceFixtureState) bool {
		return state.ActiveMonitors == 1 && slices.Contains(state.RemovedHeads, 1)
	})
	if err != nil {
		return nil, err
	}
	if err := waitAssistanceCaptureStopped(ctx, r.vm.guest); err != nil {
		return nil, err
	}
	settle, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	previous, stable := -1, 0
	for stable < 3 {
		var media browserMedia
		if err := r.browser.call(settle, "observe", nil, &media, 5*time.Second); err != nil {
			return nil, err
		}
		if media.MarkerHead == 0 {
			return nil, errors.New("other-head media arrived after selected-head removal")
		}
		if media.OpenInputChannels == 0 && media.FramesDecoded == previous {
			stable++
		} else {
			stable = 0
		}
		previous = media.FramesDecoded
		boundary.MediaAfter = &media
		select {
		case <-settle.Done():
			return nil, errors.New("media or input authority remained after hot-unplug")
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err := r.saveNativeBoundary(scenario, boundary); err != nil {
		return nil, err
	}
	return session, nil
}

func acceptedAssistanceUnplugEnd(cause agentv1.AssistanceEndCause, detail string) bool {
	switch cause {
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED:
		return detail == "portal_session_closed"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE:
		return detail == "capture_exited" || detail == "display_disappeared" || detail == "capture_switch_failed"
	default:
		return false
	}
}
