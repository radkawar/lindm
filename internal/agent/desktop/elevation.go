// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	actionElevationPause  = "elevation_pause"
	actionElevationResume = "elevation_resume"
)

var errElevationPaused = errors.New("local_elevation_pause")

// Elevation guidance (docs/architecture.md §9, Tier 3). Neither GNOME nor
// polkit tells an unprivileged client that a protected credential prompt is
// open, so lindm never claims automatic detection: the pause starts before
// the privileged action, from the operator's guidance request or the
// employee's own Pause action, and only the employee's local Resume ends it.
// Pressed keys and buttons are released and queued input is discarded
// before the guidance appears; pointer, buttons, scroll, keysyms, keycodes,
// special keys and clipboard all stay refused while paused. lindm never
// supplies, stores or relays a credential.

func (s *session) elevationPaused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inputState.GetPaused() && s.inputState.GetPause() == agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION
}

// beginElevation pauses all remote injection and shows the local guidance.
// The caller holds r.modalMu. The pause outlives this call until Resume.
func (s *session) beginElevation(ctx context.Context, r *sessionResources, guidance string) error {
	if !policyEnabled(s.granted.GetPolicy().GetElevation()) {
		return errors.New("elevation_not_granted")
	}
	r.input.mu.Lock()
	paused := r.input.paused
	r.input.mu.Unlock()
	if paused {
		return errElevationPaused
	}
	// Nothing the operator sent earlier, queued or already dequeued, can land
	// on the prompt.
	epoch, err := pauseRemoteInput(ctx, r, s.deps.callTimeout)
	s.mu.Lock()
	if epoch != 0 {
		s.inputState = &agentv1.AssistanceInputState{Epoch: epoch, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}
	}
	expireClipboardResult(s.commandResult, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "local_elevation_pause")
	s.mu.Unlock()
	if err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "input_pause_failed")
		return err
	}
	pause, cancel := context.WithTimeout(ctx, s.deps.callTimeout)
	err = r.grant.PauseClipboard(pause)
	cancel()
	if err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "clipboard_pause_failed")
		return err
	}
	notice, err := s.postPrompt(ctx, r, s.elevationNotification(r.markup, guidance))
	if err != nil {
		// Input stays paused: a pause never resumes without the employee.
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "elevation_guidance_failed")
		return err
	}
	go s.awaitElevationResume(r, notice, guidance)
	return nil
}

// pauseRemoteInput pauses native injection first, under the input lock that
// every injection holds, so a frame the pump already took from the peer queue
// can no longer be injected; it bumps the epoch and releases held presses.
// Only then does the peer advance to that epoch and discard queued frames.
// A non-zero epoch means local input is paused even if an error follows.
func pauseRemoteInput(ctx context.Context, r *sessionResources, timeout time.Duration) (uint32, error) {
	pause, cancel := context.WithTimeout(ctx, timeout)
	epoch, err := r.input.pauseModal(pause)
	cancel()
	if epoch == 0 {
		return 0, err
	}
	return epoch, errors.Join(err, r.peer.SetInputState(epoch, true))
}

func (s *session) elevationNotification(markup bool, guidance string) Notification {
	operator := s.invitation.GetOperatorDisplay()
	guidance = strings.TrimSpace(guidance)
	if markup {
		operator, guidance = html.EscapeString(operator), html.EscapeString(guidance)
	}
	body := fmt.Sprintf("Remote pointer, keyboard, shortcuts and clipboard are paused. Enter any password or administrator approval yourself; %s cannot type or click and lindm never receives it.", operator)
	if guidance != "" {
		body = fmt.Sprintf("Note from %s: %s\n", operator, guidance) + body
	}
	body += "\nChoose Resume remote control when you have finished."
	return Notification{
		Summary:    "Remote control paused for your password",
		Body:       body,
		Actions:    []NotificationAction{{Key: actionElevationResume, Label: "Resume remote control"}},
		Critical:   true,
		Persistent: true,
	}
}

// awaitElevationResume keeps the guidance visible until the employee chooses
// Resume. Dismissing it re-posts it; the session ending leaves input paused.
func (s *session) awaitElevationResume(r *sessionResources, notice Notice, guidance string) {
	life := s.life
	for {
		var action string
		select {
		case action = <-notice.Result():
		case <-life.Done():
			closing, cancel := context.WithTimeout(context.WithoutCancel(life), s.deps.callTimeout)
			s.logIfErr("close elevation guidance", notice.Close(closing))
			cancel()
			return
		}
		if action == actionStop {
			// The guidance's Stop ended the session.
			return
		}
		if action == actionElevationResume {
			if err := s.resumeElevation(r); err != nil && life.Err() == nil {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "elevation_resume_failed")
			}
			return
		}
		timer := time.NewTimer(s.deps.repostInterval)
		select {
		case <-timer.C:
		case <-life.Done():
			timer.Stop()
			return
		}
		post, cancel := context.WithTimeout(life, s.deps.callTimeout)
		next, err := s.postPrompt(post, r, s.elevationNotification(r.markup, guidance))
		cancel()
		if err != nil {
			if life.Err() == nil {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "elevation_guidance_failed")
			}
			return
		}
		notice = next
	}
}

// resumeElevation is the only path out of an elevation pause: a new input
// epoch that never accepts input generated before the pause.
func (s *session) resumeElevation(r *sessionResources) error {
	r.modalMu.Lock()
	defer r.modalMu.Unlock()
	r.input.mu.Lock()
	defer r.input.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return nil
	}
	if !r.input.paused || r.input.epoch == ^uint32(0) || s.inputState.GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION {
		return errors.New("input_epoch_exhausted_or_not_paused")
	}
	if err := r.grant.ResumeClipboard(); err != nil {
		return err
	}
	r.input.epoch++
	if err := r.peer.SetInputState(r.input.epoch, false); err != nil {
		return err
	}
	r.input.paused = false
	s.inputState = &agentv1.AssistanceInputState{Epoch: r.input.epoch}
	s.logger.Info("remote assistance elevation pause resumed locally")
	return nil
}

// localElevation runs the employee's own Pause action from the indicator.
func (s *session) localElevation(ctx context.Context, r *sessionResources) {
	r.modalMu.Lock()
	defer r.modalMu.Unlock()
	if err := s.beginElevation(ctx, r, ""); err != nil && !errors.Is(err, errElevationPaused) {
		s.logger.Warn("remote assistance local elevation pause failed", "err", err)
	}
}
