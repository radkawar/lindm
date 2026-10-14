// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
	"sync"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	actionAudioOutput    = "audio_output_"
	actionAudioNone      = "audio_none"
	actionMicrophone     = "microphone_share"
	actionMicrophoneNone = "microphone_none"
	actionAudioMute      = "audio_mute"
	actionAudioUnmute    = "audio_unmute"
	actionAudioStop      = "audio_stop"
	// opusFrameTicks is one 20 ms Opus frame at the 48 kHz RTP clock.
	opusFrameTicks = 960
	// maxOutputChoices leaves room for the "Don't share" action within the
	// three buttons desktops reliably show.
	maxOutputChoices = 2
)

// AudioSource is one PipeWire output or microphone the employee may select.
type AudioSource struct {
	Serial      uint64
	Description string
	Microphone  bool
}

// AudioDevices lists and captures the user's own audio sources. Nothing is
// captured without the employee's selection in this session.
type AudioDevices interface {
	Sources(ctx context.Context) ([]AudioSource, error)
	// Start encodes the selected sources as Opus RTP.
	Start(ctx context.Context, selected []AudioSource) (Capture, error)
}

func shortLabel(value string) string {
	if len(value) > 40 {
		return value[:37] + "..."
	}
	return value
}

// chooseAudio asks the employee, after Allow, which output's sound (if any)
// to share and, separately under ON, whether to share the microphone. The
// screen-sharing consent never implies either choice.
func (s *session) chooseAudio(ctx context.Context, r *sessionResources, policy *agentv1.AssistancePolicy) ([]AudioSource, agentv1.AssistancePolicyMode, string) {
	off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	if !policyEnabled(policy.GetAudio()) {
		return nil, off, "not_requested_or_allowed"
	}
	if s.deps.audio == nil || s.deps.audioUnavailableReason != "" {
		if s.deps.audioUnavailableReason != "" {
			return nil, off, s.deps.audioUnavailableReason
		}
		return nil, off, "audio_unavailable"
	}
	sources, err := s.deps.audio.Sources(ctx)
	if err != nil {
		s.logger.Warn("remote assistance audio sources unavailable", "err", err)
		var endErr *EndError
		if errors.As(err, &endErr) {
			return nil, off, endErr.Detail
		}
		return nil, off, "audio_unavailable"
	}
	var outputs, microphones []AudioSource
	for _, source := range sources {
		if source.Microphone {
			microphones = append(microphones, source)
		} else {
			outputs = append(outputs, source)
		}
	}
	operator := s.invitation.GetOperatorDisplay()
	if r.markup {
		operator = html.EscapeString(operator)
	}
	escape := func(value string) string {
		if r.markup {
			return html.EscapeString(value)
		}
		return value
	}
	var selected []AudioSource
	if len(outputs) > 0 {
		actions := make([]NotificationAction, 0, maxOutputChoices+1)
		for i, output := range outputs[:min(len(outputs), maxOutputChoices)] {
			actions = append(actions, NotificationAction{Key: actionAudioOutput + strconv.Itoa(i), Label: "Share " + escape(shortLabel(output.Description))})
		}
		actions = append(actions, NotificationAction{Key: actionAudioNone, Label: "Don't share sound"})
		body := fmt.Sprintf("%s may hear the sound of one output you choose. Your microphone is not shared by this choice. Support recordings never contain sound.", operator)
		action, err := s.ask(ctx, Notification{Summary: "Share sound with the operator?", Body: body, Actions: actions, Critical: true, Persistent: true})
		if err != nil {
			return nil, off, "audio_choice_unavailable"
		}
		if index, ok := strings.CutPrefix(action, actionAudioOutput); ok {
			if i, err := strconv.Atoi(index); err == nil && i >= 0 && i < min(len(outputs), maxOutputChoices) {
				selected = append(selected, outputs[i])
			}
		}
	}
	granted := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if policy.GetAudio() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && len(microphones) > 0 {
		microphone := microphones[0]
		body := fmt.Sprintf("Also let %s hear your microphone (%s)? This is separate from screen and sound sharing; you can mute or stop it at any time.", operator, escape(shortLabel(microphone.Description)))
		action, err := s.ask(ctx, Notification{Summary: "Share your microphone?", Body: body, Actions: []NotificationAction{{Key: actionMicrophone, Label: "Share microphone"}, {Key: actionMicrophoneNone, Label: "Don't share microphone"}}, Critical: true, Persistent: true})
		if err == nil && action == actionMicrophone {
			selected = append(selected, microphone)
			granted = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
		}
	}
	if len(selected) == 0 {
		return nil, off, "user_declined"
	}
	return selected, granted, ""
}

// ask posts a local choice and returns the employee's action.
func (s *session) ask(ctx context.Context, notification Notification) (string, error) {
	notice, err := s.deps.notifier.Notify(ctx, notification)
	if err != nil {
		return "", err
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.deps.callTimeout)
		defer cancel()
		s.logIfErr("close choice", notice.Close(closing))
	}()
	select {
	case action := <-notice.Result():
		return action, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// audioControl owns the selected sound sources. Mute stops capture entirely
// (nothing is captured while muted); Stop is final for the session.
type audioControl struct {
	session  *session
	devices  AudioDevices
	selected []AudioSource

	mu      sync.Mutex
	state   agentv1.AssistanceAudioState
	capture Capture
	notice  Notice
	// RTP continuity across capture restarts after unmute.
	seq     uint16
	ts      uint32
	offset  uint32
	fresh   bool
	written bool
}

func newAudioControl(s *session, devices AudioDevices, selected []AudioSource) *audioControl {
	state := agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED
	if len(selected) != 0 {
		state = agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING
	}
	a := &audioControl{session: s, devices: devices, selected: selected, state: state}
	a.publishLocked()
	return a
}

func (a *audioControl) publishLocked() {
	report := &agentv1.AssistanceAudioReport{State: a.state}
	if a.state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING || a.state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED {
		for _, source := range a.selected {
			if source.Microphone {
				report.MicrophoneSource = source.Description
			} else {
				report.OutputSource = source.Description
			}
		}
	}
	a.session.mu.Lock()
	a.session.audio = report
	a.session.mu.Unlock()
}

// start begins capture and shows the persistent local controls. Capture that
// cannot start stops sound sharing without ending the session.
func (a *audioControl) start(ctx context.Context, r *sessionResources) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING {
		return
	}
	if err := a.postNoticeLocked(ctx, r); err != nil {
		// Sound is never shared without its visible local controls.
		a.session.logIfErr("audio notice", err)
		a.stopLocked(ctx)
		return
	}
	if err := a.startCaptureLocked(ctx, r); err != nil {
		a.session.logIfErr("audio capture", err)
		a.stopLocked(ctx)
	}
}

func (a *audioControl) startCaptureLocked(ctx context.Context, r *sessionResources) error {
	capture, err := a.devices.Start(a.session.life, a.selected)
	if err != nil {
		return err
	}
	a.capture, a.fresh = capture, true
	go a.forward(r, capture)
	return nil
}

// forward rewrites sequence numbers and timestamps so a restarted capture
// continues the same RTP stream.
func (a *audioControl) forward(r *sessionResources, capture Capture) {
	buf := make([]byte, maxRTPPacket)
	for {
		n, err := capture.ReadPacket(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		if a.capture != capture || n < 12 {
			a.mu.Unlock()
			if a.capture != capture {
				return
			}
			continue
		}
		in := binary.BigEndian.Uint32(buf[4:8])
		if a.fresh {
			next := a.ts
			if a.written {
				next += opusFrameTicks
			}
			a.offset, a.fresh = next-in, false
		}
		a.ts = in + a.offset
		binary.BigEndian.PutUint16(buf[2:4], a.seq)
		binary.BigEndian.PutUint32(buf[4:8], a.ts)
		a.seq++
		a.written = true
		err = r.peer.WriteAudioRTP(buf[:n])
		a.mu.Unlock()
		if err != nil {
			a.session.logger.Debug("remote assistance audio write failed", "err", err)
		}
	}
}

func (a *audioControl) closeCaptureLocked() {
	if a.capture == nil {
		return
	}
	a.session.logIfErr("stop audio capture", a.capture.Close())
	a.capture = nil
}

func (a *audioControl) stopLocked(ctx context.Context) {
	a.closeCaptureLocked()
	if a.notice != nil {
		a.session.logIfErr("close audio notice", a.notice.Close(ctx))
		a.notice = nil
	}
	if a.state != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED {
		a.state = agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED
	}
	a.publishLocked()
}

func (a *audioControl) postNoticeLocked(ctx context.Context, r *sessionResources) error {
	operator := a.session.invitation.GetOperatorDisplay()
	var output, microphone string
	for _, source := range a.selected {
		if source.Microphone {
			microphone = source.Description
		} else {
			output = source.Description
		}
	}
	body := fmt.Sprintf("%s hears: ", operator)
	switch {
	case output != "" && microphone != "":
		body += fmt.Sprintf("sound of %s and your microphone (%s).", output, microphone)
	case microphone != "":
		body += fmt.Sprintf("your microphone (%s).", microphone)
	default:
		body += fmt.Sprintf("sound of %s. Your microphone is not shared.", output)
	}
	summary := "Sharing sound with the operator"
	toggle := NotificationAction{Key: actionAudioMute, Label: "Mute"}
	if a.state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED {
		summary = "Sound sharing muted"
		body = "Muted: nothing is captured or sent. " + body
		toggle = NotificationAction{Key: actionAudioUnmute, Label: "Unmute"}
	}
	if r.markup {
		body = html.EscapeString(body)
	}
	notice, err := a.session.postPrompt(ctx, r, Notification{Summary: summary, Body: body, Actions: []NotificationAction{toggle, {Key: actionAudioStop, Label: "Stop sound sharing"}}})
	if err != nil {
		return err
	}
	a.notice = notice
	go a.watch(r, notice)
	return nil
}

// watch applies the employee's local Mute, Unmute and Stop.
func (a *audioControl) watch(r *sessionResources, notice Notice) {
	life := a.session.life
	var action string
	select {
	case action = <-notice.Result():
	case <-life.Done():
		return
	}
	ctx, cancel := context.WithTimeout(life, a.session.deps.callTimeout)
	defer cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.notice != notice {
		return
	}
	a.notice = nil
	if action == actionStop {
		// The prompt's Stop ended the session.
		return
	}
	switch {
	case action == actionAudioStop:
		a.stopLocked(ctx)
		return
	case action == actionAudioMute && a.state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING:
		a.closeCaptureLocked()
		a.state = agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED
	case action == actionAudioUnmute && a.state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED:
		a.state = agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING
		if err := a.startCaptureLocked(ctx, r); err != nil {
			a.session.logIfErr("audio capture", err)
			a.stopLocked(ctx)
			return
		}
	}
	a.publishLocked()
	if err := a.postNoticeLocked(ctx, r); err != nil {
		a.session.logIfErr("audio notice", err)
		a.stopLocked(ctx)
	}
}

// close stops capture at session end.
func (a *audioControl) close(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopLocked(ctx)
}
