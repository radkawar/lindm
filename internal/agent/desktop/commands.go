package desktop

import (
	"context"
	"crypto/sha256"
	"errors"
	"html"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const maxSessionCommands = 256

func cloneDisplays(displays []*agentv1.AssistanceDisplay) []*agentv1.AssistanceDisplay {
	out := make([]*agentv1.AssistanceDisplay, len(displays))
	for i, display := range displays {
		out[i] = proto.CloneOf(display)
	}
	return out
}

func (s *session) renewAuthority(directive *agentv1.AssistanceDirective) {
	if s.deps == nil {
		return
	}
	until := directive.GetAuthorizedUntil().AsTime()
	now := s.deps.clock()
	if !until.After(now) || until.After(now.Add(30*time.Second)) {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "operator_authority_expired")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	s.authorizedUntil = until
	if s.authority != nil {
		s.authority.Stop()
	}
	s.authority = time.AfterFunc(until.Sub(now), func() {
		s.mu.Lock()
		expired := !s.deps.clock().Before(s.authorizedUntil)
		s.mu.Unlock()
		if expired {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "operator_authority_expired")
		}
	})
}

// applyCommand holds only one text-bearing command/result. Digests of prior
// identities are session-local and bounded; an old identity never repeats an
// effect after its result has been replaced. No content is logged or persisted.
func (s *session) applyCommand(command *agentv1.AssistanceCommand) {
	if s.deps == nil || s.deps.validator.Validate(command) != nil {
		return
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return
	}
	digest := sha256.Sum256(encoded)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		return
	}
	if prior, ok := s.commandHistory[command.GetRequestId()]; ok {
		if prior != digest {
			s.commandResult = commandResult(command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED, "command_identity_conflict", s.deps.clock())
		} else if s.command == nil || command.GetRequestId() != s.command.GetRequestId() {
			s.commandResult = commandResult(command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED, "command_result_expired", s.deps.clock())
		}
		return
	}
	if s.commandBusy {
		return
	}
	if len(s.commandHistory) >= maxSessionCommands {
		s.commandResult = commandResult(command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED, "session_command_limit", s.deps.clock())
		return
	}
	s.commandHistory[command.GetRequestId()] = digest
	s.command, s.commandResult, s.commandBusy = proto.CloneOf(command), nil, true
	s.commands <- s.command
}

func commandResult(command *agentv1.AssistanceCommand, status agentv1.AssistanceCommandStatus, reason string, now time.Time) *agentv1.AssistanceCommandResult {
	return &agentv1.AssistanceCommandResult{RequestId: command.GetRequestId(), Kind: command.GetKind(), Status: status, Reason: reason, CompletedAt: timestamppb.New(now)}
}

func (s *session) commandLoop(ctx context.Context, r *sessionResources) {
	defer close(r.commandDone)
	var expiry *time.Timer
	var expiryC <-chan time.Time
	defer func() {
		if expiry != nil {
			expiry.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiryC:
			expiryC = nil
			s.mu.Lock()
			expireClipboardResult(s.commandResult, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "content_expired")
			s.mu.Unlock()
		case command := <-s.commands:
			if expiry != nil {
				expiry.Stop()
				expiryC = nil
			}
			result := s.executeCommand(ctx, r, command)
			retainClipboard, incompleteSwitch := s.publishCommand(command, result, r.input)
			if incompleteSwitch {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_switch_cancelled")
			}
			if retainClipboard {
				delay := max(0, command.GetDeadline().AsTime().Sub(s.deps.clock()))
				if expiry == nil {
					expiry = time.NewTimer(delay)
				} else {
					expiry.Reset(delay)
				}
				expiryC = expiry.C
			}
		}
	}
}

// publishCommand exposes a new selected monitor and its successful completion
// in one report snapshot. Native capture/input changes are private until then.
func (s *session) publishCommand(command *agentv1.AssistanceCommand, result *agentv1.AssistanceCommandResult, input *inputControl) (retainClipboard, incompleteSwitch bool) {
	input.mu.Lock()
	defer input.mu.Unlock()
	display, generation := input.display, input.generation
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		expireClipboardResult(result, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "session_ended")
	}
	if command.GetKind() == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY {
		if result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED && s.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			s.selected, s.generation = display, generation
			input.paused = false
		} else {
			incompleteSwitch = input.paused || display != s.selected || generation != s.generation
		}
	}
	s.commandResult, s.commandBusy = result, false
	// Outbound text is no longer needed after the effect returns.
	s.command = &agentv1.AssistanceCommand{RequestId: command.GetRequestId(), Kind: command.GetKind(), Deadline: command.GetDeadline()}
	retainClipboard = result.GetKind() == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ && result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED
	return retainClipboard, incompleteSwitch
}

func expireClipboardResult(result *agentv1.AssistanceCommandResult, status agentv1.AssistanceCommandStatus, reason string) {
	if result != nil && result.GetKind() == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ && result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		result.Text, result.Status, result.Reason = "", status, reason
	}
}

func (s *session) executeCommand(parent context.Context, r *sessionResources, command *agentv1.AssistanceCommand) *agentv1.AssistanceCommandResult {
	now := s.deps.clock()
	deadline := command.GetDeadline().AsTime()
	result := commandResult(command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED, "command_not_granted", now)
	if !deadline.After(now) || deadline.After(now.Add(30*time.Second)) || deadline.After(s.invitation.GetEndsAt().AsTime()) {
		result.Status, result.Reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "command_deadline_reached"
		return result
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	if ctx.Err() != nil {
		result.Status, result.Reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "session_ended"
		return result
	}
	policy := s.granted.GetPolicy()
	var err error
	switch command.GetKind() {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
		if !policyEnabled(policy.GetClipboard()) {
			return result
		}
		err = r.grant.ClipboardWrite(ctx, command.GetText(), deadline)
		result.Reason = "clipboard_selection_set"
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		if policy.GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
			return result
		}
		result.Text, err = r.grant.ClipboardRead(ctx)
		if err != nil {
			reason, category := clipboardReadDiagnostic(err)
			s.logger.Warn("remote assistance clipboard read failed", "reason", reason, "category", category)
		}
		result.Reason = "clipboard_text_read"
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
		if !s.control || policy.GetKeyboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
			return result
		}
		err = r.input.special(ctx, command.GetSpecialKey())
		if err != nil {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "input_injection_failed")
		}
		result.Reason = "special_keys_sent"
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
		if policy.GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
			return result
		}
		err = s.selectDisplay(parent, ctx, r, command.GetDisplayId())
		result.Reason = "display_selected"
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE:
		if !policyEnabled(policy.GetMessages()) {
			return result
		}
		err = s.operatorMessage(ctx, r, command.GetText(), policy.GetMessages())
		result.Reason = "message_posted"
	default:
		result.Reason = "command_unsupported"
		return result
	}
	result.CompletedAt = timestamppb.New(s.deps.clock())
	if err == nil && ctx.Err() == nil {
		result.Status = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED
		return result
	}
	result.Text = ""
	result.Reason = "command_failed"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status, result.Reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "command_deadline_reached"
	} else if ctx.Err() != nil {
		result.Status, result.Reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "session_ended"
	}
	return result
}

// operatorMessage shows text with its authenticated sender. While the critical
// in-progress notice is on screen, GNOME shows no other banner until the
// employee dismisses it (fedora44-tier1-14: a separate message notification
// never appeared), so the message replaces that notice's content in place,
// keeping its Stop action. Without a live notice it is its own notification.
func (s *session) operatorMessage(ctx context.Context, r *sessionResources, text string, mode agentv1.AssistancePolicyMode) error {
	now := s.deps.clock()
	if now.Before(r.lastMessage.Add(2 * time.Second)) {
		return errors.New("message_rate_limited")
	}
	outstanding := now.Before(r.messageUntil)
	if r.message != nil {
		select {
		case <-r.message.Result():
			outstanding = false
		default:
		}
	}
	if outstanding && mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED {
		return errors.New("message_outstanding")
	}
	if r.message != nil {
		if err := r.message.Close(ctx); err != nil {
			return err
		}
		r.message = nil
	}
	body := s.invitation.GetOperatorDisplay() + ":\n" + text
	if r.markup {
		body = html.EscapeString(body)
	}
	r.indicatorMu.Lock()
	defer r.indicatorMu.Unlock()
	if r.indicator != nil {
		notice := s.indicatorNotification(r.markup)
		notice.Body += "\n\nMessage from your support operator\n" + body
		if err := r.indicator.Update(ctx, notice); err != nil {
			return err
		}
		r.lastMessage, r.messageUntil = now, now.Add(30*time.Second)
		return nil
	}
	notice, err := s.deps.notifier.Notify(ctx, Notification{Summary: "Message from your support operator", Body: body, Actions: []NotificationAction{{Key: "dismiss", Label: "Dismiss"}}, Lifetime: 30 * time.Second})
	if err != nil {
		return err
	}
	r.message, r.lastMessage, r.messageUntil = notice, now, now.Add(30*time.Second)
	return nil
}

func (s *session) startCapture(life, wait context.Context, r *sessionResources, stream Stream) error {
	r.input.mu.Lock()
	display, generation := r.input.display, r.input.generation
	r.input.mu.Unlock()
	if err := r.peer.BeginDisplay(display, generation); err != nil {
		return err
	}
	pipeWire, err := r.grant.OpenPipeWire(wait)
	if err != nil {
		return unavailable("pipewire_unavailable", err)
	}
	captureCtx, cancel := context.WithCancel(life)
	capture, err := s.deps.capturer.Start(captureCtx, CaptureRequest{PipeWire: pipeWire, Stream: stream})
	closeErr := pipeWire.Close()
	if err != nil {
		cancel()
		return unavailable("capture_start_failed", errors.Join(err, closeErr))
	}
	r.capture, r.captureCancel = capture, cancel
	if closeErr != nil {
		return unavailable("pipewire_close_failed", closeErr)
	}
	first := make(chan struct{})
	r.forwardDone = make(chan struct{})
	go s.forwardMedia(captureCtx, r, capture, display, generation, first, r.forwardDone)
	timer := time.NewTimer(s.deps.firstPacketTimeout)
	defer timer.Stop()
	select {
	case <-first:
		return nil
	case <-r.forwardDone:
		return unavailable("capture_exited", nil)
	case <-timer.C:
		return unavailable("capture_no_frames", nil)
	case <-wait.Done():
		return wait.Err()
	}
}

func (s *session) selectDisplay(life, ctx context.Context, r *sessionResources, id string) error {
	var selected Stream
	for _, stream := range r.grant.Streams() {
		if stream.ID == id {
			selected = stream
			break
		}
	}
	if selected.ID == "" {
		return errors.New("display_not_granted")
	}
	releases, generation, err := r.input.beginSwitch(id)
	if err != nil || generation == 0 {
		return err
	}
	s.mu.Lock()
	s.frame = DisplayFrame{}
	s.mu.Unlock()
	// Revoke the old marker before teardown. Late packets from the old capture
	// may still be emitted, but cannot publish a marker for the new source.
	if err := r.peer.BeginDisplay(id, generation); err != nil {
		return err
	}
	var releaseErrors []error
	for _, event := range releases {
		if err := r.grant.Inject(ctx, event); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	if err := errors.Join(releaseErrors...); err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "input_release_failed")
		return err
	}
	r.captureCancel()
	if err := r.capture.Close(); err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_switch_failed")
		return err
	}
	<-r.forwardDone
	r.capture, r.forwardDone = nil, nil
	if err := ctx.Err(); err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_switch_cancelled")
		return err
	}
	if err := r.grant.SelectStream(id); err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "display_disappeared")
		return err
	}
	if err := s.startCapture(life, ctx, r, selected); err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_switch_failed")
		return err
	}
	// publishCommand resumes input together with the final selection/result.
	return nil
}
