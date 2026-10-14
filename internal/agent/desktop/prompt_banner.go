// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"sync"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// GNOME shows one banner at a time, and the critical in-progress indicator
// stays the shown banner until the employee acts on it, so every later
// critical notice of the session waits behind it unseen (layers-fedora44-
// files-03: the incoming file consent never appeared). An in-session local
// notice therefore takes the indicator's place: while one is posted the
// indicator is withdrawn, the notice carries the indicator's disclosure (who
// is viewing or controlling, recording) and its Stop action, and the moment
// the last such notice resolves, is closed, or fails to post, the indicator
// is posted again. A second in-session notice still waits behind the first.

// maxPromptActions is the most actions a banner shows, Stop included.
const maxPromptActions = 3

var errPromptActions = errors.New("in-session notice has too many actions for its Stop")

// promptNotice is an in-session notice holding the indicator's banner slot.
type promptNotice struct {
	inner   Notice
	result  chan string
	closed  chan struct{}
	once    sync.Once
	release func()
}

func (p *promptNotice) Result() <-chan string { return p.result }

func (p *promptNotice) Update(ctx context.Context, notification Notification) error {
	return p.inner.Update(ctx, notification)
}

// Close withdraws the notice and gives the banner back to the indicator.
func (p *promptNotice) Close(ctx context.Context) error {
	p.once.Do(func() { close(p.closed) })
	err := p.inner.Close(ctx)
	p.release()
	return err
}

// inSessionNotification adds the indicator's disclosure and Stop, last, to an
// in-session notice's own actions.
func (s *session) inSessionNotification(r *sessionResources, notification Notification) (Notification, error) {
	if len(notification.Actions)+1 > maxPromptActions {
		return Notification{}, errPromptActions
	}
	indicator := s.indicatorNotification(r.markup, r.recorder)
	notification.Body += "\n\n" + indicator.Body
	notification.Actions = append(append([]NotificationAction(nil), notification.Actions...), NotificationAction{Key: actionStop, Label: "Stop"})
	notification.Critical, notification.Persistent = true, true
	return notification, nil
}

// postPrompt withdraws the indicator, then posts notification with the
// indicator's disclosure and Stop. Stop ends the session USER_STOPPED; any
// result, Close, a failed post or the session ending gives the banner back.
func (s *session) postPrompt(ctx context.Context, r *sessionResources, notification Notification) (Notice, error) {
	notification, err := s.inSessionNotification(r, notification)
	if err != nil {
		return nil, err
	}
	release := s.holdBanner(ctx, r)
	inner, err := s.deps.notifier.Notify(ctx, notification)
	if err != nil {
		release()
		return nil, err
	}
	p := &promptNotice{inner: inner, result: make(chan string, 1), closed: make(chan struct{}), release: release}
	go func() {
		select {
		case action := <-inner.Result():
			if action == actionStop {
				// End first, so the release reposts nothing for the ended session.
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, "local_stop")
			}
			p.release()
			p.result <- action
		case <-p.closed:
		case <-s.life.Done():
			p.release()
		}
	}()
	return p, nil
}

// holdBanner withdraws the indicator for one in-session notice and returns
// its idempotent release, which posts the indicator again once no notice
// holds the banner.
func (s *session) holdBanner(ctx context.Context, r *sessionResources) func() {
	r.indicatorMu.Lock()
	r.prompts++
	withdrawn := r.indicator
	if withdrawn != nil {
		r.indicator, r.indicatorWithdrawn = nil, true
	}
	r.indicatorMu.Unlock()
	if withdrawn != nil {
		s.logIfErr("withdraw indicator for a local notice", withdrawn.Close(ctx))
		r.signalIndicator()
	}
	var once sync.Once
	return func() { once.Do(func() { s.releaseBanner(r) }) }
}

func (s *session) releaseBanner(r *sessionResources) {
	r.indicatorMu.Lock()
	r.prompts--
	if r.prompts > 0 || !r.indicatorWithdrawn || r.indicatorClosed || s.life.Err() != nil {
		r.indicatorMu.Unlock()
		return
	}
	r.indicatorWithdrawn = false
	ctx, cancel := context.WithTimeout(s.life, s.deps.callTimeout)
	indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup, r.recorder))
	cancel()
	if err == nil {
		r.indicator = indicator
	}
	r.indicatorMu.Unlock()
	if err != nil {
		if r.recorder != nil && r.recorder.recording() {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_indicator_failed")
		} else {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "indicator_failed")
		}
		return
	}
	r.signalIndicator()
}

// showIndicator posts the in-progress indicator unless an in-session notice
// holds the banner, in which case the notice's release posts it.
func (s *session) showIndicator(ctx context.Context, r *sessionResources) error {
	r.indicatorMu.Lock()
	defer r.indicatorMu.Unlock()
	if r.prompts > 0 {
		r.indicatorWithdrawn = true
		return nil
	}
	indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup, r.recorder))
	if err != nil {
		return err
	}
	r.indicator = indicator
	return nil
}

// currentIndicator is the posted indicator, or nil while it is withdrawn.
func (r *sessionResources) currentIndicator() Notice {
	r.indicatorMu.Lock()
	defer r.indicatorMu.Unlock()
	return r.indicator
}

func (r *sessionResources) signalIndicator() {
	select {
	case r.indicatorChanged <- struct{}{}:
	default:
	}
}
