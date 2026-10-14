// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"sync"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Overlay bounds (docs/architecture.md §9, Tier 3 pointer and annotation).
const (
	annotationQueueSize  = 32
	maxAnnotationMessage = 4096
	maxAnnotationRate    = 60
	maxAnnotationStrokes = 16
	maxStrokePoints      = 64
	pointerLifetime      = 3 * time.Second
	strokeLifetime       = 30 * time.Second
	annotationTick       = 250 * time.Millisecond

	actionAnnotationClear = "annotation_clear"
	actionAnnotationHide  = "annotation_hide"
)

var errAnnotationInvalid = errors.New("annotation_invalid")

// Overlay is a compositor's non-interactive per-user overlay. It never
// receives input, draws only inside the shared monitor rectangle and never
// covers system modal dialogs or the lock screen.
type Overlay interface {
	// Check reports whether this desktop session has a qualified overlay.
	Check(ctx context.Context) error
	// Draw replaces the whole overlay with frame.
	Draw(ctx context.Context, frame OverlayFrame) error
	// Clear removes everything the overlay shows.
	Clear(ctx context.Context) error
	// Release gives up the overlay at session end.
	Release(ctx context.Context) error
}

// OverlayPoint is normalized to the shared monitor: 0..1 on both axes.
type OverlayPoint struct{ X, Y float64 }

// OverlayFrame is the complete overlay state for one shared monitor.
type OverlayFrame struct {
	X, Y, Width, Height int
	Pointer             *OverlayPoint
	Strokes             [][]OverlayPoint
}

// annotationMessage is one operator frame from the "lindm-annotate" channel.
type annotationMessage struct {
	Type       string       `json:"t"`
	Display    string       `json:"d"`
	Generation uint32       `json:"g"`
	X          float64      `json:"x"`
	Y          float64      `json:"y"`
	ID         uint32       `json:"id"`
	Points     [][2]float64 `json:"p"`
}

// parseAnnotation accepts only bounded, finite, normalized frames. Clicks,
// keys and any other event type are not part of this channel's vocabulary.
func parseAnnotation(raw []byte, mode agentv1.AssistancePolicyMode) (annotationMessage, error) {
	var message annotationMessage
	if len(raw) == 0 || len(raw) > maxAnnotationMessage || json.Unmarshal(raw, &message) != nil {
		return message, errAnnotationInvalid
	}
	normalized := func(v float64) bool { return !math.IsNaN(v) && v >= 0 && v <= 1 }
	switch message.Type {
	case "p":
		if message.Display == "" || message.Generation == 0 || !normalized(message.X) || !normalized(message.Y) || message.ID != 0 || len(message.Points) != 0 {
			return message, errAnnotationInvalid
		}
	case "s":
		if mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON || message.Display == "" || message.Generation == 0 || message.ID == 0 || len(message.Points) < 2 || len(message.Points) > maxStrokePoints {
			return message, errAnnotationInvalid
		}
		for _, point := range message.Points {
			if !normalized(point[0]) || !normalized(point[1]) {
				return message, errAnnotationInvalid
			}
		}
	case "c":
		if message.Display != "" || message.ID != 0 || len(message.Points) != 0 {
			return message, errAnnotationInvalid
		}
	default:
		return message, errAnnotationInvalid
	}
	return message, nil
}

type overlayStroke struct {
	id     uint32
	points []OverlayPoint
	at     time.Time
}

// annotationControl owns the overlay state. The operator enables it by an
// audited command; the employee's Hide is final for the session and Clear
// removes every mark. Annotation never grants or implies input.
type annotationControl struct {
	session *session
	overlay Overlay
	mode    agentv1.AssistancePolicyMode

	mu        sync.Mutex
	enabled   bool
	hidden    bool
	clears    uint32
	pointer   *OverlayPoint
	pointerAt time.Time
	strokes   []overlayStroke
	display   string
	gen       uint32
	drawn     bool
	notice    Notice
	window    []time.Time
}

func newAnnotationControl(s *session, overlay Overlay, mode agentv1.AssistancePolicyMode) *annotationControl {
	return &annotationControl{session: s, overlay: overlay, mode: mode}
}

// publish copies the content-free state into the session report.
func (a *annotationControl) publish() {
	report := &agentv1.AssistanceAnnotationReport{Enabled: a.enabled, Hidden: a.hidden, Clears: a.clears}
	a.session.mu.Lock()
	a.session.annotation = report
	a.session.mu.Unlock()
}

// setEnabled applies the operator's audited enable/disable command.
func (a *annotationControl) setEnabled(ctx context.Context, r *sessionResources, enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hidden && enabled {
		return errors.New("annotation_hidden_locally")
	}
	if a.enabled == enabled {
		return nil
	}
	a.enabled = enabled
	a.pointer, a.strokes = nil, nil
	defer a.publish()
	if !enabled {
		return errors.Join(a.closeNoticeLocked(ctx), a.clearLocked(ctx))
	}
	return a.postNoticeLocked(ctx, r)
}

func (a *annotationControl) postNoticeLocked(ctx context.Context, r *sessionResources) error {
	operator := a.session.invitation.GetOperatorDisplay()
	if r.markup {
		operator = html.EscapeString(operator)
	}
	body := fmt.Sprintf("%s can show a pointer on your shared screen. It cannot click or type.", operator)
	actions := []NotificationAction{{Key: actionAnnotationHide, Label: "Hide for this session"}}
	if a.mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		body = fmt.Sprintf("%s can show a pointer and draw short-lived marks on your shared screen. They cannot click or type.", operator)
		actions = append([]NotificationAction{{Key: actionAnnotationClear, Label: "Clear marks"}}, actions...)
	}
	notice, err := a.session.postPrompt(ctx, r, Notification{Summary: "Support pointer on your screen", Body: body, Actions: actions})
	if err != nil {
		return err
	}
	a.notice = notice
	go a.watchNotice(r, notice)
	return nil
}

func (a *annotationControl) closeNoticeLocked(ctx context.Context) error {
	if a.notice == nil {
		return nil
	}
	notice := a.notice
	a.notice = nil
	return notice.Close(ctx)
}

// watchNotice applies the employee's local Clear and Hide. A dismissed
// notice is posted again while the overlay is enabled, so its controls stay
// reachable.
func (a *annotationControl) watchNotice(r *sessionResources, notice Notice) {
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
	switch action {
	case actionAnnotationHide:
		a.hidden, a.enabled = true, false
		a.pointer, a.strokes = nil, nil
		a.clears++
		a.session.logIfErr("hide overlay", a.clearLocked(ctx))
		a.publish()
		return
	case actionAnnotationClear:
		a.strokes, a.pointer = nil, nil
		a.clears++
		a.session.logIfErr("clear overlay", a.clearLocked(ctx))
		a.publish()
	}
	if a.enabled {
		if err := a.postNoticeLocked(ctx, r); err != nil {
			// Without its local controls the overlay is not shown.
			a.enabled = false
			a.session.logIfErr("annotation notice", errors.Join(err, a.clearLocked(ctx)))
			a.publish()
		}
	}
}

func (a *annotationControl) clearLocked(ctx context.Context) error {
	if !a.drawn {
		return nil
	}
	a.drawn = false
	return a.overlay.Clear(ctx)
}

// apply admits one operator frame for the currently shared display only.
func (a *annotationControl) apply(ctx context.Context, message annotationMessage, now time.Time, display string, generation uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled || a.hidden {
		return errAnnotationInvalid
	}
	window := a.window[:0]
	for _, at := range a.window {
		if now.Sub(at) < time.Second {
			window = append(window, at)
		}
	}
	a.window = window
	if len(a.window) >= maxAnnotationRate {
		return errAnnotationInvalid
	}
	a.window = append(a.window, now)
	if message.Type != "c" && (message.Display != display || message.Generation != generation) {
		// A frame for another or an older monitor selection never reaches
		// an unshared display.
		return errAnnotationInvalid
	}
	if a.display != display || a.gen != generation {
		a.display, a.gen, a.pointer, a.strokes = display, generation, nil, nil
	}
	switch message.Type {
	case "p":
		a.pointer, a.pointerAt = &OverlayPoint{X: message.X, Y: message.Y}, now
	case "s":
		points := make([]OverlayPoint, len(message.Points))
		for i, point := range message.Points {
			points[i] = OverlayPoint{X: point[0], Y: point[1]}
		}
		replaced := false
		for i := range a.strokes {
			if a.strokes[i].id == message.ID {
				a.strokes[i].points, a.strokes[i].at, replaced = points, now, true
			}
		}
		if !replaced {
			if len(a.strokes) == maxAnnotationStrokes {
				a.strokes = a.strokes[1:]
			}
			a.strokes = append(a.strokes, overlayStroke{id: message.ID, points: points, at: now})
		}
	case "c":
		a.strokes = nil
	}
	return nil
}

// render expires ephemeral marks and draws the current frame on stream.
func (a *annotationControl) render(ctx context.Context, now time.Time, stream Stream) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pointer != nil && now.Sub(a.pointerAt) >= pointerLifetime {
		a.pointer = nil
	}
	strokes := a.strokes[:0]
	for _, stroke := range a.strokes {
		if now.Sub(stroke.at) < strokeLifetime {
			strokes = append(strokes, stroke)
		}
	}
	a.strokes = strokes
	if !a.enabled || a.hidden || (a.pointer == nil && len(a.strokes) == 0) {
		return a.clearLocked(ctx)
	}
	frame := OverlayFrame{X: stream.X, Y: stream.Y, Width: stream.Width, Height: stream.Height, Pointer: a.pointer}
	for _, stroke := range a.strokes {
		frame.Strokes = append(frame.Strokes, stroke.points)
	}
	a.drawn = true
	return a.overlay.Draw(ctx, frame)
}

// close removes the overlay and its notice at session end.
func (a *annotationControl) close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = false
	return errors.Join(a.closeNoticeLocked(ctx), a.clearLocked(ctx), a.overlay.Release(ctx))
}

// annotationLoop renders operator frames for the currently selected display
// until the session ends. Invalid or excess frames are dropped.
func (s *session) annotationLoop(ctx context.Context, r *sessionResources, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(annotationTick)
	defer ticker.Stop()
	messages := r.peer.Annotations()
	dirty := false
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-messages:
			if !ok {
				messages = nil
				continue
			}
			message, err := parseAnnotation(raw, r.annotation.mode)
			if err != nil {
				continue
			}
			display, generation := s.currentDisplay()
			if r.annotation.apply(ctx, message, s.deps.clock(), display, generation) == nil {
				dirty = true
			}
		case <-ticker.C:
			dirty = true
		}
		if !dirty {
			continue
		}
		dirty = false
		stream, ok := s.selectedStream(r)
		if !ok {
			continue
		}
		draw, cancel := context.WithTimeout(ctx, s.deps.callTimeout)
		err := r.annotation.render(draw, s.deps.clock(), stream)
		cancel()
		if err != nil && ctx.Err() == nil {
			s.logger.Warn("remote assistance overlay draw failed", "err", err)
		}
	}
}

func (s *session) currentDisplay() (string, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selected, s.generation
}

func (s *session) selectedStream(r *sessionResources) (Stream, bool) {
	display, _ := s.currentDisplay()
	for _, stream := range r.grant.Streams() {
		if stream.ID == display {
			return stream, true
		}
	}
	return Stream{}, false
}
