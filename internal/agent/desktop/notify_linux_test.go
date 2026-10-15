// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// bufferedNotice is a tracked consent notice whose dispatcher already
// forwarded the given ActionInvoked and NotificationClosed signals, in bus
// order, before wait runs; its watches are not registered, so wait's cleanup
// makes no bus call.
func bufferedNotice(id uint32, actions, closes []*dbus.Signal) *desktopNotice {
	bus := &SessionBus{done: make(chan struct{}), watches: map[*busWatch]struct{}{}}
	notice := &desktopNotice{bus: bus, id: id, result: make(chan string, 1), stop: make(chan struct{}), done: make(chan struct{}),
		actions: &busWatch{bus: bus, signals: make(chan *dbus.Signal, watchBuffer)},
		closed:  &busWatch{bus: bus, signals: make(chan *dbus.Signal, watchBuffer)},
	}
	for _, signal := range actions {
		notice.actions.signals <- signal
	}
	for _, signal := range closes {
		notice.closed.signals <- signal
	}
	return notice
}

// GNOME emits NotificationClosed right after ActionInvoked for an actionable
// notification. Natively on Rocky Linux 10.2 (GNOME 49) the lab's Allow click
// ended as prompt_dismissed: both signals were buffered in their separate
// watch channels and wait's select picked the close. Repetition makes the
// former coin flip certain to show.
func TestNoticeActionBeforeCloseIsNotDismissal(t *testing.T) {
	for range 1000 {
		notice := bufferedNotice(7,
			[]*dbus.Signal{{Body: []any{uint32(7), "allow"}}},
			[]*dbus.Signal{{Body: []any{uint32(7), uint32(2)}}})
		notice.wait()
		if got := <-notice.Result(); got != "allow" {
			t.Fatalf("Allow followed by its close read as %q", got)
		}
	}
	for name, actions := range map[string][]*dbus.Signal{
		"no action":                 nil,
		"other notification action": {{Body: []any{uint32(8), "allow"}}},
		"malformed action":          {{Body: []any{"allow"}}},
	} {
		notice := bufferedNotice(7, actions, []*dbus.Signal{{Body: []any{uint32(7), uint32(2)}}})
		notice.wait()
		if got := <-notice.Result(); got != "" {
			t.Errorf("%s: close without this notification's action read as %q", name, got)
		}
	}
}

func TestNotificationServerInformationPreservesRuntimeVersion(t *testing.T) {
	ctx := t.Context()
	server, bus := privateSessionBus(t, ctx, notificationsName)
	if err := server.ExportMethodTable(map[string]any{
		"GetServerInformation": func() (string, string, string, string, *dbus.Error) {
			return "cosmic-notifications", "System76", "1.10.0-lindm-actions.1", "1.2", nil
		},
	}, notificationsPath, notificationsIface); err != nil {
		t.Fatal(err)
	}
	notifier, err := NewDesktopNotifier(bus)
	if err != nil {
		t.Fatal(err)
	}
	name, version, err := notifier.ServerInformation(ctx)
	if err != nil || name != "cosmic-notifications" || version != "1.10.0-lindm-actions.1" {
		t.Fatalf("server information = %q %q %v", name, version, err)
	}
}

type postedNotification struct {
	id, replaces uint32
	summary      string
	actions      []string
	urgency      byte
}

// fakeNotificationServer is a controlled org.freedesktop.Notifications with
// GNOME Shell's Introspect AnimationsEnabled property, or none when absent.
type fakeNotificationServer struct {
	mu         sync.Mutex
	next       uint32
	posted     []postedNotification
	closed     []uint32
	animations *bool
}

func newFakeNotificationServer(t *testing.T, ctx context.Context) (*fakeNotificationServer, *dbus.Conn, *SessionBus) {
	t.Helper()
	server, bus := privateSessionBus(t, ctx, notificationsName, shellName)
	fake := &fakeNotificationServer{next: 1}
	if err := server.ExportMethodTable(map[string]any{
		"Notify": func(_ string, replaces uint32, _, summary, _ string, actions []string, hints map[string]dbus.Variant, _ int32) (uint32, *dbus.Error) {
			urgency, _ := hints["urgency"].Value().(byte)
			fake.mu.Lock()
			defer fake.mu.Unlock()
			id := replaces
			if id == 0 {
				id = fake.next
				fake.next++
			}
			fake.posted = append(fake.posted, postedNotification{id: id, replaces: replaces, summary: summary, actions: actions, urgency: urgency})
			return id, nil
		},
		"CloseNotification": func(id uint32) *dbus.Error {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			fake.closed = append(fake.closed, id)
			return nil
		},
	}, notificationsPath, notificationsIface); err != nil {
		t.Fatal(err)
	}
	if err := server.ExportMethodTable(map[string]any{
		"Get": func(iface, name string) (dbus.Variant, *dbus.Error) {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if fake.animations == nil || iface != introspectIface || name != "AnimationsEnabled" {
				return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.UnknownProperty", nil)
			}
			return dbus.MakeVariant(*fake.animations), nil
		},
	}, shellIntrospect, "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	return fake, server, bus
}

func (f *fakeNotificationServer) setAnimations(enabled *bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.animations = enabled
}

// nudges returns the action-less normal-urgency notifications posted after
// the first one, and the ids withdrawn so far.
func (f *fakeNotificationServer) nudges() ([]postedNotification, []uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var nudges []postedNotification
	for _, posted := range f.posted[1:] {
		if len(posted.actions) == 0 {
			nudges = append(nudges, posted)
		}
	}
	return nudges, slices.Clone(f.closed)
}

func reshowPrompt() Notification {
	return Notification{
		Summary:  "Remote assistance request",
		Body:     "body",
		Actions:  []NotificationAction{{Key: actionAllow, Label: "Allow"}, {Key: actionDecline, Label: "Decline"}},
		Critical: true, Persistent: true, Reshow: true,
	}
}

func postedNotice(t *testing.T, notice Notice) *desktopNotice {
	t.Helper()
	posted, ok := notice.(*desktopNotice)
	if !ok {
		t.Fatalf("notice is %T", notice)
	}
	return posted
}

// GNOME Shell without animations strands a critical notification queued
// behind a banner that has gone until another notification arrives
// (fedora44-aarch64 pipewire-fix-06). While the prompt awaits an answer the
// notifier posts and withdraws action-less nudges, and stops with the answer.
func TestReshowNudgesBannerQueueUntilAnswered(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fake, server, bus := newFakeNotificationServer(t, ctx)
	disabled := false
	fake.setAnimations(&disabled)
	notifier, err := NewDesktopNotifier(bus)
	if err != nil {
		t.Fatal(err)
	}
	notifier.reshowEvery = 10 * time.Millisecond
	notice, err := notifier.Notify(ctx, reshowPrompt())
	if err != nil {
		t.Fatal(err)
	}
	prompt := postedNotice(t, notice).id
	for {
		nudges, withdrawn := fake.nudges()
		if len(nudges) >= 2 && slices.Contains(withdrawn, nudges[1].id) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("no banner queue nudges while the prompt awaited an answer")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := server.Emit(notificationsPath, notificationsIface+".ActionInvoked", prompt, actionAllow); err != nil {
		t.Fatal(err)
	}
	if got := <-notice.Result(); got != actionAllow {
		t.Fatalf("answer read as %q", got)
	}
	if err := notice.Close(ctx); err != nil {
		t.Fatal(err)
	}
	nudges, withdrawn := fake.nudges()
	for _, nudge := range nudges {
		if nudge.replaces != 0 || nudge.urgency != 1 || nudge.summary != "Remote assistance request" || nudge.id == prompt {
			t.Fatalf("nudge %+v is not a new normal-urgency notification", nudge)
		}
		if !slices.Contains(withdrawn, nudge.id) {
			t.Fatalf("nudge %d was left posted", nudge.id)
		}
	}
	fake.mu.Lock()
	first := fake.posted[0]
	fake.mu.Unlock()
	if first.id != prompt || first.urgency != 2 || len(first.actions) != 4 {
		t.Fatalf("prompt posted as %+v", first)
	}
}

// Only a Reshow notification on GNOME Shell with animations disabled is
// nudged: an animated shell completes the hide outside its state update and
// shows its queue, and other servers do not expose the property.
func TestReshowOnlyWhereTheBannerQueueStrands(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fake, _, bus := newFakeNotificationServer(t, ctx)
	notifier, err := NewDesktopNotifier(bus)
	if err != nil {
		t.Fatal(err)
	}
	enabled, disabled := true, false
	for _, tc := range []struct {
		name       string
		animations *bool
		reshow     bool
		want       bool
	}{
		{"animations disabled", &disabled, true, true},
		{"animations enabled", &enabled, true, false},
		{"not GNOME Shell", nil, true, false},
		{"not requested", &disabled, false, false},
	} {
		fake.setAnimations(tc.animations)
		notification := reshowPrompt()
		notification.Reshow = tc.reshow
		notice, err := notifier.Notify(ctx, notification)
		if err != nil {
			t.Fatal(err)
		}
		if got := postedNotice(t, notice).reshow > 0; got != tc.want {
			t.Errorf("%s: nudging %v, want %v", tc.name, got, tc.want)
		}
		if err := notice.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
