//go:build linux

package desktop

import (
	"testing"

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
