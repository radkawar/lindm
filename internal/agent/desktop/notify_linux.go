//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	notificationsName  = "org.freedesktop.Notifications"
	notificationsPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notificationsIface = "org.freedesktop.Notifications"
	notificationApp    = "lindm"
)

// DesktopNotifier posts org.freedesktop.Notifications notifications on the
// session bus. Action and close signals are accepted only from the unique
// name that owned the service when the notification was posted.
type DesktopNotifier struct {
	bus *SessionBus
}

var _ Notifier = (*DesktopNotifier)(nil)

// NewDesktopNotifier returns a notifier bound to bus.
func NewDesktopNotifier(bus *SessionBus) (*DesktopNotifier, error) {
	if bus == nil {
		return nil, errors.New("desktop: missing session bus")
	}
	return &DesktopNotifier{bus: bus}, nil
}

func (n *DesktopNotifier) Capabilities(ctx context.Context) ([]string, error) {
	var capabilities []string
	if err := n.bus.call(ctx, notificationsName, notificationsPath, notificationsIface+".GetCapabilities").Store(&capabilities); err != nil {
		return nil, fmt.Errorf("notification capabilities: %w", err)
	}
	return capabilities, nil
}

func (n *DesktopNotifier) ServerName(ctx context.Context) (string, error) {
	var name, vendor, version, spec string
	if err := n.bus.call(ctx, notificationsName, notificationsPath, notificationsIface+".GetServerInformation").Store(&name, &vendor, &version, &spec); err != nil {
		return "", fmt.Errorf("notification server information: %w", err)
	}
	return name, nil
}

// Notify posts notification. Notifications without actions are not tracked:
// their Result never delivers.
func (n *DesktopNotifier) Notify(ctx context.Context, notification Notification) (Notice, error) {
	notice := &desktopNotice{bus: n.bus, result: make(chan string, 1), stop: make(chan struct{})}
	if len(notification.Actions) > 0 {
		owner, err := n.bus.nameOwner(ctx, notificationsName)
		if err != nil {
			return nil, err
		}
		if notice.actions, err = n.bus.watch(ctx, owner, notificationsPath, notificationsIface, "ActionInvoked"); err != nil {
			return nil, err
		}
		if notice.closed, err = n.bus.watch(ctx, owner, notificationsPath, notificationsIface, "NotificationClosed"); err != nil {
			return nil, errors.Join(err, notice.stopWatches())
		}
	}
	actions := make([]string, 0, 2*len(notification.Actions))
	for _, action := range notification.Actions {
		actions = append(actions, action.Key, action.Label)
	}
	urgency := byte(1)
	if notification.Critical {
		urgency = 2
	}
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgency)}
	expire := int32(-1)
	if notification.Persistent {
		expire = 0
	} else if notification.Lifetime > 0 {
		expire = int32(notification.Lifetime.Milliseconds())
	}
	err := n.bus.call(ctx, notificationsName, notificationsPath, notificationsIface+".Notify",
		notificationApp, uint32(0), "", notification.Summary, notification.Body, actions, hints, expire).Store(&notice.id)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("post notification: %w", err), notice.stopWatches())
	}
	if notice.actions != nil {
		notice.done = make(chan struct{})
		go notice.wait()
	}
	return notice, nil
}

type desktopNotice struct {
	bus      *SessionBus
	id       uint32
	actions  *busWatch
	closed   *busWatch
	result   chan string
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

func (n *desktopNotice) Result() <-chan string { return n.result }

// wait delivers the first action or close for this notification id. A lost
// bus counts as closed without an action.
func (n *desktopNotice) wait() {
	defer close(n.done)
	defer func() { _ = n.stopWatches() }()
	for {
		select {
		case <-n.stop:
			return
		case <-n.bus.done:
			n.result <- ""
			return
		case signal := <-n.actions.signals:
			var id uint32
			var key string
			if dbus.Store(signal.Body, &id, &key) == nil && id == n.id {
				n.result <- key
				return
			}
		case signal := <-n.closed.signals:
			var id, reason uint32
			if dbus.Store(signal.Body, &id, &reason) == nil && id == n.id {
				n.result <- n.bufferedAction()
				return
			}
		}
	}
}

// bufferedAction returns the key of an ActionInvoked for this notification
// that the dispatcher forwarded before its NotificationClosed, or "". The
// dispatcher forwards bus signals in order but into separate watch channels,
// and select picks among ready cases at random: GNOME closes an actionable
// notification right after ActionInvoked, so a buffered Allow would otherwise
// read as a dismissal (observed natively on Rocky Linux 10.2, GNOME 49).
func (n *desktopNotice) bufferedAction() string {
	for {
		select {
		case signal := <-n.actions.signals:
			var id uint32
			var key string
			if dbus.Store(signal.Body, &id, &key) == nil && id == n.id {
				return key
			}
		default:
			return ""
		}
	}
}

func (n *desktopNotice) stopWatches() error {
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	var errs []error
	for _, watch := range []*busWatch{n.actions, n.closed} {
		if watch != nil {
			errs = append(errs, watch.stop(ctx))
		}
	}
	return errors.Join(errs...)
}

func (n *desktopNotice) Close(ctx context.Context) error {
	err := n.bus.call(ctx, notificationsName, notificationsPath, notificationsIface+".CloseNotification", n.id).Err
	n.stopOnce.Do(func() { close(n.stop) })
	if n.done != nil {
		<-n.done
	}
	if err != nil {
		return fmt.Errorf("close notification: %w", err)
	}
	return nil
}
