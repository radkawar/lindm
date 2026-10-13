//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	notificationsName  = "org.freedesktop.Notifications"
	notificationsPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notificationsIface = "org.freedesktop.Notifications"
	notificationApp    = "lindm"
	shellName          = "org.gnome.Shell"
	shellIntrospect    = dbus.ObjectPath("/org/gnome/Shell/Introspect")
	introspectIface    = "org.gnome.Shell.Introspect"
	// reshowInterval paces the banner-queue nudges of a Reshow notification:
	// a stranded prompt appears at most this long after the banner it was
	// queued behind has gone.
	reshowInterval = 3 * time.Second
)

// DesktopNotifier posts org.freedesktop.Notifications notifications on the
// session bus. Action and close signals are accepted only from the unique
// name that owned the service when the notification was posted.
type DesktopNotifier struct {
	bus         *SessionBus
	reshowEvery time.Duration
}

var _ Notifier = (*DesktopNotifier)(nil)

// NewDesktopNotifier returns a notifier bound to bus.
func NewDesktopNotifier(bus *SessionBus) (*DesktopNotifier, error) {
	if bus == nil {
		return nil, errors.New("desktop: missing session bus")
	}
	return &DesktopNotifier{bus: bus, reshowEvery: reshowInterval}, nil
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
		if notification.Reshow && n.strandsQueuedBanners(ctx) {
			notice.reshow, notice.nudge = n.reshowEvery, Notification{Summary: notification.Summary}
		}
	}
	if err := n.bus.post(ctx, notification, 0, &notice.id); err != nil {
		return nil, errors.Join(err, notice.stopWatches())
	}
	if notice.actions != nil {
		notice.done = make(chan struct{})
		go notice.wait()
	}
	return notice, nil
}

// strandsQueuedBanners reports GNOME Shell with animations disabled, as when
// rendering is not hardware accelerated (virtual machines), during a remote
// desktop session or with reduced animation. Its message tray (GNOME 46 to
// 50) shows one banner at a time, and a critical notification posted while
// another banner is shown waits in its queue. Without animations, hiding that
// banner completes inside the tray's state update, whose re-entrancy guard
// drops the follow-up update, so the queued notification is not shown until
// another notification arrives. Any other server, or a failed read, is
// assumed to show its queue.
func (n *DesktopNotifier) strandsQueuedBanners(ctx context.Context) bool {
	value, err := n.bus.property(ctx, shellName, shellIntrospect, introspectIface, "AnimationsEnabled")
	if err != nil {
		return false
	}
	enabled, ok := value.Value().(bool)
	return ok && !enabled
}

// post calls Notify; replaces is 0 for a new notification or the id to update.
func (b *SessionBus) post(ctx context.Context, notification Notification, replaces uint32, id *uint32) error {
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
	if err := b.call(ctx, notificationsName, notificationsPath, notificationsIface+".Notify",
		notificationApp, replaces, "", notification.Summary, notification.Body, actions, hints, expire).Store(id); err != nil {
		return fmt.Errorf("post notification: %w", err)
	}
	return nil
}

// Update replaces this notification's content under its existing id.
func (n *desktopNotice) Update(ctx context.Context, notification Notification) error {
	var id uint32
	if err := n.bus.post(ctx, notification, n.id, &id); err != nil {
		return err
	}
	if id != n.id {
		return fmt.Errorf("notification server replaced %d with new id %d", n.id, id)
	}
	return nil
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
	// reshow paces nudgeQueue while the notification awaits an action; zero
	// when the server shows its queue unaided.
	reshow time.Duration
	nudge  Notification
}

func (n *desktopNotice) Result() <-chan string { return n.result }

// wait delivers the first action or close for this notification id. A lost
// bus counts as closed without an action.
func (n *desktopNotice) wait() {
	defer close(n.done)
	defer func() { _ = n.stopWatches() }()
	var nudges <-chan time.Time
	if n.reshow > 0 {
		ticker := time.NewTicker(n.reshow)
		defer ticker.Stop()
		nudges = ticker.C
	}
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
		case <-nudges:
			// A pending signal may be this notification's answer; a nudge
			// after it would be shown on its own.
			if len(n.actions.signals) == 0 && len(n.closed.signals) == 0 {
				if err := n.nudgeQueue(); err != nil {
					nudges = nil
				}
			}
		}
	}
}

// nudgeQueue posts and at once withdraws an action-less normal-urgency
// notification. GNOME Shell updates its banner queue for every new
// notification and then shows a stranded critical notification first; while
// that notification is shown, the nudge only waits behind it and is withdrawn
// unseen. Neither call is cut short by Close: a nudge left posted would be
// shown on its own. A failure ends the nudges of this notification.
func (n *desktopNotice) nudgeQueue() error {
	ctx, cancel := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancel()
	var id uint32
	if err := n.bus.post(ctx, n.nudge, 0, &id); err != nil {
		return err
	}
	withdraw, cancelWithdraw := context.WithTimeout(context.Background(), busCallTimeout)
	defer cancelWithdraw()
	if err := n.bus.call(withdraw, notificationsName, notificationsPath, notificationsIface+".CloseNotification", id).Err; err != nil {
		return fmt.Errorf("withdraw banner queue nudge: %w", err)
	}
	return nil
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
