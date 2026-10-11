//go:build linux

package osupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"lindm/internal/agent/nativeexec"
)

const (
	notifyTimeout       = 5 * time.Second
	maxNotificationBody = 1024
	notificationsName   = "org.freedesktop.Notifications"
	notificationsPath   = dbus.ObjectPath("/org/freedesktop/Notifications")
	notificationApp     = "lindm"
	notificationSummary = "System restart scheduled"
	// Notifications urgency hint: 2 = critical (Desktop Notifications spec).
	notificationUrgency = byte(2)
)

var errNotifyInput = errors.New("notification_input_invalid")

// rebootMessage is the logind wall message and the desktop notification
// body. Lab lanes match this exact text.
func rebootMessage(notice string, at time.Time, loc *time.Location) string {
	text := "(lindm: reboot scheduled for " + at.In(loc).Format(time.RFC1123) + " to complete OS updates)"
	if notice != "" {
		return notice + " " + text
	}
	return text
}

func userBusPath(uid uint32) string {
	return "/run/user/" + strconv.FormatUint(uint64(uid), 10) + "/bus"
}

// notifyUsers starts one `os-update notify` child per user through
// nativeexec with that user's logind-reported UID and primary GID (no
// supplementary groups), nativeexec's fixed environment plus only the user's
// own session bus, and a 5 s bound after which its process group is killed.
// It stops when ctx ends and returns how many children reported success.
func notifyUsers(ctx context.Context, executable string, users []sessionUser, body string) uint32 {
	var notified uint32
	for _, user := range users {
		if ctx.Err() != nil {
			break
		}
		if notifyUser(ctx, executable, user, body) == nil {
			notified++
		}
	}
	return notified
}

func notifyUser(ctx context.Context, executable string, user sessionUser, body string) error {
	bus := userBusPath(user.uid)
	var st unix.Stat_t
	if err := unix.Lstat(bus, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != user.uid {
		return errUntrustedBus
	}
	_, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: executable, Args: []string{"os-update", "notify"},
		Env:        []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=" + bus},
		Stdin:      []byte(body),
		Credential: &syscall.Credential{Uid: user.uid, Gid: user.gid, Groups: []uint32{}},
		Timeout:    notifyTimeout, StdoutLimit: 4096, StderrLimit: 4096,
	})
	return err
}

// Notify is the unprivileged `lindm-agent os-update notify` child. It refuses
// root and any bus other than the caller's own /run/user/<uid>/bus. It reads
// the bounded body from stdin and posts one critical notification within the
// 5 s bound.
func Notify(ctx context.Context, stdin io.Reader) error {
	uid := os.Geteuid()
	if uid == 0 || os.Getuid() == 0 {
		return errors.New("os-update notify refuses root")
	}
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	path, ok := strings.CutPrefix(address, "unix:path=")
	if !ok || path != userBusPath(uint32(uid)) {
		return errNotifyInput
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxNotificationBody+1))
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxNotificationBody {
		return errNotifyInput
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	return notifyDesktop(ctx, path, uint32(uid), string(data))
}

// notifyDesktop posts the notification on the session bus at path, whose
// daemon must run as uid. A notification server may be D-Bus activated, so
// auto-start stays allowed on the user's own bus.
func notifyDesktop(ctx context.Context, path string, uid uint32, body string) (err error) {
	for _, r := range body {
		if r < 0x20 || r == 0x7f {
			return errNotifyInput
		}
	}
	conn, closeConn, err := dialBus(ctx, path, uid)
	if err != nil {
		return fmt.Errorf("connect session bus: %w", err)
	}
	defer func() { err = errors.Join(err, closeConn()) }()
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(notificationUrgency)}
	var id uint32
	if err := conn.Object(notificationsName, notificationsPath).CallWithContext(ctx, notificationsName+".Notify", 0,
		notificationApp, uint32(0), "", notificationSummary, body, []string{}, hints, int32(-1)).Store(&id); err != nil {
		return fmt.Errorf("post notification: %w", err)
	}
	return nil
}
