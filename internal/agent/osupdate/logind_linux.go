//go:build linux

package osupdate

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	systemBusSocket = "/run/dbus/system_bus_socket"
	logindName      = "org.freedesktop.login1"
	logindPath      = dbus.ObjectPath("/org/freedesktop/login1")
	logindManager   = "org.freedesktop.login1.Manager"
	logindSession   = "org.freedesktop.login1.Session"
	logindUser      = "org.freedesktop.login1.User"
	maxSessions     = 1024
)

var (
	errUntrustedBus = errors.New("untrusted_bus")
	errBusDeadline  = errors.New("bus_deadline_required")
)

// dialBus connects to a fixed D-Bus socket path whose server process must run
// as peerUID (SO_PEERCRED). It never uses an environment-selected bus or
// autolaunch. The socket deadline and cancellation bound the whole connection
// lifetime by ctx.
func dialBus(ctx context.Context, path string, peerUID uint32) (_ *dbus.Conn, _ func() error, err error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, errBusDeadline
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, nil, errUntrustedBus
	}
	defer func() {
		if err != nil {
			_ = socket.Close()
		}
	}()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	fd, err := socket.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := fd.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, nil, err
	}
	if peerErr != nil || peer == nil || peer.Uid != peerUID {
		return nil, nil, errUntrustedBus
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); close(closed) })
	stopCancellation := func() {
		if !stop() {
			<-closed
		}
	}
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		stopCancellation()
		return nil, nil, err
	}
	return conn, func() error {
		stopCancellation()
		return conn.Close()
	}, nil
}

// logind is an authenticated connection to the root-owned logind name owner.
// The unique owner name stays pinned for every call, as in the action
// provider's power boundary.
type logind struct {
	conn  *dbus.Conn
	owner string
	close func() error
}

func openLogind(ctx context.Context) (_ *logind, err error) {
	conn, closeConn, err := dialBus(ctx, systemBusSocket, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeConn())
		}
	}()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, logindName).Store(&owner); err != nil {
		return nil, err
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil {
		return nil, err
	}
	if uid != 0 {
		return nil, fmt.Errorf("%w: logind", errUntrustedBus)
	}
	return &logind{conn: conn, owner: owner, close: closeConn}, nil
}

func (l *logind) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return l.conn.Object(l.owner, path).CallWithContext(ctx, method, dbus.FlagNoAutoStart, args...)
}

// powerState is logind's current shutdown schedule and blocking inhibitors.
type powerState struct {
	pending   bool
	kind      string
	scheduled time.Time
	inhibited bool
}

type logindInhibitor struct {
	What string
	Who  string
	Why  string
	Mode string
	UID  uint32
	PID  uint32
}

func (l *logind) power(ctx context.Context) (powerState, error) {
	var properties map[string]dbus.Variant
	if err := l.call(ctx, logindPath, "org.freedesktop.DBus.Properties.GetAll", logindManager).Store(&properties); err != nil {
		return powerState{}, err
	}
	var state powerState
	preparing, ok := properties["PreparingForShutdown"].Value().(bool)
	if !ok {
		return powerState{}, errors.New("logind_property_invalid")
	}
	var scheduled struct {
		Kind string
		Usec uint64
	}
	value, ok := properties["ScheduledShutdown"]
	if !ok || dbus.Store([]any{value.Value()}, &scheduled) != nil {
		return powerState{}, errors.New("logind_property_invalid")
	}
	// logind reports USEC_INFINITY or zero when nothing is scheduled.
	hasTime := scheduled.Usec != 0 && scheduled.Usec != ^uint64(0)
	state.pending = preparing || scheduled.Kind != "" || hasTime
	state.kind = scheduled.Kind
	if hasTime && scheduled.Usec <= uint64(1)<<62 {
		state.scheduled = time.UnixMicro(int64(scheduled.Usec))
	}
	var inhibitors []logindInhibitor
	if err := l.call(ctx, logindPath, logindManager+".ListInhibitors").Store(&inhibitors); err != nil {
		return powerState{}, err
	}
	for _, inhibitor := range inhibitors {
		// Delay inhibitors remain logind's responsibility at shutdown time.
		if slices.Contains(strings.Split(inhibitor.What, ":"), "shutdown") && inhibitor.Mode != "delay" {
			state.inhibited = true
		}
	}
	return state, nil
}

// scheduleReboot sets the wall message first so the announcement carries it,
// then schedules the reboot at the absolute time.
func (l *logind) scheduleReboot(ctx context.Context, wall string, at time.Time) error {
	if err := l.call(ctx, logindPath, logindManager+".SetWallMessage", wall, true).Err; err != nil {
		return fmt.Errorf("set wall message: %w", err)
	}
	if err := l.call(ctx, logindPath, logindManager+".ScheduleShutdown", "reboot", uint64(at.UnixMicro())).Err; err != nil {
		return fmt.Errorf("schedule shutdown: %w", err)
	}
	return nil
}

type logindSessionEntry struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

// sessionUser is a graphical session owner with the primary group logind
// reports for it. No NSS lookup is made: a static binary would only see
// /etc/passwd and miss directory (SSSD, AD) users.
type sessionUser struct{ uid, gid uint32 }

// graphicalUsers returns the distinct non-root owners, sorted by UID, of an
// active local graphical (x11 or wayland) user-class session.
func (l *logind) graphicalUsers(ctx context.Context) ([]sessionUser, error) {
	var sessions []logindSessionEntry
	if err := l.call(ctx, logindPath, logindManager+".ListSessions").Store(&sessions); err != nil {
		return nil, err
	}
	if len(sessions) > maxSessions {
		sessions = sessions[:maxSessions]
	}
	var users []sessionUser
	seen := make(map[uint32]bool)
	for _, session := range sessions {
		if session.UID == 0 || seen[session.UID] {
			continue
		}
		var properties map[string]dbus.Variant
		if err := l.call(ctx, session.Path, "org.freedesktop.DBus.Properties.GetAll", logindSession).Store(&properties); err != nil {
			// A session may close between listing and reading.
			continue
		}
		kind, _ := properties["Type"].Value().(string)
		class, _ := properties["Class"].Value().(string)
		active, _ := properties["Active"].Value().(bool)
		if (kind != "x11" && kind != "wayland") || class != "user" || !active {
			continue
		}
		var owner struct {
			UID  uint32
			Path dbus.ObjectPath
		}
		value, ok := properties["User"]
		if !ok || dbus.Store([]any{value.Value()}, &owner) != nil || owner.UID != session.UID {
			continue
		}
		var userProperties map[string]dbus.Variant
		if err := l.call(ctx, owner.Path, "org.freedesktop.DBus.Properties.GetAll", logindUser).Store(&userProperties); err != nil {
			continue
		}
		uid, uidOK := userProperties["UID"].Value().(uint32)
		gid, gidOK := userProperties["GID"].Value().(uint32)
		if !uidOK || !gidOK || uid != session.UID || gid == 0 {
			continue
		}
		seen[uid] = true
		users = append(users, sessionUser{uid: uid, gid: gid})
	}
	slices.SortFunc(users, func(a, b sessionUser) int { return cmp.Compare(a.uid, b.uid) })
	return users, nil
}
