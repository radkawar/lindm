//go:build linux

package actionprovider

import (
	"context"
	"crypto/sha256"
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

const logindName = "org.freedesktop.login1"
const logindManager = "org.freedesktop.login1.Manager"
const logindPath = dbus.ObjectPath("/org/freedesktop/login1")

type graphicalSession struct {
	ID     string
	Locked bool
}

type logindSession struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

// LogindSession is one logind session read over the trusted system bus. It
// carries only the properties remote assistance binds to; it is not a cache.
type LogindSession struct {
	ID      string
	UID     uint32
	User    string
	Class   string
	Type    string
	Desktop string
	Remote  bool
	Active  bool
	Locked  bool
}

const maxLogindSessions = 128

// withTrustedLogind never uses the caller's bus address or interactive
// authorization. The fixed system-bus peer and the resolved logind owner must
// both be root. Every operation owns a bounded connection.
func withTrustedLogind(ctx context.Context, operate func(context.Context, *dbus.Conn, string) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return ErrUnsupported
	}
	defer func() { _ = socket.Close() }()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return err
	}
	fd, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := fd.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil || peer == nil || peer.Uid != 0 {
		return fmt.Errorf("%w: untrusted_system_bus", ErrUnsupported)
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, logindName).Store(&owner); err != nil {
		return err
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil {
		return err
	}
	if uid != 0 {
		return fmt.Errorf("%w: untrusted_logind", ErrUnsupported)
	}
	return operate(ctx, conn, owner)
}

func listLogindSessions(ctx context.Context, conn *dbus.Conn, owner string) ([]logindSession, error) {
	var sessions []logindSession
	if err := conn.Object(owner, logindPath).CallWithContext(ctx, logindManager+".ListSessions", dbus.FlagNoAutoStart).Store(&sessions); err != nil {
		return nil, err
	}
	if len(sessions) > maxLogindSessions {
		return nil, ErrUnsupported
	}
	for _, session := range sessions {
		if session.ID == "" || len(session.ID) > 64 || !session.Path.IsValid() {
			return nil, ErrUnsupported
		}
	}
	return sessions, nil
}

func logindProperties(ctx context.Context, conn *dbus.Conn, owner string, path dbus.ObjectPath) (map[string]dbus.Variant, error) {
	var properties map[string]dbus.Variant
	if err := conn.Object(owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, "org.freedesktop.login1.Session").Store(&properties); err != nil {
		return nil, err
	}
	return properties, nil
}

// ReadLogindSessions returns the sessions selected by match, read from root
// logind over the trusted system bus. match sees only ListSessions facts, so
// unrelated sessions cost no property round trip. A property of the wrong
// type fails the whole read rather than producing a partial view.
func ReadLogindSessions(ctx context.Context, match func(id string, uid uint32) bool) ([]LogindSession, error) {
	if match == nil {
		return nil, ErrUnsupported
	}
	var out []LogindSession
	err := withTrustedLogind(ctx, func(ctx context.Context, conn *dbus.Conn, owner string) error {
		sessions, err := listLogindSessions(ctx, conn, owner)
		if err != nil {
			return err
		}
		for _, session := range sessions {
			if !match(session.ID, session.UID) {
				continue
			}
			properties, err := logindProperties(ctx, conn, owner, session.Path)
			if err != nil {
				return err
			}
			read := LogindSession{ID: session.ID, UID: session.UID, User: session.User}
			var ok [6]bool
			read.Class, ok[0] = properties["Class"].Value().(string)
			read.Type, ok[1] = properties["Type"].Value().(string)
			read.Desktop, ok[2] = properties["Desktop"].Value().(string)
			read.Remote, ok[3] = properties["Remote"].Value().(bool)
			read.Active, ok[4] = properties["Active"].Value().(bool)
			read.Locked, ok[5] = properties["LockedHint"].Value().(bool)
			for _, present := range ok {
				if !present {
					return ErrUnsupported
				}
			}
			out = append(out, read)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// logindSessions observes, locks or terminates graphical sessions over the
// trusted system bus. Ambiguous mutations are not retried.
func logindSessions(ctx context.Context, operation string) ([]graphicalSession, error) {
	var graphical []graphicalSession
	err := withTrustedLogind(ctx, func(ctx context.Context, conn *dbus.Conn, owner string) error {
		manager := conn.Object(owner, logindPath)
		if operation == "lock" {
			return manager.CallWithContext(ctx, logindManager+".LockSessions", dbus.FlagNoAutoStart).Err
		}
		if operation != "observe" && operation != "terminate" {
			return ErrUnsupported
		}
		sessions, err := listLogindSessions(ctx, conn, owner)
		if err != nil {
			return err
		}
		for _, session := range sessions {
			properties, err := logindProperties(ctx, conn, owner, session.Path)
			if err != nil {
				return err
			}
			class, ok := properties["Class"].Value().(string)
			if !ok {
				return ErrUnsupported
			}
			kind, ok := properties["Type"].Value().(string)
			if !ok {
				return ErrUnsupported
			}
			if class != "user" || (kind != "wayland" && kind != "x11") {
				continue
			}
			locked, ok := properties["LockedHint"].Value().(bool)
			if !ok {
				return ErrUnsupported
			}
			graphical = append(graphical, graphicalSession{ID: session.ID, Locked: locked})
		}
		if operation == "terminate" {
			for _, session := range graphical {
				if err := manager.CallWithContext(ctx, logindManager+".TerminateSession", dbus.FlagNoAutoStart, session.ID).Err; err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return graphical, nil
}

func (p *Provider) sessions(ctx context.Context, terminate bool) (bool, []byte, error) {
	if p.sessionNative == nil {
		return false, nil, ErrUnsupported
	}
	sessions, err := p.sessionNative(ctx, "observe")
	if err != nil {
		return false, nil, err
	}
	locked := true
	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		locked = locked && session.Locked
		ids = append(ids, session.ID)
	}
	if terminate {
		locked = len(sessions) == 0
	}
	slices.Sort(ids)
	digest := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return locked, digest[:], nil
}

func (p *Provider) lockSessions(ctx context.Context, terminate bool) error {
	if p.sessionNative == nil {
		return ErrUnsupported
	}
	if _, err := p.sessionNative(ctx, "lock"); err != nil {
		return err
	}
	if terminate {
		_, err := p.sessionNative(ctx, "terminate")
		return err
	}
	return nil
}
