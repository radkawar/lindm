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

// logindSessions never uses the caller's bus address or interactive authorization.
// The fixed system-bus peer and the resolved logind owner must both be root.
// Every operation owns a bounded connection; ambiguous mutations are not retried.
func logindSessions(ctx context.Context, operation string) (_ []graphicalSession, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, ErrUnsupported
	}
	defer func() { _ = socket.Close() }()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, err
	}
	fd, err := socket.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := fd.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	if peerErr != nil || peer == nil || peer.Uid != 0 {
		return nil, fmt.Errorf("%w: untrusted_system_bus", ErrUnsupported)
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
		return nil, err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, logindName).Store(&owner); err != nil {
		return nil, err
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil {
		return nil, err
	}
	if uid != 0 {
		return nil, fmt.Errorf("%w: untrusted_logind", ErrUnsupported)
	}
	manager := conn.Object(owner, logindPath)
	if operation == "lock" {
		return nil, manager.CallWithContext(ctx, logindManager+".LockSessions", dbus.FlagNoAutoStart).Err
	}
	if operation != "observe" && operation != "terminate" {
		return nil, ErrUnsupported
	}
	var sessions []logindSession
	if err := manager.CallWithContext(ctx, logindManager+".ListSessions", dbus.FlagNoAutoStart).Store(&sessions); err != nil {
		return nil, err
	}
	if len(sessions) > 128 {
		return nil, ErrUnsupported
	}
	var graphical []graphicalSession
	for _, session := range sessions {
		if session.ID == "" || len(session.ID) > 64 || !session.Path.IsValid() {
			return nil, ErrUnsupported
		}
		var properties map[string]dbus.Variant
		if err := conn.Object(owner, session.Path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, "org.freedesktop.login1.Session").Store(&properties); err != nil {
			return nil, err
		}
		class, ok := properties["Class"].Value().(string)
		if !ok {
			return nil, ErrUnsupported
		}
		kind, ok := properties["Type"].Value().(string)
		if !ok {
			return nil, ErrUnsupported
		}
		if class != "user" || (kind != "wayland" && kind != "x11") {
			continue
		}
		locked, ok := properties["LockedHint"].Value().(bool)
		if !ok {
			return nil, ErrUnsupported
		}
		graphical = append(graphical, graphicalSession{ID: session.ID, Locked: locked})
	}
	if operation == "terminate" {
		for _, session := range graphical {
			if err := manager.CallWithContext(ctx, logindManager+".TerminateSession", dbus.FlagNoAutoStart, session.ID).Err; err != nil {
				return nil, err
			}
		}
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
