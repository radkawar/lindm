//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	systemBusSocket      = "/run/dbus/system_bus_socket"
	logindName           = "org.freedesktop.login1"
	logindPath           = dbus.ObjectPath("/org/freedesktop/login1")
	logindManagerIface   = "org.freedesktop.login1.Manager"
	logindSessionIface   = "org.freedesktop.login1.Session"
	logindLockSignal     = logindSessionIface + ".Lock"
	logindSleepSignal    = logindManagerIface + ".PrepareForSleep"
	lockSubscriptionSize = 4
)

// LogindLockMonitor watches logind's lock signals on the system bus. Signals
// are accepted only from the unique name that owns org.freedesktop.login1 and
// runs as root; the helper reads, never calls, logind lock methods.
type LogindLockMonitor struct{}

var _ LockMonitor = LogindLockMonitor{}

// Subscribe connects a private system-bus connection, resolves the session's
// object path and registers both match rules before returning. Only setup is
// bounded by ctx; the subscription lives until Close.
func (LogindLockMonitor) Subscribe(ctx context.Context, sessionID string) (_ LockSubscription, err error) {
	if sessionID == "" {
		return nil, errors.New("lock watch requires a logind session")
	}
	ctx, cancel := context.WithTimeout(ctx, busConnectTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", systemBusSocket)
	if err != nil {
		return nil, fmt.Errorf("connect system bus: %w", err)
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(errors.New("system bus is not a unix socket"), raw.Close())
	}
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, errors.Join(err, socket.Close())
	}
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Getuid()))))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("connect system bus: %w", err), socket.Close())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close())
		}
	}()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, logindName).Store(&owner); err != nil {
		return nil, fmt.Errorf("resolve logind owner: %w", err)
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid); err != nil {
		return nil, fmt.Errorf("resolve logind uid: %w", err)
	}
	if uid != 0 {
		return nil, errors.New("logind owner is not root")
	}
	var path dbus.ObjectPath
	if err := conn.Object(owner, logindPath).CallWithContext(ctx, logindManagerIface+".GetSession", dbus.FlagNoAutoStart, sessionID).Store(&path); err != nil {
		return nil, fmt.Errorf("resolve logind session: %w", err)
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(owner), dbus.WithMatchObjectPath(path), dbus.WithMatchInterface(logindSessionIface), dbus.WithMatchMember("Lock")); err != nil {
		return nil, fmt.Errorf("watch logind lock: %w", err)
	}
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(owner), dbus.WithMatchObjectPath(logindPath), dbus.WithMatchInterface(logindManagerIface), dbus.WithMatchMember("PrepareForSleep")); err != nil {
		return nil, fmt.Errorf("watch logind sleep: %w", err)
	}
	// The private connection outlives setup; only setup had a deadline.
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	subscription := &logindLockSubscription{conn: conn, locked: make(chan string, lockSubscriptionSize), done: make(chan struct{})}
	go subscription.dispatch(signals, owner, path)
	return subscription, nil
}

type logindLockSubscription struct {
	conn      *dbus.Conn
	locked    chan string
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (s *logindLockSubscription) Locked() <-chan string { return s.locked }

// dispatch ends when the connection closes; the closed Locked channel then
// tells the helper the watch is gone.
func (s *logindLockSubscription) dispatch(signals <-chan *dbus.Signal, owner string, path dbus.ObjectPath) {
	defer close(s.done)
	defer close(s.locked)
	for signal := range signals {
		if signal.Sender != owner {
			continue
		}
		detail := ""
		switch {
		case signal.Name == logindLockSignal && signal.Path == path:
			detail = lockDetailLogindLock
		case signal.Name == logindSleepSignal && signal.Path == logindPath && len(signal.Body) == 1:
			if start, ok := signal.Body[0].(bool); ok && start {
				detail = lockDetailSleep
			}
		}
		if detail == "" {
			continue
		}
		select {
		case s.locked <- detail:
		default:
			// A pending lock already ends every session; repeats add nothing.
		}
	}
}

func (s *logindLockSubscription) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.conn.Close()
		<-s.done
	})
	return s.closeErr
}
