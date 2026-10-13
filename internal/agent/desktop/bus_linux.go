//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busConnectTimeout = 10 * time.Second
	busCallTimeout    = 10 * time.Second
	watchBuffer       = 16
)

// SessionBus is the user's D-Bus session bus with one signal dispatcher.
// Watches are routed by sender, object path and member; a watch whose
// buffer is full drops further signals.
type SessionBus struct {
	conn    *dbus.Conn
	signals chan *dbus.Signal
	done    chan struct{}

	mu      sync.Mutex
	watches map[*busWatch]struct{}
}

type busWatch struct {
	bus          *SessionBus
	sender       string
	path         dbus.ObjectPath
	name         string
	options      []dbus.MatchOption
	signals      chan *dbus.Signal
	overflow     chan struct{}
	overflowOnce sync.Once
}

// ConnectSessionBus connects to DBUS_SESSION_BUS_ADDRESS (never an
// autolaunched or system bus). Close releases it.
func ConnectSessionBus(ctx context.Context) (*SessionBus, error) {
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if address == "" {
		return nil, errors.New("DBUS_SESSION_BUS_ADDRESS is not set")
	}
	ctx, cancel := context.WithTimeout(ctx, busConnectTimeout)
	defer cancel()
	type result struct {
		conn *dbus.Conn
		err  error
	}
	connected := make(chan result, 1)
	go func() {
		conn, err := dbus.Connect(address)
		connected <- result{conn, err}
	}()
	var conn *dbus.Conn
	select {
	case r := <-connected:
		if r.err != nil {
			return nil, fmt.Errorf("connect session bus: %w", r.err)
		}
		conn = r.conn
	case <-ctx.Done():
		go func() {
			if r := <-connected; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("connect session bus: %w", ctx.Err())
	}
	if !conn.SupportsUnixFDs() {
		_ = conn.Close()
		return nil, errors.New("session bus does not support fd passing")
	}
	bus := &SessionBus{
		conn:    conn,
		signals: make(chan *dbus.Signal, 64),
		done:    make(chan struct{}),
		watches: map[*busWatch]struct{}{},
	}
	conn.Signal(bus.signals)
	go bus.dispatch()
	return bus, nil
}

// Close closes the connection and waits for the dispatcher.
func (b *SessionBus) Close() error {
	err := b.conn.Close()
	<-b.done
	return err
}

func (b *SessionBus) dispatch() {
	defer close(b.done)
	for signal := range b.signals {
		b.mu.Lock()
		for watch := range b.watches {
			matches := signal.Name == watch.name || (strings.HasSuffix(watch.name, ".") && strings.HasPrefix(signal.Name, watch.name))
			if signal.Sender != watch.sender || !matches || (watch.path != "" && signal.Path != watch.path) {
				continue
			}
			select {
			case watch.signals <- signal:
			default:
				watch.overflowOnce.Do(func() { close(watch.overflow) })
			}
		}
		b.mu.Unlock()
	}
}

// nameOwner resolves the unique name owning a well-known service name.
func (b *SessionBus) nameOwner(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, busCallTimeout)
	defer cancel()
	var owner string
	if err := b.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, name).Store(&owner); err != nil {
		return "", fmt.Errorf("resolve %s owner: %w", name, err)
	}
	return owner, nil
}

// watch subscribes to iface.member signals from sender (a unique name) on
// path before the caller triggers them.
func (b *SessionBus) watch(ctx context.Context, sender string, path dbus.ObjectPath, iface, member string) (*busWatch, error) {
	options := []dbus.MatchOption{
		dbus.WithMatchSender(sender),
		dbus.WithMatchInterface(iface),
	}
	if member != "" {
		options = append(options, dbus.WithMatchMember(member))
	}
	if path != "" {
		options = append(options, dbus.WithMatchObjectPath(path))
	}
	watch := &busWatch{
		bus:      b,
		sender:   sender,
		path:     path,
		name:     iface + "." + member,
		options:  options,
		signals:  make(chan *dbus.Signal, watchBuffer),
		overflow: make(chan struct{}),
	}
	b.mu.Lock()
	b.watches[watch] = struct{}{}
	b.mu.Unlock()
	call, cancel := context.WithTimeout(ctx, busCallTimeout)
	defer cancel()
	if err := b.conn.AddMatchSignalContext(call, options...); err != nil {
		b.mu.Lock()
		delete(b.watches, watch)
		b.mu.Unlock()
		return nil, fmt.Errorf("add match %s: %w", watch.name, err)
	}
	return watch, nil
}

// stop removes the watch and its match rule.
func (w *busWatch) stop(ctx context.Context) error {
	w.bus.mu.Lock()
	_, ok := w.bus.watches[w]
	delete(w.bus.watches, w)
	w.bus.mu.Unlock()
	if !ok {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, busCallTimeout)
	defer cancel()
	if err := w.bus.conn.RemoveMatchSignalContext(call, w.options...); err != nil {
		return fmt.Errorf("remove match %s: %w", w.name, err)
	}
	return nil
}

// call invokes method on dest/path with a bounded context.
func (b *SessionBus) call(ctx context.Context, dest string, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	call, cancel := context.WithTimeout(ctx, busCallTimeout)
	defer cancel()
	return b.conn.Object(dest, path).CallWithContext(call, method, 0, args...)
}

// property reads one property with a bounded context.
func (b *SessionBus) property(ctx context.Context, dest string, path dbus.ObjectPath, iface, name string) (dbus.Variant, error) {
	var value dbus.Variant
	if err := b.call(ctx, dest, path, "org.freedesktop.DBus.Properties.Get", iface, name).Store(&value); err != nil {
		return dbus.Variant{}, fmt.Errorf("read %s.%s: %w", iface, name, err)
	}
	return value, nil
}
