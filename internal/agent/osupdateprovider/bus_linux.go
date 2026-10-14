// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"lindm/internal/resource"
)

const systemdName = "org.freedesktop.systemd1"
const managerPath = dbus.ObjectPath("/org/freedesktop/systemd1")

// timerView is the stable systemd state of lindm-os-update.timer. Next-elapse
// times are deliberately not captured: they are volatile, not configuration.
type timerView struct {
	loaded    bool // loaded from the owned fragment without foreign drop-ins
	active    bool // ActiveState=active with no reload pending
	calendars []string
}

type nativeManager interface {
	Timer(context.Context) (*timerView, error)
	ServiceInstalled(context.Context) (bool, error)
	Conflicts(context.Context, []string) ([]string, error)
	Reload(context.Context) error
	Runtime(context.Context, string) error
	Close() error
}

type systemdBus struct {
	conn   *dbus.Conn
	socket *net.UnixConn
	owner  string
}

var _ nativeManager = (*systemdBus)(nil)

// openBus connects to the system bus as root and accepts only a root-owned
// systemd manager, the same peer checks as the systemd definition provider.
func openBus(ctx context.Context) (_ nativeManager, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(ErrUnsupported, raw.Close())
	}
	b := &systemdBus{socket: socket}
	defer func() {
		if err != nil {
			err = errors.Join(err, b.Close())
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	rc, err := socket.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := rc.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	if peerErr != nil || peer == nil || peer.Uid != 0 {
		return nil, errors.Join(ErrConflict, peerErr)
	}
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, err
	}
	b.conn, err = dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		return nil, err
	}
	if err := b.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, systemdName).Store(&b.owner); err != nil {
		return nil, err
	}
	var uid uint32
	if err := b.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, b.owner).Store(&uid); err != nil || uid != 0 {
		return nil, errors.Join(ErrConflict, err)
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *systemdBus) Close() error {
	var err error
	if b.socket != nil {
		err = b.socket.Close()
		b.socket = nil
	}
	if b.conn != nil {
		err = errors.Join(err, b.conn.Close())
		b.conn = nil
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (b *systemdBus) call(ctx context.Context, method string, args ...any) *dbus.Call {
	deadline, ok := ctx.Deadline()
	if !ok {
		return &dbus.Call{Err: ErrUnsupported}
	}
	if err := b.socket.SetWriteDeadline(deadline); err != nil {
		return &dbus.Call{Err: err}
	}
	return b.conn.Object(b.owner, managerPath).CallWithContext(ctx, systemdName+".Manager."+method, dbus.FlagNoAutoStart, args...)
}

func property(values map[string]dbus.Variant, key string, out any) error {
	v, ok := values[key]
	if !ok {
		return fmt.Errorf("%w: missing %s", ErrUnsupported, key)
	}
	if err := v.Store(out); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsupported, key, err)
	}
	return nil
}

type unitState struct {
	id, load, active, fragment string
	dropIns                    []string
	transient, reload, pending bool
	object                     dbus.BusObject
}

func (b *systemdBus) unit(ctx context.Context, name string) (*unitState, error) {
	var path dbus.ObjectPath
	if err := b.call(ctx, "LoadUnit", name).Store(&path); err != nil {
		return nil, err
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return nil, ErrUnsupported
	}
	u := &unitState{object: b.conn.Object(b.owner, path)}
	var values map[string]dbus.Variant
	if err := u.object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+".Unit").Store(&values); err != nil {
		return nil, err
	}
	var job struct {
		ID   uint32
		Path dbus.ObjectPath
	}
	for _, field := range []struct {
		key string
		out any
	}{{"Id", &u.id}, {"LoadState", &u.load}, {"ActiveState", &u.active}, {"FragmentPath", &u.fragment}, {"DropInPaths", &u.dropIns}, {"Transient", &u.transient}, {"NeedDaemonReload", &u.reload}, {"Job", &job}} {
		if err := property(values, field.key, field.out); err != nil {
			return nil, err
		}
	}
	if u.id != name {
		return nil, fmt.Errorf("%w: %s is an alias of %s", ErrConflict, name, u.id)
	}
	u.pending = job.ID != 0 || job.Path != "/"
	return u, nil
}

type calendarTimer struct {
	Base, Spec string
	Next       uint64
}

func (b *systemdBus) Timer(ctx context.Context) (*timerView, error) {
	u, err := b.unit(ctx, resource.OSUpdateTimerUnit)
	if err != nil {
		return nil, err
	}
	if u.pending {
		return nil, fmt.Errorf("%w: %s job pending", ErrConflict, resource.OSUpdateTimerUnit)
	}
	if u.transient || u.load == "masked" || (u.fragment != "" && u.fragment != resource.OSUpdateTimerPath) || len(u.dropIns) != 0 {
		return nil, fmt.Errorf("%w: foreign %s definition", ErrConflict, resource.OSUpdateTimerUnit)
	}
	view := &timerView{}
	if u.load != "loaded" {
		// not-found, or the owned file failed to load (bad-setting/error).
		return view, nil
	}
	if u.fragment != resource.OSUpdateTimerPath {
		return nil, fmt.Errorf("%w: %s has no owned fragment", ErrConflict, resource.OSUpdateTimerUnit)
	}
	var values map[string]dbus.Variant
	if err := u.object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+".Timer").Store(&values); err != nil {
		return nil, err
	}
	var calendars []calendarTimer
	if err := property(values, "TimersCalendar", &calendars); err != nil {
		return nil, err
	}
	if len(calendars) > 7 {
		return nil, ErrConflict
	}
	view.loaded = true
	view.active = u.active == "active" && !u.reload
	for _, c := range calendars {
		if c.Base != "OnCalendar" || len(c.Spec) > 256 {
			return nil, ErrConflict
		}
		view.calendars = append(view.calendars, c.Spec)
	}
	return view, nil
}

// ServiceInstalled reports whether the package-provided window run service is
// loadable; the timer must never point at a missing unit.
func (b *systemdBus) ServiceInstalled(ctx context.Context) (bool, error) {
	u, err := b.unit(ctx, resource.OSUpdateServiceUnit)
	if err != nil {
		return false, err
	}
	return u.load == "loaded" && !u.transient, nil
}

var conflictName = regexp.MustCompile(`^[a-zA-Z0-9@_.-]{1,128}[.](timer|service)$`)

// Conflicts lists native automatic-update units matching the closed patterns
// that are enabled or active and could install outside the window.
func (b *systemdBus) Conflicts(ctx context.Context, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	var files []struct{ Path, State string }
	if err := b.call(ctx, "ListUnitFilesByPatterns", []string{}, patterns).Store(&files); err != nil {
		return nil, err
	}
	var units []struct {
		Name, Description, Load, Active, Sub, Following string
		Path                                            dbus.ObjectPath
		JobID                                           uint32
		JobType                                         string
		JobPath                                         dbus.ObjectPath
	}
	if err := b.call(ctx, "ListUnitsByPatterns", []string{}, patterns).Store(&units); err != nil {
		return nil, err
	}
	if len(files) > 64 || len(units) > 64 {
		return nil, ErrConflict
	}
	var names []string
	add := func(name string) error {
		if !conflictName.MatchString(name) {
			return ErrConflict
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
		return nil
	}
	for _, file := range files {
		if file.State == "enabled" || file.State == "enabled-runtime" {
			if err := add(file.Path[strings.LastIndexByte(file.Path, '/')+1:]); err != nil {
				return nil, err
			}
		}
	}
	for _, unit := range units {
		if unit.Active == "active" || unit.Active == "activating" || unit.Active == "reloading" {
			if err := add(unit.Name); err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(names)
	if len(names) > 8 {
		return nil, ErrConflict
	}
	return names, nil
}

func (b *systemdBus) Reload(ctx context.Context) error { return b.call(ctx, "Reload").Err }

// Runtime queues StartUnit, RestartUnit or StopUnit for the owned timer and
// waits until its job finished in the expected state.
func (b *systemdBus) Runtime(ctx context.Context, method string) error {
	want := "active"
	switch method {
	case "StartUnit", "RestartUnit":
	case "StopUnit":
		want = "inactive"
	default:
		return ErrUnsupported
	}
	var job dbus.ObjectPath
	if err := b.call(ctx, method, resource.OSUpdateTimerUnit, "fail").Store(&job); err != nil {
		return err
	}
	if !job.IsValid() {
		return ErrOutcomeUnknown
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		u, err := b.unit(ctx, resource.OSUpdateTimerUnit)
		if err != nil {
			return err
		}
		if !u.pending {
			if u.active == want {
				return nil
			}
			return fmt.Errorf("%w: %s is %s", ErrOutcomeUnknown, resource.OSUpdateTimerUnit, u.active)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
