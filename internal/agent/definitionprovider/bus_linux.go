//go:build linux

package definitionprovider

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
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/serviceprovider"
)

const systemdName = "org.freedesktop.systemd1"
const managerPath = dbus.ObjectPath("/org/freedesktop/systemd1")

type unitView struct {
	id, fragment, active, fileState string
	dropIns                         []string
	pending, reload                 bool
	invocation                      []byte
	properties                      map[string]dbus.Variant
}

type nativeManager interface {
	Version() string
	Unit(context.Context, string, string) (*unitView, error)
	Links(context.Context, string) ([]*resourcev1.InstallLink, error)
	Reload(context.Context) error
	Enable(context.Context, string, bool) error
	Runtime(context.Context, string, bool) error
	Close() error
}

type systemdBus struct {
	conn           *dbus.Conn
	socket         *net.UnixConn
	owner, version string
}

var _ nativeManager = (*systemdBus)(nil)

func openBus(ctx context.Context) (_ nativeManager, err error) {
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
		return nil, errors.Join(ErrProtected, peerErr)
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
		return nil, errors.Join(ErrProtected, err)
	}
	var version dbus.Variant
	if err := b.conn.Object(b.owner, managerPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, systemdName+".Manager", "Version").Store(&version); err != nil {
		return nil, err
	}
	if err := version.Store(&b.version); err != nil {
		return nil, err
	}
	// Version strings may carry a distro suffix; native properties and verify
	// independently fail closed when a requested facility is unavailable.
	parts := strings.Fields(b.version)
	if len(parts) == 0 {
		return nil, ErrUnsupported
	}
	major, err := strconv.Atoi(strings.SplitN(parts[0], ".", 2)[0])
	if err != nil || major < 255 {
		return nil, fmt.Errorf("%w: systemd 255 or newer required", ErrUnsupported)
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *systemdBus) Version() string { return b.version }
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
func absentUnit(err error) bool {
	var e dbus.Error
	return errors.As(err, &e) && (e.Name == "org.freedesktop.systemd1.NoSuchUnit" || e.Name == "org.freedesktop.systemd1.NoSuchUnitFile" || e.Name == "org.freedesktop.DBus.Error.FileNotFound")
}
func (b *systemdBus) Unit(ctx context.Context, name, kind string) (*unitView, error) {
	var path dbus.ObjectPath
	if err := b.call(ctx, "LoadUnit", name).Store(&path); err != nil {
		if absentUnit(err) {
			return nil, nil
		}
		return nil, err
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return nil, ErrUnsupported
	}
	var values map[string]dbus.Variant
	object := b.conn.Object(b.owner, path)
	if err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+".Unit").Store(&values); err != nil {
		return nil, err
	}
	var id, load string
	var names []string
	var transient bool
	for _, field := range []struct {
		key string
		out any
	}{{"Id", &id}, {"Names", &names}, {"LoadState", &load}, {"Transient", &transient}} {
		if err := property(values, field.key, field.out); err != nil {
			return nil, err
		}
	}
	if err := canonicalUnit(name, id, names); err != nil {
		return nil, err
	}
	if load == "not-found" {
		return nil, nil
	}
	if load != "loaded" || transient {
		return nil, fmt.Errorf("%w: nonpersistent or unloaded unit", ErrUnsupported)
	}
	v := &unitView{id: id}
	var job struct {
		ID   uint32
		Path dbus.ObjectPath
	}
	for _, field := range []struct {
		key string
		out any
	}{{"FragmentPath", &v.fragment}, {"DropInPaths", &v.dropIns}, {"ActiveState", &v.active}, {"NeedDaemonReload", &v.reload}, {"InvocationID", &v.invocation}, {"Job", &job}} {
		if err := property(values, field.key, field.out); err != nil {
			return nil, err
		}
	}
	v.pending = job.ID != 0 || job.Path != "/"
	if v.fragment == "" || len(v.dropIns) > 64 {
		return nil, ErrUnsupported
	}
	if err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+"."+kind).Store(&v.properties); err != nil {
		return nil, err
	}
	if kind == "Timer" {
		if err := b.call(ctx, "GetUnitFileState", name).Store(&v.fileState); err != nil {
			return nil, err
		}
	}
	return v, nil
}
func (b *systemdBus) Links(ctx context.Context, name string) ([]*resourcev1.InstallLink, error) {
	var all []*resourcev1.InstallLink
	for _, runtime := range []bool{false, true} {
		var links []string
		if err := b.call(ctx, "GetUnitFileLinks", name, runtime).Store(&links); err != nil {
			if absentUnit(err) {
				continue
			}
			return nil, err
		}
		if len(links) > 128 {
			return nil, ErrUnsupported
		}
		for _, path := range links {
			// The only supported install effect is the deterministic WantedBy.
			if runtime || path != unitRoot+"/timers.target.wants/"+name {
				return nil, fmt.Errorf("%w: unrelated timer install link", ErrConflict)
			}
			link, err := captureLink(path, unitRoot+"/"+name)
			if err != nil {
				return nil, err
			}
			all = append(all, link)
		}
	}
	slices.SortFunc(all, func(a, b *resourcev1.InstallLink) int { return strings.Compare(a.GetPath(), b.GetPath()) })
	if len(all) > 1 {
		return nil, ErrConflict
	}
	return all, nil
}
func (b *systemdBus) Reload(ctx context.Context) error { return b.call(ctx, "Reload").Err }
func (b *systemdBus) Enable(ctx context.Context, name string, enabled bool) error {
	var changes []struct{ Type, Path, Source string }
	if enabled {
		var carries bool
		if err := b.call(ctx, "EnableUnitFiles", []string{name}, false, false).Store(&carries, &changes); err != nil {
			return err
		}
		if !carries {
			return ErrNotConverged
		}
	} else {
		if err := b.call(ctx, "DisableUnitFiles", []string{name}, false).Store(&changes); err != nil {
			return err
		}
	}
	for _, change := range changes {
		if change.Path != unitRoot+"/timers.target.wants/"+name || (enabled && (change.Type != "symlink" || change.Source != unitRoot+"/"+name)) || (!enabled && change.Type != "unlink") {
			return ErrOutcomeUnknown
		}
	}
	return nil
}
func (b *systemdBus) Runtime(ctx context.Context, name string, active bool) error {
	method := "StopUnit"
	if active {
		method = "StartUnit"
	}
	var job dbus.ObjectPath
	if err := b.call(ctx, method, name, "fail").Store(&job); err != nil {
		return err
	}
	if !job.IsValid() {
		return ErrOutcomeUnknown
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		v, err := b.Unit(ctx, name, "Timer")
		if err != nil {
			return err
		}
		if v != nil && !v.pending {
			if (active && v.active == "active") || (!active && v.active == "inactive") {
				return nil
			}
			return ErrNotConverged
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func targetFingerprint(ctx context.Context, v *unitView, ownedPath string) ([]byte, error) {
	drops := make([]string, 0, len(v.dropIns))
	for _, path := range v.dropIns {
		if path != ownedPath {
			drops = append(drops, path)
		}
	}
	return serviceprovider.DefinitionFingerprint(ctx, v.fragment, drops)
}
func effectiveOptions(v *unitView) (*resourcev1.SystemdEffectiveOptions, error) {
	o := &resourcev1.SystemdEffectiveOptions{}
	for _, field := range []struct {
		key string
		out any
	}{{"CPUWeight", &o.CpuWeight}, {"MemoryMax", &o.MemoryMax}, {"TasksMax", &o.TasksMax}, {"NoNewPrivileges", &o.NoNewPrivileges}} {
		if err := property(v.properties, field.key, field.out); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type monotonicTimer struct {
	Base        string
	Value, Next uint64
}
type calendarTimer struct {
	Base, Spec string
	Next       uint64
}

func timerSchedule(v *unitView) (*resourcev1.TimerDefinition, []byte, error) {
	var mono []monotonicTimer
	var calendar []calendarTimer
	var unit string
	var accuracy, random uint64
	var persistent, wake, onClock, onZone bool
	for _, field := range []struct {
		key string
		out any
	}{{"TimersMonotonic", &mono}, {"TimersCalendar", &calendar}, {"Unit", &unit}, {"AccuracyUSec", &accuracy}, {"RandomizedDelayUSec", &random}, {"Persistent", &persistent}, {"WakeSystem", &wake}, {"OnClockChange", &onClock}, {"OnTimezoneChange", &onZone}} {
		if err := property(v.properties, field.key, field.out); err != nil {
			return nil, nil, err
		}
	}
	if accuracy != 1000000 || random != 0 || persistent || wake || onClock || onZone || protectedUnit(unit) {
		return nil, nil, ErrUnsupported
	}
	t := &resourcev1.TimerDefinition{Unit: v.id, Service: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: unit}, Enabled: v.fileState == "enabled"}
	if len(calendar) == 1 && len(mono) == 0 && calendar[0].Base == "OnCalendar" {
		var hour, minute uint32
		if _, err := fmt.Sscanf(calendar[0].Spec, "*-*-* %02d:%02d:00 UTC", &hour, &minute); err != nil || calendar[0].Spec != fmt.Sprintf("*-*-* %02d:%02d:00 UTC", hour, minute) {
			return nil, nil, ErrUnsupported
		}
		t.Schedule = &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_Daily{Daily: &resourcev1.DailyTimerSchedule{Hour: hour, Minute: minute}}}
	} else if len(calendar) == 0 && len(mono) == 2 {
		slices.SortFunc(mono, func(a, b monotonicTimer) int { return strings.Compare(a.Base, b.Base) })
		if mono[0].Base != "OnActiveUSec" || mono[1].Base != "OnUnitActiveUSec" || mono[0].Value != mono[1].Value || mono[0].Value%1000000 != 0 || mono[0].Value/1000000 > 31536000 {
			return nil, nil, ErrUnsupported
		}
		t.Schedule = &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_IntervalSeconds{IntervalSeconds: uint32(mono[0].Value / 1000000)}}
	} else {
		return nil, nil, ErrUnsupported
	}
	if err := validateMessage(t); err != nil {
		return nil, nil, err
	}
	stable := proto.CloneOf(t)
	stable.Enabled = false
	digest, err := messageDigest(stable)
	return t, digest, err
}
func emptyDigest() []byte { d := sha256.Sum256(nil); return d[:] }

func canonicalUnit(requested, id string, names []string) error {
	if len(names) > 128 {
		return ErrUnsupported
	}
	if requested != id || protectedUnit(id) {
		return ErrProtected
	}
	for _, alias := range names {
		if protectedUnit(alias) {
			return ErrProtected
		}
	}
	return nil
}
