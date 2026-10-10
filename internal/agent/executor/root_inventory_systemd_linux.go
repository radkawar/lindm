//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// PID 1's private socket is root-only and accepts direct peer-to-peer D-Bus.
// The executor does not use the system bus here: passing pipe descriptors
// through a bus broker requires the broker's own LSM permission to write the
// executor's pipe. Fedora 44 SELinux denies that for system_dbusd_t and the
// broker drops the connection; PID 1 receives the descriptors directly.
const (
	systemdPrivateSocket    = "/run/systemd/private"
	systemdManagerPath      = dbus.ObjectPath("/org/freedesktop/systemd1")
	systemdManager          = "org.freedesktop.systemd1.Manager"
	systemdUnitInterface    = "org.freedesktop.systemd1.Unit"
	systemdServiceInterface = "org.freedesktop.systemd1.Service"
	systemdProperties       = "org.freedesktop.DBus.Properties.PropertiesChanged"
	rootInventoryDrainDelay = 100 * time.Millisecond
	// Only signals about this connection's unit are queued; PID 1 emits a
	// handful per unit lifetime. Overflow fails the observation closed.
	rootInventorySignalLimit = 64
)

// siginfo si_code values reported by systemd as ExecMainCode.
const (
	cldExited int32 = 1
	cldKilled int32 = 2
	cldDumped int32 = 3
)

type systemdProperty struct {
	Name  string
	Value dbus.Variant
}

func newSystemdProperty(name string, value any) systemdProperty {
	return systemdProperty{Name: name, Value: dbus.MakeVariant(value)}
}

type systemdExec struct {
	Path          string
	Arguments     []string
	IgnoreFailure bool
}

type systemdList struct {
	AllowList bool
	Values    []string
}

type systemdAuxiliaryUnit struct {
	Name       string
	Properties []systemdProperty
}

// systemdUnitPath is PID 1's object path for unit (sd-bus label escaping).
func systemdUnitPath(unit string) dbus.ObjectPath {
	var path strings.Builder
	path.WriteString("/org/freedesktop/systemd1/unit/")
	for i := range len(unit) {
		c := unit[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (c >= '0' && c <= '9' && i > 0) {
			path.WriteByte(c)
			continue
		}
		fmt.Fprintf(&path, "_%02x", c)
	}
	return dbus.ObjectPath(path.String())
}

// systemdUnitSignals runs synchronously in the connection's read loop, so the
// queue preserves PID 1's emission order. It never blocks that loop.
type systemdUnitSignals struct {
	unit     string
	path     dbus.ObjectPath
	queue    chan *dbus.Signal
	overflow atomic.Bool
}

func (h *systemdUnitSignals) DeliverSignal(_, _ string, signal *dbus.Signal) {
	relevant := signal.Path == h.path && signal.Name == systemdProperties
	if signal.Path == systemdManagerPath && signal.Name == systemdManager+".JobRemoved" && len(signal.Body) == 4 {
		name, ok := signal.Body[2].(string)
		relevant = ok && name == h.unit
	}
	if !relevant {
		return
	}
	select {
	case h.queue <- signal:
	default:
		h.overflow.Store(true)
	}
}

type systemdPrivateUnit struct {
	conn    *dbus.Conn
	address string
	peerUID uint32
	signals *systemdUnitSignals
}

var _ rootInventoryUnits = (*systemdPrivateUnit)(nil)

func openSystemdPrivateUnit(ctx context.Context, unit string) (rootInventoryUnits, error) {
	units, err := openSystemdUnit(ctx, systemdPrivateSocket, 0, unit)
	if err != nil {
		return nil, err
	}
	return units, nil
}

// openSystemdUnit authenticates a direct connection to the manager listening on
// address, whose peer must run as peerUID (root for PID 1).
func openSystemdUnit(ctx context.Context, address string, peerUID uint32, unit string) (_ *systemdPrivateUnit, resultErr error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", address)
	if err != nil {
		return nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(errors.New("systemd private transport is not a Unix socket"), raw.Close())
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, socket.Close())
		}
	}()
	if err := requireSocketPeer(socket, peerUID); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, err
	}
	signals := &systemdUnitSignals{unit: unit, path: systemdUnitPath(unit), queue: make(chan *dbus.Signal, rootInventorySignalLimit)}
	conn, err := dbus.DialUnix(socket, dbus.WithSignalHandler(signals))
	if err != nil {
		return nil, err
	}
	// A direct connection has no bus driver: authenticate, but never Hello.
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := awaitSystemdRunning(ctx, conn); err != nil {
		return nil, errors.Join(fmt.Errorf("systemd private connection handshake: %w", err), conn.Close())
	}
	return &systemdPrivateUnit{conn: conn, address: address, peerUID: peerUID, signals: signals}, nil
}

// awaitSystemdRunning returns once PID 1 has answered a descriptor-free call.
// D-Bus lets a client send right after BEGIN, but an sd-bus server reads the
// authentication greedily: whatever arrives in the same read as BEGIN is
// either rejected with the connection (descriptors, "connection reset by
// peer") or left unparsed in its buffer until the socket becomes readable
// again. A busy PID 1 (package installation, daemon-reload, policy load) hits
// both. Each unanswered Ping is followed by another one: the new bytes wake
// PID 1, which then answers the stranded call as well.
func awaitSystemdRunning(ctx context.Context, conn *dbus.Conn) error {
	manager := conn.Object("org.freedesktop.systemd1", systemdManagerPath)
	replies := make(chan *dbus.Call, 32)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for delay, sent := 25*time.Millisecond, 0; ; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-conn.Context().Done():
			return errors.New("systemd private connection closed")
		case call := <-replies:
			return call.Err
		case <-timer.C:
			if sent == cap(replies) {
				return errors.New("systemd did not answer the connection handshake")
			}
			manager.GoWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", dbus.FlagNoAutoStart, replies)
			sent++
			timer.Reset(delay)
			delay = min(2*delay, time.Second)
		}
	}
}

func requireSocketPeer(socket *net.UnixConn, uid uint32) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		credential, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if credential == nil || credential.Uid != uid {
		return errors.New("systemd private socket peer has an unexpected owner")
	}
	return nil
}

func (u *systemdPrivateUnit) manager(ctx context.Context, method string, args ...any) *dbus.Call {
	return u.conn.Object("org.freedesktop.systemd1", systemdManagerPath).CallWithContext(ctx, systemdManager+"."+method, dbus.FlagNoAutoStart, args...)
}

// run passes fresh stdout/stderr pipes to PID 1, reads both concurrently with
// fixed bounds, and returns stdout only after the unit's main process exited 0.
func (u *systemdPrivateUnit) run(ctx context.Context, properties []systemdProperty) ([]byte, error) {
	stdout := &rootInventoryOutput{limit: rootInventoryOutputLimit}
	stderr := &rootInventoryOutput{limit: rootInventoryDiagnosticLimit}
	outputs := make([]*os.File, 0, 2)
	readers := make([]chan struct{}, 0, 2)
	writers := make([]*os.File, 0, 2)
	closeWriters := func() {
		for _, writer := range writers {
			_ = writer.Close()
		}
		writers = writers[:0]
	}
	defer func() {
		closeWriters()
		// Joining the readers never waits on PID 1 or the helper.
		for i, reader := range outputs {
			_ = reader.SetReadDeadline(time.Now())
			<-readers[i]
			_ = reader.Close()
		}
	}()
	for _, sink := range []*rootInventoryOutput{stdout, stderr} {
		reader, writer, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		done := make(chan struct{})
		outputs, readers, writers = append(outputs, reader), append(readers, done), append(writers, writer)
		go func() { defer close(done); _, _ = io.Copy(sink, reader) }()
		name := "StandardOutputFileDescriptor"
		if sink == stderr {
			name = "StandardErrorFileDescriptor"
		}
		properties = append(properties, newSystemdProperty(name, dbus.UnixFD(writer.Fd())))
	}
	var job dbus.ObjectPath
	err := u.manager(ctx, "StartTransientUnit", u.signals.unit, "fail", properties, []systemdAuxiliaryUnit{}).Store(&job)
	// PID 1 holds its own duplicates once the call was sent; keeping ours
	// would only delay end-of-file after the helper exits.
	closeWriters()
	if err != nil {
		return nil, fmt.Errorf("start transient unit: %w", err)
	}
	if !job.IsValid() || !strings.HasPrefix(string(job), "/org/freedesktop/systemd1/job/") {
		return nil, errors.New("systemd returned an invalid job path")
	}
	exit, err := awaitSystemdUnit(ctx, u.conn.Context(), u.signals, job)
	if err == nil {
		// The unit's cgroup is empty: every byte is already in the pipes.
		for _, reader := range outputs {
			_ = reader.SetReadDeadline(time.Now().Add(rootInventoryDrainDelay))
		}
		for _, done := range readers {
			<-done
		}
		if stdout.overflow || stderr.overflow {
			err = errors.New("root inventory unit output exceeds bound")
		} else if (exit.jobResult != "done" && exit.jobResult != "") || exit.unitResult != "success" || exit.code != cldExited || exit.status != 0 {
			err = errors.New("root inventory unit did not exit successfully")
		}
	}
	if err != nil || ctx.Err() != nil {
		return nil, &rootInventoryFailure{
			cause: errors.Join(err, ctx.Err()), jobResult: exit.jobResult, unitResult: exit.unitResult,
			exitCode: exit.code, exitStatus: exit.status, diagnostic: rootInventoryDiagnostic(stderr.buffer.Bytes()),
		}
	}
	return stdout.buffer.Bytes(), nil
}

type systemdUnitExit struct {
	jobResult, unitResult string
	code, status          int32
}

// awaitSystemdUnit waits until the unit's main process has exited and the unit
// is inactive or failed. A failed start job ends the wait after a short grace
// for the failure's exit status. PID 1 emits the Service properties (result and
// main-process status) before the Unit state in the same flush, and flushes a
// collected unit's final change before removing it. UnitRemoved is not
// terminal: daemon-reload sends it for every unit, including one that is still
// running, while it suppresses JobRemoved. A successful exit therefore does not
// require having observed JobRemoved.
func awaitSystemdUnit(ctx context.Context, disconnected context.Context, signals *systemdUnitSignals, job dbus.ObjectPath) (systemdUnitExit, error) {
	var exit systemdUnitExit
	var grace <-chan time.Time
	for {
		if signals.overflow.Load() {
			return exit, errors.New("systemd unit signal queue overflow")
		}
		var signal *dbus.Signal
		select {
		case <-ctx.Done():
			return exit, ctx.Err()
		case <-disconnected.Done():
			return exit, errors.New("systemd private connection closed")
		case <-grace:
			return exit, nil
		case signal = <-signals.queue:
		}
		switch signal.Name {
		case systemdManager + ".JobRemoved":
			if path, ok := signal.Body[1].(dbus.ObjectPath); ok && path == job {
				exit.jobResult, _ = signal.Body[3].(string)
				if exit.jobResult == "" {
					exit.jobResult = "invalid"
				}
				if exit.jobResult != "done" && grace == nil {
					timer := time.NewTimer(rootInventoryDrainDelay)
					defer timer.Stop()
					grace = timer.C
				}
			}
		case systemdProperties:
			if len(signal.Body) != 3 {
				continue
			}
			iface, _ := signal.Body[0].(string)
			changed, _ := signal.Body[1].(map[string]dbus.Variant)
			switch iface {
			case systemdServiceInterface:
				for name, target := range map[string]any{"Result": &exit.unitResult, "ExecMainCode": &exit.code, "ExecMainStatus": &exit.status} {
					if value, ok := changed[name]; ok {
						if err := value.Store(target); err != nil {
							return exit, fmt.Errorf("systemd service property %s: %w", name, err)
						}
					}
				}
			case systemdUnitInterface:
				// The inactive state reported before the main process ran has
				// no exit code; only a reaped main process ends the wait.
				state, ok := changed["ActiveState"]
				if !ok || exit.code == 0 {
					continue
				}
				if value, _ := state.Value().(string); value == "inactive" || value == "failed" {
					return exit, nil
				}
			}
		}
	}
}

// stop submits StopUnit and joins its job. An already collected unit is not an
// error: there is nothing left to stop.
func (u *systemdPrivateUnit) stop(ctx context.Context) (resultErr error) {
	if u.conn.Context().Err() != nil {
		// The lost connection may have delivered the start before it closed.
		// Its stop needs a live connection; never report a stale outcome.
		fresh, err := openSystemdUnit(ctx, u.address, u.peerUID, u.signals.unit)
		if err != nil {
			return fmt.Errorf("reconnect for stop: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, fresh.close()) }()
		return fresh.stop(ctx)
	}
	var job dbus.ObjectPath
	if err := u.manager(ctx, "StopUnit", u.signals.unit, "replace").Store(&job); err != nil {
		var native dbus.Error
		if errors.As(err, &native) && native.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return nil
		}
		return fmt.Errorf("stop transient unit: %w", err)
	}
	for {
		if u.signals.overflow.Load() {
			return errors.New("systemd unit signal queue overflow")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("await stop job: %w", ctx.Err())
		case <-u.conn.Context().Done():
			return errors.New("systemd private connection closed")
		case signal := <-u.signals.queue:
			if signal.Name != systemdManager+".JobRemoved" {
				continue
			}
			if path, ok := signal.Body[1].(dbus.ObjectPath); ok && path == job {
				if result, _ := signal.Body[3].(string); result != "done" {
					return fmt.Errorf("stop job result %q", result)
				}
				return nil
			}
		}
	}
}

func (u *systemdPrivateUnit) close() error {
	err := u.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
