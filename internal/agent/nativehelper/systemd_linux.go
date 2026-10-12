//go:build linux

package nativehelper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

const managerName = "org.freedesktop.systemd1"
const managerPath = dbus.ObjectPath("/org/freedesktop/systemd1")
const managerInterface = "org.freedesktop.systemd1.Manager"
const helperExecutable = "/usr/libexec/lindm/lindm-agent"
const transactionTimeout = 15 * time.Minute

type nativeBus struct {
	connection *dbus.Conn
	socket     *net.UnixConn
	owner      string
}

type unitProperty struct {
	Name  string
	Value dbus.Variant
}

type unitExec struct {
	Path          string
	Arguments     []string
	IgnoreFailure bool
}

type auxiliaryUnit struct {
	Name       string
	Properties []unitProperty
}

func openBus(ctx context.Context) (_ *nativeBus, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(errors.New("package_helper_bus_transport"), raw.Close())
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, socket.Close())
		}
	}()
	if err := requireRootPeer(socket); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, err
	}
	connection, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		return nil, err
	}
	bus := &nativeBus{connection: connection, socket: socket}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, connection.Close())
		}
	}()
	if err := connection.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, managerName).Store(&bus.owner); err != nil {
		return nil, err
	}
	var uid uint32
	if err := connection.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, bus.owner).Store(&uid); err != nil || uid != 0 {
		return nil, fmt.Errorf("package helper systemd owner not trusted: %w", errors.Join(err, errors.New("systemd_owner_not_root")))
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return bus, nil
}

func (bus *nativeBus) close() error {
	socketErr := bus.socket.Close()
	if errors.Is(socketErr, net.ErrClosed) {
		socketErr = nil
	}
	connectionErr := bus.connection.Close()
	if errors.Is(connectionErr, net.ErrClosed) {
		connectionErr = nil
	}
	return errors.Join(socketErr, connectionErr)
}

func unitName(transactionID, phase string) string {
	return "lindm-package-" + transactionID + "-" + phase + ".service"
}

func transientProperties(directory, transactionID, phase string) []unitProperty {
	apply := phase == "apply"
	property := func(name string, value any) unitProperty {
		return unitProperty{Name: name, Value: dbus.MakeVariant(value)}
	}
	paths := []string{directory}
	families := []string{"AF_UNIX", "AF_INET", "AF_INET6"}
	capabilities := uint64(1) << unix.CAP_DAC_READ_SEARCH
	if apply {
		paths = append(paths, "/etc", "/usr", "/var", "/run", "-/opt", "-/boot")
		families = []string{"AF_UNIX", "AF_NETLINK"}
		for _, capability := range []uint{unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FOWNER, unix.CAP_FSETID, unix.CAP_KILL, unix.CAP_SETGID, unix.CAP_SETUID, unix.CAP_SETFCAP, unix.CAP_SYS_CHROOT} {
			capabilities |= uint64(1) << capability
		}
	}
	return []unitProperty{
		property("Description", "Lindm bounded native package transaction"),
		property("Type", "exec"),
		property("User", "root"), property("Group", "root"),
		property("ExecStart", []unitExec{{Path: helperExecutable, Arguments: []string{helperExecutable, "package-transaction", "-transaction", transactionID, "-phase", phase}}}),
		property("Restart", "no"), property("RuntimeMaxUSec", uint64(transactionTimeout/time.Microsecond)),
		property("TimeoutStopUSec", uint64(30*time.Second/time.Microsecond)),
		property("KillMode", "control-group"), property("UMask", uint32(0077)),
		property("StandardOutput", "journal"), property("StandardError", "journal"),
		property("WorkingDirectory", directory), property("ProtectSystem", "strict"),
		property("ProtectHome", "yes"), property("PrivateDevices", true), property("PrivateTmp", true),
		property("ProtectKernelTunables", true), property("ProtectKernelModules", true),
		property("ProtectKernelLogs", true), property("ProtectControlGroups", true),
		// RPM's SELinux plugin runs scriptlets in rpm_script_t; under
		// NoNewPrivileges that exec is refused and every scriptlet exits 127.
		property("NoNewPrivileges", !apply), property("RestrictSUIDSGID", !apply),
		property("CapabilityBoundingSet", capabilities), property("ReadWritePaths", paths),
		property("PrivateNetwork", apply), property("RestrictAddressFamilies", struct {
			AllowList bool
			Families  []string
		}{true, families}),
		property("LimitCORE", uint64(0)), property("MemorySwapMax", uint64(0)),
	}
}

// packageProperties confines one package transaction phase. zypper refuses
// every transaction while / itself is a read-only mount ("The target
// filesystem is mounted as read-only", exit 5), even with /etc, /usr and /var
// writable as ProtectSystem=strict's ReadWritePaths leave them, so a zypper
// apply unit also keeps / writable; every other confinement is unchanged.
func packageProperties(directory string, request *agentv1.NativePackageTransactionRequest, phase string) []unitProperty {
	properties := transientProperties(directory, request.GetTransactionId(), phase)
	if phase != "apply" || platform.Of(request.GetPlatform()).Native().Packages.Backend != platform.BackendZypper {
		return properties
	}
	for i := range properties {
		if paths, ok := properties[i].Value.Value().([]string); ok && properties[i].Name == "ReadWritePaths" {
			properties[i].Value = dbus.MakeVariant(append(slices.Clone(paths), "/"))
		}
	}
	return properties
}

func (bus *nativeBus) start(ctx context.Context, directory string, request *agentv1.NativePackageTransactionRequest, phase string) error {
	properties := transientProperties(directory, request.GetTransactionId(), phase)
	if phase == "prepare" && request.CandidatePinContents != nil {
		// The fixed existing destination (DNF5 versionlock.toml or the DNF4
		// plugin list) is custody-checked immediately before launch. Only the
		// staging unit sees the candidate lock; the host does not.
		properties = append(properties, unitProperty{Name: "BindReadOnlyPaths", Value: dbus.MakeVariant([]struct {
			Source        string
			Destination   string
			IgnoreMissing bool
			Flags         uint64
		}{{filepath.Join(directory, candidatePinName), request.GetOriginalPin().GetPath(), false, 0}})})
	}
	return bus.startUnit(ctx, unitName(request.GetTransactionId(), phase), properties)
}

func (bus *nativeBus) startUnit(ctx context.Context, name string, properties []unitProperty) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = bus.socket.Close() })
	defer stop()
	var job dbus.ObjectPath
	err := bus.connection.Object(bus.owner, managerPath).CallWithContext(ctx, managerInterface+".StartTransientUnit", dbus.FlagNoAutoStart,
		name, "fail", properties, []auxiliaryUnit{}).Store(&job)
	if err != nil {
		return fmt.Errorf("start native package unit: %w", err)
	}
	if !job.IsValid() {
		return errors.New("package_helper_invalid_systemd_job")
	}
	return nil
}

func (bus *nativeBus) stop(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = bus.socket.Close() })
	defer stop()
	return bus.connection.Object(bus.owner, managerPath).CallWithContext(ctx, managerInterface+".StopUnit", dbus.FlagNoAutoStart, name, "replace").Err
}

func (bus *nativeBus) active(ctx context.Context, name string) (bool, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var path dbus.ObjectPath
	err := bus.connection.Object(bus.owner, managerPath).CallWithContext(ctx, managerInterface+".GetUnit", dbus.FlagNoAutoStart, name).Store(&path)
	if err != nil {
		var native dbus.Error
		if errors.As(err, &native) && native.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return false, false, nil
		}
		return false, false, err
	}
	var state dbus.Variant
	if err := bus.connection.Object(bus.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, managerName+".Unit", "ActiveState").Store(&state); err != nil {
		return false, true, err
	}
	value, ok := state.Value().(string)
	if !ok {
		return false, true, errors.New("package_helper_unit_state_invalid")
	}
	switch value {
	case "active", "activating", "deactivating", "reloading":
		return true, true, nil
	case "inactive", "failed":
		return false, true, nil
	default:
		return false, true, errors.New("package_helper_unit_state_unknown")
	}
}
