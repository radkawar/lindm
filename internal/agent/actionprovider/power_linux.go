// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// powerBus is the native D-Bus boundary, not a replacement power state machine.
// The connection pins the authenticated logind owner throughout check and effect.
type powerBus interface {
	CallWithContext(context.Context, string, dbus.Flags, ...any) *dbus.Call
}

type powerRequest struct {
	method  string
	kind    string
	delay   uint32
	message string
}

func powerAction(spec *agentv1.DeviceActionSpec) (powerRequest, bool) {
	if action := spec.GetRestart(); action != nil {
		return powerRequest{"Reboot", "reboot", action.GetDelaySeconds(), action.GetMessage()}, true
	}
	if action := spec.GetShutdown(); action != nil {
		return powerRequest{"PowerOff", "poweroff", action.GetDelaySeconds(), action.GetMessage()}, true
	}
	return powerRequest{}, false
}

// openLogindPower uses neither environment-selected buses nor autoactivation.
// A bounded socket and root peer/owner checks match the session provider boundary.
func openLogindPower(ctx context.Context) (powerBus, func() error, error) {
	conn, owner, closeConnection, err := openRootSystemBus(ctx, logindName)
	if err != nil {
		return nil, nil, err
	}
	return conn.Object(owner, logindPath), closeConnection, nil
}

// openRootSystemBus dials the fixed system bus socket, requires a root bus peer
// and a root-owned connection for the well-known name, and returns that owner.
func openRootSystemBus(ctx context.Context, name string) (_ *dbus.Conn, _ string, _ func() error, err error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, "", nil, err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, "", nil, ErrUnsupported
	}
	defer func() {
		if err != nil {
			_ = socket.Close()
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, "", nil, ErrUnsupported
	}
	if err := socket.SetDeadline(deadline); err != nil {
		return nil, "", nil, err
	}
	fd, err := socket.SyscallConn()
	if err != nil {
		return nil, "", nil, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := fd.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, "", nil, err
	}
	if peerErr != nil || peer == nil || peer.Uid != 0 {
		return nil, "", nil, fmt.Errorf("%w: untrusted_system_bus", ErrUnsupported)
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
		return nil, "", nil, err
	}
	closeConnection := func() error {
		stopCancellation()
		return conn.Close()
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeConnection())
		}
	}()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, name).Store(&owner); err != nil {
		return nil, "", nil, err
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil {
		return nil, "", nil, err
	}
	if uid != 0 {
		return nil, "", nil, fmt.Errorf("%w: untrusted_bus_name_owner", ErrUnsupported)
	}
	return conn, owner, closeConnection, nil
}

func powerBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return "", fmt.Errorf("%w: boot_identity_unavailable", ErrUnsupported)
	}
	return value, nil
}

func (p *Provider) observePower(ctx context.Context, spec *agentv1.DeviceActionSpec) (_ *agentv1.DeviceActionObservation, err error) {
	observation := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock())}
	if !p.config.GetAllowPowerActions() || p.openPower == nil || p.bootID == nil {
		observation.Reason = "power_actions_not_qualified"
		return observation, nil
	}
	observation.BootId, err = p.bootID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bus, closeBus, err := p.openPower(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeBus()) }()
	request, _ := powerAction(spec)
	_, err = inspectPower(ctx, bus, request)
	if errors.Is(err, ErrUnsupported) || errors.Is(err, ErrConflict) {
		observation.Reason = err.Error()
		return observation, nil
	}
	if err != nil {
		return nil, err
	}
	observation.Supported = true
	return observation, nil
}

type powerInhibitor struct {
	What string
	Who  string
	Why  string
	Mode string
	UID  uint32
	PID  uint32
}

// inspectPower refuses existing schedules rather than replacing even an identical
// request owned by another actor. Delay inhibitors remain logind's responsibility.
func inspectPower(ctx context.Context, bus powerBus, request powerRequest) (bool, error) {
	var description string
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.Introspectable.Introspect", dbus.FlagNoAutoStart).Store(&description); err != nil {
		return false, err
	}
	if len(description) > 128<<10 {
		return false, ErrUnsupported
	}
	var node introspect.Node
	if err := xml.Unmarshal([]byte(description), &node); err != nil {
		return false, err
	}
	hasMethod := func(name string) bool {
		for _, iface := range node.Interfaces {
			if iface.Name == logindManager {
				for _, method := range iface.Methods {
					if method.Name == name {
						return true
					}
				}
			}
		}
		return false
	}
	method := request.method + "WithFlags"
	if request.delay != 0 {
		method = "ScheduleShutdown"
	}
	if !hasMethod(method) || !hasMethod("Can"+request.method) || !hasMethod("ListInhibitors") {
		return false, fmt.Errorf("%w: native_power_method_unavailable", ErrUnsupported)
	}
	var capability string
	if err := bus.CallWithContext(ctx, logindManager+".Can"+request.method, dbus.FlagNoAutoStart).Store(&capability); err != nil {
		return false, err
	}
	if capability != "yes" {
		return false, fmt.Errorf("%w: native_power_not_authorized", ErrUnsupported)
	}
	var properties map[string]dbus.Variant
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, logindManager).Store(&properties); err != nil {
		return false, err
	}
	preparing, ok := properties["PreparingForShutdown"].Value().(bool)
	if !ok {
		return false, ErrUnsupported
	}
	var scheduled struct {
		Kind string
		Usec uint64
	}
	value, ok := properties["ScheduledShutdown"]
	if !ok || dbus.Store([]any{value.Value()}, &scheduled) != nil {
		return false, ErrUnsupported
	}
	// logind exposes USEC_INFINITY when no operation is scheduled.
	if preparing || scheduled.Kind != "" || (scheduled.Usec != 0 && scheduled.Usec != ^uint64(0)) {
		return false, fmt.Errorf("%w: native_power_already_pending", ErrConflict)
	}
	var inhibitors []powerInhibitor
	if err := bus.CallWithContext(ctx, logindManager+".ListInhibitors", dbus.FlagNoAutoStart).Store(&inhibitors); err != nil {
		return false, err
	}
	for _, inhibitor := range inhibitors {
		if slices.Contains(strings.Split(inhibitor.What, ":"), "shutdown") && inhibitor.Mode != "delay" {
			return false, fmt.Errorf("%w: native_power_inhibited", ErrConflict)
		}
	}
	return hasMethod("SetWallMessage"), nil
}

// applyPower reobserves on the same authenticated connection before consuming
// durable authority. A reply proves acceptance only; neither power loss nor a
// changed boot has been observed here. There is no retry or schedule cancellation.
func (p *Provider) applyPower(ctx context.Context, plan *agentv1.DeviceActionPlan, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	if !p.config.GetAllowPowerActions() || p.openPower == nil || p.bootID == nil {
		return nil, ErrUnsupported
	}
	boot, err := p.bootID()
	if err != nil {
		return nil, err
	}
	if boot == "" || boot != plan.GetBefore().GetBootId() {
		return nil, ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bus, closeBus, err := p.openPower(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeBus()) }()
	request, _ := powerAction(plan.GetSpec())
	wall, err := inspectPower(ctx, bus, request)
	if err != nil {
		return nil, err
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if request.message != "" && wall {
		if err := bus.CallWithContext(ctx, logindManager+".SetWallMessage", dbus.FlagNoAutoStart, request.message, true).Err; err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		// Wall-message authorization does not extend the signed power deadline.
		// The executor rechecks the consumed authority without consuming twice.
		if err := gate(ctx); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if request.delay != 0 {
		deadline := p.clock().Add(time.Duration(request.delay) * time.Second).UnixMicro()
		err = bus.CallWithContext(ctx, logindManager+".ScheduleShutdown", dbus.FlagNoAutoStart, request.kind, uint64(deadline)).Err
	} else {
		// ROOT_CHECK_INHIBITORS closes the check/request race even for root on
		// older logind. Never fall back to the inhibitor-bypassing legacy call.
		err = bus.CallWithContext(ctx, logindManager+"."+request.method+"WithFlags", dbus.FlagNoAutoStart, uint64(1)).Err
	}
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return &agentv1.DeviceActionVerification{
		BootId: boot, PowerRequestAccepted: true,
		Evidence: "outcome_unknown_until_contact",
		After:    &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true, BootId: boot},
	}, nil
}
