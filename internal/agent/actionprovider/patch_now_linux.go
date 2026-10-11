//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/resource"
)

const (
	systemdName    = "org.freedesktop.systemd1"
	systemdManager = "org.freedesktop.systemd1.Manager"
	systemdUnit    = "org.freedesktop.systemd1.Unit"
	systemdPath    = dbus.ObjectPath("/org/freedesktop/systemd1")

	// A patch-now request is consumed by the runner immediately; this bounds a
	// request left behind by a unit that never started.
	patchNowRequestLifetime = 10 * time.Minute
	patchNowEvidence        = "native_patch_run_started"
)

// systemdBus resolves objects owned by the authenticated root systemd
// connection. The connection pins that owner throughout check and effect.
type systemdBus interface {
	Object(dbus.ObjectPath) powerBus
}

type rootSystemd struct {
	conn  *dbus.Conn
	owner string
}

func (r rootSystemd) Object(path dbus.ObjectPath) powerBus {
	return r.conn.Object(r.owner, path)
}

func openSystemd(ctx context.Context) (systemdBus, func() error, error) {
	conn, owner, closeConnection, err := openRootSystemBus(ctx, systemdName)
	if err != nil {
		return nil, nil, err
	}
	return rootSystemd{conn: conn, owner: owner}, closeConnection, nil
}

// unitState loads (never starts) a unit and returns its load and active state.
func unitState(ctx context.Context, bus systemdBus, name string) (string, string, error) {
	var path dbus.ObjectPath
	if err := bus.Object(systemdPath).CallWithContext(ctx, systemdManager+".LoadUnit", dbus.FlagNoAutoStart, name).Store(&path); err != nil {
		return "", "", err
	}
	if !path.IsValid() {
		return "", "", ErrUnsupported
	}
	unit := bus.Object(path)
	var load, active dbus.Variant
	if err := unit.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, systemdUnit, "LoadState").Store(&load); err != nil {
		return "", "", err
	}
	if err := unit.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, systemdUnit, "ActiveState").Store(&active); err != nil {
		return "", "", err
	}
	loadState, ok := load.Value().(string)
	activeState, ok2 := active.Value().(string)
	if !ok || !ok2 {
		return "", "", ErrUnsupported
	}
	return loadState, activeState, nil
}

// inspectPatchRun requires the packaged patch-now unit and refuses while either
// lindm run unit is running; the runner's lock is not a queue for this action.
func inspectPatchRun(ctx context.Context, bus systemdBus) error {
	load, active, err := unitState(ctx, bus, resource.OSUpdateNowUnit)
	if err != nil {
		return err
	}
	if load != "loaded" {
		return fmt.Errorf("%w: patch_run_unit_missing", ErrUnsupported)
	}
	if patchUnitBusy(active) {
		return fmt.Errorf("%w: patch_run_in_progress", ErrConflict)
	}
	load, active, err = unitState(ctx, bus, resource.OSUpdateServiceUnit)
	if err != nil {
		return err
	}
	if load == "loaded" && patchUnitBusy(active) {
		return fmt.Errorf("%w: patch_run_in_progress", ErrConflict)
	}
	return nil
}

func patchUnitBusy(active string) bool {
	switch active {
	case "active", "activating", "deactivating", "reloading", "refreshing":
		return true
	}
	return false
}

func (p *Provider) observePatchNow(ctx context.Context) (_ *agentv1.DeviceActionObservation, err error) {
	observation := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock())}
	if !p.config.GetAllowPatchNow() || p.openSystemd == nil || p.bootID == nil {
		observation.Reason = "patch_now_not_qualified"
		return observation, nil
	}
	observation.BootId, err = p.bootID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bus, closeBus, err := p.openSystemd(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeBus()) }()
	err = inspectPatchRun(ctx, bus)
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

// applyPatchNow reobserves on the same authenticated connection before
// consuming durable authority, hands the runner one bounded request and starts
// its static unit. Job completion and installation are never awaited here.
func (p *Provider) applyPatchNow(ctx context.Context, plan *agentv1.DeviceActionPlan, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	if !p.config.GetAllowPatchNow() || p.openSystemd == nil || p.bootID == nil || p.patchNowDir == "" {
		return nil, ErrUnsupported
	}
	action := plan.GetSpec().GetPatchNow()
	if action == nil || plan.GetActionId() == "" {
		return nil, ErrConflict
	}
	boot, err := p.bootID()
	if err != nil {
		return nil, err
	}
	if boot == "" || boot != plan.GetBefore().GetBootId() {
		return nil, ErrConflict
	}
	now := p.clock()
	lifetime := patchNowRequestLifetime
	// The executor bounds the caller context by the signed action expiry.
	if deadline, ok := ctx.Deadline(); ok {
		lifetime = min(lifetime, time.Until(deadline))
	}
	if lifetime <= 0 {
		return nil, ErrConflict
	}
	notAfter := now.Add(lifetime)
	request := &agentv1.OSUpdatePatchNowRequest{ActionId: plan.GetActionId(), Selection: action.GetSelection(), RebootPolicy: proto.CloneOf(action.GetRebootPolicy()), RequestedAt: timestamppb.New(now), NotAfter: timestamppb.New(notAfter)}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bus, closeBus, err := p.openSystemd(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeBus()) }()
	if err := inspectPatchRun(ctx, bus); err != nil {
		return nil, err
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if err := writePatchNowRequest(p.patchNowDir, encoded); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	// "fail" refuses to replace a queued conflicting job; the unit's own
	// runner lock serializes against the window and status units.
	var job dbus.ObjectPath
	if err := bus.Object(systemdPath).CallWithContext(ctx, systemdManager+".StartUnit", dbus.FlagNoAutoStart, resource.OSUpdateNowUnit, "fail").Store(&job); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return &agentv1.DeviceActionVerification{
		Verified: true, PatchRunStarted: true, Evidence: patchNowEvidence,
		After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true, BootId: boot},
	}, nil
}

// writePatchNowRequest atomically replaces the single request in a private
// root-owned directory. The parent (/run/lindm) is the executor's own runtime
// directory; only the leaf is created here.
func writePatchNowRequest(dir string, encoded []byte) (err error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		return fmt.Errorf("%w: patch_now_directory_untrusted", ErrConflict)
	}
	file, err := os.CreateTemp(dir, ".patch-now-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(temp)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, filepath.Join(dir, filepath.Base(resource.OSUpdatePatchNowRequestPath))); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
