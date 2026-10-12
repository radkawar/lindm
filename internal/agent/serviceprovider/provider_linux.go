//go:build linux

// Package serviceprovider manages existing canonical system services over a
// private native systemd connection. A plan is evidence, not execution authority:
// callers hold their resource fence and consume authority in Apply's callback.
// External systemd administrators can race observations and effects; this API is
// not a global systemd transaction or compare-and-swap operation.
// Enable/disable follows systemd's [Install] semantics, which can affect related
// links/units. Enabled/disabled evidence does not establish link ownership or
// authorize ownership-safe profile removal. Persistent link changes reload the
// native manager, which also incorporates other pending definitions. This
// provider never installs definitions. Its resourcev1 envelope binds the native
// evidence and reconcile operation; release refuses unknown prior ownership
// rather than inventing a restoration baseline.
package serviceprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

const Capability = "systemd.service.v1"

var (
	ErrUnsupported    = errors.New("unsupported service operation")
	ErrConflict       = errors.New("service precondition conflict")
	ErrOutcomeUnknown = errors.New("service effect outcome unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("service state not converged"))
	// ErrBaselineUnknown identifies release refusal without implying ownership
	// or a restorable baseline for preexisting native service state.
	ErrBaselineUnknown = errors.Join(ErrUnsupported, errors.New("baseline_unknown"))
)

const (
	setupTimeout     = 10 * time.Second
	operationTimeout = 90 * time.Second
	cleanupTimeout   = 5 * time.Second
	systemdName      = "org.freedesktop.systemd1"
	managerPath      = dbus.ObjectPath("/org/freedesktop/systemd1")
	managerInterface = "org.freedesktop.systemd1.Manager"
)

// Config contains executor-owned context, never transport-supplied native facts.
// Ownership binds the signed profile resource; it does not establish an undo
// baseline for preexisting systemd state. No ownership journal is consulted:
// release remains baseline_unknown rather than claiming a restorable ledger.
type Config struct {
	ExecutorIncarnation string
	Ownership           *agentv1.ResourceOwnershipBinding
	Platform            *resourcev1.PlatformProduct
}

// Provider serializes its own operations, but does not lock out external systemd
// clients. Close may interrupt an operation. A canceled in-flight operation can
// retire the connection; reopen it rather than retrying an uncertain effect.
// The zero value is not an open provider.
type Provider struct {
	conn              *dbus.Conn
	socket            *net.UnixConn
	owner             string
	gate              chan struct{}
	closeOnce         sync.Once
	closeErr          error
	incarnation       string
	backend           *resourcev1.BackendSelection
	ownershipRevision []byte
}

var _ resourceprovider.Provider = (*Provider)(nil)

// Open connects only to the root-owned peer at the fixed local system bus socket.
// ctx bounds dial, EXTERNAL authentication, Hello and subscription, not the
// lifetime of the returned connection. Interactive authorization is never used.
func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := validator(); err != nil {
		return nil, err
	}
	incarnation, err := uuid.Parse(config.ExecutorIncarnation)
	if err != nil || incarnation == uuid.Nil || incarnation.String() != config.ExecutorIncarnation || config.Ownership == nil || config.Platform == nil {
		return nil, fmt.Errorf("%w: missing executor context", ErrUnsupported)
	}
	if err := validateMessage(config.Ownership); err != nil {
		return nil, err
	}
	if err := validateMessage(config.Platform); err != nil {
		return nil, err
	}
	binding, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config.Ownership)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("lindm.systemd-ownership-baseline-unknown.v1\x00"))
	_, _ = hash.Write(binding)
	conn, socket, owner, err := dialSystemd(ctx)
	if err != nil {
		return nil, err
	}
	stop := closeOnCancel(ctx, socket)
	defer stop()
	p := &Provider{
		conn: conn, socket: socket, owner: owner, gate: make(chan struct{}, 1),
		incarnation: config.ExecutorIncarnation, ownershipRevision: hash.Sum(nil),
	}
	p.gate <- struct{}{}
	var version dbus.Variant
	if err := conn.Object(p.owner, managerPath).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, managerInterface, "Version").Store(&version); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("read systemd version: %w", err)
	}
	var nativeVersion string
	if err := version.Store(&nativeVersion); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("%w: systemd version: %v", ErrUnsupported, err)
	}
	p.backend = &resourcev1.BackendSelection{
		Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: nativeVersion,
		ProviderVersion: "systemd.service.v1", Product: proto.CloneOf(config.Platform),
	}
	if err := validateMessage(p.backend); err != nil {
		_ = p.Close()
		return nil, err
	}
	if err := p.manager(ctx, "Subscribe").Err; err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("subscribe systemd jobs: %w", err)
	}
	stop()
	if err := ctx.Err(); err != nil {
		_ = p.Close()
		return nil, err
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// dialSystemd authenticates to the root-owned system bus and resolves the
// root-owned systemd manager. The socket keeps ctx's deadline; callers clear it.
func dialSystemd(ctx context.Context) (*dbus.Conn, *net.UnixConn, string, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, nil, "", fmt.Errorf("connect system bus: %w", err)
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, nil, "", fmt.Errorf("%w: non-Unix system bus", ErrUnsupported)
	}
	stop := closeOnCancel(ctx, socket)
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		_ = socket.Close()
		return nil, nil, "", err
	}
	if err := rootPeer(socket); err != nil {
		_ = socket.Close()
		return nil, nil, "", err
	}
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		_ = socket.Close()
		return nil, nil, "", fmt.Errorf("authenticate system bus: %w", err)
	}
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, systemdName).Store(&owner); err != nil {
		_ = conn.Close()
		return nil, nil, "", fmt.Errorf("resolve systemd owner: %w", err)
	}
	var ownerUID uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&ownerUID); err != nil || ownerUID != 0 {
		_ = conn.Close()
		return nil, nil, "", fmt.Errorf("%w: systemd bus owner must be root: %v", ErrUnsupported, err)
	}
	return conn, socket, owner, nil
}

// EnableUnitFile persistently enables one installed unit file over the same
// authenticated systemd manager path resources use, then reloads the manager.
// It never starts the unit and never interacts with the caller.
func EnableUnitFile(ctx context.Context, unit string) error {
	if ctx == nil || unit == "" {
		return fmt.Errorf("%w: missing unit", ErrUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	conn, socket, owner, err := dialSystemd(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := closeOnCancel(ctx, socket)
	defer stop()
	manager := conn.Object(owner, managerPath)
	var carries bool
	var changes []struct{ Type, Path, Source string }
	if err := manager.CallWithContext(ctx, managerInterface+".EnableUnitFiles", dbus.FlagNoAutoStart, []string{unit}, false, false).Store(&carries, &changes); err != nil {
		return fmt.Errorf("enable unit file: %w", err)
	}
	if err := manager.CallWithContext(ctx, managerInterface+".Reload", dbus.FlagNoAutoStart).Err; err != nil {
		return fmt.Errorf("reload after enablement: %w", err)
	}
	return nil
}

func rootPeer(socket *net.UnixConn) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if peer == nil || peer.Uid != 0 {
		return fmt.Errorf("%w: system bus peer is not root", ErrUnsupported)
	}
	return nil
}

// closeOnCancel also bounds godbus's synchronous socket writes. Waiting for a
// started callback before returning prevents it from closing a later operation.
func closeOnCancel(ctx context.Context, socket *net.UnixConn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = socket.Close()
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		// Close the socket first: godbus Close can wait for an active writer.
		if p.socket != nil {
			p.closeErr = p.socket.Close()
		}
		if p.conn != nil {
			if err := p.conn.Close(); p.closeErr == nil {
				p.closeErr = err
			}
		}
		if errors.Is(p.closeErr, net.ErrClosed) {
			p.closeErr = nil
		}
	})
	return p.closeErr
}

func (p *Provider) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: nil context", ErrUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	if p == nil || p.conn == nil || p.socket == nil || p.gate == nil {
		cancel()
		return nil, nil, dbus.ErrClosed
	}
	select {
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	case <-p.gate:
	}
	if err := ctx.Err(); err != nil {
		p.gate <- struct{}{}
		cancel()
		return nil, nil, err
	}
	if err := p.conn.Context().Err(); err != nil {
		p.gate <- struct{}{}
		cancel()
		return nil, nil, dbus.ErrClosed
	}
	stop := closeOnCancel(ctx, p.socket)
	return ctx, func() {
		stop()
		cancel()
		p.gate <- struct{}{}
	}, nil
}

func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	if desired.GetSystemdService() == nil {
		return nil, fmt.Errorf("%w: non-systemd resource", ErrUnsupported)
	}
	unit := desired.GetSystemdService().GetUnit()
	if err := validateUnit(unit); err != nil {
		return nil, err
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	native, err := p.observe(ctx, unit)
	if err != nil {
		return nil, err
	}
	return observationEnvelope(native, p.incarnation, p.backend), nil
}

func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	if err := resource.ValidateDesired(desired); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if desired.GetSystemdService() == nil {
		return nil, fmt.Errorf("%w: non-systemd resource", ErrUnsupported)
	}
	switch operation {
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE:
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE:
		return nil, ErrBaselineUnknown
	default:
		return nil, fmt.Errorf("%w: unknown resource operation", ErrUnsupported)
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	before, err := p.observe(ctx, desired.GetSystemdService().GetUnit())
	if err != nil {
		return nil, err
	}
	return planFor(desired, observationEnvelope(before, p.incarnation, p.backend), p.ownershipRevision)
}

func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := p.checkBinding(plan, false); err != nil {
		return nil, err
	}
	return p.verify(ctx, plan)
}

func (p *Provider) verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	after, err := p.observe(ctx, plan.GetSystemdService().GetDesired().GetUnit())
	if err != nil {
		return nil, err
	}
	result, err := verification(plan, after, p.incarnation)
	if err != nil {
		return nil, err
	}
	if result.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		return result, ErrNotConverged
	}
	return result, nil
}

func (p *Provider) checkBinding(plan *resourcev1.ResourcePlan, applying bool) error {
	// Read-only restart reconciliation must not replay effects, but can report
	// fresh evidence for a RUNNING record admitted by a previous incarnation.
	if (applying && p.incarnation != plan.GetBefore().GetMetadata().GetExecutorIncarnation()) ||
		!proto.Equal(p.backend, plan.GetBackend()) ||
		!bytes.Equal(p.ownershipRevision, plan.GetOwnershipRevisionSha256()) {
		return fmt.Errorf("%w: executor or ownership binding changed", ErrConflict)
	}
	return nil
}
