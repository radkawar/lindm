//go:build linux

// Package serviceprovider manages existing canonical system services over a
// private native systemd connection. A plan is evidence, not execution authority:
// callers must hold their resource lock and durably authorize a start themselves.
// External systemd administrators can race observations and effects; this API is
// not a global systemd transaction or compare-and-swap operation.
// Enable/disable follows systemd's [Install] semantics, which can affect related
// links/units. Enabled/disabled evidence does not establish link ownership or
// authorize ownership-safe profile removal. Persistent link changes reload the
// native manager, which also incorporates other pending definitions. This
// provider never installs definitions.
package serviceprovider

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
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const Capability = "systemd.service.v1"

var (
	ErrUnsupported    = errors.New("unsupported service operation")
	ErrConflict       = errors.New("service precondition conflict")
	ErrOutcomeUnknown = errors.New("service effect outcome unknown")
	ErrNotConverged   = errors.New("service state not converged")
)

const (
	setupTimeout     = 10 * time.Second
	operationTimeout = 90 * time.Second
	cleanupTimeout   = 5 * time.Second
	systemdName      = "org.freedesktop.systemd1"
	managerPath      = dbus.ObjectPath("/org/freedesktop/systemd1")
	managerInterface = "org.freedesktop.systemd1.Manager"
)

// Provider serializes its own operations, but does not lock out external systemd
// clients. Close may interrupt an operation. A canceled in-flight operation can
// retire the connection; reopen it rather than retrying an uncertain effect.
// The zero value is not an open provider.
type Provider struct {
	conn      *dbus.Conn
	socket    *net.UnixConn
	owner     string
	gate      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Open connects only to the root-owned peer at the fixed local system bus socket.
// ctx bounds dial, EXTERNAL authentication, Hello and subscription, not the
// lifetime of the returned connection. Interactive authorization is never used.
func Open(ctx context.Context) (*Provider, error) {
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
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, fmt.Errorf("connect system bus: %w", err)
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: non-Unix system bus", ErrUnsupported)
	}
	stop := closeOnCancel(ctx, socket)
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		_ = socket.Close()
		return nil, err
	}
	if err := rootPeer(socket); err != nil {
		_ = socket.Close()
		return nil, err
	}
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("authenticate system bus: %w", err)
	}
	p := &Provider{conn: conn, socket: socket, gate: make(chan struct{}, 1)}
	p.gate <- struct{}{}
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, systemdName).Store(&p.owner); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("resolve systemd owner: %w", err)
	}
	var ownerUID uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, p.owner).Store(&ownerUID); err != nil || ownerUID != 0 {
		_ = p.Close()
		return nil, fmt.Errorf("%w: systemd bus owner must be root: %v", ErrUnsupported, err)
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

func (p *Provider) Observe(ctx context.Context, unit string) (*agentv1.ServiceObservation, error) {
	if err := validateUnit(unit); err != nil {
		return nil, err
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	return p.observe(ctx, unit)
}

func (p *Provider) Plan(ctx context.Context, desired *agentv1.ServiceDesiredState) (*agentv1.ServicePlan, error) {
	if err := validateMessage(desired); err != nil {
		return nil, err
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	before, err := p.observe(ctx, desired.GetUnit())
	if err != nil {
		return nil, err
	}
	return planFor(desired, before)
}

func (p *Provider) Verify(ctx context.Context, plan *agentv1.ServicePlan) (*agentv1.ServiceVerification, error) {
	if err := validatePlan(plan); err != nil {
		return nil, err
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	return p.verify(ctx, plan)
}

func (p *Provider) verify(ctx context.Context, plan *agentv1.ServicePlan) (*agentv1.ServiceVerification, error) {
	after, err := p.observe(ctx, plan.GetDesired().GetUnit())
	if err != nil {
		return nil, err
	}
	result := verification(plan, after)
	if !result.GetConverged() {
		return result, ErrNotConverged
	}
	return result, nil
}
