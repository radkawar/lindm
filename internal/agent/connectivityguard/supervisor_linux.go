//go:build linux

package connectivityguard

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/firewallprovider"
)

// Supervise runs in a dedicated installed root service, not an executor goroutine.
// Any unfinished record on supervisor restart is rolled back, even on the same
// boot. Runtime expiry uses CLOCK_BOOTTIME, including system suspend. A failure
// leaves CONFLICT custody instead of retrying an uncertain inverse.
func Supervise(ctx context.Context, directory string, config *agentv1.NativeFirewallProviderConfig) error {
	s, err := openStore(directory)
	if err != nil {
		return err
	}
	defer func() { _ = s.close() }()
	singleton, err := s.lock("supervisor-instance.lock")
	if err != nil {
		return err
	}
	defer func() { _ = singleton.Close() }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := recoverBounded(s, config, true)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return drain(s, config)
		case <-ticker.C:
		}
	}
	if err := publishPolicy(s, config); err != nil {
		return err
	}
	ready, err := s.lock("supervisor.lock")
	if err != nil {
		return err
	}
	defer func() { _ = ready.Close() }()
	if err := notifyReady(ctx); err != nil {
		return errors.Join(err, ready.Close(), drain(s, config))
	}
	for {
		select {
		case <-ctx.Done():
			// Withdraw admission before draining, independently of the cancelled signal
			// context. The fixed unit's stop budget exceeds this bounded inverse window.
			closeErr := ready.Close()
			drainErr := drain(s, config)
			return errors.Join(closeErr, drainErr)
		case <-ticker.C:
			if err := recoverBounded(s, config, false); err != nil && !errors.Is(err, unix.EWOULDBLOCK) {
				return err
			}
		}
	}
}
func recoverRecord(ctx context.Context, s *store, config *agentv1.NativeFirewallProviderConfig, restart bool) (err error) {
	lock, err := s.lock("record.lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	r, err := s.load()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Disabled provisioning may monitor an empty store, never abandon retained
	// recovery custody or guess a native policy under missing root configuration.
	if config == nil {
		return ErrConflict
	}
	if terminal(r.GetPhase()) {
		return nil
	}
	defer func() {
		if err != nil && !terminal(r.GetPhase()) {
			r.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFLICT
			err = errors.Join(err, s.save(r))
		}
	}()
	liveBoot, err := bootID()
	if err != nil {
		return err
	}
	start, startErr := processStart(r.GetWorkerPid())
	alive := liveBoot == r.GetBootId() && startErr == nil && start == r.GetWorkerStartTicks()
	now, err := bootTime()
	if err != nil {
		return err
	}
	if !recoveryRequired(r, restart, liveBoot, now, alive) {
		return nil
	}
	if alive {
		// pidfd + start-time recheck closes PID reuse between discovery and signal.
		fd, err := unix.PidfdOpen(int(r.GetWorkerPid()), 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		start, err := processStart(r.GetWorkerPid())
		if err != nil || start != r.GetWorkerStartTicks() {
			return ErrConflict
		}
		if r.GetWorkerPid() == uint32(os.Getpid()) {
			return ErrConflict
		}
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
		// Do not race inverse against a still-running native netlink/file effect.
		if _, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 5000); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 0)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrConflict
		}
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = firewallprovider.RollbackNative(rollbackCtx, config, r.GetRequest(), r.GetApplied(), func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		r.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFLICT
	} else {
		r.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ROLLED_BACK
	}
	// Never replay after a failed inverse, including failures caused by a foreign
	// generation or changed expression. Operator-visible custody remains intact.
	return errors.Join(err, s.save(r))
}
func recoveryRequired(r *agentv1.ConnectivityGuardRecord, restart bool, boot string, now uint64, alive bool) bool {
	return !terminal(r.GetPhase()) && (restart || boot != r.GetBootId() || now >= r.GetDeadlineBoottimeNs() || !alive)
}
func notifyReady(ctx context.Context) error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "unixgram", address)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = connection.Write([]byte("READY=1"))
	return err
}
func publishPolicy(s *store, config *agentv1.NativeFirewallProviderConfig) error {
	var encoded []byte
	if config != nil {
		if err := s.validate(config); err != nil {
			return err
		}
		var err error
		encoded, err = proto.MarshalOptions{Deterministic: true}.Marshal(config)
		if err != nil {
			return err
		}
	}
	file, err := s.open("supervisor.lock", true)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	return file.Sync()
}
func drain(s *store, config *agentv1.NativeFirewallProviderConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := recoverRecord(ctx, s, config, true)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func recoverBounded(s *store, config *agentv1.NativeFirewallProviderConfig, restart bool) error {
	// SIGTERM must not cancel an already-started exact inverse halfway through.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return recoverRecord(ctx, s, config, restart)
}
