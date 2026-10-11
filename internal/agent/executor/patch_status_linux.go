//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const (
	// resource.OSUpdateStatusPath is written by the root runner (0600 root).
	patchStatusLimit = 64 << 10
	// A status older than this, from another boot, or older than a native
	// package database or metadata change is recomputed offline.
	patchStatusMaxAge = time.Hour
	// At most one refresh start per executor process in this interval.
	patchStatusRefreshInterval = 5 * time.Minute
	// Bounds the system bus StartUnit call; the job itself is never awaited.
	patchStatusStartTimeout = 5 * time.Second
	// Clock skew tolerated before a status counts as written in the future.
	patchStatusFutureSkew = 5 * time.Minute
	// Bounds the number of native objects inspected for the fingerprint.
	patchStatusFingerprintLimit = 4096
	systemBusSocket             = "/run/dbus/system_bus_socket"
	systemdBusName              = "org.freedesktop.systemd1"
)

// patchStatusFingerprints lists the native package databases and repository
// metadata whose change invalidates a computed status. Directory mtimes catch
// renames of downloaded lists; apt preserves the remote mtime of list files.
func patchStatusFingerprints() []string {
	return []string{
		"/var/lib/dpkg/status",
		"/var/lib/rpm/rpmdb.sqlite",
		"/var/lib/apt/lists",
		"/var/lib/apt/lists/*Release",
		"/var/cache/libdnf5/*/repodata",
		"/var/cache/libdnf5/*/repodata/repomd.xml",
		"/var/cache/dnf/*/repodata",
		"/var/cache/dnf/*/repodata/repomd.xml",
	}
}

var (
	errPatchStatusMissing = errors.New("patch_status_not_computed")
	errPatchStatusInvalid = errors.New("patch_status_invalid")
)

// patchStatusReader publishes the runner's offline status unmodified and
// requests a recompute when it is stale. It never runs native package tools.
type patchStatusReader struct {
	path         string
	owner        uint32
	fingerprints []string
	// wall is the UTC wall clock compared with observed_at; monotonic only
	// throttles refresh starts.
	wall      func() time.Time
	monotonic func() time.Time
	bootID    func() (string, error)
	validate  func(proto.Message) error
	refresh   func(context.Context) error
	logger    *slog.Logger

	mu          sync.Mutex
	lastRefresh time.Time
}

func newPatchStatusReader(s *Service) *patchStatusReader {
	return &patchStatusReader{
		path: resource.OSUpdateStatusPath, fingerprints: patchStatusFingerprints(),
		wall: s.now, monotonic: s.clock, bootID: s.bootID, validate: s.admit,
		refresh: func(ctx context.Context) error {
			return startSystemUnit(ctx, resource.OSUpdateStatusUnit, "replace")
		},
		logger: s.logger,
	}
}

// GetPatchStatus returns the last offline patch status. A missing, invalid,
// old or superseded status starts lindm-os-update-status.service without
// waiting for its job; the response never blocks on native package tools.
func (s *Service) GetPatchStatus(ctx context.Context, req *connect.Request[agentv1.GetPatchStatusRequest]) (*connect.Response[agentv1.GetPatchStatusResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || req.Msg == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(req.Msg); err != nil {
		return nil, mapError(err)
	}
	if s.patchStatus == nil {
		return nil, mapError(errInternal)
	}
	response := &agentv1.GetPatchStatusResponse{Observation: s.patchStatus.observe(ctx)}
	if err := s.admit(response); err != nil {
		s.patchStatus.log().Warn("patch status response rejected", "error", err)
		return nil, mapError(errInternal)
	}
	return noStore(response), nil
}

func (r *patchStatusReader) log() *slog.Logger {
	if r.logger == nil {
		return slog.Default()
	}
	return r.logger
}

// observe classifies the stored status and requests at most one refresh.
func (r *patchStatusReader) observe(ctx context.Context) *agentv1.PatchStatusObservation {
	now := r.wall().UTC()
	boot, bootErr := r.bootID()
	if _, err := uuid.Parse(boot); bootErr != nil || err != nil {
		boot = ""
	}
	unavailable := func(reason string) *agentv1.PatchStatusObservation {
		return &agentv1.PatchStatusObservation{ObservedAt: timestamppb.New(now), BootId: boot, Reason: reason}
	}
	stored, err := r.read()
	var result *agentv1.PatchStatusObservation
	stale := true
	switch {
	case errors.Is(err, errPatchStatusMissing):
		result = unavailable(errPatchStatusMissing.Error())
	case err != nil:
		r.log().Warn("patch status rejected", "error", err)
		result = unavailable(errPatchStatusInvalid.Error())
	case stored.GetObservedAt().AsTime().After(now.Add(patchStatusFutureSkew)):
		r.log().Warn("patch status rejected", "error", "observed_after_now")
		result = unavailable(errPatchStatusInvalid.Error())
	case boot == "":
		result = unavailable("patch_status_boot_id_unavailable")
		stale = false
	case stored.GetBootId() != "" && stored.GetBootId() != boot:
		result = unavailable("patch_status_previous_boot")
	default:
		result = stored
		observed := stored.GetObservedAt().AsTime()
		stale = now.Sub(observed) > patchStatusMaxAge || r.changedSince(observed)
	}
	if stale {
		r.requestRefresh(ctx)
	}
	return result
}

// read opens the status without following links and accepts only a bounded
// root-owned regular file that is not writable by group or others.
func (r *patchStatusReader) read() (_ *agentv1.PatchStatusObservation, resultErr error) {
	fd, err := unix.Open(r.path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, errPatchStatusMissing
	}
	if err != nil {
		return nil, fmt.Errorf("open patch status: %w", err)
	}
	file := os.NewFile(uintptr(fd), "patch-status")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("stat patch status: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != r.owner || stat.Mode&0o022 != 0 || stat.Size < 1 || stat.Size > patchStatusLimit {
		return nil, errors.New("patch status is not a bounded protected file")
	}
	data, err := io.ReadAll(io.LimitReader(file, patchStatusLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read patch status: %w", err)
	}
	if len(data) > patchStatusLimit {
		return nil, errors.New("patch status exceeds its bound")
	}
	observation := new(agentv1.PatchStatusObservation)
	if err := proto.Unmarshal(data, observation); err != nil {
		return nil, fmt.Errorf("decode patch status: %w", err)
	}
	if err := protodata.ValidateClosed(observation.ProtoReflect()); err != nil {
		return nil, fmt.Errorf("patch status has unknown fields: %w", err)
	}
	if err := r.validate(observation); err != nil {
		return nil, fmt.Errorf("validate patch status: %w", err)
	}
	return observation, nil
}

// changedSince reports whether a native package database or repository
// metadata object changed after observed. Unreadable sources are absent.
func (r *patchStatusReader) changedSince(observed time.Time) bool {
	inspected := 0
	for _, pattern := range r.fingerprints {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if inspected == patchStatusFingerprintLimit {
				return false
			}
			inspected++
			info, err := os.Lstat(match)
			if err == nil && info.ModTime().After(observed) {
				return true
			}
		}
	}
	return false
}

// requestRefresh starts the status unit at most once per interval. Failures
// are logged; the next stale observation after the interval retries.
func (r *patchStatusReader) requestRefresh(ctx context.Context) {
	now := r.monotonic()
	r.mu.Lock()
	if !r.lastRefresh.IsZero() && !now.Before(r.lastRefresh) && now.Sub(r.lastRefresh) < patchStatusRefreshInterval {
		r.mu.Unlock()
		return
	}
	r.lastRefresh = now
	r.mu.Unlock()
	if err := r.refresh(ctx); err != nil {
		r.log().Warn("patch status refresh not started", "unit", resource.OSUpdateStatusUnit, "error", err)
	}
}

// startSystemUnit enqueues a start job through the system bus without waiting
// for it. Neither environment-selected buses nor autoactivation are used; the
// broker socket and the systemd1 name owner must both belong to root.
func startSystemUnit(ctx context.Context, unit, mode string) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, patchStatusStartTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", systemBusSocket)
	if err != nil {
		return err
	}
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return errors.Join(errors.New("system bus is not a Unix socket"), raw.Close())
	}
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		return errors.Join(err, socket.Close())
	}
	if err := requireSocketPeer(socket, 0); err != nil {
		return errors.Join(err, socket.Close())
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	conn, err := dbus.ConnectUnix(socket, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid()))))
	if err != nil {
		return errors.Join(err, socket.Close())
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, systemdBusName).Store(&owner); err != nil {
		return err
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil {
		return err
	}
	if uid != 0 {
		return errors.New("systemd bus owner is not root")
	}
	var job dbus.ObjectPath
	return conn.Object(owner, systemdManagerPath).CallWithContext(ctx, systemdManager+".StartUnit", dbus.FlagNoAutoStart, unit, mode).Store(&job)
}
