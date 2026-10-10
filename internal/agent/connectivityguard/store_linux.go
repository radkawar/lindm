//go:build linux

// Package connectivityguard owns one root-only, durable firewall rollback slot.
// It neither executes arbitrary programs nor changes executor/service semantics.
package connectivityguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

var ErrConflict = errors.New("connectivity_guard_conflict")
var ErrExpired = errors.New("connectivity_guard_expired")
var ErrUnconfirmed = errors.New("connectivity_guard_unconfirmed")

const StateDirectory = "/var/lib/lindm/connectivity-guard"
const maxRecord = 4 << 20
const recordName = "firewall-guard.pb"
const ConfirmationPath = "/lindm.device.v1.ConnectivityGuard/Confirm"
const ExporterLabel = "EXPORTER-lindm-connectivity-guard-v1"

type store struct {
	fd    int
	rules protovalidate.Validator
}

func openStore(directory string) (*store, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("connectivity_guard_requires_root")
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(&agentv1.ConnectivityGuardRecord{}, &agentv1.ConnectivityGuardConfig{}, &agentv1.ConnectivityConfirmation{}, &agentv1.ConnectivityConfirmationResponse{}, &agentv1.ConnectivityProbePacket{}, &agentv1.ConnectivityProbeResponse{}, &agentv1.ConnectivityProbeCommand{}, &agentv1.ConnectivityVerificationEvidence{}, &agentv1.NativeFirewallProviderConfig{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return &store{fd: fd, rules: rules}, nil
}
func (s *store) close() error { return unix.Close(s.fd) }
func (s *store) validate(m proto.Message) error {
	if err := protodata.ValidateClosed(m.ProtoReflect()); err != nil {
		return err
	}
	return s.rules.Validate(m)
}
func (s *store) open(name string, create bool) (*os.File, error) {
	exists, err := statefs.CheckFile(s.fd, name)
	if err != nil {
		return nil, err
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if !exists {
		if !create {
			return nil, os.ErrNotExist
		}
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(s.fd, name, flags, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if st.Uid != 0 || st.Nlink != 1 || st.Mode&07777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.Join(statefs.ErrUnsafe, f.Close())
	}
	return f, nil
}
func (s *store) lock(name string) (*os.File, error) {
	f, err := s.open(name, true)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// lockWorker is the native worker's record lock. The supervisor polls the same
// lock non-blockingly every 100ms and holds it only for a check or an exact
// inverse, so contention is transient: the worker waits, bounded by its own
// deadline, instead of failing an applied transaction as outcome-unknown.
// The supervisor itself never waits; its ticker retries.
func (s *store) lockWorker(ctx context.Context, name string) (*os.File, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		f, err := s.lock(name)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return f, err
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), err)
		case <-ticker.C:
		}
	}
}
func (s *store) load() (*agentv1.ConnectivityGuardRecord, error) {
	f, err := s.open(recordName, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecord {
		return nil, ErrConflict
	}
	r := new(agentv1.ConnectivityGuardRecord)
	if err := proto.Unmarshal(data, r); err != nil {
		return nil, err
	}
	if err := s.validate(r); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *store) save(r *agentv1.ConnectivityGuardRecord) error {
	if err := s.validate(r); err != nil {
		return err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > maxRecord {
		return ErrConflict
	}
	// A crash can leave only this fixed scratch file; never follow or truncate it.
	if exists, err := statefs.CheckFile(s.fd, recordName+".new"); err != nil {
		return err
	} else if exists {
		if err := unix.Unlinkat(s.fd, recordName+".new", 0); err != nil {
			return err
		}
	}
	f, err := s.open(recordName+".new", true)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := unix.Renameat(s.fd, recordName+".new", s.fd, recordName); err != nil {
		return err
	}
	return unix.Fsync(s.fd)
}
func bootTime() (uint64, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		return 0, err
	}
	return uint64(t.Nano()), nil
}
func bootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(data)), err
}
func processStart(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, ErrConflict
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return 0, ErrConflict
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
func terminal(p agentv1.ConnectivityGuardPhase) bool {
	return p == agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_COMMITTED || p == agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ROLLED_BACK || p == agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFLICT
}
func remaining(r *agentv1.ConnectivityGuardRecord) (time.Duration, error) {
	boot, err := bootID()
	if err != nil {
		return 0, err
	}
	now, err := bootTime()
	if err != nil {
		return 0, err
	}
	if boot != r.GetBootId() || now >= r.GetDeadlineBoottimeNs() {
		return 0, ErrExpired
	}
	return time.Duration(r.GetDeadlineBoottimeNs() - now), nil
}
