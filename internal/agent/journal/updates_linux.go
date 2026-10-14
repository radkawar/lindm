// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"buf.build/go/protovalidate"
	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

// UpdateStore owns the separate fsync/rename checkpoint for native transactions.
// The executor serializes callers under its update worker, not its identity mutex.
// Helpers never mutate this checkpoint; they own only their transaction directory.
type UpdateStore struct {
	dir       *os.File
	Directory string
	validator protovalidate.Validator
	current   *agentv1.AgentUpdateJournal
	failed    bool
}

// updateRules compiles the update checkpoint schemas once per process; see
// journalRules.
var updateRules = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(&agentv1.AgentUpdateJournal{}, &agentv1.AgentUpdateTransaction{}), protovalidate.WithDisableLazy())
})

// OpenUpdates refuses missing checkpoints in an existing directory. Deleting a
// checkpoint cannot reset the installed-version high-water mark.
func OpenUpdates(executorDirectory string) (_ *UpdateStore, resultErr error) {
	parent, err := statefs.OpenDirectory(executorDirectory)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parent)) }()
	created := false
	if err := unix.Mkdirat(parent, "updates", 0700); err == nil {
		created = true
		if err := unix.Fsync(parent); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	directory := filepath.Join(executorDirectory, "updates")
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, errors.Join(ErrAlreadyOpen, err)
	}
	validator, err := updateRules()
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	s := &UpdateStore{dir: os.NewFile(uintptr(fd), "update-journal"), Directory: directory, validator: validator}
	defer func() {
		if resultErr != nil {
			_ = s.Close()
		}
	}()
	if created {
		if err := s.Save(&agentv1.AgentUpdateJournal{FormatVersion: 1, Phase: "idle", ObservedAt: timestamppb.Now()}); err != nil {
			return nil, err
		}
	} else {
		state := &agentv1.AgentUpdateJournal{}
		if err := ReadUpdateRecord(directory, "state.pb", state); err != nil {
			return nil, errors.Join(ErrRecoveryHold, err)
		}
		if err := s.validator.Validate(state); err != nil {
			return nil, ErrRecoveryHold
		}
		s.current = state
	}
	return s, nil
}

func (s *UpdateStore) Load() *agentv1.AgentUpdateJournal { return proto.CloneOf(s.current) }
func (s *UpdateStore) Close() error                      { return s.dir.Close() }

// Save atomically records the exact transaction before native launch and fences
// installed-version regression. It never clears an unresolved transaction.
func (s *UpdateStore) Save(next *agentv1.AgentUpdateJournal) error {
	if s.failed {
		return ErrRecoveryHold
	}
	if err := s.validator.Validate(next); err != nil {
		return err
	}
	if err := protodata.ValidateClosed(next.ProtoReflect()); err != nil {
		return err
	}
	if prior := s.current; prior != nil {
		if prior.GetInstalledVersion() != "" && (!semver.IsValid("v"+next.GetInstalledVersion()) || semver.Compare("v"+next.GetInstalledVersion(), "v"+prior.GetInstalledVersion()) < 0) {
			return errors.New("update installed version rollback")
		}
		if prior.GetTransaction() != nil && prior.GetPhase() != "installed" && prior.GetPhase() != "rejected" && !proto.Equal(prior.GetTransaction(), next.GetTransaction()) {
			return errors.New("update unresolved transaction replacement")
		}
	}
	if err := WriteUpdateRecord(s.Directory, "state.pb", next); err != nil {
		// Rename may have succeeded before a directory-sync error. Never let a
		// later write overwrite that ambiguous committed transaction.
		s.failed = true
		return err
	}
	s.current = proto.CloneOf(next)
	return nil
}

// ReadUpdateRecord reads only a checked private regular protobuf record.
func ReadUpdateRecord(directory, name string, target proto.Message) (resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	exists, err := statefs.CheckFile(fd, name)
	if err != nil {
		return err
	}
	if !exists {
		return os.ErrNotExist
	}
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fileFD), "update-record")
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("update record exceeds limit")
	}
	if err := proto.Unmarshal(data, target); err != nil {
		return err
	}
	return protodata.ValidateClosed(target.ProtoReflect())
}

// WriteUpdateRecord publishes a bounded protobuf through a same-directory atomic
// rename, syncing both file contents and the containing directory.
func WriteUpdateRecord(directory, name string, record proto.Message) (resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	if _, err := statefs.CheckFile(fd, name); err != nil {
		return err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("update record exceeds limit")
	}
	file, err := os.CreateTemp(directory, ".checkpoint-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(directory, name)); err != nil {
		return err
	}
	return unix.Fsync(fd)
}
