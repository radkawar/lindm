// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package recovery executes a single original-device sanitization handoff. It
// never enrolls a replacement device, supplies ordinary device credentials, or
// restarts an effect whose durable consumption is uncertain.
package recovery

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

const maximumJournalBytes = 1 << 20

var ErrConsumed = errors.New("recovery_effect_already_consumed")

// Journal pins a protected, separately provisioned off-target directory and
// holds its exclusive execution lock. Native media resolution must independently
// prove this directory is outside the complete erased device/controller scope.
// Neither filesystem permissions nor this lock protects against compromised root.
type Journal struct {
	mu        sync.Mutex
	directory *os.File
	lock      *os.File
}

func OpenJournal(path string) (_ *Journal, err error) {
	fd, err := statefs.OpenDirectory(path)
	if err != nil {
		return nil, fmt.Errorf("open recovery journal: %w", err)
	}
	directory := os.NewFile(uintptr(fd), path)
	defer func() {
		if err != nil {
			err = errors.Join(err, directory.Close())
		}
	}()
	if _, err := statefs.CheckFile(fd, "execution.lock"); err != nil {
		return nil, err
	}
	lockFD, err := unix.Openat(fd, "execution.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(lockFD), "execution.lock")
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	if _, err := statefs.CheckFile(fd, "execution.lock"); err != nil {
		return nil, err
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock recovery journal: %w", err)
	}
	return &Journal{directory: directory, lock: lock}, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return errors.Join(j.lock.Close(), j.directory.Close())
}

// Load rejects missing, oversized, unknown-field or unsafe journal data. An
// absent journal is distinct from an empty/corrupt existing journal.
func (j *Journal) Load(destination proto.Message) (found bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fd := int(j.directory.Fd())
	found, err = statefs.CheckFile(fd, "journal.pb")
	if err != nil || !found {
		return found, err
	}
	fileFD, err := unix.Openat(fd, "journal.pb", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return true, err
	}
	file := os.NewFile(uintptr(fileFD), "journal.pb")
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, maximumJournalBytes+1))
	if err != nil {
		return true, err
	}
	if len(data) == 0 || len(data) > maximumJournalBytes {
		return true, errors.New("invalid recovery journal size")
	}
	if err := proto.Unmarshal(data, destination); err != nil {
		return true, err
	}
	return true, protodata.ValidateClosed(destination.ProtoReflect())
}

// Save completes file and directory fsync before returning. A successful rename
// followed by a failed directory fsync is ambiguous; callers must not execute.
func (j *Journal) Save(message proto.Message) (err error) {
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maximumJournalBytes {
		return errors.New("invalid recovery journal size")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	fd := int(j.directory.Fd())
	if _, err := statefs.CheckFile(fd, "journal.pb"); err != nil {
		return err
	}
	name := "checkpoint-" + uuid.NewString()
	fileFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fileFD), name)
	defer func() {
		removeErr := unix.Unlinkat(fd, name, 0)
		if !errors.Is(removeErr, unix.ENOENT) {
			err = errors.Join(err, removeErr)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := unix.Renameat(fd, name, fd, "journal.pb"); err != nil {
		return err
	}
	return j.directory.Sync()
}

func (j *Journal) Consumed() (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return statefs.CheckFile(int(j.directory.Fd()), "effect.consumed")
}

// Consume irrevocably reserves this one-action journal before either the server
// effect checkpoint or native call. Crashes and missing acknowledgments never
// remove this marker. Re-provisioning an old action directory is prohibited.
func (j *Journal) Consume() (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fd, err := unix.Openat(int(j.directory.Fd()), "effect.consumed", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		return ErrConsumed
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "effect.consumed")
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return j.directory.Sync()
}
