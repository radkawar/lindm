// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

const operationsLock = "/run/lindm-operations.lock"
const inheritedLeaseEnvironment = "LINDM_OPERATIONS_LEASE_FD"

// UpgradeLease serializes native lifecycle work and every state-mutating day2
// operation. Closing a duplicated child descriptor never unlocks its parent: the
// lock belongs to the shared open-file description and lasts until its final close.
type UpgradeLease struct {
	file          *os.File
	once          sync.Once
	closeError    error
	state         sync.Mutex
	closed        bool
	restartTimers bool
}

func (lease *UpgradeLease) Close() error {
	if lease == nil {
		return errors.New("operations: missing_operations_lease")
	}
	lease.once.Do(func() {
		lease.state.Lock()
		lease.closed = true
		restart := lease.restartTimers
		lease.state.Unlock()
		if lease.file == nil {
			lease.closeError = errors.New("operations: missing_operations_lease")
			return
		}
		lease.closeError = lease.file.Close()
		if restart {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "systemctl", "start", "lindmd-backup.timer", "lindmd-release-check.timer")
			command.Env = cleanEnvironment()
			command.Stdout = io.Discard
			command.Stderr = io.Discard
			command.WaitDelay = 5 * time.Second
			if command.Run() != nil {
				lease.closeError = errors.Join(lease.closeError, errors.New("operations: timer_restart_failed"))
			}
		}
	})
	return lease.closeError
}

// Validate rejects missing, closed, replaced or unsafe operation descriptors at
// installer admission, before any lifecycle state is read or mutated.
func (lease *UpgradeLease) Validate() (err error) {
	if lease == nil {
		return errors.New("operations: missing_operations_lease")
	}
	lease.state.Lock()
	defer lease.state.Unlock()
	if lease.closed || lease.file == nil {
		return errors.New("operations: closed_operations_lease")
	}
	var stat unix.Stat_t
	if unix.Fstat(int(lease.file.Fd()), &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		return errors.New("operations: unsafe_operations_lease")
	}
	checked, current, err := custody.OpenRoot(operationsLock, unix.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, checked.Close()) }()
	if current.Dev != stat.Dev || current.Ino != stat.Ino {
		return errors.New("operations: replaced_operations_lease")
	}
	if unix.Flock(int(lease.file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("operations: operations_lease_not_exclusive")
	}
	return nil
}

// RestartTimersOnClose records installer timer ownership on the operation lease.
// Close drops the exclusive descriptor before starting timers, including when
// the apply caller, rather than the installer, owns the supplied lease.
func (lease *UpgradeLease) RestartTimersOnClose() error {
	if err := lease.Validate(); err != nil {
		return err
	}
	lease.state.Lock()
	defer lease.state.Unlock()
	if lease.closed {
		return errors.New("operations: closed_operations_lease")
	}
	lease.restartTimers = true
	return nil
}

func AcquireUpgradeLease(ctx context.Context) (lease *UpgradeLease, err error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("operations: root_required")
	}
	parent, _, err := custody.OpenRoot("/run", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	fd, err := unix.Openat(int(parent.Fd()), "lindm-operations.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	own := os.NewFile(uintptr(fd), operationsLock)
	keep := false
	defer func() {
		if !keep {
			err = errors.Join(err, own.Close())
		}
	}()
	checked, stat, err := custody.OpenRoot(operationsLock, unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = checked.Close(); err != nil {
		return nil, err
	}
	var opened unix.Stat_t
	if err = unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if opened.Dev != stat.Dev || opened.Ino != stat.Ino || opened.Nlink != 1 || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0077 != 0 {
		return nil, errors.New("operations: unsafe_operations_lease")
	}
	if inherited := os.Getenv(inheritedLeaseEnvironment); inherited != "" {
		inheritedFD, parseErr := strconv.Atoi(inherited)
		if parseErr != nil || inheritedFD < 3 || inheritedFD > 1024 {
			return nil, errors.New("operations: invalid_inherited_lease")
		}
		var inheritedStat unix.Stat_t
		if err = unix.Fstat(inheritedFD, &inheritedStat); err != nil || inheritedStat.Dev != stat.Dev || inheritedStat.Ino != stat.Ino {
			return nil, errors.New("operations: invalid_inherited_lease")
		}
		if err = unix.Flock(inheritedFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, errors.New("operations: inherited_lease_not_exclusive")
		}
		lease = &UpgradeLease{file: os.NewFile(uintptr(inheritedFD), operationsLock)}
		return lease, nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			keep = true
			return &UpgradeLease{file: own}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// Backup deliberately executes the currently installed server, not the new
// installer's linked backup code. Its archive therefore binds the real installed
// package version and the old schema before migration.
func (lease *UpgradeLease) Backup(ctx context.Context, options BackupOptions) error {
	args := []string{"backup", "-config", options.Config, "-recipient-file", options.RecipientFile, "-output-dir", options.OutputDirectory}
	if options.HealthPath != "" && options.HealthPath != BackupHealthPath {
		return errors.New("operations: native_backup_health_path_required")
	}
	if options.ConfirmFenced {
		args = append(args, "-confirm-fenced")
	}
	return lease.runInstalled(ctx, args)
}

// CheckRelease runs the replacement executable so its installed-version claim
// cannot be the still-running updater's old build stamp.
func (lease *UpgradeLease) CheckRelease(ctx context.Context) error {
	return lease.runInstalled(ctx, []string{"update", "check"})
}

func (lease *UpgradeLease) runInstalled(ctx context.Context, args []string) error {
	command := exec.CommandContext(ctx, "/usr/bin/lindmd", args...)
	command.Env = append(cleanEnvironment(), inheritedLeaseEnvironment+"=3")
	command.ExtraFiles = []*os.File{lease.file}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return errors.New("operations: installed_operation_failed")
	}
	return nil
}
