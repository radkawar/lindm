// SPDX-License-Identifier: Apache-2.0

// Package filelock coordinates processes with owner-only, no-follow file locks.
package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TryLockFile takes the lock only if it is free; ok is false, with nothing
// taken, while it is held.
func TryLockFile(path string) (unlock func() error, ok bool, err error) {
	file, err := openLock(path)
	if err != nil {
		return nil, false, err
	}
	if ok, err := tryFlock(file); err != nil || !ok {
		return nil, false, errors.Join(err, file.Close())
	}
	return hold(file), true, nil
}

// LockFile takes an exclusive flock on path, waiting until ctx ends. While the
// lock is busy, waiting is called with the holder's record each time it
// changes (a new holder, or a holder's progress). The flock is the authority;
// the record is diagnostic. The returned unlock releases it; a crashed holder
// releases it implicitly.
func LockFile(ctx context.Context, path string, waiting func(holder string)) (unlock func() error, err error) {
	file, err := openLock(path)
	if err != nil {
		return nil, err
	}
	for last := ""; ; {
		ok, err := tryFlock(file)
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		if ok {
			return hold(file), nil
		}
		if waiting != nil {
			// A record mid-rewrite reads empty; report only complete changes.
			recorded, _ := os.ReadFile(path)
			if holder := strings.TrimSpace(string(recorded)); holder != "" && holder != last {
				waiting(holder)
				last = holder
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func openLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
}

// tryFlock takes the exclusive flock on file without waiting; it reports
// false while another open file description holds it.
func tryFlock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock %s: %w", file.Name(), err)
	}
	return true, nil
}

// hold records this process as the holder of file's flock and returns its
// release.
func hold(file *os.File) (unlock func() error) {
	holder := "pid " + strconv.Itoa(os.Getpid()) + " " + strings.Join(os.Args, " ") + "\n"
	if err := file.Truncate(0); err == nil {
		_, _ = file.WriteAt([]byte(holder), 0)
	}
	return func() error {
		return errors.Join(file.Truncate(0), syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
	}
}
