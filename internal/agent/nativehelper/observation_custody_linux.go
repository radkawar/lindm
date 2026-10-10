//go:build linux

package nativehelper

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

const maximumNativeObservers = 64

// Capacity covers incomplete observers too. A request cannot leave unlimited
// private native records by repeatedly interrupting the read boundary. Only
// systemd-confirmed inactive, old read-only units are swept; effects are never
// discovered or replayed here.
func observationDirectory(ctx context.Context, bus *nativeBus, stateDirectory, id string) (directory string, resultErr error) {
	state, err := statefs.OpenDirectory(stateDirectory)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(state)) }()
	if err := unix.Mkdirat(state, "resource-observations", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	if err := unix.Fsync(state); err != nil {
		return "", err
	}
	parent := filepath.Join(stateDirectory, "resource-observations")
	fd, err := statefs.OpenDirectory(parent)
	if err != nil {
		return "", err
	}
	handle := os.NewFile(uintptr(fd), "native-observation-custody")
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return "", err
	}
	entries, err := handle.ReadDir(maximumNativeObservers + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(entries) > maximumNativeObservers {
		return "", errors.New("native_observation_capacity")
	}
	retained := 0
	for _, entry := range entries {
		parsed, err := uuid.Parse(entry.Name())
		if err != nil || parsed == uuid.Nil || parsed.String() != entry.Name() || !entry.IsDir() {
			return "", errors.New("native_observation_custody_shape")
		}
		info, err := entry.Info()
		if err != nil {
			return "", err
		}
		if time.Since(info.ModTime()) > 2*observationTimeout {
			active, _, err := bus.active(ctx, "lindm-observe-"+entry.Name()+".service")
			if err != nil {
				return "", err
			}
			if !active {
				stale := filepath.Join(parent, entry.Name())
				check, err := statefs.OpenDirectory(stale)
				if err != nil {
					return "", err
				}
				if err := unix.Close(check); err != nil {
					return "", err
				}
				if err := removeObservation(stale); err != nil {
					return "", err
				}
				continue
			}
		}
		retained++
	}
	if retained >= maximumNativeObservers {
		return "", errors.New("native_observation_capacity")
	}
	return resourceDirectory(stateDirectory, "resource-observations", id, true)
}
