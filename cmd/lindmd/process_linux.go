//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDumps changes the shared process memory descriptor, so it applies
// to every Go thread. Unlike RLIMIT_CORE, this also blocks piped host collectors.
// It runs before configuration, credential files or database rows are loaded.
func disableCoreDumps() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable process memory dumps: %w", err)
	}
	return nil
}
