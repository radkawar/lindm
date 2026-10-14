// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
)

// heavyJobGuests is the memory, in local guest-equivalents (max_memory_mib),
// that one race-enabled suite must find available, with the lab's headroom.
const heavyJobGuests = 1

// heavyJobNice lowers heavy jobs below VM lanes in CPU scheduling.
const heavyJobNice = 10

// admitHeavyJob prepares this process for a CPU- and memory-heavy host job
// (race-enabled unit or integration suites). Gates do not queue behind lab
// lanes in the slot FIFO; instead the job waits for the local host's memory
// admission, writing each changed wait reason to log, and the process and
// every child it starts run at nice 10 so VM lanes keep CPU priority.
func admitHeavyJob(ctx context.Context, name string, log io.Writer) error {
	cfg, err := labhost.Load()
	if err != nil {
		return fmt.Errorf("heavy job admission: %w", err)
	}
	var host *labv1.LabHost
	for _, candidate := range cfg.GetHosts() {
		if candidate.GetTransport() == "local" {
			host = candidate
			break
		}
	}
	if host == nil {
		return errors.New("heavy job admission: no local lab host is configured")
	}
	slots, err := labhost.OpenSlots(host)
	if err != nil {
		return fmt.Errorf("heavy job admission: %w", err)
	}
	if err := slots.AwaitMemory(ctx, heavyJobGuests, func(reason string) {
		_, _ = fmt.Fprintf(log, "%s: waiting for lab host %s memory: %s\n", name, host.GetName(), reason)
	}); err != nil {
		return fmt.Errorf("heavy job admission on %s: %w", host.GetName(), err)
	}
	// Niceness only rises here; an already lower priority is kept.
	current, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		return fmt.Errorf("heavy job priority: %w", err)
	}
	// The raw syscall returns 20-nice.
	if nice := 20 - current; nice < heavyJobNice {
		if err := unix.Setpriority(unix.PRIO_PROCESS, 0, heavyJobNice); err != nil {
			return fmt.Errorf("heavy job priority: %w", err)
		}
	}
	return nil
}
