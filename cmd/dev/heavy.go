package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
)

// heavyJobGuests is the local lab capacity, in guest-equivalents (each the
// host's max_vcpus and max_memory_mib), that one race-enabled suite reserves.
// One keeps a heavy job from starving behind continuous single-guest lanes
// while still taking a VM's share of CPU and memory away from the lab.
const heavyJobGuests = 1

// heavyJob reserves local lab host capacity for a CPU- and memory-heavy host
// job (race-enabled unit or integration suites) through the same flock and
// memory admission as VM lanes, so neither oversubscribes the other. It waits
// until admitted, writing each changed wait reason to log. Close the returned
// release when the job and all its children have exited.
func heavyJob(ctx context.Context, name string, log io.Writer) (release func() error, err error) {
	cfg, err := labhost.Load()
	if err != nil {
		return nil, fmt.Errorf("heavy job admission: %w", err)
	}
	var host *labv1.LabHost
	for _, candidate := range cfg.GetHosts() {
		if candidate.GetTransport() == "local" {
			host = candidate
			break
		}
	}
	if host == nil {
		return nil, errors.New("heavy job admission: no local lab host is configured")
	}
	slots, err := labhost.OpenSlots(host)
	if err != nil {
		return nil, fmt.Errorf("heavy job admission: %w", err)
	}
	leases, err := slots.AcquireNReporting(ctx, heavyJobGuests, func(reason string) {
		_, _ = fmt.Fprintf(log, "%s: waiting for lab host %s admission: %s\n", name, host.GetName(), reason)
	})
	if err != nil {
		return nil, fmt.Errorf("heavy job admission on %s: %w", host.GetName(), err)
	}
	_, _ = fmt.Fprintf(log, "%s: admitted on lab host %s (%d guest-equivalent)\n", name, host.GetName(), heavyJobGuests)
	return func() error {
		var err error
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
		return err
	}, nil
}
