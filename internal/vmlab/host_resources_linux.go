//go:build linux

package vmlab

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// HostResourceEvidence describes the lab host, never the managed guest.
// Swap counters are cumulative pages since host boot; subtract snapshots to
// distinguish historical swap occupancy from activity during a run.
type HostResourceEvidence struct {
	ObservedAt         time.Time `json:"observed_at"`
	LoadAverage        string    `json:"load_average"`
	MemoryAvailableKiB uint64    `json:"memory_available_kib"`
	SwapTotalKiB       uint64    `json:"swap_total_kib"`
	SwapFreeKiB        uint64    `json:"swap_free_kib"`
	SwapInPages        uint64    `json:"swap_in_pages"`
	SwapOutPages       uint64    `json:"swap_out_pages"`
}

func captureHostResources() (*HostResourceEvidence, error) {
	load, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, fmt.Errorf("read host load: %w", err)
	}
	memory, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("read host memory: %w", err)
	}
	swap, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return nil, fmt.Errorf("read host swap activity: %w", err)
	}
	return parseHostResources(string(load), string(memory), string(swap), time.Now().UTC())
}

func parseHostResources(load, memory, swap string, now time.Time) (*HostResourceEvidence, error) {
	result := &HostResourceEvidence{ObservedAt: now, LoadAverage: strings.TrimSpace(load)}
	fields := map[string]*uint64{"MemAvailable:": &result.MemoryAvailableKiB, "SwapTotal:": &result.SwapTotalKiB, "SwapFree:": &result.SwapFreeKiB, "pswpin": &result.SwapInPages, "pswpout": &result.SwapOutPages}
	for line := range strings.SplitSeq(memory+"\n"+swap, "\n") {
		values := strings.Fields(line)
		if len(values) == 0 {
			continue
		}
		target, ok := fields[values[0]]
		if !ok {
			continue
		}
		if len(values) < 2 {
			return nil, fmt.Errorf("host resource %s missing value", values[0])
		}
		value, err := strconv.ParseUint(values[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("host resource %s: %w", values[0], err)
		}
		*target = value
		delete(fields, values[0])
	}
	if len(fields) != 0 || len(strings.Fields(load)) != 5 {
		return nil, fmt.Errorf("host resource observation incomplete")
	}
	return result, nil
}
