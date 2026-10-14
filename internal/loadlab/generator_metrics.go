// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// GeneratorMetrics separates client resource saturation from server latency.
// CPUSeconds is cumulative process CPU; RSSBytes is current resident memory.
type GeneratorMetrics struct {
	CPUSeconds float64
	RSSBytes   uint64
}

func measureGenerator() (GeneratorMetrics, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return GeneratorMetrics{}, err
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return GeneratorMetrics{}, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return GeneratorMetrics{}, errors.New("short generator process statm")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return GeneratorMetrics{}, err
	}
	return GeneratorMetrics{CPUSeconds: float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6, RSSBytes: pages * uint64(os.Getpagesize())}, nil
}
