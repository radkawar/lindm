// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"testing"
	"time"
)

func TestHostResourceEvidence(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	memory := "MemTotal: 64000 kB\nMemAvailable: 32000 kB\nSwapTotal: 16000 kB\nSwapFree: 4000 kB\n"
	swap := "pgfault 99\npswpin 12\npswpout 34\n"
	got, err := parseHostResources("1.00 2.00 3.00 2/100 123\n", memory, swap, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.MemoryAvailableKiB != 32000 || got.SwapTotalKiB != 16000 || got.SwapFreeKiB != 4000 || got.SwapInPages != 12 || got.SwapOutPages != 34 || !got.ObservedAt.Equal(now) {
		t.Fatalf("incorrect host snapshot: %+v", got)
	}
	for _, input := range []string{"pswpin 12\n", "pswpin nope\npswpout 34\n", "pswpin -1\npswpout 34\n"} {
		if _, err := parseHostResources("1 2 3 2/100 123", memory, input, now); err == nil {
			t.Fatalf("accepted incomplete/invalid swap counters %q", input)
		}
	}
	if _, err := parseHostResources("", memory, swap, now); err == nil {
		t.Fatal("accepted absent load observation")
	}
}
