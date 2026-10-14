// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import "testing"

func TestNativeBootTimeUsesKernelUnixSeconds(t *testing.T) {
	// Kernel btime is independent of procps uptime options, date implementations,
	// guest timezone and localization. It must retain the exact epoch value.
	for _, tc := range []struct {
		record string
		want   uint64
	}{
		{"btime 1791583200\n", 1791583200},
		{"btime 0\n", 0},
		{"btime 4294967296\n", 4294967296},
	} {
		got, err := parseTruthBootTime([]byte(tc.record))
		if err != nil || got.GetStatus() != truthSuccess || got.GetValue() != tc.want {
			t.Fatalf("boot record %q = %v, %v; want exact Unix seconds %d", tc.record, got, err, tc.want)
		}
	}
}

func TestNativeBootTimeRejectsMissingOrAmbiguousEvidence(t *testing.T) {
	for _, record := range []string{
		"",
		"btime 1791583200",
		"btime \n",
		"btime +1791583200\n",
		"btime -1\n",
		"btime 1.0\n",
		"btime 1 extra\n",
		"btime 1\nbtime 2\n",
		"btime 1\n\n",
		"btime 1\r\n",
		"btime 1\x00\n",
		"btime 18446744073709551616\n",
		"cpu 1 2 3\n",
	} {
		if got, err := parseTruthBootTime([]byte(record)); err == nil || got != nil {
			t.Fatalf("accepted incomplete or invalid boot evidence %q: %v, %v", record, got, err)
		}
	}
}
