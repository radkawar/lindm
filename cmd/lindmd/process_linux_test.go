//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerDisablesMemoryDumpability(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if dumpable != 0 {
		t.Fatalf("server remains dumpable: %d", dumpable)
	}
}
