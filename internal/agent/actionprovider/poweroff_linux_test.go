// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestForcedPoweroffIgnoresReportAndReadFailure(t *testing.T) {
	for _, readErr := range []error{nil, errors.New("timer descriptor lost")} {
		waits, powers := 0, 0
		err := awaitForcedPoweroff(func() error {
			waits++
			if waits == 1 {
				return unix.EINTR
			}
			return readErr
		}, func() error { powers++; return nil })
		if err != nil || waits != 2 || powers != 1 {
			t.Fatalf("deadline did not force poweroff: waits=%d poweroffs=%d err=%v", waits, powers, err)
		}
	}
}

func TestForcedPoweroffRetriesKernelFailureWithoutRearming(t *testing.T) {
	waits, powers := 0, 0
	err := awaitForcedPoweroff(func() error { waits++; return nil }, func() error {
		powers++
		if powers == 1 {
			return unix.EBUSY
		}
		return nil
	})
	if err != nil || waits != 1 || powers != 2 {
		t.Fatalf("failed poweroff abandoned deadline: %d %d %v", waits, powers, err)
	}
	if liveRootEffectTimeout >= LiveRootPoweroffDelay || LiveRootPoweroffDelay > 120*time.Second {
		t.Fatal("poweroff deadline lost bounded report opportunity")
	}
}
