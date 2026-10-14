// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type VMDispatchClockEvidence struct {
	OffsetSeconds      int       `json:"offset_seconds"`
	HostSetAt          time.Time `json:"host_set_at"`
	GuestClock         string    `json:"guest_clock"`
	PreviousNTP        string    `json:"previous_ntp"`
	RestoredHostAt     time.Time `json:"restored_host_at"`
	RestoredGuestClock string    `json:"restored_guest_clock"`
}

// vmDispatchClockOffset changes only the owned guest, restoring both its clock
// and its original network-time setting even when the scenario fails.
func vmDispatchClockOffset(ctx context.Context, vm *guestVM, offset int, run func() error) (evidence *VMDispatchClockEvidence, err error) {
	ntp, err := vm.run(ctx, "timedatectl show --value -p NTP", nil, 128, 10*time.Second)
	if err != nil {
		return nil, err
	}
	previous := strings.TrimSpace(string(ntp))
	if previous != "yes" && previous != "no" {
		return nil, fmt.Errorf("unexpected guest NTP state %q", previous)
	}
	evidence = &VMDispatchClockEvidence{OffsetSeconds: offset, PreviousNTP: previous}
	if err := lifecycleCommand(ctx, vm, "disable guest time synchronization", "timedatectl set-ntp false"); err != nil {
		return evidence, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		evidence.RestoredHostAt = time.Now().UTC()
		value, restoreErr := vm.run(cleanup, "sudo -n date --set="+nativeQuote("@"+strconv.FormatInt(evidence.RestoredHostAt.Unix(), 10))+" --iso-8601=ns && sudo -n timedatectl set-ntp "+previous, nil, 4096, 15*time.Second)
		evidence.RestoredGuestClock = string(value)
		err = errors.Join(err, restoreErr)
	}()
	evidence.HostSetAt = time.Now().UTC()
	target := evidence.HostSetAt.Add(time.Duration(offset) * time.Second)
	value, err := vm.run(ctx, "sudo -n date --set="+nativeQuote("@"+strconv.FormatInt(target.Unix(), 10))+" --iso-8601=ns && timedatectl show -p NTP", nil, 4096, 10*time.Second)
	evidence.GuestClock = string(value)
	if err != nil {
		return evidence, err
	}
	return evidence, run()
}
