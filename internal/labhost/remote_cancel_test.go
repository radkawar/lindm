// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Stopping a held demo closes each worker's stdin lease while cancelling its
// context. Observed live: when the owner's close won that race, exec reported
// "exec: canceling Cmd: close |1: file already closed" and the clean Ctrl-C
// stop failed. An already-closed lease is the requested stop.
func TestLeaseCancelAfterOwnerCloseIsCleanStop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	command := executionCommand(ctx, "", "exec sleep 0.5")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Cancel, command.WaitDelay = cancelByClosingLease(stdin), 10*time.Second
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := command.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("owner stop reported %v, want context cancellation only", err)
	}
}
