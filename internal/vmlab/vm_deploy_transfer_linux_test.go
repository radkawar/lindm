// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

type deployTransferCloser struct{ err error }

func (c deployTransferCloser) Close() error { return c.err }

func TestDeployTransferCloseDistinguishesCompletedChannelFromFailure(t *testing.T) {
	failure := errors.New("actual transfer failure")
	cleanup := errors.New("unexpected cleanup failure")
	for _, closeErr := range []error{nil, io.EOF, fmt.Errorf("closed channel: %w", io.EOF)} {
		if err := closeDeployTransfer(nil, deployTransferCloser{err: closeErr}); err != nil {
			t.Fatalf("completed transfer failed on channel cleanup: %v", err)
		}
		if err := closeDeployTransfer(failure, deployTransferCloser{err: closeErr}); !errors.Is(err, failure) {
			t.Fatalf("real transfer failure was discarded: %v", err)
		}
		if err := closeDeployTransfer(io.EOF, deployTransferCloser{err: closeErr}); !errors.Is(err, io.EOF) {
			t.Fatalf("actual transfer EOF was discarded: %v", err)
		}
	}
	err := closeDeployTransfer(failure, deployTransferCloser{err: cleanup})
	if !errors.Is(err, failure) || !errors.Is(err, cleanup) {
		t.Fatalf("unexpected cleanup or transfer failure was discarded: %v", err)
	}
}
