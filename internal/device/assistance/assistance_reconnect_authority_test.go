// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"testing"
	"time"
)

// An automatic invitation issued with authority observed long before its
// sync transaction lapsed two seconds later (layers-fedora44-reconnect-13);
// it waits for a fresh observation instead.
func TestAutomaticReconnectNeedsAuthorityMargin(t *testing.T) {
	now := time.Date(2026, 10, 14, 6, 5, 35, 0, time.UTC)
	for _, c := range []struct {
		remaining time.Duration
		usable    bool
	}{
		{30 * time.Second, true},
		{assistanceReconnectAuthorityMargin, true},
		{assistanceReconnectAuthorityMargin - time.Millisecond, false},
		{2 * time.Second, false},
		{-time.Second, false},
	} {
		if got := automaticReconnectAuthorityUsable(now.Add(c.remaining), now); got != c.usable {
			t.Errorf("remaining %v usable = %t, want %t", c.remaining, got, c.usable)
		}
	}
}
