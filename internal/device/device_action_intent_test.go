// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"
	"time"

	"lindm/internal/device/core"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

// Regression: a remote aarch64 lane created its first escrow action 50 s after
// publishing a fresh delegation. The intent was backdated by the full device
// clock tolerance, before the delegation's own NotBefore, so the server's
// verifier rejected its own signed intent and CreateDeviceAction returned
// internal (debian12-arm64-dgx21-device-actions-encryption-04).
func TestDeviceActionIntentNeverPrecedesDelegation(t *testing.T) {
	now := time.Date(2026, 10, 11, 9, 36, 24, 0, time.UTC)
	for name, test := range map[string]struct {
		delegationNotBefore time.Time
		want                time.Time
	}{
		"fresh delegation":   {now.Add(-50 * time.Second), now.Add(-50 * time.Second)},
		"exactly tolerance":  {now.Add(-trust.MaxDeviceClockSkew), now.Add(-trust.MaxDeviceClockSkew)},
		"settled delegation": {now.Add(-time.Hour), now.Add(-trust.MaxDeviceClockSkew)},
	} {
		t.Run(name, func(t *testing.T) {
			delegation := &agentv1.ExecutionDelegation{NotBefore: timestamppb.New(test.delegationNotBefore), ExpiresAt: timestamppb.New(now.Add(4 * time.Hour))}
			got := core.DeviceActionNotBefore(now, delegation)
			if !got.Equal(test.want) {
				t.Fatalf("intent NotBefore = %v, want %v", got, test.want)
			}
			if got.Before(delegation.GetNotBefore().AsTime()) || got.After(now) {
				t.Fatalf("intent window %v..now escapes delegation from %v", got, test.delegationNotBefore)
			}
		})
	}
}
