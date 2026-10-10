package devlab

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func TestServiceChallengeWindowDeviceClockTolerance(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		skew time.Duration
		want bool
	}{
		{"ahead ninety seconds", 90 * time.Second, true},
		{"behind ninety seconds", -90 * time.Second, true},
		{"ahead inclusive boundary", trust.MaxDeviceClockSkew, true},
		{"ahead beyond boundary", trust.MaxDeviceClockSkew + time.Nanosecond, false},
		{"expired exclusive boundary", -trust.MaxDeviceClockSkew - 30*time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := &agentv1.ServiceExecutionIntent{NotBefore: timestamppb.New(now.Add(-5 * time.Minute)), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute))}
			challenge := &agentv1.ServiceExecutionChallenge{IssuedAt: timestamppb.New(now.Add(tc.skew)), ExpiresAt: timestamppb.New(now.Add(tc.skew + 30*time.Second))}
			if got := serviceChallengeWindow(now, intent, challenge); got != tc.want {
				t.Fatalf("signing window accepted=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestServiceChallengeWindowDoesNotExtendIntent(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                        string
		start, end, issued, expires time.Duration
	}{
		{"host intent expired", -time.Minute, 0, -30 * time.Second, -time.Second},
		{"host intent not yet valid", time.Second, time.Minute, 2 * time.Second, 30 * time.Second},
		{"challenge predates intent", -time.Second, time.Minute, -2 * time.Second, 28 * time.Second},
		{"challenge outlives intent", -time.Minute, time.Second, 0, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := &agentv1.ServiceExecutionIntent{NotBefore: timestamppb.New(now.Add(tc.start)), ExpiresAt: timestamppb.New(now.Add(tc.end))}
			challenge := &agentv1.ServiceExecutionChallenge{IssuedAt: timestamppb.New(now.Add(tc.issued)), ExpiresAt: timestamppb.New(now.Add(tc.expires))}
			if serviceChallengeWindow(now, intent, challenge) {
				t.Fatal("device-clock tolerance extended host intent authority")
			}
		})
	}
}
