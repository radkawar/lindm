// SPDX-License-Identifier: Apache-2.0

package assistancerecording

import (
	agentv1 "lindm/gen/lindm/agent/v1"
)

// Intersect is the stricter of two recording bounds. An absent or unbounded
// side never enables recording.
func Intersect(a, b *agentv1.AssistanceRecordingPolicy) *agentv1.AssistanceRecordingPolicy {
	if a.GetRetentionDays() == 0 || b.GetRetentionDays() == 0 || a.GetMaxBytes() < MinRecordingBytes || b.GetMaxBytes() < MinRecordingBytes {
		return nil
	}
	return &agentv1.AssistanceRecordingPolicy{
		RetentionDays: min(a.GetRetentionDays(), b.GetRetentionDays(), MaxRetentionDays),
		MaxBytes:      min(a.GetMaxBytes(), b.GetMaxBytes(), MaxRecordingBytes),
	}
}

// Required reports whether a consented policy makes recording a condition of
// the session rather than a local choice.
func Required(requested, effective agentv1.AssistancePolicyMode) bool {
	return requested == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && effective == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
}
