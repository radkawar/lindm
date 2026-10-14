// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Every catalogue value yields a stored reason the hold release recognizes and
// the resource row's 128-character reason column accepts.
func TestCapabilityNotEnabledReasonCoversCatalogue(t *testing.T) {
	seen := make(map[string]bool)
	for value := range agentv1.ManagementCapability_name {
		capability := agentv1.ManagementCapability(value)
		if capability == agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_UNSPECIFIED {
			continue
		}
		reason := CapabilityNotEnabledReason(capability)
		if !strings.HasPrefix(reason, "capability_") || !strings.HasSuffix(reason, "_not_enabled") || len(reason) > 128 || strings.ToLower(reason) != reason || seen[reason] {
			t.Fatalf("capability %s has reason %q", capability, reason)
		}
		seen[reason] = true
	}
	if got := CapabilityNotEnabledReason(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS); got != "capability_custom_file_roots_not_enabled" {
		t.Fatalf("reason=%s", got)
	}
}

func TestCapabilityAuditListNamesBothSides(t *testing.T) {
	if got := capabilityList(nil); got != "none" {
		t.Fatalf("empty=%q", got)
	}
	if got := capabilityList([]int16{1, 2, 4, 6}); got != "packages,files,local_accounts,os_updates" {
		t.Fatalf("list=%q", got)
	}
}
