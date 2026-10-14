// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Every device policy a scenario sets must fit the deployment and agent
// ceiling, or the server refuses it assistance_policy_ceiling
// (layers-fedora44-tier3-02).
func TestAssistanceCeilingAdmitsEveryScenarioPolicy(t *testing.T) {
	ceiling := assistanceCeilingPolicy().ProtoReflect()
	unattendedOn := assistanceTierThreePolicy()
	unattendedOn.Unattended = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	for name, policy := range map[string]*agentv1.AssistancePolicy{"full": assistanceFullPolicy(), "tier three": assistanceTierThreePolicy(), "unattended on": unattendedOn} {
		fields := policy.ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			if field.Kind() != protoreflect.EnumKind {
				continue
			}
			if got, limit := policy.ProtoReflect().Get(field).Enum(), ceiling.Get(field).Enum(); got > limit {
				t.Errorf("%s policy %s=%d exceeds ceiling %d", name, field.Name(), got, limit)
			}
		}
	}
	limits, want := assistanceCeilingPolicy().GetUnattendedLimits(), assistanceTierThreePolicy().GetUnattendedLimits()
	if limits.GetMaxApprovalSeconds() < want.GetMaxApprovalSeconds() || limits.GetMaxEnrollmentDays() < want.GetMaxEnrollmentDays() || limits.GetMaxSessionSeconds() < want.GetMaxSessionSeconds() {
		t.Fatalf("ceiling unattended limits %v narrower than the lane's %v", limits, want)
	}
}
