// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func passwordDimensionFixture() *agentv1.ResourceOwnershipSnapshot {
	return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyObservation{PamOwner: "sssd", Effective: &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14), MaxAgeDays: proto.Uint32(90), FailureLimit: proto.Uint32(3)}}}}, PasswordPolicy: &agentv1.PasswordPolicyOwnership{ManagerProfile: "sssd", EnabledFeatures: []agentv1.PasswordNativeFeature{1, 3}}}
}
func TestPasswordOwnershipDoesNotAcquireAccountOrUnrelatedDimensions(t *testing.T) {
	before := passwordDimensionFixture()
	after := proto.CloneOf(before)
	after.Observation.GetPasswordPolicy().Effective.MaxAgeDays = proto.Uint32(180)
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_LENGTH, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_MANAGER}
	if !PasswordOwnershipMatches(before, after, dimensions) {
		t.Fatal("unowned future aging blocked length ownership")
	}
	if passwordOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, dimensions[0]) || passwordOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX) {
		t.Fatal("account and password policy ownership dimensions overlapped")
	}
	after.Observation.GetPasswordPolicy().Effective.MinLength = proto.Uint32(16)
	if PasswordOwnershipMatches(before, after, dimensions) {
		t.Fatal("changed owned length accepted")
	}
}
func TestPasswordOwnershipDetectsNativeManagerReplacement(t *testing.T) {
	before := passwordDimensionFixture()
	after := proto.CloneOf(before)
	after.PasswordPolicy.ManagerProfile = "custom/administrator"
	after.Observation.GetPasswordPolicy().PamOwner = "custom/administrator"
	if PasswordOwnershipMatches(before, after, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_MANAGER}) {
		t.Fatal("replaced PAM owner matched")
	}
}
func TestPasswordDimensionsRequireExplicitDesiredPresence(t *testing.T) {
	record := &agentv1.ResourceExecutionRecord{NativePlan: &resourcev1.ResourcePlan{Plan: &resourcev1.ResourcePlan_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyPlan{Desired: &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}}}}}
	if !passwordOwnershipDimensionAllowed(record, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_LENGTH) || passwordOwnershipDimensionAllowed(record, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_MAX_AGE) {
		t.Fatal("unmanaged login defaults acquired")
	}
}

func TestPasswordAcquisitionUsesNativeBaselineAfterActivation(t *testing.T) {
	baseline := passwordDimensionFixture()
	baseline.Observation.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY}
	baseline.Observation.GetPasswordPolicy().Effective.MinClasses = nil
	baseline.PasswordPolicy.Files = []*agentv1.PasswordNativeFileSnapshot{{Kind: 1, Content: []byte("# baseline\n")}}
	current := proto.CloneOf(baseline)
	current.Observation.GetPasswordPolicy().Effective.MinClasses = proto.Uint32(0)
	current.PasswordPolicy.Files[0].Content = []byte("minlen = 14\ndcredit = 0\nucredit = 0\nlcredit = 0\nocredit = 0\nlocal_users_only\n")
	ledger := &agentv1.ResourceOwnershipLedger{Baseline: baseline, LastApplied: proto.CloneOf(current), OwnedDimensions: []agentv1.ResourceOwnedDimension{40, 49}}
	if !baselineOwnershipDimensionMatches(ledger, current, 41) {
		t.Fatal("native default becoming observable blocked later signed acquisition")
	}
	current.PasswordPolicy.Files[0].Content = append(current.PasswordPolicy.Files[0].Content, []byte("minclass = 2\n")...)
	if baselineOwnershipDimensionMatches(ledger, current, 41) {
		t.Fatal("external newly acquired key was treated as original baseline")
	}
}

func TestPasswordAcquisitionBindsLowerPrecedenceGeneration(t *testing.T) {
	baseline := passwordDimensionFixture()
	baseline.PasswordPolicy.QualityDropinsSha256 = make([]byte, 32)
	baseline.PasswordPolicy.Files = []*agentv1.PasswordNativeFileSnapshot{{Kind: 1, Content: []byte("# native baseline\n")}}
	current := proto.CloneOf(baseline)
	current.PasswordPolicy.QualityDropinsSha256[0] = 1
	ledger := &agentv1.ResourceOwnershipLedger{Baseline: baseline, LastApplied: proto.CloneOf(baseline), OwnedDimensions: []agentv1.ResourceOwnedDimension{40, 49}}
	if PasswordBaselineDimensionMatches(ledger, current, 41) {
		t.Fatal("changed lower-precedence generation acquired after module activation")
	}
}
