// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestCapabilityPolicyRequiresExactDelegatedPlanCapability(t *testing.T) {
	f := newExecutionFixture(t, 1)
	plan, start, other := testKey(t), testKey(t), testKey(t)
	delegation := &agentv1.ExecutionDelegation{
		DeploymentId: f.root.GetDeploymentId(), RootVersion: 1, Version: 1,
		NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)),
		Delegates: []*agentv1.ExecutionDelegate{
			{Key: executionTestKey(t, plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{CapabilityPolicyCapability}},
			{Key: executionTestKey(t, start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{CapabilityPolicyCapability}},
			{Key: executionTestKey(t, other), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}},
		},
	}
	verified, err := f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	policy := func(deployment string) *agentv1.AgentCapabilityPolicy {
		return &agentv1.AgentCapabilityPolicy{
			FormatVersion: 1, DeploymentId: deployment, DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(),
			Version: 3, IssuedAt: timestamppb.New(f.now),
			Capabilities: []agentv1.ManagementCapability{agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES},
		}
	}
	for _, tc := range []struct {
		name   string
		key    ed25519.PrivateKey
		policy *agentv1.AgentCapabilityPolicy
		at     time.Time
		valid  bool
	}{
		{name: "authorized", key: plan, policy: policy(f.root.GetDeploymentId()), at: f.now, valid: true},
		{name: "start role", key: start, policy: policy(f.root.GetDeploymentId()), at: f.now},
		{name: "undelegated plan key", key: other, policy: policy(f.root.GetDeploymentId()), at: f.now},
		{name: "offline root", key: f.keys[0], policy: policy(f.root.GetDeploymentId()), at: f.now},
		{name: "foreign deployment", key: plan, policy: policy(uuid.NewString()), at: f.now},
		{name: "expired delegation", key: plan, policy: policy(f.root.GetDeploymentId()), at: f.now.Add(2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := executionSign(t, f.authority, tc.policy, tc.key)
			got, err := f.verifier.VerifyCapabilityPolicy(t.Context(), f.root, verified, envelope, tc.at)
			if tc.valid != (err == nil) {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && (got.GetVersion() != 3 || len(got.GetCapabilities()) != 2) {
				t.Fatalf("policy = %v", got)
			}
		})
	}
	if _, err := f.verifier.VerifyCapabilityPolicy(t.Context(), f.root, verified, executionSign(t, f.authority, policy(uuid.NewString()), plan), f.now); !errors.Is(err, ErrCapabilityPolicyBinding) {
		t.Fatalf("binding err = %v", err)
	}
}

func TestCapabilityPolicyPayloadTypeIsDomainSeparated(t *testing.T) {
	f := newExecutionFixture(t, 1)
	plan := testKey(t)
	delegation := executionSign(t, f.authority, &agentv1.ExecutionDelegation{
		DeploymentId: f.root.GetDeploymentId(), RootVersion: 1, Version: 1,
		NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)),
		Delegates: []*agentv1.ExecutionDelegate{{Key: executionTestKey(t, plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{CapabilityPolicyCapability}}},
	}, f.keys...)
	verified, err := f.verifier.VerifyDelegation(t.Context(), f.root, delegation, 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// A delegation envelope signed by the same chain is not a capability policy.
	if _, err := f.verifier.VerifyCapabilityPolicy(t.Context(), f.root, verified, delegation, f.now); err == nil {
		t.Fatal("delegation envelope accepted as capability policy")
	}
}
