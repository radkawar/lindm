// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

func fileAuthorityTestProof(name string) (*assistanceScenarioEvidence, *assistanceFileAuthorityProof) {
	scenario := &assistanceScenarioEvidence{Name: name, Mode: "control", SessionID: uuid.NewString(), DeviceID: uuid.NewString(), OperatorID: uuid.NewString(), OperatorDisplay: "File reviewer"}
	mode := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if name == "files-policy" {
		mode = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	}
	if name == "files-permission" {
		mode = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	}
	policy := &agentv1.AssistancePolicy{Files: mode}
	proof := &assistanceFileAuthorityProof{Requested: proto.CloneOf(policy), Effective: proto.CloneOf(policy), Granted: &agentv1.AssistanceCapabilities{Policy: proto.CloneOf(policy)}, PolicyBefore: &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}, BeforeState: adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE, AfterState: adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE}
	if name == "files-limited" {
		proof.PolicyBefore.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	}
	refusal := &assistanceFileRefusal{RequestID: uuid.NewString(), Boundary: "direction", Code: "failed_precondition", Reason: "assistance_files_not_granted", HTTPStatus: 400, Actor: &assistanceActor{ID: scenario.OperatorID, Display: scenario.OperatorDisplay, Role: "owner", Permissions: []string{"remote_assistance.view", "remote_assistance.control", "remote_assistance.files"}, ObservedAt: time.Now().UTC()}}
	refusal.Actions.RequestDisabled = true
	refusal.Audit = &assistanceAuditEvidence{ID: uuid.NewString(), ActorID: scenario.OperatorID, ResourceID: scenario.SessionID, TargetDeviceID: scenario.DeviceID, Action: "assistance.file.deny", Details: map[string]string{"request": refusal.RequestID, "result": "denied", "reason": refusal.Reason}}
	if name == "files-permission" {
		refusal.Boundary, refusal.Code, refusal.Reason, refusal.HTTPStatus = "permission", "not_found", "not_found", 404
		refusal.Actor.Role = assistanceNoFilesRole
		refusal.Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard", "remote_assistance.clipboard"}
		refusal.Actions.SendDisabled = true
		refusal.Audit.Details["reason"] = "files_scope_denied"
	}
	if name == "files-policy" {
		proof.AfterState = adminv1.AssistanceState_ASSISTANCE_STATE_ENDED
		proof.EndCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST
		proof.PolicyAfter = &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF}
		proof.PolicyRequest, proof.PolicyActor = uuid.NewString(), uuid.NewString()
		proof.PolicyAudit = &assistanceAuditEvidence{ID: uuid.NewString(), ActorID: proof.PolicyActor, ResourceID: scenario.DeviceID, TargetDeviceID: scenario.DeviceID, Action: "assistance.policy", Details: map[string]string{"request": proof.PolicyRequest}}
		refusal.Boundary, refusal.Reason = "policy", "assistance_not_active"
		refusal.Audit.Details["reason"] = "session_not_active"
	}
	proof.Refusal = refusal
	return scenario, proof
}

// These are verifier unit fixtures, not evidence of a native portal or transfer.
func TestFileAuthorityWitnessRejectsWrongBoundaryAndAttribution(t *testing.T) {
	for _, name := range []string{"files-limited", "files-permission", "files-policy"} {
		t.Run(name, func(t *testing.T) {
			scenario, proof := fileAuthorityTestProof(name)
			if err := verifyFileAuthority(scenario, proof); err != nil {
				t.Fatal(err)
			}
			mutations := map[string]func(*assistanceFileAuthorityProof){
				"missing_actor": func(p *assistanceFileAuthorityProof) { p.Refusal.Actor = nil },
				"other_creator": func(p *assistanceFileAuthorityProof) { p.Refusal.Actor.ID = uuid.NewString() },
				"missing_view_authority": func(p *assistanceFileAuthorityProof) {
					p.Refusal.Actor.Permissions = []string{"remote_assistance.control", "remote_assistance.files"}
				},
				"missing_control_authority": func(p *assistanceFileAuthorityProof) {
					p.Refusal.Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.files"}
				},
				"other_request_audit":      func(p *assistanceFileAuthorityProof) { p.Refusal.Audit.Details["request"] = uuid.NewString() },
				"wrong_action":             func(p *assistanceFileAuthorityProof) { p.Refusal.Audit.Action = "assistance.file.complete" },
				"wrong_target":             func(p *assistanceFileAuthorityProof) { p.Refusal.Audit.TargetDeviceID = uuid.NewString() },
				"permission_not_direction": func(p *assistanceFileAuthorityProof) { p.Refusal.Code = "permission_denied" },
				"wrong_http":               func(p *assistanceFileAuthorityProof) { p.Refusal.HTTPStatus = 500 },
				"inactive_start":           func(p *assistanceFileAuthorityProof) { p.BeforeState = adminv1.AssistanceState_ASSISTANCE_STATE_ENDED },
				"missing_grant":            func(p *assistanceFileAuthorityProof) { p.Granted = nil },
			}
			if name == "files-policy" {
				mutations["did_not_end"] = func(p *assistanceFileAuthorityProof) { p.AfterState = adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE }
				mutations["unrelated_end"] = func(p *assistanceFileAuthorityProof) {
					p.EndCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
				}
				mutations["wrong_policy_actor"] = func(p *assistanceFileAuthorityProof) { p.PolicyAudit.ActorID = uuid.NewString() }
			} else {
				mutations["unexpected_end"] = func(p *assistanceFileAuthorityProof) { p.AfterState = adminv1.AssistanceState_ASSISTANCE_STATE_ENDED }
				mutations["action_enabled"] = func(p *assistanceFileAuthorityProof) { p.Refusal.Actions.RequestDisabled = false }
			}
			for label, mutate := range mutations {
				t.Run(label, func(t *testing.T) {
					scenario, proof := fileAuthorityTestProof(name)
					mutate(proof)
					if verifyFileAuthority(scenario, proof) == nil {
						t.Fatal("tampered authority proof accepted")
					}
				})
			}
		})
	}
}
