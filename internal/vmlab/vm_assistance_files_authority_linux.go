// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

type assistanceFileRefusal struct {
	RequestID  string                   `json:"requestId"`
	Boundary   string                   `json:"boundary"`
	Code       string                   `json:"code"`
	Reason     string                   `json:"reason"`
	HTTPStatus int                      `json:"httpStatus"`
	Actor      *assistanceActor         `json:"actor"`
	Audit      *assistanceAuditEvidence `json:"audit"`
	Actions    struct {
		SendDisabled    bool `json:"sendDisabled"`
		RequestDisabled bool `json:"requestDisabled"`
	} `json:"actions"`
}

type assistanceFileAuthorityProof struct {
	Requested     *agentv1.AssistancePolicy       `json:"requested"`
	Effective     *agentv1.AssistancePolicy       `json:"effective"`
	Granted       *agentv1.AssistanceCapabilities `json:"granted"`
	PolicyBefore  *agentv1.AssistancePolicy       `json:"policy_before"`
	PolicyAfter   *agentv1.AssistancePolicy       `json:"policy_after,omitempty"`
	PolicyRequest string                          `json:"policy_request,omitempty"`
	PolicyActor   string                          `json:"policy_actor,omitempty"`
	PolicyAudit   *assistanceAuditEvidence        `json:"policy_audit,omitempty"`
	Refusal       *assistanceFileRefusal          `json:"refusal"`
	BeforeState   adminv1.AssistanceState         `json:"before_state"`
	AfterState    adminv1.AssistanceState         `json:"after_state"`
	EndCause      agentv1.AssistanceEndCause      `json:"end_cause"`
}

func (r *assistanceRun) fileAuthorityScenario(ctx context.Context, scenario *assistanceScenarioEvidence, session *adminv1.AssistanceSession) (_ *assistanceFileAuthorityProof, err error) {
	policy, err := r.owner.Admin.GetAssistancePolicy(ctx, connect.NewRequest(&adminv1.GetAssistancePolicyRequest{DeviceId: r.deviceID}))
	if err != nil {
		return nil, err
	}
	proof := &assistanceFileAuthorityProof{Requested: session.GetRequestedCapabilities(), Effective: session.GetEffectiveCapabilities(), Granted: session.GetGrantedCapabilities(), PolicyBefore: policy.Msg.GetPolicy(), BeforeState: session.GetState()}
	kind := "direction"
	if scenario.Name == "files-permission" {
		kind = "permission"
	}
	if scenario.Name == "files-policy" {
		kind = "policy"
		restricted := proto.CloneOf(proof.PolicyBefore)
		restricted.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		restricted.FileLimits = nil
		proof.PolicyRequest, proof.PolicyActor = uuid.NewString(), r.owner.AccountID
		updated, updateErr := r.owner.Admin.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: proof.PolicyRequest, DeviceId: r.deviceID, Policy: restricted}))
		if updateErr != nil {
			return nil, updateErr
		}
		proof.PolicyAfter = updated.Msg.GetPolicy()
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			_, restoreErr := r.owner.Admin.UpdateAssistancePolicy(cleanup, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: r.deviceID, Policy: proof.PolicyBefore}))
			err = errors.Join(err, restoreErr)
		}()
		proof.PolicyAudit, err = r.authorizationAudit(ctx, r.deviceID, proof.PolicyActor, "assistance.policy", proof.PolicyRequest)
		if err != nil {
			return nil, err
		}
		terminal, terminalErr := r.waitSession(ctx, scenario, 45*time.Second, "file policy withdrawal", ended)
		if terminalErr != nil {
			return nil, terminalErr
		}
		proof.AfterState, proof.EndCause = terminal.GetState(), terminal.GetEndCause()
	}
	refusal := new(assistanceFileRefusal)
	if err := r.browser.call(ctx, "fileRefuse", map[string]any{"boundary": kind}, refusal, 30*time.Second); err != nil {
		return nil, err
	}
	refusal.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.deny", refusal.RequestID)
	if err != nil {
		return nil, err
	}
	proof.Refusal = refusal
	if scenario.Name != "files-policy" {
		current, currentErr := r.owner.Admin.GetAssistanceSession(ctx, connect.NewRequest(&adminv1.GetAssistanceSessionRequest{SessionId: scenario.SessionID}))
		if currentErr != nil {
			return nil, currentErr
		}
		proof.AfterState, proof.EndCause = current.Msg.GetSession().GetState(), current.Msg.GetSession().GetEndCause()
	}
	return proof, verifyFileAuthority(scenario, proof)
}

func verifyFileAuthority(scenario *assistanceScenarioEvidence, proof *assistanceFileAuthorityProof) error {
	expectedPolicy := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	if scenario.Name == "files-limited" {
		expectedPolicy = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	}
	if proof == nil || proof.BeforeState != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || proof.Requested == nil || proof.Effective == nil || proof.Granted == nil || proof.PolicyBefore.GetFiles() != expectedPolicy {
		return errors.New("file authority proof lacks independently granted active policy")
	}
	refusal := proof.Refusal
	if refusal == nil || !vmValidID(refusal.RequestID) || verifyAssistanceActor(scenario, refusal.Actor) != nil || refusal.Audit == nil {
		return errors.New("file refusal lacks an authenticated creator and exact audit")
	}
	audit := refusal.Audit
	if !vmValidID(audit.ID) || audit.ActorID != scenario.OperatorID || audit.ResourceID != scenario.SessionID || audit.TargetDeviceID != scenario.DeviceID || audit.Action != "assistance.file.deny" || audit.Details["request"] != refusal.RequestID || audit.Details["result"] != "denied" {
		return errors.New("file refusal audit is not attributed to the actual attempt")
	}
	switch scenario.Name {
	case "files-limited":
		if !refusal.Actions.RequestDisabled {
			return errors.New("limited outgoing file action remains enabled")
		}
		if proof.Requested.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || proof.Effective.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || proof.Granted.GetPolicy().GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || refusal.Boundary != "direction" || refusal.Code != "failed_precondition" || refusal.HTTPStatus != 400 || refusal.Reason != "assistance_files_not_granted" || audit.Details["reason"] != refusal.Reason || !slices.Contains(refusal.Actor.Permissions, "remote_assistance.files") {
			return errors.New("limited files were not refused at the direction capability boundary")
		}
	case "files-permission":
		if !refusal.Actions.SendDisabled || !refusal.Actions.RequestDisabled {
			return errors.New("file actions remain enabled for a creator without permission")
		}
		if proof.Granted.GetPolicy().GetFiles() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || refusal.Actor.Role != assistanceNoFilesRole || slices.Contains(refusal.Actor.Permissions, "remote_assistance.files") || refusal.Boundary != "permission" || refusal.Code != "not_found" || refusal.HTTPStatus != 404 || audit.Details["reason"] != "files_scope_denied" {
			return errors.New("file refusal was not the independently restricted creator permission")
		}
	case "files-policy":
		policyAudit := proof.PolicyAudit
		if proof.Granted.GetPolicy().GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON || proof.PolicyAfter.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || !vmValidID(proof.PolicyRequest) || !vmValidID(proof.PolicyActor) || policyAudit == nil || !vmValidID(policyAudit.ID) || policyAudit.ActorID != proof.PolicyActor || policyAudit.ResourceID != scenario.DeviceID || policyAudit.Action != "assistance.policy" || policyAudit.Details["request"] != proof.PolicyRequest || proof.AfterState != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED || proof.EndCause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST || refusal.Boundary != "policy" || refusal.Code != "failed_precondition" || refusal.HTTPStatus != 400 || refusal.Reason != "assistance_not_active" || audit.Details["reason"] != "session_not_active" {
			return errors.New("file policy revocation lacks exact authority change, session termination and denial")
		}
		return nil
	default:
		return errors.New("unexpected file authority scenario")
	}
	if proof.AfterState != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || proof.EndCause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
		return errors.New("direction or permission refusal unexpectedly ended assistance")
	}
	return nil
}
