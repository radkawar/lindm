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

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

const assistanceNoClipboardRole = "assistance-no-clipboard"

// assistanceActor is a whitelist from the real authenticated /auth/session
// response. In particular it cannot serialize the response's CSRF token.
type assistanceActor struct {
	ID          string    `json:"id"`
	Display     string    `json:"display"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
	ObservedAt  time.Time `json:"observed_at"`
}

func verifyAssistanceActor(scenario *assistanceScenarioEvidence, actor *assistanceActor) error {
	if actor == nil || !vmValidID(actor.ID) || actor.ID != scenario.OperatorID || actor.Display == "" || actor.Display != scenario.OperatorDisplay || actor.ObservedAt.IsZero() || !slices.Contains(actor.Permissions, "remote_assistance.view") || scenario.Mode == "control" && !slices.Contains(actor.Permissions, "remote_assistance.control") {
		return errors.New("authenticated actor does not match the server-bound session creator")
	}
	return nil
}

type assistanceAuthorityWitness struct {
	Requested         *agentv1.AssistancePolicy       `json:"requested"`
	Effective         *agentv1.AssistancePolicy       `json:"effective"`
	Granted           *agentv1.AssistanceCapabilities `json:"granted"`
	PolicyBefore      *agentv1.AssistancePolicy       `json:"policy_before"`
	PolicyAfter       *agentv1.AssistancePolicy       `json:"policy_after,omitempty"`
	DeploymentCeiling *agentv1.AssistancePolicy       `json:"deployment_ceiling"`
	PolicyActorID     string                          `json:"policy_actor_id,omitempty"`
	PolicyRequestID   string                          `json:"policy_request_id,omitempty"`
	PolicyAudit       *assistanceAuditEvidence        `json:"policy_audit,omitempty"`
	DenialAudit       *assistanceAuditEvidence        `json:"denial_audit"`
}

// Keep the administrative owner and the restricted session creator separate.
// Enrollment is real, and a distinct Chromium cookie jar owns the whole session.
func (r *assistanceRun) restrictedClipboardScenario(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string, spec assistanceScenarioSpec) (err error) {
	browser, err := openAssistanceOperator(ctx, fixture, options, private, "assistance-restricted", assistanceNoClipboardRole)
	if err != nil {
		return err
	}
	previous := r.browser
	r.browser = browser
	defer func() { r.browser = previous; err = errors.Join(err, browser.Close()) }()
	return r.scenario(ctx, spec)
}

func (r *assistanceRun) authorizationWitness(ctx context.Context, scenario *assistanceScenarioEvidence, session *adminv1.AssistanceSession) (err error) {
	if err := r.startFixture(ctx, 1); err != nil {
		return err
	}
	var marker struct {
		Head int `json:"head"`
	}
	if err := r.browser.call(ctx, "marker", nil, &marker, 45*time.Second); err != nil {
		return err
	}
	if marker.Head != 0 {
		return errors.New("authorization witness received another native head")
	}
	if _, err := r.pointerWitness(ctx, 0, 0.5, 0.6); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "keys", map[string]any{"key": "Control+c", "mode": "Physical keys"}, nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "independent native clipboard copy", func(state *assistanceFixtureState) bool {
		return len(state.Keys) > 0 && state.Keys[len(state.Keys)-1].Symbol == "c"
	}); err != nil {
		return err
	}
	before, err := r.localClipboardPaste(ctx)
	if err != nil {
		return err
	}
	if before.Pasted != before.ClipboardSource {
		return errors.New("native clipboard was not initialized with the independent guest nonce")
	}
	policy, err := r.owner.Admin.GetAssistancePolicy(ctx, connect.NewRequest(&adminv1.GetAssistancePolicyRequest{DeviceId: r.deviceID}))
	if err != nil {
		return err
	}
	authority := &assistanceAuthorityWitness{Requested: session.GetRequestedCapabilities(), Effective: session.GetEffectiveCapabilities(), Granted: session.GetGrantedCapabilities(), PolicyBefore: policy.Msg.GetPolicy(), DeploymentCeiling: policy.Msg.GetCeiling()}
	kind, name := "permission", "clipboard-permission-refused"
	var terminal *adminv1.AssistanceSession
	if scenario.Name == "clipboard-policy" {
		kind, name = "policy", "clipboard-policy-revoked"
		restricted := assistanceFullPolicy()
		restricted.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		authority.PolicyActorID, authority.PolicyRequestID = r.owner.AccountID, uuid.NewString()
		changed, changeErr := r.owner.Admin.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: authority.PolicyRequestID, DeviceId: r.deviceID, Policy: restricted}))
		if changeErr != nil {
			return changeErr
		}
		defer func() {
			_, restoreErr := r.owner.Admin.UpdateAssistancePolicy(context.WithoutCancel(ctx), connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: r.deviceID, Policy: authority.PolicyBefore}))
			err = errors.Join(err, restoreErr)
		}()
		authority.PolicyAfter = changed.Msg.GetPolicy()
		authority.PolicyAudit, err = r.authorizationAudit(ctx, r.deviceID, authority.PolicyActorID, "assistance.policy", authority.PolicyRequestID)
		if err != nil {
			return err
		}
		terminal, err = r.waitSession(ctx, scenario, 45*time.Second, "per-device policy revocation", ended)
		if err != nil {
			return err
		}
	}
	var boundary assistanceNativeBoundary
	if err := r.browser.call(ctx, "refuse", map[string]any{"boundary": kind}, &boundary, 45*time.Second); err != nil {
		return err
	}
	after, err := r.localClipboardPaste(ctx)
	if err != nil {
		return err
	}
	boundary.Boundary, boundary.GuestBefore, boundary.Guest = name, before, after
	boundary.ClipboardBefore, boundary.ClipboardAfter = before.Pasted, after.Pasted
	boundary.Authority = authority
	if terminal != nil {
		boundary.EndCause, boundary.EndDetail = assistanceCauseText(terminal.GetEndCause()), terminal.GetEndDetail()
	}
	authority.DenialAudit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.clipboard", boundary.RequestID)
	if err != nil {
		return err
	}
	return r.saveNativeBoundary(scenario, &boundary)
}

// Audit writes commit with the real RPC. An unrelated actor/404 is not proof of
// capability denial. Never project request metadata into an authorization result.
func (r *assistanceRun) authorizationAudit(ctx context.Context, resource, actor, action, request string) (*assistanceAuditEvidence, error) {
	token := ""
	for range 50 {
		response, err := r.owner.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 200, PageToken: token}))
		if err != nil {
			return nil, err
		}
		for _, event := range response.Msg.GetEvents() {
			if event.GetResourceId() == resource && event.GetActorId() == actor && event.GetAction() == action && event.GetTargetDeviceId() == r.deviceID && event.GetDetails()["request"] == request {
				return &assistanceAuditEvidence{ID: event.GetId(), OccurredAt: event.GetOccurredAt().AsTime(), ActorID: event.GetActorId(), Action: event.GetAction(), ResourceID: event.GetResourceId(), Reason: event.GetReason(), TargetDeviceID: event.GetTargetDeviceId(), Details: event.GetDetails()}, nil
			}
		}
		token = response.Msg.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil, errors.New("authority boundary lacks a matching real actor/request audit event")
}

func verifyAssistanceAuthorityBoundary(scenario *assistanceScenarioEvidence, boundary *assistanceNativeBoundary) error {
	if err := verifyAssistanceActor(scenario, boundary.Actor); err != nil {
		return err
	}
	a := boundary.Authority
	if a == nil || a.DenialAudit == nil || !vmValidID(scenario.DeviceID) || !vmValidID(a.DenialAudit.ID) || a.DenialAudit.OccurredAt.IsZero() || a.DenialAudit.ActorID != scenario.OperatorID || a.DenialAudit.ResourceID != scenario.SessionID || a.DenialAudit.TargetDeviceID != scenario.DeviceID || a.DenialAudit.Action != "assistance.clipboard" || a.DenialAudit.Details["request"] != boundary.RequestID || a.DenialAudit.Details["result"] != "denied" || a.DenialAudit.Details["kind"] != "clipboard_write" || a.DenialAudit.Details["direction"] != "operator_to_user" {
		return errors.New("clipboard authority refusal lacks matching authenticated actor, request and audit decision")
	}
	on, off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	if a.PolicyBefore.GetClipboard() != on || a.DeploymentCeiling.GetClipboard() != on || boundary.GuestBefore.Pasted != boundary.GuestBefore.ClipboardSource {
		return errors.New("authorization witness lacks unrestricted policy baseline and independent native nonce")
	}
	if boundary.Boundary == "clipboard-permission-refused" {
		if boundary.Actor.Role != assistanceNoClipboardRole || slices.Contains(boundary.Actor.Permissions, "remote_assistance.clipboard") || !slices.Contains(boundary.Actor.Permissions, "remote_assistance.keyboard") || boundary.Code != "not_found" || boundary.HTTPStatus != 404 || boundary.Reason != "not_found" || a.DenialAudit.Details["reason"] != "capability_scope_denied" {
			return errors.New("refusal does not prove missing clipboard permission while view and control remain authorized")
		}
		if a.Requested.GetClipboard() > off || a.Effective.GetClipboard() > off || a.Granted.GetPolicy().GetClipboard() > off || a.Requested.GetKeyboard() != on || a.Effective.GetKeyboard() != on || a.Granted.GetPolicy().GetKeyboard() != on {
			return errors.New("restricted creator did not establish its own allowed live keyboard session")
		}
		return nil
	}
	if a.Requested.GetClipboard() != on || a.Effective.GetClipboard() != on || a.Granted.GetPolicy().GetClipboard() != on || !slices.Contains(boundary.Actor.Permissions, "remote_assistance.clipboard") || a.PolicyAfter.GetClipboard() != off {
		return errors.New("policy revocation did not narrow a real full-grant clipboard session")
	}
	if !vmValidID(a.PolicyActorID) || a.PolicyActorID == scenario.OperatorID || !vmValidID(a.PolicyRequestID) || a.PolicyAudit == nil || !vmValidID(a.PolicyAudit.ID) || a.PolicyAudit.OccurredAt.IsZero() || a.PolicyAudit.ActorID != a.PolicyActorID || a.PolicyAudit.ResourceID != scenario.DeviceID || a.PolicyAudit.TargetDeviceID != scenario.DeviceID || a.PolicyAudit.Action != "assistance.policy" || a.PolicyAudit.Details["request"] != a.PolicyRequestID || a.PolicyAudit.Details["result"] != "updated" || a.PolicyAudit.Details["reason"] != "policy_updated" || a.PolicyAudit.Details["clipboard"] != "off" {
		return errors.New("policy revocation lacks the real administrative update and audit")
	}
	if boundary.Code != "failed_precondition" || boundary.HTTPStatus != 400 && boundary.HTTPStatus != 412 || boundary.Reason != "assistance_ended" || boundary.EndCause != "authorization_lost" || boundary.EndDetail != "policy_changed" || a.DenialAudit.Details["reason"] != "session_ended" {
		return errors.New("clipboard refusal was not caused by per-device policy revocation")
	}
	return nil
}
