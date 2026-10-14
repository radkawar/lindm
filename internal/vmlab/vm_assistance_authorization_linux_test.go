// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func authorityBoundaryFixture(name string) (*assistanceScenarioEvidence, *assistanceNativeBoundary) {
	const actor = "11111111-1111-4111-8111-111111111111"
	const owner = "22222222-2222-4222-8222-222222222222"
	const device = "33333333-3333-4333-8333-333333333333"
	const request = "44444444-4444-4444-8444-444444444444"
	const nonce = "555555555555555555555555"
	scenario := &assistanceScenarioEvidence{Name: name, Mode: "control", SessionID: "session", DeviceID: device, OperatorID: actor, OperatorDisplay: "Real Operator", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	before := &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123, ClipboardSource: nonce, Pasted: nonce, PasteSerial: 1}
	after := *before
	after.PasteSerial = 2
	authority := &assistanceAuthorityWitness{
		Requested: assistanceFullPolicy(), Effective: assistanceFullPolicy(), Granted: &agentv1.AssistanceCapabilities{Policy: assistanceFullPolicy()},
		PolicyBefore: assistanceFullPolicy(), DeploymentCeiling: assistanceFullPolicy(),
		DenialAudit: &assistanceAuditEvidence{ID: request, OccurredAt: time.Now(), ActorID: actor, Action: "assistance.clipboard", ResourceID: "session", TargetDeviceID: device, Details: map[string]string{"request": request, "result": "denied", "kind": "clipboard_write", "direction": "operator_to_user"}},
	}
	boundary := &assistanceNativeBoundary{Boundary: "clipboard-permission-refused", SessionID: "session", RequestID: request, Code: "not_found", Reason: "not_found", HTTPStatus: 404, ObservedAt: time.Now(), ClipboardBefore: nonce, ClipboardAfter: nonce, GuestBefore: before, Guest: &after, Authority: authority,
		Actor: &assistanceActor{ID: actor, Display: "Real Operator", Role: assistanceNoClipboardRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard"}, ObservedAt: time.Now()},
	}
	if name == "clipboard-permission" {
		authority.Requested.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		authority.Effective.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		authority.Granted.Policy.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		authority.DenialAudit.Details["reason"] = "capability_scope_denied"
		return scenario, boundary
	}
	boundary.Boundary = "clipboard-policy-revoked"
	boundary.Actor.Role = "owner"
	boundary.Actor.Permissions = append(boundary.Actor.Permissions, "remote_assistance.clipboard")
	boundary.Code, boundary.Reason, boundary.HTTPStatus = "failed_precondition", "assistance_ended", 400
	boundary.EndCause, boundary.EndDetail = "authorization_lost", "policy_changed"
	authority.PolicyAfter = assistanceFullPolicy()
	authority.PolicyAfter.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	authority.PolicyActorID, authority.PolicyRequestID = owner, owner
	authority.PolicyAudit = &assistanceAuditEvidence{ID: owner, OccurredAt: time.Now(), ActorID: owner, Action: "assistance.policy", ResourceID: device, TargetDeviceID: device, Details: map[string]string{"request": owner, "result": "updated", "reason": "policy_updated", "clipboard": "off"}}
	authority.DenialAudit.Details["reason"] = "session_ended"
	return scenario, boundary
}

func TestAssistancePermissionDenialRequiresSpecificLiveCreatorAuthority(t *testing.T) {
	scenario, boundary := authorityBoundaryFixture("clipboard-permission")
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*assistanceNativeBoundary){
		"missing view": func(b *assistanceNativeBoundary) {
			b.Actor.Permissions = []string{"remote_assistance.control", "remote_assistance.keyboard"}
		},
		"missing control": func(b *assistanceNativeBoundary) {
			b.Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.keyboard"}
		},
		"clipboard actually present": func(b *assistanceNativeBoundary) {
			b.Actor.Permissions = append(b.Actor.Permissions, "remote_assistance.clipboard")
		},
		"other creator":         func(b *assistanceNativeBoundary) { b.Actor.ID = "22222222-2222-4222-8222-222222222222" },
		"generic not found":     func(b *assistanceNativeBoundary) { b.Authority.DenialAudit = nil },
		"view scope denial":     func(b *assistanceNativeBoundary) { b.Authority.DenialAudit.Action = "assistance.command_denied" },
		"another request audit": func(b *assistanceNativeBoundary) { b.RequestID = "66666666-6666-4666-8666-666666666666" },
		"inactive baseline": func(b *assistanceNativeBoundary) {
			b.Authority.Granted.Policy.Keyboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		},
		"stale native paste":       func(b *assistanceNativeBoundary) { b.Guest.PasteSerial = b.GuestBefore.PasteSerial },
		"changed native clipboard": func(b *assistanceNativeBoundary) { b.Guest.Pasted = "changed" },
		"another GTK process":      func(b *assistanceNativeBoundary) { b.Guest.PID++ },
		"another guest session":    func(b *assistanceNativeBoundary) { b.Guest.SessionID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			scenario, boundary := authorityBoundaryFixture("clipboard-permission")
			alter(boundary)
			if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
				t.Fatal("unproven permission boundary qualified Tier1")
			}
		})
	}
}

func TestAssistancePolicyDenialRequiresActualAdministrativeRevocation(t *testing.T) {
	scenario, boundary := authorityBoundaryFixture("clipboard-policy")
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*assistanceNativeBoundary){
		"requested limited only": func(b *assistanceNativeBoundary) {
			b.Authority.Requested.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
		},
		"no policy downgrade": func(b *assistanceNativeBoundary) {
			b.Authority.PolicyAfter.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
		},
		"missing update audit":      func(b *assistanceNativeBoundary) { b.Authority.PolicyAudit = nil },
		"unrelated policy actor":    func(b *assistanceNativeBoundary) { b.Authority.PolicyAudit.ActorID = b.Actor.ID },
		"ordinary operator stop":    func(b *assistanceNativeBoundary) { b.EndCause, b.EndDetail = "operator_stopped", "" },
		"capability denial instead": func(b *assistanceNativeBoundary) { b.Reason = "assistance_capability_not_granted" },
		"role denial instead": func(b *assistanceNativeBoundary) {
			b.Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.control"}
		},
		"stale clipboard proof": func(b *assistanceNativeBoundary) { b.Guest.PasteSerial = b.GuestBefore.PasteSerial },
	} {
		t.Run(name, func(t *testing.T) {
			scenario, boundary := authorityBoundaryFixture("clipboard-policy")
			alter(boundary)
			if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
				t.Fatal("unproven per-device policy revocation qualified Tier1")
			}
		})
	}
}

func TestAssistanceAuthorityAuditsRequireTypedAttribution(t *testing.T) {
	const other = "66666666-6666-4666-8666-666666666666"
	for _, name := range []string{"clipboard-permission", "clipboard-policy"} {
		t.Run(name, func(t *testing.T) {
			for field, alter := range map[string]func(*assistanceAuditEvidence){
				"actor":         func(a *assistanceAuditEvidence) { a.ActorID = other },
				"resource":      func(a *assistanceAuditEvidence) { a.ResourceID = other },
				"target device": func(a *assistanceAuditEvidence) { a.TargetDeviceID = other },
				"request":       func(a *assistanceAuditEvidence) { a.Details["request"] = other },
				"result":        func(a *assistanceAuditEvidence) { a.Details["result"] = "succeeded" },
				"kind":          func(a *assistanceAuditEvidence) { a.Details["kind"] = "clipboard_read" },
				"direction":     func(a *assistanceAuditEvidence) { a.Details["direction"] = "user_to_operator" },
				"reason":        func(a *assistanceAuditEvidence) { a.Details["reason"] = "scope_denied" },
				"reason token fallback": func(a *assistanceAuditEvidence) {
					a.Reason = "device=" + a.TargetDeviceID + " request=" + a.Details["request"] + " result=denied kind=clipboard_write direction=operator_to_user reason=" + a.Details["reason"]
					a.Details = nil
				},
				"device token fallback": func(a *assistanceAuditEvidence) {
					a.Details["device"] = a.TargetDeviceID
					a.TargetDeviceID = ""
				},
			} {
				t.Run(field, func(t *testing.T) {
					scenario, boundary := authorityBoundaryFixture(name)
					alter(boundary.Authority.DenialAudit)
					if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
						t.Fatal("unattributed denial audit qualified Tier1")
					}
				})
			}
			t.Run("operator text is not metadata", func(t *testing.T) {
				scenario, boundary := authorityBoundaryFixture(name)
				boundary.Authority.DenialAudit.Reason = "request=" + other + " result=succeeded reason=scope_denied"
				if boundary.Authority.PolicyAudit != nil {
					boundary.Authority.PolicyAudit.Reason = "request=" + other + " clipboard=on"
				}
				if err := verifyAssistanceNativeBoundary(scenario, boundary); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestAssistancePolicyAuditRequiresTypedUpdate(t *testing.T) {
	const other = "66666666-6666-4666-8666-666666666666"
	for field, alter := range map[string]func(*assistanceAuditEvidence){
		"resource":      func(a *assistanceAuditEvidence) { a.ResourceID = other },
		"target device": func(a *assistanceAuditEvidence) { a.TargetDeviceID = other },
		"action":        func(a *assistanceAuditEvidence) { a.Action = "assistance.end" },
		"request":       func(a *assistanceAuditEvidence) { a.Details["request"] = other },
		"result":        func(a *assistanceAuditEvidence) { a.Details["result"] = "denied" },
		"reason":        func(a *assistanceAuditEvidence) { a.Details["reason"] = "scope_denied" },
		"clipboard":     func(a *assistanceAuditEvidence) { a.Details["clipboard"] = "on" },
		"reason token fallback": func(a *assistanceAuditEvidence) {
			a.Reason = "request=" + a.Details["request"] + " result=updated reason=policy_updated clipboard=off"
			a.Details = nil
		},
		"device token fallback": func(a *assistanceAuditEvidence) {
			a.Details["device"] = a.TargetDeviceID
			a.TargetDeviceID = ""
		},
	} {
		t.Run(field, func(t *testing.T) {
			scenario, boundary := authorityBoundaryFixture("clipboard-policy")
			alter(boundary.Authority.PolicyAudit)
			if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
				t.Fatal("unattributed policy update qualified Tier1")
			}
		})
	}
}
