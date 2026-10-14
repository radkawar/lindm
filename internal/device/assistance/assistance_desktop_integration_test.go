// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// Desktop gates are persisted device policy within the ceiling, narrow like
// any capability, and reach the device only through the effective policy;
// an operator request never carries them.
func TestAssistanceDesktopGatesReachInvitationsFromPolicyOnly(t *testing.T) {
	on, limited, off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	f := newAssistanceFixture(t, 0)
	full := allAssistanceCapabilities()
	full.KdePlasma, full.X11 = on, on
	f.svc.AssistanceCeiling = proto.CloneOf(full)
	update := func(policy *agentv1.AssistancePolicy) error {
		_, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: policy}))
		return err
	}
	if err := update(full); err != nil {
		t.Fatal(err)
	}
	narrowed := proto.CloneOf(full)
	narrowed.X11 = off
	if err := update(narrowed); err != nil {
		t.Fatalf("turning the X11 gate off: %v", err)
	}
	var narrowedAudits int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.policy' AND details->>'result'='updated' AND details->>'x11'='off' AND details->>'kde_plasma'='on'", f.deviceID).Scan(&narrowedAudits); err != nil {
		t.Fatal(err)
	}
	if narrowedAudits != 1 {
		t.Fatalf("policy audits with x11 off and kde_plasma on = %d", narrowedAudits)
	}
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	request.RequestedCapabilities = &agentv1.AssistancePolicy{Messages: on, KdePlasma: on, X11: on}
	if _, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	directives := f.sync(t)
	if len(directives) != 1 {
		t.Fatalf("directives = %d", len(directives))
	}
	invitation := directives[0].GetInvitation()
	if requested := invitation.GetRequestedCapabilities(); requested.GetKdePlasma() != off || requested.GetX11() != off || requested.GetMessages() != on {
		t.Fatalf("operator request carried a desktop gate: %v", requested)
	}
	if effective := invitation.GetEffectiveCapabilities(); effective.GetKdePlasma() != on || effective.GetX11() != off || effective.GetMessages() != on || effective.GetClipboard() != off {
		t.Fatalf("effective desktop gates = %v", effective)
	}
	f.svc.AssistanceCeiling.KdePlasma = limited
	if err := update(full); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("device policy above the KDE ceiling: %v", err)
	}
}
