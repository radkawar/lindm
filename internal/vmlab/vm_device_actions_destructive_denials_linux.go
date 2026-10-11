//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

func nativeDestructiveApprovalNegatives(ctx context.Context, vm *guestVM, fixture *devlab.AuthorityFixture, owner *devlab.OwnerSession, approver **devlab.OwnerSession, deviceID, generation string, secondary, encrypted *agentv1.StorageTarget) ([]actionDenialEvidence, error) {
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: secondary, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE}}}
	changed := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Target: encrypted, Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE}}}
	return nativeDestructiveSpecNegatives(ctx, vm, fixture, owner, approver, deviceID, generation, spec, changed, []string{"destructive_self_approval", "destructive_spec_digest_changed", "destructive_expired_approval", "destructive_revoked_approver"})
}

func nativeDestructiveSpecNegatives(ctx context.Context, vm *guestVM, fixture *devlab.AuthorityFixture, owner *devlab.OwnerSession, approver **devlab.OwnerSession, deviceID, generation string, spec, changed *agentv1.DeviceActionSpec, scenarios []string) ([]actionDenialEvidence, error) {
	var evidence []actionDenialEvidence
	for _, scenario := range scenarios {
		if err := owner.StepUp(ctx); err != nil {
			return evidence, err
		}
		request := actionRequestFor(deviceID, generation, spec)
		request.ExpiresAt = timestamppb.New(time.Now().Add(destructiveNegativeLifetime(scenario)))
		created, err := owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: uint32(destructiveNegativeApprovalLifetime / time.Second), Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
		if err != nil {
			return evidence, err
		}
		decision := &adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "disposable recovery destructive approval rejection probe"}
		if scenario == "destructive_self_approval" {
			_, rejected := owner.Admin.ApproveApproval(ctx, connect.NewRequest(decision))
			denial, err := actionDenial(scenario, rejected, connect.CodePermissionDenied)
			if err != nil {
				return evidence, err
			}
			evidence = append(evidence, denial)
			continue
		}
		approved, err := (*approver).ApproveApproval(ctx, connect.NewRequest(decision))
		if err != nil {
			return evidence, err
		}
		request.ApprovalId = approved.Msg.GetApproval().GetId()
		switch scenario {
		case "destructive_spec_digest_changed":
			// Both targets/methods are genuinely locally qualified. The negative
			// must reach server digest binding, not fail native target discovery.
			request.Spec = changed
		case "destructive_expired_approval":
			if err := lifecycleDelay(ctx, time.Until(approved.Msg.GetApproval().GetExpiresAt().AsTime().Add(time.Second))); err != nil {
				return evidence, err
			}
		case "destructive_revoked_approver":
			account := (*approver).AccountID
			if err := (*approver).Close(ctx); err != nil {
				return evidence, err
			}
			*approver = nil
			if err := fixture.RevokeAccount(ctx, account); err != nil {
				return evidence, err
			}
		}
		if err := lifecycleCommand(ctx, vm, "verify recovery presence relay before negative authority probe", "systemctl is-active --quiet lindm-agent.service"); err != nil {
			return evidence, err
		}
		if err := waitNativeActionPresence(ctx, owner, deviceID); err != nil {
			return evidence, err
		}
		if err := lifecycleCommand(ctx, vm, "reserve negative action for nonexecuting probe", "systemctl stop lindm-agent.service"); err != nil {
			return evidence, err
		}
		action, err := owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
		if err != nil {
			return evidence, err
		}
		input, err := protojson.Marshal(&agentv1.GetDeviceActionRequest{ActionId: action.Msg.GetAction().GetActionId()})
		if err != nil {
			return evidence, err
		}
		data, err := vm.run(ctx, "sudo -n -u lindm -- "+guestLifecycleProbe+" guest action-authorize-denied", bytes.NewReader(input), 16<<10, 30*time.Second)
		if err != nil {
			return evidence, err
		}
		var denial actionDenialEvidence
		if err := json.Unmarshal(data, &denial); err != nil {
			return evidence, err
		}
		if denial.Code != connect.CodePermissionDenied.String() || denial.Reason == "" || denial.ObservedAt.IsZero() {
			return evidence, errors.New("invalid native server approval-denial evidence")
		}
		denial.Scenario = scenario
		evidence = append(evidence, denial)
		if scenario == "destructive_revoked_approver" {
			if err := fixture.RestoreAccount(ctx, approved.Msg.GetApproval().GetApproverId()); err != nil {
				return evidence, err
			}
			*approver, err = fixture.OpenApproverSession(ctx)
			if err != nil {
				return evidence, err
			}
		}
		// No Start RPC exists in the probe. Let only this unstarted intent and
		// its root challenge expire before reconnecting normal dispatch.
		if err := lifecycleDelay(ctx, time.Until(action.Msg.GetAction().GetExpiresAt().AsTime().Add(time.Second))); err != nil {
			return evidence, err
		}
		if err := lifecycleCommand(ctx, vm, "resume recovery after rejected intent expiry", "systemctl start lindm-agent.service"); err != nil {
			return evidence, err
		}
	}
	return evidence, waitNativeActionPresence(ctx, owner, deviceID)
}

// destructiveNegativeApprovalLifetime is the short approval the expired-approval
// probe outlives before presenting it.
const destructiveNegativeApprovalLifetime = 60 * time.Second

// destructiveNegativeLifetime is the approved request's own validity. The
// approval binds it, so it must still be unexpired when CreateDeviceAction
// finally runs: after the approval-expiry wait (expired probe only) and the
// bounded presence/inventory wait. A fixed 40/110 s let a slow inventory
// publication turn the intended approval denial into device_action_expiry.
func destructiveNegativeLifetime(scenario string) time.Duration {
	lifetime := 40*time.Second + nativeActionPresenceTimeout
	if scenario == "destructive_expired_approval" {
		lifetime += destructiveNegativeApprovalLifetime + time.Second
	}
	return lifetime
}
