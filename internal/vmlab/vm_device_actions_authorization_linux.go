//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
	"lindm/internal/rpcreason"
)

type actionDenialEvidence struct {
	Scenario   string    `json:"scenario"`
	Code       string    `json:"code"`
	Reason     string    `json:"reason"`
	ObservedAt time.Time `json:"observed_at"`
}

func actionDenial(name string, err error, expected connect.Code) (actionDenialEvidence, error) {
	var rpc *connect.Error
	if !errors.As(err, &rpc) || rpc.Code() != expected || rpcreason.Get(rpc) == "" {
		return actionDenialEvidence{}, fmt.Errorf("%s did not receive expected %s denial (observed %s, reason %q)", name, expected, connect.CodeOf(err), func() string {
			if rpc != nil {
				return rpcreason.Get(rpc)
			}
			return ""
		}())
	}
	return actionDenialEvidence{Scenario: name, Code: rpc.Code().String(), Reason: rpcreason.Get(rpc), ObservedAt: time.Now().UTC()}, nil
}

func nativeApprovalNegatives(ctx context.Context, fixture *devlab.AuthorityFixture, owner *devlab.OwnerSession, approver **devlab.OwnerSession, deviceID, actionID string) ([]actionDenialEvidence, error) {
	var evidence []actionDenialEvidence
	for _, scenario := range []string{"self_approval", "digest_changed", "expired_approval", "revoked_approver"} {
		if err := owner.StepUp(ctx); err != nil {
			return evidence, err
		}
		request := &adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: deviceID, ActionId: actionID, Reason: "native escrow approval rejection qualification"}
		created, err := owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 60, Payload: &adminv1.CreateApprovalRequest_RevealRecoveryKey{RevealRecoveryKey: request}}))
		if err != nil {
			return evidence, err
		}
		approval := created.Msg.GetApproval()
		decision := &adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "native independently authenticated approval test"}
		if scenario == "self_approval" {
			_, rejected := owner.Admin.ApproveApproval(ctx, connect.NewRequest(decision))
			observation, err := actionDenial(scenario, rejected, connect.CodePermissionDenied)
			if err != nil {
				return evidence, err
			}
			evidence = append(evidence, observation)
			continue
		}
		approved, err := (*approver).ApproveApproval(ctx, connect.NewRequest(decision))
		if err != nil {
			return evidence, err
		}
		approval = approved.Msg.GetApproval()
		request.ApprovalId = approval.GetId()
		switch scenario {
		case "digest_changed":
			request.Reason = "different exact approved reason must invalidate digest"
		case "expired_approval":
			if err := lifecycleDelay(ctx, time.Until(approval.GetExpiresAt().AsTime().Add(time.Second))); err != nil {
				return evidence, err
			}
		case "revoked_approver":
			// Revoke the session before disabling the principal so cleanup never
			// masks the actual negative with an already-revoked logout failure.
			accountID := (*approver).AccountID
			if err := (*approver).Close(ctx); err != nil {
				return evidence, err
			}
			*approver = nil
			if err := fixture.RevokeAccount(ctx, accountID); err != nil {
				return evidence, err
			}
		}
		response, rejected := owner.Admin.RevealRecoveryKey(ctx, connect.NewRequest(request))
		if response != nil {
			clear(response.Msg.RecoveryKey)
			response.Msg.RecoveryKey = nil
		}
		observation, err := actionDenial(scenario, rejected, connect.CodePermissionDenied)
		if err != nil {
			return evidence, err
		}
		evidence = append(evidence, observation)
		if scenario == "revoked_approver" {
			if err := fixture.RestoreAccount(ctx, approval.GetApproverId()); err != nil {
				return evidence, err
			}
			*approver, err = fixture.OpenApproverSession(ctx)
			if err != nil {
				return evidence, err
			}
		}
	}
	return evidence, nil
}

func nativeOfflineDenial(ctx context.Context, vm *EncryptedVM, owner *devlab.OwnerSession, deviceID, generation string) (actionDenialEvidence, error) {
	if err := lifecycleCommand(ctx, vm.guest, "disconnect action management transport", "systemctl stop lindm-agent.service"); err != nil {
		return actionDenialEvidence{}, err
	}
	// This is expiry of actual server presence, not a test clock or DB edit.
	if err := lifecycleDelay(ctx, 65*time.Second); err != nil {
		return actionDenialEvidence{}, err
	}
	request := actionRequestFor(deviceID, generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}})
	_, rejected := owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	result, err := actionDenial("offline_start", rejected, connect.CodeFailedPrecondition)
	if err != nil {
		return result, err
	}
	if result.Reason != "device_action_offline" {
		return result, errors.New("offline request failed for a different prerequisite")
	}
	if err := lifecycleCommand(ctx, vm.guest, "reconnect action management transport", "systemctl start lindm-agent.service"); err != nil {
		return result, err
	}
	return result, nil
}
