// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

type actionDispatchEvidence struct {
	ActionID     string    `json:"action_id"`
	IntentSHA256 string    `json:"intent_sha256"`
	ServerState  string    `json:"server_state"`
	RootState    string    `json:"root_state"`
	Failure      string    `json:"failure"`
	StartedAt    time.Time `json:"started_at"`
	ObservedAt   time.Time `json:"observed_at"`
	NewKeyslot   *uint32   `json:"new_keyslot,omitempty"`
}

func actionRequestFor(deviceID, generation string, spec *agentv1.DeviceActionSpec) *adminv1.CreateDeviceActionRequest {
	return &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: deviceID, EnrollmentGeneration: generation, Spec: spec, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "disposable encrypted VM native action qualification"}
}

func approveNativeAction(ctx context.Context, owner, approver *devlab.OwnerSession, request *adminv1.CreateDeviceActionRequest) error {
	if err := owner.StepUp(ctx); err != nil {
		return err
	}
	created, err := owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 300, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
	if err != nil {
		return err
	}
	approved, err := approver.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independent native VM destructive qualification approval"}))
	if err != nil {
		return err
	}
	if approved.Msg.GetApproval().GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED || approved.Msg.GetApproval().GetRequesterId() == approved.Msg.GetApproval().GetApproverId() {
		return errors.New("native action approval did not establish two distinct humans")
	}
	request.ApprovalId = approved.Msg.GetApproval().GetId()
	return nil
}

func prepareActionStatusFile(ctx context.Context, vm *guestVM, actionID string) (string, error) {
	if !vmValidID(actionID) {
		return "", errors.New("invalid action ID")
	}
	// A failed transport can leave its request file behind. Diagnostics use a
	// separate connection and must not collide with that still-owned file.
	path := "/run/lindm/native-action-" + actionID + "-" + uuid.NewString() + ".json"
	data, err := protojson.Marshal(&agentv1.GetDeviceActionRequest{ActionId: actionID})
	if err != nil {
		return "", err
	}
	_, err = vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote("umask 077; set -C; cat > "+nativeQuote(path)), bytes.NewReader(data), 4096, 10*time.Second)
	return path, err
}

func nativeActionStatus(ctx context.Context, vm *guestVM, path string) (*agentv1.DeviceActionStatus, error) {
	result, err := vm.runResult(ctx, "sudo -n "+packaging.BinaryPath+" action-status -file "+nativeQuote(path), nil, 128<<10, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		if strings.TrimSpace(string(result.Stderr)) == "lindm-agent: not_found: device_action_not_found" {
			return nil, nil
		}
		return nil, errors.New("packaged executor action-status failed")
	}
	response := new(agentv1.GetDeviceActionResponse)
	if err := protojson.Unmarshal(result.Stdout, response); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}

// dispatchNativeAction never signs or directly calls a native provider. The real
// server, installed relay, root challenge and installed executor own every effect.
// stopAtEscrow deliberately withholds retirement credential for crash injection.
func dispatchNativeAction(ctx context.Context, vm *guestVM, owner *devlab.OwnerSession, request *adminv1.CreateDeviceActionRequest, credential []byte, stopAtEscrow bool) (_ *actionDispatchEvidence, _ *agentv1.DeviceActionStatus, err error) {
	if err := waitNativeActionPresence(ctx, owner, request.GetDeviceId()); err != nil {
		return nil, nil, err
	}
	created, err := owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, nil, err
	}
	id := created.Msg.GetAction().GetActionId()
	defer func() { err = diagnoseNativeAction(ctx, vm, id, err) }()
	path, err := prepareActionStatusFile(ctx, vm, id)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, cleanupErr := vm.run(cleanup, "sudo -n rm -- "+nativeQuote(path), nil, 4096, 10*time.Second)
		err = errors.Join(err, cleanupErr)
	}()
	// The installed management loop discovers work and supplied credentials.
	// Restarting for each phase defeats that loop and hits packaged start limits.
	if err := lifecycleCommand(ctx, vm, "verify continuous action relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	startCredential, receiptCredential := false, false
	rotation := request.GetSpec().GetEscrowRotate()
	needsRetirementCredential := rotation != nil && rotation.RetireKeyslot != nil
	for {
		status, err := nativeActionStatus(ctx, vm, path)
		if err != nil {
			return nil, nil, err
		}
		if status != nil {
			state := status.GetState()
			if len(credential) != 0 && state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED && !startCredential {
				if err := supplyActionCredential(ctx, vm, id, credential); err != nil {
					return nil, nil, err
				}
				startCredential = true
			}
			if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW && !stopAtEscrow && !receiptCredential && needsRetirementCredential {
				if len(credential) == 0 {
					return nil, nil, errors.New("escrow receipt phase lacks root operator credential")
				}
				if err := supplyActionCredential(ctx, vm, id, credential); err != nil {
					return nil, nil, err
				}
				receiptCredential = true
			}
			if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED || state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED || state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
				return nil, status, fmt.Errorf("native action %s ended %s/%s", id, state, status.GetFailure())
			}
			if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || (stopAtEscrow && state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW) {
				server, err := owner.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: id}))
				if err != nil {
					return nil, status, err
				}
				if server.Msg.GetAction().GetStatus().GetState() == state {
					evidence := &actionDispatchEvidence{ActionID: id, IntentSHA256: hex.EncodeToString(status.GetIntentSha256()), RootState: state.String(), ServerState: server.Msg.GetAction().GetStatus().GetState().String(), Failure: status.GetFailure().String(), ObservedAt: time.Now().UTC()}
					if status.GetStartedAt() != nil {
						evidence.StartedAt = status.GetStartedAt().AsTime()
					}
					if escrow := status.GetVerification().GetEscrow(); escrow != nil {
						slot := escrow.GetNewKeyslot()
						evidence.NewKeyslot = &slot
					}
					return evidence, status, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("native action result deadline: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
