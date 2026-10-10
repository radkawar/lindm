//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

type actionEncryptionEvidence struct {
	LUKSUUID          string                          `json:"luks_uuid"`
	LUKSVersion       uint32                          `json:"luks_version"`
	Keyslots          []uint32                        `json:"keyslots"`
	Tokens            []*agentv1.LUKSTokenObservation `json:"tokens"`
	TPMVersion        string                          `json:"tpm_version"`
	SecureBoot        bool                            `json:"secure_boot"`
	RootEncrypted     bool                            `json:"root_encrypted"`
	HostOracleMatched bool                            `json:"host_oracle_matched"`
}

// Capture public observations only; raw headers and native token blobs never enter evidence.
func captureActionEncryption(ctx context.Context, machine *actionMachine, control *vmControlPlane) (*actionEncryptionEvidence, error) {
	detail, err := control.GetDevice(ctx, machine.deviceID)
	if err != nil {
		return nil, err
	}
	native := detail.GetHost().GetObservation().GetDetails()
	if err := compareInspectHardware(&machine.vm.hardware, native); err != nil {
		return nil, err
	}
	guest, err := observeEncryptedGuest(ctx, machine.vm, machine.vm.firmware.SecureBoot)
	if err != nil {
		return nil, err
	}
	response, err := control.session.Admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: machine.deviceID}))
	if err != nil {
		return nil, err
	}
	observation := response.Msg.GetObservation()
	if !observation.GetEncrypted() || observation.GetTarget().GetLuksUuid() != machine.target.Identity.GetLuksUuid() {
		return nil, errors.New("server encryption observation does not identify encrypted root")
	}
	return &actionEncryptionEvidence{LUKSUUID: observation.GetTarget().GetLuksUuid(), LUKSVersion: 2, Keyslots: slices.Clone(observation.GetOccupiedKeyslots()), Tokens: observation.GetLuksTokens(), TPMVersion: guest.TPMVersion, SecureBoot: guest.SecureBoot, RootEncrypted: true}, nil
}

func compareActionEncryption(ctx context.Context, vm *EncryptedVM, evidence *actionEncryptionEvidence) error {
	headers, err := vm.Headers(ctx)
	if err != nil {
		return err
	}
	return compareActionEncryptionHeaders(headers, evidence)
}

func compareActionEncryptionHeaders(headers []EncryptedHeader, evidence *actionEncryptionEvidence) error {
	slots, err := actionHeaderSlots(headers, evidence.LUKSUUID)
	if err != nil {
		return err
	}
	if !slices.Equal(slots, evidence.Keyslots) {
		return errors.New("server keyslots differ from powered-off host oracle")
	}
	for _, header := range headers {
		if header.UUID != evidence.LUKSUUID {
			continue
		}
		var metadata struct {
			Tokens map[string]struct {
				Type     string   `json:"type"`
				Keyslots []string `json:"keyslots"`
			} `json:"tokens"`
		}
		if err := json.Unmarshal(header.JSON, &metadata); err != nil {
			return err
		}
		if len(metadata.Tokens) != len(evidence.Tokens) {
			return errors.New("server token count differs from host oracle")
		}
		for _, token := range evidence.Tokens {
			native, ok := metadata.Tokens[strconv.FormatUint(uint64(token.GetTokenId()), 10)]
			if !ok || native.Type != token.GetType() || len(native.Keyslots) != len(token.GetKeyslots()) {
				return errors.New("server token differs from host oracle")
			}
			for i, slot := range native.Keyslots {
				if slot != strconv.FormatUint(uint64(token.GetKeyslots()[i]), 10) {
					return errors.New("server token keyslots differ from host oracle")
				}
			}
		}
	}
	evidence.HostOracleMatched = true
	return nil
}

func rejectActionRecoveryBoot(ctx context.Context, vm *EncryptedVM, key []byte, kind string) (*actionBootEvidence, error) {
	text, err := actionRecoveryText(key)
	if err != nil {
		return nil, err
	}
	boot, rejected := vm.ColdBoot(ctx, text)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if rejected == nil || rejected.Error() != "encrypted boot rejected unlock secret" || boot.Accepted || !boot.PromptSeen {
		return nil, errors.New("cold boot did not explicitly reject retired recovery key")
	}
	return &actionBootEvidence{Credential: kind, Boot: boot, ObservedAt: time.Now().UTC()}, nil
}

func nativeRevealRequirements(ctx context.Context, fixture *devlab.AuthorityFixture, owner *devlab.OwnerSession, approver **devlab.OwnerSession, deviceID, actionID string) ([]actionDenialEvidence, error) {
	var observations []actionDenialEvidence
	request := &adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: deviceID, ActionId: actionID}
	response, rejected := owner.Admin.RevealRecoveryKey(ctx, connect.NewRequest(request))
	if response != nil {
		clear(response.Msg.RecoveryKey)
	}
	if connect.CodeOf(rejected) != connect.CodeInvalidArgument {
		return observations, errors.New("missing reveal reason was not rejected by request validation")
	}
	denial := actionDenialEvidence{Scenario: "reveal_reason_required", Code: connect.CodeOf(rejected).String(), Reason: "request_validation", ObservedAt: time.Now().UTC()}
	observations = append(observations, denial)
	if err := (*approver).Close(ctx); err != nil {
		return observations, err
	}
	accountID := (*approver).AccountID
	*approver = nil
	restricted, err := fixture.OpenRestrictedRecoverySession(ctx)
	if err != nil {
		return observations, err
	}
	request.Reason = "dedicated recovery read permission negative"
	response, rejected = restricted.Admin.RevealRecoveryKey(ctx, connect.NewRequest(request))
	if response != nil {
		clear(response.Msg.RecoveryKey)
	}
	closeErr := restricted.Close(ctx)
	restoreErr := fixture.RestoreAccount(ctx, accountID)
	if err := errors.Join(closeErr, restoreErr); err != nil {
		return observations, err
	}
	*approver, err = fixture.OpenApproverSession(ctx)
	if err != nil {
		return observations, err
	}
	denial, err = actionDenial("reveal_dedicated_permission_required", rejected, connect.CodePermissionDenied)
	if err != nil {
		return observations, err
	}
	observations = append(observations, denial)
	// Let real assurance expire; never modify a production clock or database.
	if err := owner.StepUp(ctx); err != nil {
		return observations, err
	}
	if err := lifecycleDelay(ctx, 5*time.Minute+time.Second); err != nil {
		return observations, err
	}
	response, rejected = owner.Admin.RevealRecoveryKey(ctx, connect.NewRequest(request))
	if response != nil {
		clear(response.Msg.RecoveryKey)
	}
	denial, err = actionDenial("reveal_recent_step_up_required", rejected, connect.CodePermissionDenied)
	if err != nil {
		return observations, err
	}
	if denial.Reason != "recent_step_up_required" {
		return observations, errors.New("reveal denial did not enforce expired assurance")
	}
	observations = append(observations, denial)
	return observations, nil
}

func waitCrashServerState(ctx context.Context, control *vmControlPlane, actionID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		response, err := control.session.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: actionID}))
		if err != nil {
			return "", err
		}
		state := response.Msg.GetAction().GetStatus().GetState()
		if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			return state.String(), nil
		}
		select {
		case <-ctx.Done():
			return "", errors.New("server did not converge to interrupted rotation outcome_unknown")
		case <-ticker.C:
		}
	}
}
