//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

// requestProof signs only the closed recovery request vocabulary. The private
// one-action key is never presented as TLS identity or forwarded to the server.
func requestProof(ctx context.Context, authority *trust.Authority, key ed25519.PrivateKey, credential *agentv1.DeviceActionRecoveryCredential, envelope []byte, bootID, incarnation string, operation agentv1.RecoveryOperation, payload proto.Message, now time.Time) ([]byte, error) {
	digest, err := trust.DeviceActionDigest(payload)
	if err != nil {
		return nil, err
	}
	credentialDigest := sha256.Sum256(envelope)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	proof := &agentv1.RecoveryRequestProof{
		CredentialId: credential.GetCredentialId(), CredentialSha256: credentialDigest[:],
		RequestId: uuid.NewString(), BootId: bootID, ExecutorIncarnation: incarnation,
		Nonce: nonce, Operation: operation, PayloadSha256: digest[:],
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)),
	}
	return authority.Sign(ctx, proof, key)
}

func checkedResponse[T any](response *connect.Response[T], err error, validator protovalidate.Validator) (*T, error) {
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil {
		return nil, errors.New("recovery_missing_response")
	}
	message, ok := any(response.Msg).(proto.Message)
	if !ok {
		return nil, errors.New("recovery_invalid_response")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validator.Validate(message); err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (r *runner) proof(ctx context.Context, operation agentv1.RecoveryOperation, payload proto.Message) ([]byte, error) {
	return requestProof(ctx, r.authority, r.key, r.credential, r.record.GetCredentialEnvelope(), r.bootID, r.incarnation, operation, payload, r.clock())
}

func (r *runner) acquire(ctx context.Context) (*recoveryv1.AcquireRecoveryWorkResponse, error) {
	request := new(recoveryv1.AcquireRecoveryWorkRequest)
	proof, err := r.proof(ctx, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, request)
	if err != nil {
		return nil, err
	}
	request.CredentialEnvelope, request.RequestProof = r.record.GetCredentialEnvelope(), proof
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := r.client.AcquireRecoveryWork(ctx, connect.NewRequest(request))
	return checkedResponse(response, err, r.validator)
}

func (r *runner) authorize(ctx context.Context, challenge *agentv1.DeviceActionChallenge) ([]byte, error) {
	request := &recoveryv1.AuthorizeRecoveryStartRequest{Challenge: challenge, RecoveryImageSha256: r.record.GetHandoff().GetRecoveryImageSha256()}
	proof, err := r.proof(ctx, agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, request)
	if err != nil {
		return nil, err
	}
	request.CredentialEnvelope, request.RequestProof = r.record.GetCredentialEnvelope(), proof
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := r.client.AuthorizeRecoveryStart(ctx, connect.NewRequest(request))
	checked, err := checkedResponse(response, err, r.validator)
	if err != nil {
		return nil, err
	}
	return checked.GetStartGrantEnvelope(), nil
}

func (r *runner) checkpoint(ctx context.Context, phase agentv1.RecoveryPhase) error {
	previous := r.record.GetCheckpoint()
	checkpoint := &agentv1.RecoveryCheckpoint{
		CredentialId: r.credential.GetCredentialId(), ActionId: r.record.GetHandoff().GetIntent().GetActionId(),
		BootId: r.bootID, ExecutorIncarnation: r.incarnation, Sequence: 1, Phase: phase, At: timestamppb.New(r.clock()),
	}
	if previous != nil {
		digest, err := trust.DeviceActionDigest(previous)
		if err != nil {
			return err
		}
		checkpoint.Sequence, checkpoint.PreviousSha256 = previous.GetSequence()+1, digest[:]
	}
	if len(r.record.GetStartGrantEnvelope()) != 0 {
		digest := sha256.Sum256(r.record.GetStartGrantEnvelope())
		checkpoint.GrantSha256 = digest[:]
	}
	r.record.Checkpoint = checkpoint
	r.record.CheckpointReceiptEnvelope = nil
	if err := r.journal.Save(r.record); err != nil {
		return err
	}
	request := &recoveryv1.CheckpointRecoveryActionRequest{Checkpoint: checkpoint, Journal: r.record}
	proof, err := r.proof(ctx, agentv1.RecoveryOperation_RECOVERY_OPERATION_CHECKPOINT, request)
	if err != nil {
		return err
	}
	request.CredentialEnvelope, request.RequestProof = r.record.GetCredentialEnvelope(), proof
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := r.client.CheckpointRecoveryAction(ctx, connect.NewRequest(request))
	checked, err := checkedResponse(response, err, r.validator)
	if err != nil {
		return err
	}
	digest, err := trust.DeviceActionDigest(checkpoint)
	if err != nil {
		return err
	}
	if checked.GetSequence() != checkpoint.GetSequence() || !bytes.Equal(checked.GetCheckpointSha256(), digest[:]) {
		return errors.New("recovery_checkpoint_ack_mismatch")
	}
	if _, err := r.verifier.VerifyRecoveryCheckpointReceipt(ctx, r.record.GetAcceptedRoot(), r.delegation, checked.GetReceiptEnvelope(), checkpoint, r.clock()); err != nil {
		return err
	}
	r.record.CheckpointReceiptEnvelope = checked.GetReceiptEnvelope()
	return r.journal.Save(r.record)
}

func (r *runner) report(ctx context.Context, nonce []byte) error {
	before := r.record.GetHandoff().GetChallenge().GetNativePlan().GetBefore()
	if r.record.GetChallenge() != nil {
		before = r.record.GetChallenge().GetNativePlan().GetBefore()
	}
	status := &agentv1.DeviceActionStatus{
		ActionId: r.record.GetHandoff().GetIntent().GetActionId(), IntentSha256: r.record.GetHandoff().GetIntentSha256(),
		State: r.record.GetState(), Failure: r.record.GetFailure(), AcceptedAt: r.record.GetAcceptedAt(),
		StartedAt: r.record.GetStartedAt(), CompletedAt: r.record.GetCompletedAt(), Verification: r.record.GetVerification(),
		Before: before,
	}
	request := &recoveryv1.ReportRecoveryResultRequest{Status: status, ResultNonce: nonce}
	proof, err := r.proof(ctx, agentv1.RecoveryOperation_RECOVERY_OPERATION_REPORT_RESULT, request)
	if err != nil {
		return err
	}
	request.CredentialEnvelope, request.RequestProof = r.record.GetCredentialEnvelope(), proof
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := r.client.ReportRecoveryResult(ctx, connect.NewRequest(request))
	checked, err := checkedResponse(response, err, r.validator)
	if err != nil {
		return err
	}
	if !checked.GetClosed() && r.record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		return errors.New("recovery_result_not_committed")
	}
	return nil
}
