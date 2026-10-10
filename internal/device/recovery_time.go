package device

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

// GetRecoveryTime is public and returns only nonce-bound time and public trust.
// It neither authenticates a device principal nor creates action authority,
// consumes a credential, records a receipt, or changes any durable state.
func (s *Service) GetRecoveryTime(ctx context.Context, req *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || protodata.ValidateClosed(req.Msg.ProtoReflect()) != nil {
		return nil, invalid("invalid_recovery_time")
	}
	if s.signing == nil || s.execution == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Hold the current authority snapshot stable through signing, including
	// signer revocation. No device, session, approval or action locks are taken.
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	_, update, err := s.execution.ForDevice(ctx, tx, req.Msg.GetRootVersion(), req.Msg.GetDelegationVersion(), req.Msg.GetMinimumRecoveryEpoch(), req.Msg.GetRootSha256(), req.Msg.GetDelegationSha256())
	if err != nil {
		return nil, executionError(err)
	}
	if update == nil {
		// Recovery requires explicit signed authority even at unchanged versions.
		update = &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: snapshot.DelegationEnvelope}
	}
	now, err := dispatchClock(ctx, devicedb.New(tx))
	if err != nil {
		return nil, mapErr(err)
	}
	expires := now.Add(30 * time.Second)
	// Delegates have no independent validity dates; the current signed
	// delegation is the START signer's expiry as well as its role/capability.
	for _, limit := range []time.Time{snapshot.Root.GetExpiresAt().AsTime(), snapshot.Delegation.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !expires.After(now) {
		return nil, rpcError(connect.CodeFailedPrecondition, "recovery_time_window_empty")
	}
	digest, err := trust.DeviceActionDigest(req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	statement := &agentv1.RecoveryTimeStatement{
		DeploymentId: s.deploymentID.String(), RequestSha256: digest[:],
		ServerTime: timestamppb.New(now), ExpiresAt: timestamppb.New(expires),
		RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(),
	}
	envelope, err := s.authority.Sign(ctx, statement, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	response := &recoveryv1.GetRecoveryTimeResponse{ServerTime: statement.ServerTime, TimeEnvelope: envelope, TrustUpdate: update}
	if _, err := verifier.VerifyRecoveryTimeStatement(ctx, snapshot.Root, snapshot.Delegation, response, req.Msg, snapshot.AcceptedAt, 0); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}
