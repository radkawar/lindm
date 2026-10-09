//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/trust"
)

// GetExecutionTrust reports only authenticated protected state. Expiry blocks
// new effects, not historical inspection; reading never retires credentials,
// changes trust counters, or opens a native provider.
func (s *Service) GetExecutionTrust(ctx context.Context, req *connect.Request[agentv1.GetExecutionTrustRequest]) (*connect.Response[agentv1.GetExecutionTrustResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.getExecutionTrust(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) getExecutionTrust(ctx context.Context, req *agentv1.GetExecutionTrustRequest) (*agentv1.GetExecutionTrustResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.loadBound(ctx)
	if err != nil {
		return nil, err
	}
	current := loaded.execution
	rootDigest, err := trust.ExecutionRootDigest(current.root)
	if err != nil {
		return nil, errInternal
	}
	view := &agentv1.GetExecutionTrustResponse{
		RootVersion: current.root.GetVersion(), RootSha256: rootDigest[:],
		RootExpiresAt: proto.CloneOf(current.root.GetExpiresAt()),
	}
	if current.delegation != nil {
		delegationDigest := sha256.Sum256(current.state.GetDelegationEnvelope())
		view.DelegationVersion = current.delegation.GetVersion()
		view.DelegationSha256 = delegationDigest[:]
		view.MinimumRecoveryEpoch = current.delegation.GetMinimumRecoveryEpoch()
		view.AcceptedAt = proto.CloneOf(current.state.GetAcceptedAt())
		view.DelegationExpiresAt = proto.CloneOf(current.delegation.GetExpiresAt())
	}
	return view, nil
}

// UpdateExecutionTrust verifies rotations and a root-signed delegation against
// protected bootstrap material, then commits the trust row before acknowledgment.
// It does not start work, select verification keys, or change enrollment pins.
func (s *Service) UpdateExecutionTrust(ctx context.Context, req *connect.Request[agentv1.UpdateExecutionTrustRequest]) (*connect.Response[agentv1.UpdateExecutionTrustResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.updateExecutionTrust(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) updateExecutionTrust(ctx context.Context, req *agentv1.UpdateExecutionTrustRequest) (*agentv1.UpdateExecutionTrustResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	recorded, revision := loaded.execution.state, loaded.execution.revision
	verifier, current, prior := loaded.execution.verifier, loaded.execution.root, loaded.execution.delegation
	sum, err := requestDigest(req)
	if err != nil {
		return nil, err
	}
	// Exact retransmission returns the historical receipt. It must not commit,
	// extend expiry, or treat a later clock as a reason to erase authority.
	if prior != nil && sameRequest(sum, recorded.GetRequestSha256()) {
		return executionReceipt(recorded.GetRoot(), prior), nil
	}
	now := s.now()
	if prior != nil && now.Before(recorded.GetAcceptedAt().AsTime()) {
		return nil, errExecutionTrustRejected
	}
	for _, transition := range req.GetRootTransitions() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next, err := verifier.VerifyRootTransition(ctx, current, transition, now)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errExecutionTrustRejected
		}
		current = next
	}
	previousVersion, minimumEpoch := uint64(0), uint64(0)
	if prior != nil {
		previousVersion = recorded.GetDelegationVersion()
		minimumEpoch = recorded.GetMinimumRecoveryEpoch()
	}
	delegation, err := verifier.VerifyDelegation(ctx, current, req.GetDelegationEnvelope(), previousVersion, minimumEpoch, now)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errExecutionTrustRejected
	}
	next := &agentv1.ExecutionTrustState{
		FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(),
		Root: current, DelegationEnvelope: bytes.Clone(req.GetDelegationEnvelope()),
		AcceptedAt: protoTimestamp(now), RequestSha256: append([]byte(nil), sum[:]...),
		DelegationVersion: delegation.GetVersion(), MinimumRecoveryEpoch: delegation.GetMinimumRecoveryEpoch(),
	}
	if err := s.commitExecutionTrust(ctx, revision, next); err != nil {
		return nil, err
	}
	return executionReceipt(current, delegation), nil
}

type boundExecutionTrust struct {
	state      *agentv1.ExecutionTrustState
	revision   int64
	verifier   *trust.ExecutionVerifier
	root       *agentv1.ExecutionRoot
	delegation *agentv1.ExecutionDelegation
}

// Bind both authority records before exposing status, credentials, or mutations.
// The result is reused by trust updates rather than verifying the record twice.
func bindExecutionTrust(ctx context.Context, authority *trust.Authority, store *journal.Store, loaded *bound) error {
	recorded, revision, err := store.LoadExecutionTrust(ctx)
	if err != nil {
		if errors.Is(err, journal.ErrRecoveryHold) {
			return errRecoveryHold
		}
		return err
	}
	verifier, err := authority.NewExecutionVerifier(loaded.bootstrap)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errRecoveryHold
	}
	root, delegation, err := reconstructExecutionTrust(ctx, verifier, loaded, recorded)
	if err != nil {
		return err
	}
	loaded.execution = boundExecutionTrust{
		state: recorded, revision: revision, verifier: verifier,
		root: root, delegation: delegation,
	}
	return nil
}

// reconstructExecutionTrust checks a configured record at its original acceptance
// time. Expiration relative to the current clock blocks new effects only; it is
// not damage of the stored receipt.
func reconstructExecutionTrust(ctx context.Context, verifier *trust.ExecutionVerifier, loaded *bound, recorded *agentv1.ExecutionTrustState) (*agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, error) {
	if recorded == nil || recorded.GetFormatVersion() != 1 || recorded.GetInstallationId() != loaded.state.GetInstallationId() {
		return nil, nil, errRecoveryHold
	}
	if recorded.GetRoot() == nil {
		if recorded.GetAcceptedAt() != nil || len(recorded.GetDelegationEnvelope()) != 0 || len(recorded.GetRequestSha256()) != 0 || recorded.GetDelegationVersion() != 0 || recorded.GetMinimumRecoveryEpoch() != 0 {
			return nil, nil, errRecoveryHold
		}
		return loaded.bootstrap.Root, nil, nil
	}
	if recorded.GetAcceptedAt() == nil || recorded.GetDelegationVersion() == 0 || len(recorded.GetRequestSha256()) != sha256.Size || len(recorded.GetDelegationEnvelope()) == 0 {
		return nil, nil, errRecoveryHold
	}
	delegation, err := verifier.VerifyDelegation(ctx, recorded.GetRoot(), recorded.GetDelegationEnvelope(), recorded.GetDelegationVersion()-1, recorded.GetMinimumRecoveryEpoch(), recorded.GetAcceptedAt().AsTime())
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errRecoveryHold
	}
	if delegation.GetVersion() != recorded.GetDelegationVersion() || delegation.GetMinimumRecoveryEpoch() != recorded.GetMinimumRecoveryEpoch() || delegation.GetRootVersion() != recorded.GetRoot().GetVersion() || delegation.GetDeploymentId() != loaded.bootstrap.Root.GetDeploymentId() {
		return nil, nil, errRecoveryHold
	}
	return recorded.GetRoot(), delegation, nil
}

func (s *Service) commitExecutionTrust(ctx context.Context, revision int64, state *agentv1.ExecutionTrustState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := s.store.UpdateExecutionTrust(ctx, revision, state); err != nil {
		switch {
		case errors.Is(err, journal.ErrConflict):
			return errInternal
		case errors.Is(err, journal.ErrTrustRejected):
			return errExecutionTrustRejected
		case errors.Is(err, journal.ErrRecoveryHold):
			s.noteTrustDamage()
			return errRecoveryHold
		default:
			return err
		}
	}
	return nil
}

func (s *Service) noteTrustDamage() {
	s.hold = true
	s.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
}

func executionReceipt(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation) *agentv1.UpdateExecutionTrustResponse {
	return &agentv1.UpdateExecutionTrustResponse{
		RootVersion: root.GetVersion(), DelegationVersion: delegation.GetVersion(),
		MinimumRecoveryEpoch: delegation.GetMinimumRecoveryEpoch(),
		ExpiresAt:            timestamppb.New(delegation.GetExpiresAt().AsTime()),
	}
}

func requestDigest(req *agentv1.UpdateExecutionTrustRequest) ([sha256.Size]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return [sha256.Size]byte{}, errInternal
	}
	return sha256.Sum256(encoded), nil
}

func sameRequest(sum [sha256.Size]byte, stored []byte) bool {
	return len(stored) == len(sum) && subtle.ConstantTimeCompare(sum[:], stored) == 1
}
