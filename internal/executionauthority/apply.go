package executionauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/executionauthority/authoritydb"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

// Apply requires the caller's fresh principal authorization lock. It does not
// commit: principal fence, authority, retained receipt and audit share one tx.
// Lock order is principal -> authority -> device -> action.
func (s *Store) Apply(ctx context.Context, tx pgx.Tx, request *agentv1.UpdateExecutionTrustRequest, actorID uuid.UUID, reason string) (*agentv1.UpdateExecutionTrustResponse, error) {
	if tx == nil || actorID == uuid.Nil || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 512 || strings.TrimSpace(reason) == "" {
		return nil, ErrRejected
	}
	encoded, err := encodeRequest(request)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	q := authoritydb.New(tx)
	row, err := q.LockAuthority(ctx)
	if err != nil {
		return nil, stateError(err)
	}
	if row.DeploymentID == nil {
		return nil, ErrCorrupt
	}
	if *row.DeploymentID != s.deploymentID || !bytes.Equal(row.TrustDomainDigest, s.domain[:]) {
		return nil, ErrIncompatible
	}
	// This lookup precedes clock, current authority, rollback and capacity
	// checks. A historical retry never becomes a new admission after expiry.
	prior, err := q.GetUpdate(ctx, digest[:])
	if err == nil {
		if !bytes.Equal(prior.RequestDocument, encoded) {
			return nil, ErrCorrupt
		}
		return s.historicalReceipt(ctx, q, prior)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	snapshot, err := s.snapshot(ctx, q, row)
	if err != nil {
		return nil, err
	}
	// PostgreSQL transaction_timestamp()/now() would date this mutation before
	// a potentially long lock wait. Read wall time only once the lock is held.
	now, err := readClock(ctx, q)
	if err != nil {
		return nil, err
	}
	if now.Before(row.AcceptedAt.Time) {
		return nil, ErrRejected
	}
	if row.UpdateCount >= maxUpdates || len(request.GetRootTransitions()) > maxRoots-int(row.RootCount) {
		return nil, ErrCapacity
	}
	current := snapshot.Root
	roots := make([]authoritydb.InsertRootParams, 0, len(request.GetRootTransitions()))
	retained := int64(len(encoded))
	for index, transition := range request.GetRootTransitions() {
		next, err := s.verifier.VerifyRootTransition(ctx, current, transition, now)
		if err != nil {
			return nil, rejectContext(ctx, ErrRejected)
		}
		rootBytes, err := marshal(next)
		if err != nil || len(rootBytes) > maxRootBytes {
			return nil, ErrRejected
		}
		transitionBytes, err := marshal(transition)
		if err != nil {
			return nil, ErrRejected
		}
		digest, err := trust.ExecutionRootDigest(next)
		if err != nil {
			return nil, ErrRejected
		}
		roots = append(roots, authoritydb.InsertRootParams{
			Position: row.RootCount + int32(index) + 1, RootVersion: counter(next.GetVersion()),
			RootDigest: digest[:], RootDocument: rootBytes, TransitionDocument: transitionBytes,
			AcceptedAt: timestamp(now),
		})
		retained += int64(len(rootBytes) + len(transitionBytes))
		current = next
	}
	delegation, err := s.verifier.VerifyDelegation(ctx, current, request.GetDelegationEnvelope(), snapshot.Delegation.GetVersion(), snapshot.Delegation.GetMinimumRecoveryEpoch(), now)
	if err != nil {
		return nil, rejectContext(ctx, ErrRejected)
	}
	receipt := executionReceipt(current, delegation)
	receiptBytes, err := marshal(receipt)
	if err != nil {
		return nil, err
	}
	retained += int64(len(receiptBytes))
	if retained > maxRetainedBytes-row.RetainedBytes {
		return nil, ErrCapacity
	}
	rootBytes := row.RootDocument
	if len(roots) != 0 {
		rootBytes = roots[len(roots)-1].RootDocument
	}
	// No write precedes final delegation verification and all capacity checks.
	for _, root := range roots {
		if err := q.InsertRoot(ctx, root); err != nil {
			return nil, err
		}
	}
	stamp, auditID := timestamp(now), uuid.New()
	if err := q.InsertAudit(ctx, authoritydb.InsertAuditParams{
		ID: auditID, OccurredAt: stamp, ActorID: &actorID,
		Action: auditkind.ExecutionAuthorityUpdate.String(), ResourceID: s.deploymentID.String(), Reason: reason,
	}); err != nil {
		return nil, err
	}
	if err := q.InsertUpdate(ctx, authoritydb.InsertUpdateParams{
		RequestDigest: digest[:], RequestDocument: encoded, ReceiptDocument: receiptBytes,
		Revision: row.Revision + 1, AcceptedAt: stamp, AuditID: auditID,
	}); err != nil {
		return nil, err
	}
	if err := q.SetAuthority(ctx, authoritydb.SetAuthorityParams{
		DeploymentID: &s.deploymentID, TrustDomainDigest: s.domain[:], RootDocument: rootBytes,
		DelegationEnvelope: request.GetDelegationEnvelope(), AcceptedAt: stamp, Revision: row.Revision + 1,
		RootCount: row.RootCount + int32(len(roots)), UpdateCount: row.UpdateCount + 1,
		RetainedBytes: row.RetainedBytes + retained,
	}); err != nil {
		return nil, err
	}
	return receipt, nil
}

func encodeRequest(request *agentv1.UpdateExecutionTrustRequest) ([]byte, error) {
	if request == nil || len(request.GetRootTransitions()) > maxTransitions || len(request.GetDelegationEnvelope()) == 0 || len(request.GetDelegationEnvelope()) > maxEnvelopeBytes {
		return nil, ErrRejected
	}
	if err := protodata.ValidateClosed(request.ProtoReflect()); err != nil {
		return nil, ErrRejected
	}
	for _, transition := range request.GetRootTransitions() {
		if transition == nil || len(transition.GetPreviousQuorumEnvelope()) == 0 || len(transition.GetPreviousQuorumEnvelope()) > maxEnvelopeBytes || len(transition.GetNextQuorumEnvelope()) == 0 || len(transition.GetNextQuorumEnvelope()) > maxEnvelopeBytes {
			return nil, ErrRejected
		}
	}
	encoded, err := marshal(request)
	if err != nil || len(encoded) > maxRequestBytes {
		return nil, ErrRejected
	}
	return encoded, nil
}

func executionReceipt(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation) *agentv1.UpdateExecutionTrustResponse {
	return &agentv1.UpdateExecutionTrustResponse{
		RootVersion: root.GetVersion(), DelegationVersion: delegation.GetVersion(),
		MinimumRecoveryEpoch: delegation.GetMinimumRecoveryEpoch(), ExpiresAt: proto.CloneOf(delegation.GetExpiresAt()),
	}
}

func rejectContext(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}
