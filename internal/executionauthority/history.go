package executionauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
	"lindm/internal/trust"
)

func decodeRoot(row authoritydb.ExecutionAuthorityRoot) (*agentv1.ExecutionRoot, error) {
	root := new(agentv1.ExecutionRoot)
	if err := unmarshal(row.RootDocument, root); err != nil || row.RootVersion != counter(root.GetVersion()) || !row.AcceptedAt.Valid || row.AcceptedAt.InfinityModifier != pgtype.Finite {
		return nil, ErrCorrupt
	}
	digest, err := trust.ExecutionRootDigest(root)
	if err != nil || !bytes.Equal(digest[:], row.RootDigest) {
		return nil, ErrCorrupt
	}
	return root, nil
}

// Startup authenticates every retained root from the original signed bootstrap,
// not from an operator-supplied replacement or the mutable current singleton.
func (s *Store) checkHistory(ctx context.Context, q *authoritydb.Queries, row authoritydb.ExecutionAuthority, snapshot *Snapshot, initial *agentv1.ExecutionRoot) error {
	roots, err := q.ListRoots(ctx, row.RootCount)
	if err != nil {
		return err
	}
	if len(roots) != int(row.RootCount) || len(roots) == 0 {
		return ErrCorrupt
	}
	current := initial
	acceptedAt := row.InitializedAt.Time
	for index, stored := range roots {
		root, err := decodeRoot(stored)
		if err != nil || stored.Position != int32(index)+1 || stored.AcceptedAt.Time.Before(acceptedAt) {
			return ErrCorrupt
		}
		if index == 0 {
			if len(stored.TransitionDocument) != 0 || !proto.Equal(root, initial) || !stored.AcceptedAt.Time.Equal(acceptedAt) {
				return ErrCorrupt
			}
		} else {
			transition := new(agentv1.ExecutionRootTransition)
			if err := unmarshal(stored.TransitionDocument, transition); err != nil {
				return ErrCorrupt
			}
			next, err := s.verifier.VerifyRootTransition(ctx, current, transition, stored.AcceptedAt.Time)
			if err != nil || !proto.Equal(next, root) {
				return rejectContext(ctx, ErrCorrupt)
			}
		}
		current, acceptedAt = root, stored.AcceptedAt.Time
	}
	if !proto.Equal(current, snapshot.Root) || row.AcceptedAt.Time.Before(acceptedAt) {
		return ErrCorrupt
	}
	if snapshot.Delegation == nil && !row.AcceptedAt.Time.Equal(row.InitializedAt.Time) {
		return ErrCorrupt
	}
	return nil
}

// admissionDocuments authenticates the immutable record's exact request bytes
// before its receipt is used as a version/recovery/expiry binding.
func admissionDocuments(stored authoritydb.ExecutionAuthorityUpdate) (*agentv1.UpdateExecutionTrustRequest, *agentv1.UpdateExecutionTrustResponse, error) {
	digest := sha256.Sum256(stored.RequestDocument)
	if !bytes.Equal(digest[:], stored.RequestDigest) || !stored.AcceptedAt.Valid || stored.AcceptedAt.InfinityModifier != pgtype.Finite || stored.Revision < 2 {
		return nil, nil, ErrCorrupt
	}
	request := new(agentv1.UpdateExecutionTrustRequest)
	receipt := new(agentv1.UpdateExecutionTrustResponse)
	if err := unmarshal(stored.RequestDocument, request); err != nil {
		return nil, nil, ErrCorrupt
	}
	if _, err := encodeRequest(request); err != nil {
		return nil, nil, ErrCorrupt
	}
	if err := unmarshal(stored.ReceiptDocument, receipt); err != nil || receipt.GetRootVersion() == 0 || receipt.GetDelegationVersion() == 0 || receipt.GetExpiresAt() == nil {
		return nil, nil, ErrCorrupt
	}
	return request, receipt, nil
}

func (s *Store) historicalReceipt(ctx context.Context, q *authoritydb.Queries, stored authoritydb.ExecutionAuthorityUpdate) (*agentv1.UpdateExecutionTrustResponse, error) {
	request, receipt, err := admissionDocuments(stored)
	if err != nil {
		return nil, err
	}
	rootRow, err := q.GetRoot(ctx, counter(receipt.GetRootVersion()))
	if err != nil {
		return nil, stateError(err)
	}
	root, err := decodeRoot(rootRow)
	if err != nil {
		return nil, err
	}
	delegation, err := s.verifier.VerifyDelegation(ctx, root, request.GetDelegationEnvelope(), 0, 0, stored.AcceptedAt.Time)
	if err != nil || !proto.Equal(receipt, executionReceipt(root, delegation)) {
		return nil, rejectContext(ctx, ErrCorrupt)
	}
	return receipt, nil
}

func consecutive(previous, next uint64) bool { return previous != math.MaxUint64 && next == previous+1 }
