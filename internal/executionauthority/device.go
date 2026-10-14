// SPDX-License-Identifier: Apache-2.0

package executionauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
)

// ForDevice reads a coherent desired snapshot without a global mutation lock.
// Callers authenticate the device under its mutation lock or a coherent read-only
// snapshot. The first row fixes the final root/delegation; append-only history is
// bounded by that row's root_count, including under READ COMMITTED. Reported
// counters/hashes select public documents, never establish a device-applied receipt.
func (s *Store) ForDevice(ctx context.Context, tx pgx.Tx, rootVersion, delegationVersion, minimumEpoch uint64, rootDigest, delegationDigest []byte) (*Snapshot, *agentv1.UpdateExecutionTrustRequest, error) {
	if tx == nil || rootVersion == 0 || len(rootDigest) != sha256.Size || (delegationVersion == 0 && len(delegationDigest) != 0) || (delegationVersion != 0 && len(delegationDigest) != sha256.Size) {
		return nil, nil, ErrIncompatible
	}
	q := authoritydb.New(tx)
	row, err := q.GetAuthority(ctx)
	if err != nil {
		return nil, nil, stateError(err)
	}
	snapshot, err := s.snapshot(ctx, q, row)
	if err != nil {
		return nil, nil, err
	}
	currentRoot := snapshot.Root.GetVersion()
	currentDelegation := snapshot.Delegation.GetVersion()
	currentEpoch := snapshot.Delegation.GetMinimumRecoveryEpoch()
	if rootVersion > currentRoot || delegationVersion > currentDelegation || minimumEpoch > currentEpoch {
		return nil, nil, ErrServerBehind
	}
	known, err := q.GetRoot(ctx, counter(rootVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrIncompatible
	}
	if err != nil {
		return nil, nil, err
	}
	root, err := decodeRoot(known)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(known.RootDigest, rootDigest) || known.Position > row.RootCount {
		return nil, nil, ErrIncompatible
	}
	if delegationVersion == currentDelegation {
		if rootVersion != currentRoot || minimumEpoch != currentEpoch {
			return nil, nil, ErrIncompatible
		}
		if currentDelegation != 0 {
			digest := sha256.Sum256(snapshot.DelegationEnvelope)
			if !bytes.Equal(digest[:], delegationDigest) {
				return nil, nil, ErrIncompatible
			}
		}
		return snapshot, nil, nil
	}
	missing := row.RootCount - known.Position
	if missing > maxTransitions {
		return nil, nil, ErrReprovisioning
	}
	now, err := readClock(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	if now.Before(row.AcceptedAt.Time) {
		return nil, nil, ErrReprovisioning
	}
	updates, err := q.ListRootRange(ctx, authoritydb.ListRootRangeParams{FirstPosition: known.Position, LastPosition: row.RootCount})
	if err != nil {
		return nil, nil, err
	}
	if len(updates) != int(missing) {
		return nil, nil, ErrCorrupt
	}
	request := &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    make([]*agentv1.ExecutionRootTransition, 0, len(updates)),
		DelegationEnvelope: snapshot.DelegationEnvelope,
	}
	for index, stored := range updates {
		next, err := decodeRoot(stored)
		if err != nil || stored.Position != known.Position+int32(index)+1 || !consecutive(root.GetVersion(), next.GetVersion()) {
			return nil, nil, ErrCorrupt
		}
		transition := new(agentv1.ExecutionRootTransition)
		if err := unmarshal(stored.TransitionDocument, transition); err != nil {
			return nil, nil, ErrCorrupt
		}
		verified, err := s.verifier.VerifyRootTransition(ctx, root, transition, now)
		if err != nil {
			return nil, nil, rejectContext(ctx, ErrReprovisioning)
		}
		if !proto.Equal(verified, next) {
			return nil, nil, ErrCorrupt
		}
		request.RootTransitions = append(request.RootTransitions, transition)
		root = next
	}
	if !proto.Equal(root, snapshot.Root) {
		return nil, nil, ErrCorrupt
	}
	delegation, err := s.verifier.VerifyDelegation(ctx, root, snapshot.DelegationEnvelope, delegationVersion, minimumEpoch, now)
	if err != nil {
		return nil, nil, rejectContext(ctx, ErrReprovisioning)
	}
	if !proto.Equal(delegation, snapshot.Delegation) {
		return nil, nil, ErrCorrupt
	}
	return snapshot, request, nil
}
