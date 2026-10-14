// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

// A transaction-local cache: no catalog or profile load per fleet member. The
// bounds cover decoded documents as well as input bytes; no global stale cache.
type impactCatalog struct {
	assignments     []*policyv1.TargetCandidate
	assignmentIndex map[uuid.UUID]int
	digest          []byte
	groups          map[string]targetingdb.DynamicTargetGroup
	decodedGroups   map[string]*adminv1.DynamicTargetGroup
	missingGroups   map[string]bool
	definitions     map[string]impactDefinitions
	rollouts        map[string]*rolloutInput
	bytes           int
}
type impactDefinitions struct {
	Values map[string][]byte
	Valid  bool
}

func loadImpactCatalog(ctx context.Context, q *targetingdb.Queries) (*impactCatalog, error) {
	c := &impactCatalog{groups: make(map[string]targetingdb.DynamicTargetGroup), decodedGroups: make(map[string]*adminv1.DynamicTargetGroup), missingGroups: make(map[string]bool), definitions: make(map[string]impactDefinitions), rollouts: make(map[string]*rolloutInput)}
	c.assignmentIndex = make(map[uuid.UUID]int)
	h := sha256.New()
	after := uuid.Nil
	for {
		rows, err := q.ListTargetAssignments(ctx, targetingdb.ListTargetAssignmentsParams{AfterID: after, RowLimit: 100})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			c.bytes += len(row.Definition)
			if c.bytes > 16<<20 || len(c.assignments) == 10000 {
				return nil, ErrCapacity
			}
			a := new(policyv1.TargetAssignment)
			if err := proto.Unmarshal(row.Definition, a); err != nil {
				return nil, err
			}
			candidate := &policyv1.TargetCandidate{Assignment: a, Revision: uint64(row.Revision), ActorId: row.ActorID.String()}
			b, err := encoded(candidate)
			if err != nil {
				return nil, err
			}
			_, _ = h.Write(digest("impact.catalog.entry", b))
			c.assignmentIndex[row.ID] = len(c.assignments)
			c.assignments = append(c.assignments, candidate)
			after = row.ID
		}
		if len(rows) < 100 {
			break
		}
	}
	c.digest = h.Sum(nil)
	return c, nil
}

func (e *evaluation) dynamicGroup(ctx context.Context, id string) (targetingdb.DynamicTargetGroup, error) {
	if e.catalog != nil {
		if row, ok := e.catalog.groups[id]; ok {
			return row, nil
		}
		if e.catalog.missingGroups[id] {
			return targetingdb.DynamicTargetGroup{}, pgx.ErrNoRows
		}
	}
	row, err := e.q.GetDynamicGroup(ctx, uuid.MustParse(id))
	if e.catalog != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			e.catalog.missingGroups[id] = true
		}
		if err == nil {
			e.catalog.bytes += len(row.Definition)
			if e.catalog.bytes > 16<<20 {
				return row, ErrCapacity
			}
			e.catalog.groups[id] = row
		}
	}
	return row, err
}
func (e *evaluation) groupDefinitions(ctx context.Context, id string, expression *adminv1.TargetExpression) (map[string][]byte, bool, error) {
	if e.catalog != nil {
		if d, ok := e.catalog.definitions[id]; ok {
			return d.Values, d.Valid, nil
		}
	}
	values, valid, err := expressionDefinitions(ctx, e.q, expression)
	if err == nil && e.catalog != nil {
		for _, b := range values {
			e.catalog.bytes += len(b)
		}
		if e.catalog.bytes > 16<<20 {
			return nil, false, ErrCapacity
		}
		e.catalog.definitions[id] = impactDefinitions{Values: values, Valid: valid}
	}
	return values, valid, err
}
func (s *Store) assignmentRollout(ctx context.Context, e *evaluation, id string) (*rolloutInput, error) {
	if e.catalog != nil {
		if state := e.catalog.rollouts[id]; state != nil {
			return state, nil
		}
	}
	row, err := e.q.GetRollout(ctx, uuid.MustParse(id))
	if err != nil {
		return nil, err
	}
	state := &rolloutInput{Revision: row.Revision, RingIndex: row.RingIndex, Paused: row.Paused}
	if e.catalog != nil {
		// Bound the identifier and fixed durable vector, without loading live health.
		e.catalog.bytes += len(id) + 32
		if e.catalog.bytes > 16<<20 {
			return nil, ErrCapacity
		}
		e.catalog.rollouts[id] = state
	}
	return state, nil
}

func (e *evaluation) decodeDynamicGroup(id string, definition []byte) (*adminv1.DynamicTargetGroup, error) {
	if e.catalog != nil {
		if group := e.catalog.decodedGroups[id]; group != nil {
			return group, nil
		}
	}
	group := new(adminv1.DynamicTargetGroup)
	if err := proto.Unmarshal(definition, group); err != nil {
		return nil, err
	}
	if err := validateExpression(group.Expression); err != nil {
		return nil, err
	}
	if e.catalog != nil {
		e.catalog.decodedGroups[id] = group
	}
	return group, nil
}

func (s *Store) warmImpactProposal(ctx context.Context, q *targetingdb.Queries, catalog *impactCatalog, proposal *policyv1.TargetAssignment) error {
	e := &evaluation{q: q, catalog: catalog}
	warm := func(target *policyv1.TargetRef) error {
		id := target.GetDynamicGroupId()
		if id == "" {
			return nil
		}
		row, err := e.dynamicGroup(ctx, id)
		if err != nil {
			return err
		}
		group, err := e.decodeDynamicGroup(id, row.Definition)
		if err != nil {
			return err
		}
		_, _, err = e.groupDefinitions(ctx, id, group.Expression)
		return err
	}
	if err := warm(proposal.Target); err != nil {
		return err
	}
	for _, target := range proposal.Exclusions {
		if err := warm(target); err != nil {
			return err
		}
	}
	if proposal.RolloutId != nil {
		if _, err := s.assignmentRollout(ctx, e, *proposal.RolloutId); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) collectImpact(ctx context.Context, e *evaluation, proposal *policyv1.TargetAssignment, expected uint64, actor string) (policyv1.TargetMatch, error) {
	e.input.CatalogDigest = e.catalog.digest
	match := unknown
	collect := func(a *policyv1.TargetAssignment, revision uint64, actor string) error {
		item, candidate, err := s.matchAssignment(ctx, e, a, revision, actor)
		if err != nil {
			return err
		}
		e.limit(item.timeLimit)
		// Excluded inputs matter too: a changed exclusion or last-seen predicate
		// can enlarge the reviewed blast radius without changing saved definitions.
		for id, group := range item.input.Groups {
			e.input.Groups[id] = group
		}
		for id, rollout := range item.input.Rollouts {
			e.input.Rollouts[id] = rollout
		}
		if candidate.Match != excluded {
			e.input.Assignments = append(e.input.Assignments, candidate)
			if len(e.input.Assignments) > 128 {
				return ErrCapacity
			}
		}
		if a.AssignmentId == proposal.AssignmentId {
			match = candidate.Match
		}
		return nil
	}
	replaced, hasPrevious := e.catalog.assignmentIndex[uuid.MustParse(proposal.AssignmentId)]
	for i, candidate := range e.catalog.assignments {
		if hasPrevious && i == replaced {
			continue
		}
		if err := collect(candidate.Assignment, candidate.Revision, candidate.ActorId); err != nil {
			return unknown, err
		}
	}
	if err := collect(proposal, expected+1, actor); err != nil {
		return unknown, err
	}
	slices.SortFunc(e.input.Assignments, func(a, b *policyv1.TargetCandidate) int {
		if a.Assignment.Priority > b.Assignment.Priority {
			return -1
		}
		if a.Assignment.Priority < b.Assignment.Priority {
			return 1
		}
		return strings.Compare(a.Assignment.AssignmentId, b.Assignment.AssignmentId)
	})
	return match, nil
}
