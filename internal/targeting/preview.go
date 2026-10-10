package targeting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

type groupInput struct {
	ID                   uuid.UUID
	Kind                 int16
	Revision             int64
	Definition           []byte
	AttributeDefinitions map[string][]byte
	Match                policyv1.TargetMatch
	UsesLastSeen         bool
}
type inputs struct {
	Device        targetingdb.TargetingDeviceRow
	Assignments   []*policyv1.TargetCandidate
	Groups        map[string]groupInput
	Rollouts      map[string]*adminv1.RolloutState
	CatalogDigest []byte
}

// deviceMembershipInput deliberately names the device fences retained in a
// preview. Heartbeats are not membership changes unless an evaluated dynamic
// predicate references last-seen; native observation freshness remains pinned.
type deviceMembershipInput struct {
	ID                   uuid.UUID
	CurrentGenerationID  *uuid.UUID
	State                string
	Hostname             string
	OsID                 string
	OsVersion            string
	HostnameStatus       int16
	OsIDStatus           int16
	OsVersionStatus      int16
	HostSequence         int64
	HostDigest           []byte
	Architecture         string
	LastSeenAt           *pgtype.Timestamptz `json:",omitempty"`
	HostReceivedAt       pgtype.Timestamptz
	Metadata             []byte
	Labels               []string
	Groups               []string
	PreviousPreviewID    string
	ResourceAssignmentID string
}
type evaluation struct {
	q              *targetingdb.Queries
	input          inputs
	metadata       *adminv1.DeviceMetadata
	now, timeLimit time.Time
}

func loadEvaluation(ctx context.Context, q *targetingdb.Queries, p identity.Principal, perm identity.Permission, id uuid.UUID) (*evaluation, error) {
	u, scopes, err := scope(p, perm)
	if err != nil {
		return nil, err
	}
	return loadInput(ctx, q, id, u, scopes)
}
func loadInput(ctx context.Context, q *targetingdb.Queries, id uuid.UUID, u bool, scopes []byte) (*evaluation, error) {
	if _, err := q.LockTargetingDevice(ctx, id); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	d, err := q.TargetingDevice(ctx, targetingdb.TargetingDeviceParams{DeviceID: id, Unrestricted: u, Scopes: scopes})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	m := new(adminv1.DeviceMetadata)
	if err := protojson.Unmarshal(d.Metadata, m); err != nil {
		return nil, err
	}
	return &evaluation{q: q, input: inputs{Device: d, Groups: make(map[string]groupInput), Rollouts: make(map[string]*adminv1.RolloutState)}, metadata: m, now: now.Time, timeLimit: now.Time.Add(15 * time.Minute)}, nil
}
func (e *evaluation) limit(t time.Time) {
	if t.After(e.now) && t.Before(e.timeLimit) {
		e.timeLimit = t
	}
}
func (e *evaluation) target(ctx context.Context, t *policyv1.TargetRef) (policyv1.TargetMatch, error) {
	if id := t.GetDeviceId(); id != "" {
		if uuid.MustParse(id) == e.input.Device.ID {
			return included, nil
		}
		return excluded, nil
	}
	if id := t.GetStaticGroupId(); id != "" {
		return e.staticGroup(id), nil
	}
	id := uuid.MustParse(t.GetDynamicGroupId()).String()
	if g, ok := e.input.Groups["dynamic:"+id]; ok {
		return g.Match, nil
	}
	row, err := e.q.GetDynamicGroup(ctx, uuid.MustParse(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	g := new(adminv1.DynamicTargetGroup)
	if err := proto.Unmarshal(row.Definition, g); err != nil {
		return unknown, err
	}
	if err := validateExpression(g.Expression); err != nil {
		return unknown, err
	}
	usesLastSeen := false
	for _, node := range g.Expression.Nodes {
		if id := node.GetStaticGroupId(); id != "" {
			e.staticGroup(id)
		}
		if f := node.GetPredicate(); f != nil && (f.LastSeenFrom != nil || f.LastSeenUntil != nil) {
			usesLastSeen = true
		}
	}
	definitions, valid, err := expressionDefinitions(ctx, e.q, g.Expression)
	if err != nil {
		return unknown, err
	}
	result := unknown
	if valid {
		result = evaluate(g.Expression, e.input.Device, e.metadata, e.now)
	}
	if e.input.Device.HostReceivedAt.Valid {
		e.limit(e.input.Device.HostReceivedAt.Time.Add(time.Duration(g.Expression.InventoryMaxAgeSeconds) * time.Second))
	}
	e.input.Groups["dynamic:"+id] = groupInput{ID: uuid.MustParse(id), Kind: 2, Revision: row.Revision, Definition: row.Definition, AttributeDefinitions: definitions, Match: result, UsesLastSeen: valid && usesLastSeen}
	return result, nil
}
func (e *evaluation) staticGroup(id string) policyv1.TargetMatch {
	id = uuid.MustParse(id).String()
	result := excluded
	if slices.Contains(e.input.Device.Groups, id) {
		result = included
	}
	e.input.Groups["static:"+id] = groupInput{ID: uuid.MustParse(id), Kind: 1, Match: result}
	return result
}
func (s *Store) collect(ctx context.Context, e *evaluation) error {
	catalog := sha256.New()
	after := uuid.Nil
	for {
		rows, err := e.q.ListTargetAssignments(ctx, targetingdb.ListTargetAssignmentsParams{AfterID: after, RowLimit: 100})
		if err != nil {
			return err
		}
		for _, row := range rows {
			a := new(policyv1.TargetAssignment)
			if err := proto.Unmarshal(row.Definition, a); err != nil {
				return err
			}
			item := *e
			item.input = inputs{Device: e.input.Device, Groups: make(map[string]groupInput), Rollouts: make(map[string]*adminv1.RolloutState)}
			match, err := item.target(ctx, a.Target)
			if err != nil {
				return err
			}
			for _, x := range a.Exclusions {
				m, err := item.target(ctx, x)
				if err != nil {
					return err
				}
				if m == included {
					match = excluded
					break
				}
				if m == unknown && match == included {
					match = unknown
				}
			}
			if a.ActivatesAt != nil {
				item.limit(a.ActivatesAt.AsTime())
				if item.now.Before(a.ActivatesAt.AsTime()) {
					match = excluded
				}
			}
			if a.ExpiresAt != nil {
				item.limit(a.ExpiresAt.AsTime())
				if !item.now.Before(a.ExpiresAt.AsTime()) {
					match = excluded
				}
			}
			if a.Disabled {
				match = excluded
			}
			if a.RolloutId != nil {
				state, err := s.rolloutState(ctx, item.q, uuid.MustParse(*a.RolloutId))
				if err != nil {
					return err
				}
				item.input.Rollouts[*a.RolloutId] = state
				if match != excluded {
					if state.Paused {
						match = unknown
					} else {
						m, err := item.q.GetRolloutMember(ctx, targetingdb.GetRolloutMemberParams{RolloutID: uuid.MustParse(*a.RolloutId), RingIndex: int32(state.RingIndex), DeviceID: item.input.Device.ID})
						if errors.Is(err, pgx.ErrNoRows) {
							match = excluded
						} else if err != nil {
							return err
						} else if m != int16(included) {
							match = excluded
						}
					}
				}
			}
			candidate := &policyv1.TargetCandidate{Assignment: a, Revision: uint64(row.Revision), ActorId: row.ActorID.String(), Match: match}
			// Stream fixed-size entry digests, including excluded definitions, without
			// loading the fleet-wide assignment catalog into the device preview.
			item.input.Assignments = []*policyv1.TargetCandidate{candidate}
			entry, err := inputDigest(&item)
			if err != nil {
				return err
			}
			_, _ = catalog.Write(entry)
			e.limit(item.timeLimit)
			if match != excluded {
				e.input.Assignments = append(e.input.Assignments, candidate)
				if len(e.input.Assignments) > 128 {
					return ErrCapacity
				}
				for id, g := range item.input.Groups {
					e.input.Groups[id] = g
				}
				for id, r := range item.input.Rollouts {
					e.input.Rollouts[id] = r
				}
			}
			after = row.ID
		}
		if len(rows) < 100 {
			break
		}
	}
	e.input.CatalogDigest = catalog.Sum(nil)
	slices.SortFunc(e.input.Assignments, func(a, b *policyv1.TargetCandidate) int {
		if a.Assignment.Priority > b.Assignment.Priority {
			return -1
		}
		if a.Assignment.Priority < b.Assignment.Priority {
			return 1
		}
		return strings.Compare(a.Assignment.AssignmentId, b.Assignment.AssignmentId)
	})
	return nil
}
func inputDigest(e *evaluation) ([]byte, error) {
	d := &e.input.Device
	device := deviceMembershipInput{
		ID: d.ID, CurrentGenerationID: d.CurrentGenerationID, State: d.State,
		Hostname: d.Hostname, OsID: d.OsID, OsVersion: d.OsVersion,
		HostnameStatus: d.HostnameStatus, OsIDStatus: d.OsIDStatus, OsVersionStatus: d.OsVersionStatus,
		HostSequence: d.HostSequence, HostDigest: d.HostDigest, Architecture: d.Architecture,
		HostReceivedAt: d.HostReceivedAt, Metadata: d.Metadata, Labels: d.Labels, Groups: d.Groups,
		PreviousPreviewID: d.PreviousPreviewID, ResourceAssignmentID: d.ResourceAssignmentID,
	}
	for _, g := range e.input.Groups {
		if g.UsesLastSeen {
			device.LastSeenAt = &d.LastSeenAt
			break
		}
	}
	// collect hashes each catalog entry with its own dependencies before excluding
	// candidates, so a last-seen change cannot silently admit an excluded target.
	b, err := json.Marshal(struct {
		Device        deviceMembershipInput
		Assignments   []*policyv1.TargetCandidate
		Groups        map[string]groupInput
		Rollouts      map[string]*adminv1.RolloutState
		CatalogDigest []byte
	}{device, e.input.Assignments, e.input.Groups, e.input.Rollouts, e.input.CatalogDigest})
	if err != nil {
		return nil, err
	}
	return digest("input", b), nil
}
func (s *Store) Preview(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.PreviewTargetAssignmentsRequest, resolve Resolver) (*policyv1.TargetPreview, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, ErrRejected
	}
	q, err := begin(ctx, tx, p, perm, false)
	if err != nil {
		return nil, err
	}
	e, err := loadEvaluation(ctx, q, p, perm, uuid.MustParse(r.DeviceId))
	if err != nil {
		return nil, err
	}
	if err := s.collect(ctx, e); err != nil {
		return nil, err
	}
	if e.input.Device.CurrentGenerationID == nil || e.input.Device.State != "active" {
		return nil, ErrNotReady
	}
	resolution, err := resolve(ctx, tx, e.input.Assignments)
	if err != nil {
		return nil, err
	}
	if resolution == nil {
		return nil, ErrRejected
	}
	rb, err := encoded(resolution)
	if err != nil {
		return nil, err
	}
	in, err := inputDigest(e)
	if err != nil {
		return nil, err
	}
	preview := &policyv1.TargetPreview{PreviewId: uuid.NewString(), DeviceId: e.input.Device.ID.String(), GenerationId: e.input.Device.CurrentGenerationID.String(), InputSha256: in, Candidates: e.input.Assignments, EvaluatedAt: timestamppb.New(e.now), ValidUntil: timestamppb.New(e.timeLimit), Resolution: resolution, ResolutionSha256: digest("resolution", rb)}
	if e.input.Device.PreviousPreviewID != "" {
		preview.PreviousPreviewId = proto.String(e.input.Device.PreviousPreviewID)
	}
	b, err := encoded(preview)
	if err != nil {
		return nil, err
	}
	preview.PreviewSha256 = digest("preview", b)
	b, err = encoded(preview)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(preview.PreviewId)
	if err = q.InsertTargetPreview(ctx, targetingdb.InsertTargetPreviewParams{ID: id, DeviceID: e.input.Device.ID, ActorID: p.ID, Document: b, Digest: preview.PreviewSha256}); err != nil {
		return nil, err
	}
	for _, g := range e.input.Groups {
		if err = q.InsertTargetMembership(ctx, targetingdb.InsertTargetMembershipParams{PreviewID: id, GroupID: g.ID, GroupKind: g.Kind, GroupRevision: g.Revision, DeviceID: e.input.Device.ID, InputDigest: in, Membership: int16(g.Match)}); err != nil {
			return nil, err
		}
	}
	return preview, nil
}
func (s *Store) Activate(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ActivateTargetPreviewRequest, activate Activator) (*policyv1.TargetPreview, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	if activate == nil {
		return nil, ErrRejected
	}
	q, err := begin(ctx, tx, p, perm, false)
	if err != nil {
		return nil, err
	}
	row, err := q.GetTargetPreview(ctx, uuid.MustParse(r.PreviewId))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if row.ActorID != p.ID || row.DeviceID != uuid.MustParse(r.DeviceId) {
		return nil, ErrNotFound
	}
	e, err := loadEvaluation(ctx, q, p, perm, row.DeviceID)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.ActivateTargetPreviewResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, "targeting.preview.activate", r, out); ok || err != nil {
		return out.Preview, err
	}
	preview := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(row.Document, preview); err != nil {
		return nil, err
	}
	if !bytes.Equal(row.Digest, r.PreviewSha256) || !e.now.Before(preview.ValidUntil.AsTime()) {
		return nil, ErrConflict
	}
	if err := s.collect(ctx, e); err != nil {
		return nil, err
	}
	in, err := inputDigest(e)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in, preview.InputSha256) {
		return nil, ErrConflict
	}
	for _, c := range preview.Candidates {
		if c.Match == unknown {
			return nil, ErrNotReady
		}
	}
	if err := activate(ctx, tx, preview); err != nil {
		return nil, err
	}
	if err = q.SetTargetExecutionHead(ctx, targetingdb.SetTargetExecutionHeadParams{DeviceID: row.DeviceID, PreviewID: uuid.MustParse(r.PreviewId)}); err != nil {
		return nil, err
	}
	if err := s.RecordExecutionHealth(ctx, tx, row.DeviceID, uuid.MustParse(preview.GenerationId), uuid.MustParse(preview.PreviewId)); err != nil {
		return nil, err
	}
	out.Preview = preview
	return preview, saveReceipt(ctx, q, p, r.RequestId, "targeting.preview.activate", row.DeviceID.String(), r.Reason, r, out)
}

// Eligible is a fresh pre-start fence, not permission to enlarge a pinned cohort.
// Call it while holding the same device/authorization transaction as start issuance.
func (s *Store) Eligible(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, preview *policyv1.TargetPreview) error {
	q, err := begin(ctx, tx, p, perm, false)
	if err != nil {
		return err
	}
	e, err := loadEvaluation(ctx, q, p, perm, uuid.MustParse(preview.DeviceId))
	if err != nil {
		return err
	}
	if e.input.Device.State != "active" || e.input.Device.CurrentGenerationID == nil || e.input.Device.CurrentGenerationID.String() != preview.GenerationId || e.input.Device.PreviousPreviewID != preview.PreviewId {
		return ErrConflict
	}
	if err := s.collect(ctx, e); err != nil {
		return err
	}
	for _, prior := range preview.Candidates {
		if prior.Match != included {
			continue
		}
		found := false
		for _, current := range e.input.Assignments {
			if prior.Assignment.AssignmentId == current.Assignment.AssignmentId {
				found = current.Match == included && current.Revision == prior.Revision
				break
			}
		}
		if !found {
			return ErrNotReady
		}
	}
	return nil
}

// Lock must precede device locks in every dispatch transaction that calls a
// targeting operation. The caller still owns fresh principal fencing.
func (s *Store) Lock(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return ErrRejected
	}
	return targetingdb.New(tx).LockTargeting(ctx)
}

// CheckExecution is exclusively a device-dispatch boundary: the caller must
// authenticate device generation and freshly authorize the adopted actor using
// its ordinary domain scope helpers. False is a gate result, not a transaction
// error: commit any automatic pause before withholding new effect authority.
func (s *Store) CheckExecution(ctx context.Context, tx pgx.Tx, deviceID, generationID, assignmentID uuid.UUID) (bool, error) {
	if err := s.Lock(ctx, tx); err != nil {
		return false, err
	}
	q := targetingdb.New(tx)
	row, err := q.GetTargetPreview(ctx, assignmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if row.DeviceID != deviceID {
		return false, nil
	}
	preview := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(row.Document, preview); err != nil {
		return false, err
	}
	if preview.GenerationId != generationID.String() {
		return false, nil
	}
	for _, c := range preview.Candidates {
		if c.Match == included && c.Assignment.RolloutId != nil {
			if _, err := s.RefreshRollout(ctx, tx, uuid.MustParse(*c.Assignment.RolloutId)); err != nil {
				return false, err
			}
		}
	}
	e, err := loadInput(ctx, q, deviceID, true, []byte("[]"))
	if err != nil {
		return false, err
	}
	if e.input.Device.State != "active" || e.input.Device.CurrentGenerationID == nil || *e.input.Device.CurrentGenerationID != generationID || e.input.Device.PreviousPreviewID != preview.PreviewId || e.input.Device.ResourceAssignmentID != assignmentID.String() {
		return false, nil
	}
	if err := s.collect(ctx, e); err != nil {
		return false, err
	}
	for _, prior := range preview.Candidates {
		if prior.Match != included {
			continue
		}
		found := false
		for _, current := range e.input.Assignments {
			if prior.Assignment.AssignmentId == current.Assignment.AssignmentId {
				found = current.Match == included && current.Revision == prior.Revision
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// ExecutionPreview reads immutable provenance only after the dispatch caller has
// checked execution eligibility under the targeting and device/head locks.
func (s *Store) ExecutionPreview(ctx context.Context, tx pgx.Tx, deviceID, generationID, assignmentID uuid.UUID) (*policyv1.TargetPreview, error) {
	if tx == nil {
		return nil, ErrRejected
	}
	row, err := targetingdb.New(tx).GetTargetPreview(ctx, assignmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	preview := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(row.Document, preview); err != nil {
		return nil, err
	}
	if row.DeviceID != deviceID || preview.GetDeviceId() != deviceID.String() || preview.GetGenerationId() != generationID.String() || preview.GetPreviewId() != assignmentID.String() {
		return nil, ErrRejected
	}
	return preview, nil
}
