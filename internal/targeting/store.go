// Package targeting owns bounded server-side membership, immutable resolution
// previews and rollout gates. It grants neither RBAC membership nor native effect
// authority. Callers must AuthorizeFresh before opening their transaction, then
// LockAuthorization at entry and again before commit; every effective contributor
// must be freshly authorized at dispatch. No network operation belongs under locks.
// Preview and cohort creation/promotion require REPEATABLE READ transactions.
// Targeting's updating singleton fence rejects stale snapshots after waiting.
// Reads use the same permission-specific identity.DeviceScopes representation as
// device's existing authorization helpers, never a second role interpretation.
// A resolution holds at most 128 applicable assignments; a rollout stage retains
// at most 10,000 evaluated device IDs with separate selected/pending/excluded counts.
// Unknown inventory never becomes implicit release. Unknown rollout health begins
// counting against its budget after initial soak; failures/unavailable count now.
package targeting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

var (
	ErrRejected = errors.New("targeting_rejected")
	ErrConflict = errors.New("targeting_revision_conflict")
	ErrNotFound = errors.New("targeting_not_found")
	ErrCapacity = errors.New("targeting_capacity")
	ErrPaused   = errors.New("rollout_paused")
	ErrNotReady = errors.New("rollout_not_ready")
)

type Store struct {
	rules protovalidate.Validator
	clock func() time.Time
}
type Resolver func(context.Context, pgx.Tx, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, error)
type Activator func(context.Context, pgx.Tx, *policyv1.TargetPreview) error

func New() (*Store, error) {
	return newStore(nil)
}

func newStore(clock func() time.Time) (*Store, error) {
	rules, err := protovalidate.New(protovalidate.WithMessages(
		&adminv1.PutDynamicGroupRequest{}, &adminv1.ListDynamicGroupsRequest{}, &adminv1.GetDynamicGroupRequest{},
		&adminv1.PutTargetAssignmentRequest{}, &adminv1.ListTargetAssignmentsRequest{},
		&adminv1.PreviewTargetAssignmentsRequest{}, &adminv1.ActivateTargetPreviewRequest{},
		&adminv1.PutRolloutRequest{}, &adminv1.ControlRolloutRequest{}, &adminv1.ListRolloutsRequest{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	return &Store{rules: rules, clock: clock}, nil
}
func (s *Store) validate(m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() {
		return ErrRejected
	}
	if proto.Size(m) > maxDocumentBytes {
		return ErrCapacity
	}
	if err := validateTargetingClosed(m.ProtoReflect()); err != nil {
		return ErrRejected
	}
	if err := s.rules.Validate(m); err != nil {
		return ErrRejected
	}
	return nil
}

const maxDocumentBytes = 1 << 20
const maxCatalogBytes = 256 << 10

func encoded(m proto.Message) ([]byte, error) {
	if proto.Size(m) > maxDocumentBytes {
		return nil, ErrCapacity
	}
	return (proto.MarshalOptions{Deterministic: true}).Marshal(m)
}
func encodedCatalog(m proto.Message) ([]byte, error) {
	if proto.Size(m) > maxCatalogBytes {
		return nil, ErrCapacity
	}
	return encoded(m)
}

// ValidateResponse applies the same transport ceiling to protobuf and JSON before
// committing a mutation receipt. Large lists fail explicitly; reduce page size.
func ValidateResponse(m proto.Message) error {
	if proto.Size(m) > maxDocumentBytes {
		return ErrCapacity
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxDocumentBytes {
		return ErrCapacity
	}
	return nil
}
func digest(domain string, b []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.targeting." + domain + ".v1\x00"))
	_, _ = h.Write(b)
	return h.Sum(nil)
}
func scope(p identity.Principal, perm identity.Permission) (bool, []byte, error) {
	u, v := identity.DeviceScopes(p, perm)
	b, err := json.Marshal(v)
	if u || len(v) == 0 {
		b = []byte("[]")
	}
	return u, b, err
}
func unrestricted(p identity.Principal, perm identity.Permission) error {
	u, _ := identity.DeviceScopes(p, perm)
	if !u {
		return ErrNotFound
	}
	return nil
}
func beginRead(tx pgx.Tx, p identity.Principal, perm identity.Permission, global bool) (*targetingdb.Queries, error) {
	if tx == nil || p.ID == uuid.Nil {
		return nil, ErrRejected
	}
	if global {
		if err := unrestricted(p, perm); err != nil {
			return nil, err
		}
	}
	return targetingdb.New(tx), nil
}
func begin(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, global bool) (*targetingdb.Queries, error) {
	q, err := beginRead(tx, p, perm, global)
	if err != nil {
		return nil, err
	}
	if err := q.LockTargeting(ctx); err != nil {
		return nil, err
	}
	return q, nil
}
func receipt(ctx context.Context, q *targetingdb.Queries, p identity.Principal, id, method string, request, response proto.Message) (bool, error) {
	b, err := encoded(request)
	if err != nil {
		return false, err
	}
	row, err := q.GetTargetingRequest(ctx, targetingdb.GetTargetingRequestParams{ActorID: p.ID, RequestID: uuid.MustParse(id)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if row.Method != method || !bytes.Equal(row.Digest, digest(method, b)) {
		return false, ErrConflict
	}
	return true, proto.Unmarshal(row.Response, response)
}
func saveReceipt(ctx context.Context, q *targetingdb.Queries, p identity.Principal, id, method, resource, reason, auditContext string, request, response proto.Message) error {
	b, err := encoded(request)
	if err != nil {
		return err
	}
	out, err := encoded(response)
	if err != nil {
		return err
	}
	if err = q.InsertTargetingRequest(ctx, targetingdb.InsertTargetingRequestParams{ActorID: p.ID, RequestID: uuid.MustParse(id), Method: method, Digest: digest(method, b), Response: out}); err != nil {
		return err
	}
	return q.TargetingAudit(ctx, targetingdb.TargetingAuditParams{ID: uuid.New(), ActorID: &p.ID, Action: method, ResourceID: resource, Reason: reason, Context: auditContext})
}

func (s *Store) PutDynamicGroup(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.PutDynamicGroupRequest) (*adminv1.PutDynamicGroupResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	if err := validateExpression(r.Group.Expression); err != nil {
		return nil, err
	}
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.PutDynamicGroupResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, "targeting.group.put", r, out); ok || err != nil {
		return out, err
	}
	if _, valid, err := expressionDefinitions(ctx, q, r.Group.Expression); err != nil {
		return nil, err
	} else if !valid {
		return nil, ErrRejected
	}
	group := proto.CloneOf(r.Group)
	group.Revision = r.ExpectedRevision + 1
	b, err := encodedCatalog(group)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(group.GroupId)
	var count int64
	if r.ExpectedRevision == 0 {
		count, err = q.PutDynamicGroup(ctx, targetingdb.PutDynamicGroupParams{ID: id, Definition: b, Expected: 0})
	} else {
		count, err = q.UpdateDynamicGroup(ctx, targetingdb.UpdateDynamicGroupParams{ID: id, Definition: b, Revision: int64(r.ExpectedRevision)})
	}
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	if err = q.InsertDynamicGroupRevision(ctx, targetingdb.InsertDynamicGroupRevisionParams{GroupID: id, Revision: int64(group.Revision), Definition: b, ActorID: p.ID}); err != nil {
		return nil, err
	}
	out.Group = group
	return out, saveReceipt(ctx, q, p, r.RequestId, "targeting.group.put", group.GroupId, r.Reason, "", r, out)
}
func (s *Store) ListDynamicGroups(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ListDynamicGroupsRequest) (*adminv1.ListDynamicGroupsResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	if r.AfterId != nil {
		after = uuid.MustParse(*r.AfterId)
	}
	rows, err := q.ListDynamicGroups(ctx, targetingdb.ListDynamicGroupsParams{AfterID: after, RowLimit: int32(r.PageSize)})
	if err != nil {
		return nil, err
	}
	out := new(adminv1.ListDynamicGroupsResponse)
	for _, row := range rows {
		g := new(adminv1.DynamicTargetGroup)
		if err := proto.Unmarshal(row.Definition, g); err != nil {
			return nil, err
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}
func (s *Store) PutAssignment(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.PutTargetAssignmentRequest) (*adminv1.PutTargetAssignmentResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.PutTargetAssignmentResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, "targeting.assignment.put", r, out); ok || err != nil {
		return out, err
	}
	exists, err := q.TargetProfileRevisionExists(ctx, uuid.MustParse(r.Assignment.ProfileRevisionId))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	if r.Assignment.RolloutId != nil {
		if _, err := q.GetRollout(ctx, uuid.MustParse(*r.Assignment.RolloutId)); err != nil {
			return nil, err
		}
	}
	if err := checkTarget(ctx, q, r.Assignment.Target); err != nil {
		return nil, err
	}
	for _, t := range r.Assignment.Exclusions {
		if err := checkTarget(ctx, q, t); err != nil {
			return nil, err
		}
	}
	b, err := encodedCatalog(r.Assignment)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(r.Assignment.AssignmentId)
	var count int64
	if r.ExpectedRevision == 0 {
		count, err = q.PutTargetAssignment(ctx, targetingdb.PutTargetAssignmentParams{ID: id, Definition: b, ActorID: p.ID})
	} else {
		count, err = q.UpdateTargetAssignment(ctx, targetingdb.UpdateTargetAssignmentParams{ID: id, Definition: b, ActorID: p.ID, Revision: int64(r.ExpectedRevision)})
	}
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	if err = q.InsertTargetAssignmentRevision(ctx, targetingdb.InsertTargetAssignmentRevisionParams{AssignmentID: id, Revision: int64(r.ExpectedRevision + 1), Definition: b, ActorID: p.ID}); err != nil {
		return nil, err
	}
	out.Assignment = &policyv1.TargetCandidate{Assignment: proto.CloneOf(r.Assignment), Revision: r.ExpectedRevision + 1, ActorId: p.ID.String()}
	return out, saveReceipt(ctx, q, p, r.RequestId, "targeting.assignment.put", id.String(), r.Reason, "", r, out)
}
func (s *Store) ListAssignments(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ListTargetAssignmentsRequest) (*adminv1.ListTargetAssignmentsResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	if r.AfterId != nil {
		after = uuid.MustParse(*r.AfterId)
	}
	rows, err := q.ListTargetAssignments(ctx, targetingdb.ListTargetAssignmentsParams{AfterID: after, RowLimit: int32(r.PageSize)})
	if err != nil {
		return nil, err
	}
	out := new(adminv1.ListTargetAssignmentsResponse)
	for _, row := range rows {
		a := new(policyv1.TargetAssignment)
		if err := proto.Unmarshal(row.Definition, a); err != nil {
			return nil, err
		}
		out.Assignments = append(out.Assignments, &policyv1.TargetCandidate{Assignment: a, Revision: uint64(row.Revision), ActorId: row.ActorID.String()})
	}
	return out, nil
}
func checkTarget(ctx context.Context, q *targetingdb.Queries, t *policyv1.TargetRef) error {
	if t.GetDeviceId() != "" {
		ok, err := q.TargetDeviceExists(ctx, uuid.MustParse(t.GetDeviceId()))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
	}
	if t.GetDynamicGroupId() != "" {
		_, err := q.GetDynamicGroup(ctx, uuid.MustParse(t.GetDynamicGroupId()))
		return err
	}
	if t.GetStaticGroupId() != "" {
		ok, err := q.TargetStaticGroupExists(ctx, uuid.MustParse(t.GetStaticGroupId()))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
	}
	return nil
}

func (s *Store) GetDynamicGroup(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.GetDynamicGroupRequest) (*adminv1.GetDynamicGroupResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	row, err := q.GetDynamicGroup(ctx, uuid.MustParse(r.GroupId))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	group := new(adminv1.DynamicTargetGroup)
	if err := proto.Unmarshal(row.Definition, group); err != nil {
		return nil, err
	}
	return &adminv1.GetDynamicGroupResponse{Group: group}, nil
}
