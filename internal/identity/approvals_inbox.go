package identity

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func approvalScopesJSON(scopes []*authv1.DeviceScope) ([]byte, error) {
	documents := make([]json.RawMessage, 0, len(scopes))
	for _, scope := range scopes {
		document, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(scope)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	return json.Marshal(documents)
}

// approvalOpen matches ListVisibleApprovals' ordering predicate: an open request
// still awaits a decision or its requester's run, and has not expired.
func approvalOpen(row *identitydb.ApprovalRequest, now time.Time) bool {
	return (row.State == "pending" || row.State == "approved") && now.Before(row.ExpiresAt.Time)
}

// An inbox page token is the keyset position of a page's last row: one
// open/closed byte, the ordering time (expiry when open, creation when closed)
// in Unix microseconds, then the approval ID.
const (
	approvalPageTokenSize = 1 + 8 + 16
	// 10000-01-01T00:00:00Z: no real approval time reaches it; tampered tokens stop here.
	approvalPageTimeLimit = 253402300800 * 1_000_000
)

func approvalPageToken(row *identitydb.ApprovalRequest, now time.Time) string {
	var raw [approvalPageTokenSize]byte
	at := row.ExpiresAt.Time
	if !approvalOpen(row, now) {
		raw[0] = 1
		at = row.CreatedAt.Time
	}
	binary.BigEndian.PutUint64(raw[1:9], uint64(at.UnixMicro()))
	copy(raw[9:], row.ID[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func parseApprovalPageToken(token string, params *identitydb.ListVisibleApprovalsParams) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != approvalPageTokenSize || raw[0] > 1 {
		return ErrApprovalInvalid
	}
	micros := int64(binary.BigEndian.Uint64(raw[1:9]))
	if micros < 0 || micros >= approvalPageTimeLimit {
		return ErrApprovalInvalid
	}
	id, err := uuid.FromBytes(raw[9:])
	if err != nil {
		return ErrApprovalInvalid
	}
	params.FirstPage = false
	params.AfterClosed = raw[0] == 1
	params.AfterAt = pgtype.Timestamptz{Time: time.UnixMicro(micros).UTC(), Valid: true}
	params.AfterID = id
	return nil
}

// ListApprovals applies action and inbox-management scopes in SQL before keyset
// pagination. Hidden requests cannot affect page sizes, tokens or audit contents.
// Open requests come first, nearest expiry first; closed ones follow, newest first.
func (s *Service) ListApprovals(ctx context.Context, actor uuid.UUID, request *adminv1.ListApprovalsRequest) ([]*adminv1.Approval, string, error) {
	if s == nil || request == nil {
		return nil, "", ErrApprovalInvalid
	}
	if err := s.rules.Validate(request); err != nil {
		return nil, "", ErrApprovalInvalid
	}
	limit := int(request.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	authorizations, visibility, err := s.approvalInboxVisibility(ctx, actor)
	if err != nil {
		return nil, "", err
	}
	// One instant orders the page, encodes its token and labels expiry, at the
	// microsecond precision PostgreSQL stores.
	now := s.clock().Truncate(time.Microsecond)
	visibility.FirstPage = true
	if request.GetPageToken() != "" {
		if err := parseApprovalPageToken(request.GetPageToken(), &visibility); err != nil {
			return nil, "", err
		}
	}
	visibility.AsOf = pgtype.Timestamptz{Time: now, Valid: true}
	visibility.RowLimit = int32(limit + 1)
	if request.GetDeviceId() != "" {
		device, err := uuid.Parse(request.GetDeviceId())
		if err != nil {
			return nil, "", ErrApprovalInvalid
		}
		visibility.DeviceID = &device
	}
	var rows []identitydb.ListVisibleApprovalsRow
	err = s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		for _, authorization := range authorizations {
			if err := s.LockAuthorization(ctx, tx, authorization, authorization.permission); err != nil {
				return err
			}
		}
		var err error
		rows, err = q.ListVisibleApprovals(ctx, visibility)
		if err != nil {
			return s.dbErr(err)
		}
		return s.insertSystemAudit(ctx, q, &actor, "approval.listed", principalResource(actor), "scoped inbox")
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		next = approvalPageToken(&rows[limit-1].ApprovalRequest, now)
		rows = rows[:limit]
	}
	out := make([]*adminv1.Approval, 0, len(rows))
	for i := range rows {
		item, err := approvalMessage((*approvalProjection)(&rows[i]), now)
		if err != nil {
			return nil, "", err
		}
		out = append(out, item)
	}
	return out, next, nil
}

type approvalRequiredScope struct {
	Unrestricted bool            `json:"unrestricted"`
	Scopes       json.RawMessage `json:"scopes"`
}

func approvalRequiredScopes(principal Principal, permission Permission) ([]approvalRequiredScope, error) {
	var required []approvalRequiredScope
	for _, grant := range approvalPermissionRequirements[permission] {
		entry := approvalRequiredScope{Scopes: json.RawMessage("[]")}
		if Authorize(principal, grant) {
			all, scopes := DeviceScopes(principal, grant)
			encoded, err := approvalScopesJSON(scopes)
			if err != nil {
				return nil, err
			}
			entry.Unrestricted, entry.Scopes = all, encoded
		}
		required = append(required, entry)
	}
	return required, nil
}

// approvalInboxVisibility is shared by the paged inbox and its pending count.
// An action grant alone never grants access to another requester's inbox.
func (s *Service) approvalInboxVisibility(ctx context.Context, actor uuid.UUID) ([]*Authorization, identitydb.ListVisibleApprovalsParams, error) {
	permissions := approvalInboxPermissions
	authorizations := make([]*Authorization, 0, len(permissions))
	visibility := identitydb.ListVisibleApprovalsParams{
		ActorID: actor, UnrestrictedPermissions: make([]string, 0, len(permissions)), ManageScopes: []byte("[]"),
	}
	scopes := make(map[string]json.RawMessage, len(permissions))
	requiredScopes := make(map[string][]approvalRequiredScope)
	for _, permission := range permissions {
		authorization, err := s.AuthorizeFresh(ctx, actor, permission)
		if errors.Is(err, ErrAuthorizationDenied) {
			continue
		}
		if err != nil {
			return nil, visibility, err
		}
		principal := authorization.Principal()
		if principal.ServiceAccount {
			continue
		}
		if len(approvalPermissionRequirements[permission]) != 0 {
			requiredScopes[string(permission)], err = approvalRequiredScopes(principal, permission)
			if err != nil {
				return nil, visibility, err
			}
		}
		authorizations = append(authorizations, authorization)
		all, restricted := DeviceScopes(principal, permission)
		if all {
			visibility.UnrestrictedPermissions = append(visibility.UnrestrictedPermissions, string(permission))
		}
		scopes[string(permission)], err = approvalScopesJSON(restricted)
		if err != nil {
			return nil, visibility, err
		}
		visibility.ManageUnrestricted, restricted = DeviceScopes(principal, PermissionManageApprovals)
		visibility.ManageScopes, err = approvalScopesJSON(restricted)
		if err != nil {
			return nil, visibility, err
		}
	}
	if len(authorizations) == 0 {
		return nil, visibility, ErrAuthorizationDenied
	}
	var err error
	visibility.Scopes, err = json.Marshal(scopes)
	if err != nil {
		return nil, visibility, err
	}
	visibility.RequiredScopes, err = json.Marshal(requiredScopes)
	return authorizations, visibility, err
}

// CountOpenApprovals counts unexpired pending records, and the actor's own
// approved requests ready for them to run, in the same authorized inbox as
// ListApprovals. It is not a claim that each request can be approved or run:
// consumption still performs the existing fresh requester/approver fences.
func (s *Service) CountOpenApprovals(ctx context.Context, actor uuid.UUID) (pending, readyToRun int64, err error) {
	if s == nil {
		return 0, 0, ErrApprovalInvalid
	}
	authorizations, visibility, err := s.approvalInboxVisibility(ctx, actor)
	if err != nil {
		return 0, 0, err
	}
	var counts identitydb.CountVisibleOpenApprovalsRow
	err = s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		for _, authorization := range authorizations {
			if err := s.LockAuthorization(ctx, tx, authorization, authorization.permission); err != nil {
				return err
			}
		}
		var err error
		counts, err = q.CountVisibleOpenApprovals(ctx, identitydb.CountVisibleOpenApprovalsParams{
			ActorID: actor, UnrestrictedPermissions: visibility.UnrestrictedPermissions,
			Scopes: visibility.Scopes, ManageUnrestricted: visibility.ManageUnrestricted, ManageScopes: visibility.ManageScopes,
			RequiredScopes: visibility.RequiredScopes,
		})
		if err != nil {
			return s.dbErr(err)
		}
		return s.insertSystemAudit(ctx, q, &actor, "approval.listed", principalResource(actor), "scoped open inbox count")
	})
	return counts.Pending, counts.ReadyToRun, err
}
