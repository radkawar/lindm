package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// ListApprovals applies action and inbox-management scopes in SQL before keyset
// pagination. Hidden requests cannot affect page sizes, tokens or audit contents.
func (s *Service) ListApprovals(ctx context.Context, actor uuid.UUID, request *adminv1.ListApprovalsRequest) ([]*adminv1.Approval, string, error) {
	if s == nil || request == nil {
		return nil, "", ErrApprovalInvalid
	}
	if err := s.rules.Validate(request); err != nil {
		return nil, "", ErrApprovalInvalid
	}
	after := uuid.Nil
	if request.GetPageToken() != "" {
		raw, err := base64.RawURLEncoding.DecodeString(request.GetPageToken())
		if err != nil {
			return nil, "", ErrApprovalInvalid
		}
		after, err = uuid.FromBytes(raw)
		if err != nil {
			return nil, "", ErrApprovalInvalid
		}
	}
	limit := int(request.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	authorizations, visibility, err := s.approvalInboxVisibility(ctx, actor)
	if err != nil {
		return nil, "", err
	}
	visibility.AfterID = after
	visibility.RowLimit = int32(limit + 1)
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
		return s.insertAudit(ctx, q, &actor, "approval.listed", principalResource(actor), "scoped inbox")
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		last := rows[limit-1].ApprovalRequest.ID
		next = base64.RawURLEncoding.EncodeToString(last[:])
		rows = rows[:limit]
	}
	out := make([]*adminv1.Approval, 0, len(rows))
	for i := range rows {
		item, err := approvalMessage((*approvalProjection)(&rows[i]), s.clock())
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

// CountPendingApprovals counts unexpired pending records in the same authorized
// inbox as ListApprovals. It is not a claim that each request can be approved:
// consumption still performs the existing fresh requester/approver fences.
func (s *Service) CountPendingApprovals(ctx context.Context, actor uuid.UUID) (int64, error) {
	if s == nil {
		return 0, ErrApprovalInvalid
	}
	authorizations, visibility, err := s.approvalInboxVisibility(ctx, actor)
	if err != nil {
		return 0, err
	}
	var count int64
	err = s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		for _, authorization := range authorizations {
			if err := s.LockAuthorization(ctx, tx, authorization, authorization.permission); err != nil {
				return err
			}
		}
		var err error
		count, err = q.CountVisiblePendingApprovals(ctx, identitydb.CountVisiblePendingApprovalsParams{
			ActorID: actor, UnrestrictedPermissions: visibility.UnrestrictedPermissions,
			Scopes: visibility.Scopes, ManageUnrestricted: visibility.ManageUnrestricted, ManageScopes: visibility.ManageScopes,
			RequiredScopes: visibility.RequiredScopes,
		})
		if err != nil {
			return s.dbErr(err)
		}
		return s.insertAudit(ctx, q, &actor, "approval.listed", principalResource(actor), "scoped pending inbox count")
	})
	return count, err
}
