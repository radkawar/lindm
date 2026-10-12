package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
)

// Enrollment is a global operation. Scope-bearing labels/groups additionally need
// account authority; ownership and attributes need inventory authority. A token
// retains the issuer's authority version, never a transferable wider admin grant.
func provisioningAssignmentAuthority(principal identity.Principal, assignment *adminv1.CreateProvisioningTokenRequest) error {
	permissions := []identity.Permission{identity.PermissionManageEnrollment}
	metadata := assignment.GetMetadata()
	if metadata != nil {
		permissions = append(permissions, identity.PermissionManageInventory)
	}
	if len(metadata.GetLabels()) != 0 || len(assignment.GetGroupIds()) != 0 {
		permissions = append(permissions, identity.PermissionManageAccounts)
	}
	if len(assignment.GetProfileRevisionIds()) != 0 {
		permissions = append(permissions, identity.PermissionAssignResources)
	}
	for _, permission := range permissions {
		if !identity.Authorize(principal, permission) {
			return rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
		}
		if err := RequireUnrestrictedPrincipal(principal, permission); err != nil {
			return err
		}
	}
	return nil
}

func provisioningAssignment(token devicedb.ProvisioningToken) (*adminv1.CreateProvisioningTokenRequest, error) {
	assignment := new(adminv1.CreateProvisioningTokenRequest)
	if err := proto.Unmarshal(token.Assignment, assignment); err != nil {
		return nil, ErrInternalState
	}
	return assignment, nil
}

func (s *Service) CreateProvisioningToken(ctx context.Context, req *connect.Request[adminv1.CreateProvisioningTokenRequest]) (*connect.Response[adminv1.CreateProvisioningTokenResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_provisioning_token")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, ExecutionError(err)
	}
	if err := provisioningAssignmentAuthority(authorization.Principal(), req.Msg); err != nil {
		return nil, err
	}
	if (req.Msg.GetApprovalRequired() && authorization.Principal().ServiceAccount) || (len(req.Msg.GetProfileRevisionIds()) != 0 && authorization.ApprovalRequired(identity.PermissionAssignResources) && !req.Msg.GetApprovalRequired()) {
		return nil, ApprovalError(identity.ErrApprovalRequired)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.Msg)
	if err != nil {
		return nil, MapErr(err)
	}
	digest := sha256.Sum256(encoded)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, ExecutionError(err)
	}
	q := devicedb.New(tx)
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	previous, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, "CreateProvisioningToken", requestID, digest[:])
	if err != nil {
		return nil, MapErr(err)
	}
	response := new(adminv1.CreateProvisioningTokenResponse)
	if !owned {
		response.TokenId, response.ExpiresAt, response.SecretDeliveryUnknown = previous.GrantID.String(), timestamppb.New(previous.ExpiresAt.Time), true
	} else {
		if err := s.validateProvisioningAssignment(ctx, tx, req.Msg); err != nil {
			return nil, MapErr(err)
		}
		secret, hash, err := NewGrantSecret()
		if err != nil {
			return nil, MapErr(err)
		}
		now, err := DispatchClock(ctx, q)
		if err != nil {
			return nil, MapErr(err)
		}
		id := uuid.New()
		expires := now.Add(time.Duration(req.Msg.GetLifetimeSeconds()) * time.Second)
		if err := q.InsertProvisioningToken(ctx, devicedb.InsertProvisioningTokenParams{ID: id, TokenHash: hash, CreatedBy: actor.ID, AuthorizationVersion: int64(authorization.Version()), CreatedAt: Timestamptz(now), ExpiresAt: Timestamptz(expires), MaxUses: int32(req.Msg.GetMaxUses()), ApprovalRequired: req.Msg.GetApprovalRequired(), Assignment: encoded, Reason: req.Msg.GetReason(), Name: req.Msg.GetName()}); err != nil {
			return nil, MapErr(err)
		}
		if err := InsertAudit(ctx, q, &actor.ID, auditkind.ProvisioningTokenCreate, id.String(), req.Msg.GetReason()); err != nil {
			return nil, MapErr(err)
		}
		if err := CompleteAdmin(ctx, q, actor.ID, "CreateProvisioningToken", requestID, id, uuid.Nil, expires); err != nil {
			return nil, MapErr(err)
		}
		response.TokenId, response.Secret, response.ExpiresAt = id.String(), secret, timestamppb.New(expires)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, ExecutionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

func provisioningPage(token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.Nil, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return uuid.Nil, Invalid("invalid_page_token")
	}
	id, err := uuid.FromBytes(encoded)
	if err != nil {
		return uuid.Nil, Invalid("invalid_page_token")
	}
	return id, nil
}
func provisioningCursor(id uuid.UUID) string { return base64.RawURLEncoding.EncodeToString(id[:]) }

func (s *Service) ListProvisioningTokens(ctx context.Context, req *connect.Request[adminv1.ListProvisioningTokensRequest]) (*connect.Response[adminv1.ListProvisioningTokensResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := PageLimit(req.Msg.GetPageSize())
	var rows []devicedb.ListProvisioningTokensRow
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		var err error
		rows, err = q.ListProvisioningTokens(ctx, devicedb.ListProvisioningTokensParams{AfterID: after, RowLimit: limit + 1})
		return err
	})
	if err != nil {
		return nil, MapErr(err)
	}
	response := new(adminv1.ListProvisioningTokensResponse)
	var budget ResponsePageBudget
	for _, row := range rows {
		assignment, err := provisioningAssignment(devicedb.ProvisioningToken{Assignment: row.Assignment})
		if err != nil {
			return nil, MapErr(err)
		}
		item := &adminv1.ProvisioningToken{TokenId: row.ID.String(), CreatedBy: row.CreatedBy.String(), CreatorDisplayName: row.CreatorDisplayName, CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), MaxUses: uint32(row.MaxUses), UsedCount: uint32(row.UsedCount), ApprovalRequired: row.ApprovalRequired, Reason: row.Reason, Metadata: assignment.GetMetadata(), GroupIds: assignment.GetGroupIds(), ProfileRevisionIds: assignment.GetProfileRevisionIds()}
		item.Name = row.Name
		if row.RevokedAt.Valid {
			item.RevokedAt = timestamppb.New(row.RevokedAt.Time)
		}
		fits, err := budget.Take(item)
		if err != nil {
			return nil, MapErr(err)
		}
		if len(response.Tokens) == int(limit) || !fits {
			if len(response.Tokens) == 0 {
				return nil, MapErr(ErrInternalState)
			}
			id, _ := uuid.Parse(response.Tokens[len(response.Tokens)-1].TokenId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Tokens = append(response.Tokens, item)
	}
	return NoStore(response), nil
}

func (s *Service) RevokeProvisioningToken(ctx context.Context, req *connect.Request[adminv1.RevokeProvisioningTokenRequest]) (*connect.Response[adminv1.RevokeProvisioningTokenResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_provisioning_token")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	id, _ := uuid.Parse(req.Msg.GetTokenId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	digest := MutationDigest("RevokeProvisioningToken", id.String(), req.Msg.GetReason())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, "RevokeProvisioningToken", requestID, digest)
		if err != nil || !owned {
			return err
		}
		token, err := q.LockProvisioningToken(ctx, id)
		if err != nil {
			return NotFoundIfMissing(err)
		}
		if !token.RevokedAt.Valid {
			if err := q.RevokeProvisioningToken(ctx, devicedb.RevokeProvisioningTokenParams{ID: id, RevokedAt: Timestamptz(s.Now()), RevokedBy: &actor.ID, RevokeReason: req.Msg.GetReason()}); err != nil {
				return err
			}
			if err := q.RevokePendingProvisioningEnrollments(ctx, id); err != nil {
				return err
			}
			if err := InsertAudit(ctx, q, &actor.ID, auditkind.ProvisioningTokenRevoke, id.String(), req.Msg.GetReason()); err != nil {
				return err
			}
		}
		return CompleteAdmin(ctx, q, actor.ID, "RevokeProvisioningToken", requestID, id, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&adminv1.RevokeProvisioningTokenResponse{}), nil
}

func (s *Service) provisioningAuthorization(ctx context.Context, token devicedb.ProvisioningToken) (*identity.Authorization, *adminv1.CreateProvisioningTokenRequest, error) {
	if s.Identity == nil {
		return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, token.CreatedBy, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, nil, ExecutionError(err)
	}
	if int64(authorization.Version()) != token.AuthorizationVersion {
		return nil, nil, ExecutionError(identity.ErrAuthorizationChanged)
	}
	assignment, err := provisioningAssignment(token)
	if err != nil {
		return nil, nil, err
	}
	if err := provisioningAssignmentAuthority(authorization.Principal(), assignment); err != nil {
		return nil, nil, err
	}
	if len(assignment.GetProfileRevisionIds()) != 0 && authorization.ApprovalRequired(identity.PermissionAssignResources) && !token.ApprovalRequired {
		return nil, nil, ApprovalError(identity.ErrApprovalRequired)
	}
	return authorization, assignment, nil
}

func (s *Service) validateProvisioningAssignment(ctx context.Context, tx pgx.Tx, assignment *adminv1.CreateProvisioningTokenRequest) error {
	q := devicedb.New(tx)
	if err := q.LockInventoryMetadata(ctx); err != nil {
		return err
	}
	metadata := assignment.GetMetadata()
	if err := ValidateAttributeValues(ctx, q, metadata.GetAttributes()); err != nil {
		return err
	}
	if metadata.GetOwnerPrincipalId() != "" {
		id, _ := uuid.Parse(metadata.GetOwnerPrincipalId())
		found, err := q.InventoryOwnerExists(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return Invalid("owner_principal_unknown")
		}
	}
	for _, value := range assignment.GetGroupIds() {
		id, _ := uuid.Parse(value)
		found, err := q.ProvisioningGroupExists(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return Invalid("group_unknown")
		}
	}
	for _, value := range assignment.GetProfileRevisionIds() {
		id, _ := uuid.Parse(value)
		profile, err := q.ProvisioningProfileIdentity(ctx, id)
		if err != nil {
			return NotFoundIfMissing(err)
		}
		if s.Profiles == nil {
			return Invalid("profiles_unavailable")
		}
		if _, err := s.Profiles.GetInTransaction(ctx, tx, profile, id); err != nil {
			return ProfileError(err)
		}
	}
	return nil
}

func ValidateAttributeValues(ctx context.Context, q *devicedb.Queries, attributes map[string]*adminv1.AttributeValue) error {
	for key, value := range attributes {
		encoded, err := q.GetAttributeDefinition(ctx, key)
		if err == pgx.ErrNoRows {
			return Invalid("attribute_key_unknown")
		}
		if err != nil {
			return err
		}
		definition := new(adminv1.AttributeDefinition)
		if err := proto.Unmarshal(encoded, definition); err != nil {
			return ErrInternalState
		}
		if !targeting.AttributeValueMatches(definition, value) {
			return Invalid("attribute_type_mismatch")
		}
	}
	return nil
}
