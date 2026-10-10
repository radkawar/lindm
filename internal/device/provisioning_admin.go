package device

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
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
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
			return rpcError(connect.CodePermissionDenied, "permission_denied")
		}
		if err := requireUnrestrictedPrincipal(principal, permission); err != nil {
			return err
		}
	}
	return nil
}

func provisioningAssignment(token devicedb.ProvisioningToken) (*adminv1.CreateProvisioningTokenRequest, error) {
	assignment := new(adminv1.CreateProvisioningTokenRequest)
	if err := proto.Unmarshal(token.Assignment, assignment); err != nil {
		return nil, errInternalState
	}
	return assignment, nil
}

func (s *Service) CreateProvisioningToken(ctx context.Context, req *connect.Request[adminv1.CreateProvisioningTokenRequest]) (*connect.Response[adminv1.CreateProvisioningTokenResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_provisioning_token")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if s.identity == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, executionError(err)
	}
	if err := provisioningAssignmentAuthority(authorization.Principal(), req.Msg); err != nil {
		return nil, err
	}
	if (req.Msg.GetApprovalRequired() && authorization.Principal().ServiceAccount) || (len(req.Msg.GetProfileRevisionIds()) != 0 && s.identity.ApprovalRequired(identity.PermissionAssignResources) && !req.Msg.GetApprovalRequired()) {
		return nil, approvalError(identity.ErrApprovalRequired)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	digest := sha256.Sum256(encoded)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	previous, owned, err := s.beginAdminRequest(ctx, q, actor.ID, "CreateProvisioningToken", requestID, digest[:])
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.CreateProvisioningTokenResponse)
	if !owned {
		response.TokenId, response.ExpiresAt, response.SecretDeliveryUnknown = previous.GrantID.String(), timestamppb.New(previous.ExpiresAt.Time), true
	} else {
		if err := s.validateProvisioningAssignment(ctx, tx, req.Msg); err != nil {
			return nil, mapErr(err)
		}
		secret, hash, err := newGrantSecret()
		if err != nil {
			return nil, mapErr(err)
		}
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, mapErr(err)
		}
		id := uuid.New()
		expires := now.Add(time.Duration(req.Msg.GetLifetimeSeconds()) * time.Second)
		if err := q.InsertProvisioningToken(ctx, devicedb.InsertProvisioningTokenParams{ID: id, TokenHash: hash, CreatedBy: actor.ID, AuthorizationVersion: int64(authorization.Version()), CreatedAt: timestamptz(now), ExpiresAt: timestamptz(expires), MaxUses: int32(req.Msg.GetMaxUses()), ApprovalRequired: req.Msg.GetApprovalRequired(), Assignment: encoded, Reason: req.Msg.GetReason()}); err != nil {
			return nil, mapErr(err)
		}
		if err := insertAudit(ctx, q, &actor.ID, "provisioning_token.create", id.String(), req.Msg.GetReason()); err != nil {
			return nil, mapErr(err)
		}
		if err := completeAdmin(ctx, q, actor.ID, "CreateProvisioningToken", requestID, id, uuid.Nil, expires); err != nil {
			return nil, mapErr(err)
		}
		response.TokenId, response.Secret, response.ExpiresAt = id.String(), secret, timestamppb.New(expires)
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

func provisioningPage(token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.Nil, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return uuid.Nil, invalid("invalid_page_token")
	}
	id, err := uuid.FromBytes(encoded)
	if err != nil {
		return uuid.Nil, invalid("invalid_page_token")
	}
	return id, nil
}
func provisioningCursor(id uuid.UUID) string { return base64.RawURLEncoding.EncodeToString(id[:]) }

func (s *Service) ListProvisioningTokens(ctx context.Context, req *connect.Request[adminv1.ListProvisioningTokensRequest]) (*connect.Response[adminv1.ListProvisioningTokensResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_argument")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.GetPageSize())
	rows, err := devicedb.New(s.pool).ListProvisioningTokens(ctx, devicedb.ListProvisioningTokensParams{AfterID: after, RowLimit: limit + 1})
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.ListProvisioningTokensResponse)
	var budget responsePageBudget
	for _, row := range rows {
		assignment, err := provisioningAssignment(row)
		if err != nil {
			return nil, mapErr(err)
		}
		item := &adminv1.ProvisioningToken{TokenId: row.ID.String(), CreatedBy: row.CreatedBy.String(), CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), MaxUses: uint32(row.MaxUses), UsedCount: uint32(row.UsedCount), ApprovalRequired: row.ApprovalRequired, Reason: row.Reason, Metadata: assignment.GetMetadata(), GroupIds: assignment.GetGroupIds(), ProfileRevisionIds: assignment.GetProfileRevisionIds()}
		if row.RevokedAt.Valid {
			item.RevokedAt = timestamppb.New(row.RevokedAt.Time)
		}
		fits, err := budget.take(item)
		if err != nil {
			return nil, mapErr(err)
		}
		if len(response.Tokens) == int(limit) || !fits {
			if len(response.Tokens) == 0 {
				return nil, mapErr(errInternalState)
			}
			id, _ := uuid.Parse(response.Tokens[len(response.Tokens)-1].TokenId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Tokens = append(response.Tokens, item)
	}
	return noStore(response), nil
}

func (s *Service) RevokeProvisioningToken(ctx context.Context, req *connect.Request[adminv1.RevokeProvisioningTokenRequest]) (*connect.Response[adminv1.RevokeProvisioningTokenResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_provisioning_token")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	id, _ := uuid.Parse(req.Msg.GetTokenId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	digest := mutationDigest("RevokeProvisioningToken", id.String(), req.Msg.GetReason())
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, "RevokeProvisioningToken", requestID, digest)
		if err != nil || !owned {
			return err
		}
		token, err := q.LockProvisioningToken(ctx, id)
		if err != nil {
			return notFoundIfMissing(err)
		}
		if !token.RevokedAt.Valid {
			if err := q.RevokeProvisioningToken(ctx, devicedb.RevokeProvisioningTokenParams{ID: id, RevokedAt: timestamptz(s.now()), RevokedBy: &actor.ID, RevokeReason: req.Msg.GetReason()}); err != nil {
				return err
			}
			if err := q.RevokePendingProvisioningEnrollments(ctx, id); err != nil {
				return err
			}
			if err := insertAudit(ctx, q, &actor.ID, "provisioning_token.revoke", id.String(), req.Msg.GetReason()); err != nil {
				return err
			}
		}
		return completeAdmin(ctx, q, actor.ID, "RevokeProvisioningToken", requestID, id, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.RevokeProvisioningTokenResponse{}), nil
}

func (s *Service) provisioningAuthorization(ctx context.Context, token devicedb.ProvisioningToken) (*identity.Authorization, *adminv1.CreateProvisioningTokenRequest, error) {
	if s.identity == nil {
		return nil, nil, rpcError(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, token.CreatedBy, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, nil, executionError(err)
	}
	if int64(authorization.Version()) != token.AuthorizationVersion {
		return nil, nil, executionError(identity.ErrAuthorizationChanged)
	}
	assignment, err := provisioningAssignment(token)
	if err != nil {
		return nil, nil, err
	}
	if err := provisioningAssignmentAuthority(authorization.Principal(), assignment); err != nil {
		return nil, nil, err
	}
	if len(assignment.GetProfileRevisionIds()) != 0 && s.identity.ApprovalRequired(identity.PermissionAssignResources) && !token.ApprovalRequired {
		return nil, nil, approvalError(identity.ErrApprovalRequired)
	}
	return authorization, assignment, nil
}

func (s *Service) validateProvisioningAssignment(ctx context.Context, tx pgx.Tx, assignment *adminv1.CreateProvisioningTokenRequest) error {
	q := devicedb.New(tx)
	if err := q.LockInventoryMetadata(ctx); err != nil {
		return err
	}
	metadata := assignment.GetMetadata()
	if err := validateAttributeValues(ctx, q, metadata.GetAttributes()); err != nil {
		return err
	}
	if metadata.GetOwnerPrincipalId() != "" {
		id, _ := uuid.Parse(metadata.GetOwnerPrincipalId())
		found, err := q.InventoryOwnerExists(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return invalid("owner_principal_unknown")
		}
	}
	for _, value := range assignment.GetGroupIds() {
		id, _ := uuid.Parse(value)
		found, err := q.ProvisioningGroupExists(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return invalid("group_unknown")
		}
	}
	for _, value := range assignment.GetProfileRevisionIds() {
		id, _ := uuid.Parse(value)
		profile, err := q.ProvisioningProfileIdentity(ctx, id)
		if err != nil {
			return notFoundIfMissing(err)
		}
		if s.profiles == nil {
			return invalid("profiles_unavailable")
		}
		if _, err := s.profiles.GetInTransaction(ctx, tx, profile, id); err != nil {
			return profileError(err)
		}
	}
	return nil
}
