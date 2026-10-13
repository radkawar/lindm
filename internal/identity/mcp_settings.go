package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

func (s *Service) registerMCPHTTP(mux *http.ServeMux) {
	mux.Handle("GET /auth/mcp/settings", s.RequireSession(http.HandlerFunc(s.handleMCPSettings)))
	mux.Handle("POST /auth/mcp/settings", s.RequireSession(http.HandlerFunc(s.handleUpdateMCPSettings)))
	mux.Handle("POST /auth/mcp/tokens", s.RequireSession(http.HandlerFunc(s.handleIssueMCPToken)))
	mux.Handle("POST /auth/mcp/tokens/revoke", s.RequireSession(http.HandlerFunc(s.handleRevokeMCPToken)))
}

// mcpSettingsTransaction keeps settings and own-token operations behind the same
// fresh unrestricted permission and live-browser fences, including read access.
func (s *Service) mcpSettingsTransaction(ctx context.Context, fn func(*identitydb.Queries, Principal) error) error {
	actor, ok := PrincipalFromContext(ctx)
	if !ok {
		return ErrAuthorizationDenied
	}
	authorization, err := s.AuthorizeFresh(ctx, actor.ID, PermissionManageIntegrations)
	if err != nil {
		return err
	}
	fresh := authorization.Principal()
	if unrestricted, _ := DeviceScopes(fresh, PermissionManageIntegrations); !unrestricted {
		return ErrAuthorizationDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockAuthorization(ctx, tx, authorization, PermissionManageIntegrations); err != nil {
		return err
	}
	q := identitydb.New(tx)
	if err := s.checkAuthenticatedSession(ctx, q, actor.ID, true); err != nil {
		return err
	}
	if err := fn(q, fresh); err != nil {
		return err
	}
	return s.dbErr(tx.Commit(ctx))
}

func (s *Service) readMCPSettings(ctx context.Context, q *identitydb.Queries, actor uuid.UUID) (*authv1.MCPSettings, error) {
	enabled, err := q.ReadMCPEnabled(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	rows, err := q.ListOwnMCPTokens(ctx, actor)
	if err != nil {
		return nil, s.dbErr(err)
	}
	tokens := make([]*authv1.MCPToken, len(rows))
	for i, row := range rows {
		tokens[i] = mcpTokenProto(identitydb.McpToken{ID: row.ID, Label: row.Label, ProposalsAllowed: row.ProposalsAllowed,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt})
	}
	return &authv1.MCPSettings{Enabled: enabled, Tokens: tokens}, nil
}

func mcpTokenProto(row identitydb.McpToken) *authv1.MCPToken {
	return &authv1.MCPToken{Id: row.ID.String(), Label: row.Label, ProposalsAllowed: row.ProposalsAllowed,
		CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time)}
}

func (s *Service) handleMCPSettings(w http.ResponseWriter, r *http.Request) {
	var result *authv1.MCPSettings
	err := s.mcpSettingsTransaction(r.Context(), func(q *identitydb.Queries, actor Principal) error {
		var err error
		result, err = s.readMCPSettings(r.Context(), q, actor.ID)
		return err
	})
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, result)
}

func (s *Service) handleUpdateMCPSettings(w http.ResponseWriter, r *http.Request) {
	request := &authv1.UpdateMCPSettingsRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	var result *authv1.MCPSettings
	err := s.mcpSettingsTransaction(r.Context(), func(q *identitydb.Queries, actor Principal) error {
		if err := q.SetMCPEnabled(r.Context(), request.GetEnabled()); err != nil {
			return s.dbErr(err)
		}
		if err := s.insertMCPManagementAudit(r.Context(), q, actor.ID, auditkind.IdentityMCPSettingsChanged, "mcp", map[string]string{"enabled": strconv.FormatBool(request.GetEnabled())}); err != nil {
			return err
		}
		var err error
		result, err = s.readMCPSettings(r.Context(), q, actor.ID)
		return err
	})
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, result)
}

func (s *Service) issueMCPToken(ctx context.Context, request *authv1.IssueMCPTokenRequest) (*authv1.IssueMCPTokenResponse, error) {
	if err := s.rules.Validate(request); err != nil {
		return nil, ErrApprovalInvalid
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	var result *authv1.IssueMCPTokenResponse
	err = s.mcpSettingsTransaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		if actor.BreakGlass {
			return ErrAuthorizationDenied
		}
		count, err := q.CountOwnMCPTokens(ctx, actor.ID)
		if err != nil {
			return s.dbErr(err)
		}
		if count >= 100 {
			return ErrAuthorizationDenied
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		row, err := q.InsertMCPToken(ctx, identitydb.InsertMCPTokenParams{ID: uuid.New(), PrincipalID: actor.ID,
			TokenHash: domainHash(mcpTokenDomain, token), Label: request.GetLabel(), ProposalsAllowed: request.GetProposalsAllowed(),
			CreatedAt: pgStamp(now, true), ExpiresAt: pgStamp(now.Add(time.Duration(request.GetLifetimeSeconds())*time.Second), true)})
		if err != nil {
			return s.dbErr(err)
		}
		if err := s.insertMCPManagementAudit(ctx, q, actor.ID, auditkind.IdentityMCPTokenIssued, "mcp_token/"+row.ID.String(),
			map[string]string{"label": row.Label, "proposals_allowed": strconv.FormatBool(row.ProposalsAllowed), "expires_at": row.ExpiresAt.Time.UTC().Format(time.RFC3339Nano)}); err != nil {
			return err
		}
		result = &authv1.IssueMCPTokenResponse{Token: mcpTokenProto(row), BearerToken: token}
		return nil
	})
	return result, err
}

func (s *Service) handleIssueMCPToken(w http.ResponseWriter, r *http.Request) {
	request := &authv1.IssueMCPTokenRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	result, err := s.issueMCPToken(r.Context(), request)
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, result)
}

func (s *Service) revokeMCPToken(ctx context.Context, request *authv1.RevokeMCPTokenRequest) error {
	if err := s.rules.Validate(request); err != nil {
		return ErrApprovalInvalid
	}
	id, err := uuid.Parse(request.GetTokenId())
	if err != nil {
		return ErrApprovalInvalid
	}
	return s.mcpSettingsTransaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		row, err := q.RevokeOwnMCPToken(ctx, identitydb.RevokeOwnMCPTokenParams{ID: id, PrincipalID: actor.ID})
		if err != nil {
			if errors.Is(s.dbErr(err), errNotFound) {
				return ErrAuthorizationDenied
			}
			return s.dbErr(err)
		}
		return s.insertMCPManagementAudit(ctx, q, actor.ID, auditkind.IdentityMCPTokenRevoked, "mcp_token/"+row.ID.String(), map[string]string{"label": row.Label})
	})
}

func (s *Service) handleRevokeMCPToken(w http.ResponseWriter, r *http.Request) {
	request := &authv1.RevokeMCPTokenRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	if err := s.revokeMCPToken(r.Context(), request); err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, &authv1.RevokeMCPTokenResponse{})
}

func (s *Service) insertMCPManagementAudit(ctx context.Context, q *identitydb.Queries, actor uuid.UUID, action auditkind.Kind, resource string, values map[string]string) error {
	details, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor, Action: action.String(), ResourceID: resource, Details: details}))
}
