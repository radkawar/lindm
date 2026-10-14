// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

const mcpTokenDomain = "lindm.mcp-token.v1"

type mcpAccessKey struct{}

type mcpAccess struct {
	service   *Service
	actor     uuid.UUID
	hash      []byte // Empty only for a RequireSession-authenticated browser.
	proposals bool
	clientTag string
}

// MCPProposalsAllowed is a capability ceiling, never a permission grant. Only
// RequireMCP attaches this private proof; ordinary principal contexts cannot.
func MCPProposalsAllowed(ctx context.Context) bool {
	proof, ok := ctx.Value(mcpAccessKey{}).(mcpAccess)
	principal, present := PrincipalFromContext(ctx)
	return ok && present && proof.service != nil && proof.actor == principal.ID && proof.proposals
}

// MCPClientTag returns the bounded issued token label or the browser marker.
func MCPClientTag(ctx context.Context) string {
	proof, ok := ctx.Value(mcpAccessKey{}).(mcpAccess)
	principal, present := PrincipalFromContext(ctx)
	if !ok || !present || proof.service == nil || proof.actor != principal.ID {
		return ""
	}
	return proof.clientTag
}

// RequireMCP accepts browser sessions or dedicated MCP credentials only at /mcp.
// It never turns a token into a browser/CLI session or step-up proof. Domain
// handlers still perform their normal fresh permission and scope checks.
func (s *Service) RequireMCP(next http.Handler) http.Handler {
	admit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeStatus(w, http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		if _, token := ctx.Value(mcpAccessKey{}).(mcpAccess); !token {
			ctx = context.WithValue(ctx, mcpAccessKey{}, mcpAccess{service: s, actor: principal.ID, proposals: true, clientTag: "browser"})
		}
		enabled, err := identitydb.New(s.pool).ReadMCPEnabled(ctx)
		if err != nil {
			writeStatus(w, statusFor(s.dbErr(err)))
			return
		}
		if !enabled {
			if err := s.AuditMCPResult(ctx, "http", "", "denied"); err != nil {
				writeStatus(w, http.StatusServiceUnavailable)
				return
			}
			writeStatus(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
	browser := s.RequireSession(admit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prepare(w)
		if r.URL.Path != "/mcp" {
			writeStatus(w, http.StatusUnauthorized)
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) > 1 || (len(origins) == 1 && !originMatches(s.publicOrigin, origins[0])) {
			writeStatus(w, http.StatusForbidden)
			return
		}
		if len(r.Header.Values("Authorization")) == 0 {
			browser.ServeHTTP(w, r)
			return
		}
		token, _, ok := sessionCredential(r)
		if !ok {
			writeStatus(w, http.StatusUnauthorized)
			return
		}
		ctx, err := s.authenticateMCPToken(r.Context(), token)
		if err != nil {
			writeStatus(w, accountStatus(err))
			return
		}
		admit.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Service) authenticateMCPToken(ctx context.Context, token string) (context.Context, error) {
	hash := domainHash(mcpTokenDomain, token)
	stored, err := identitydb.New(s.pool).GetMCPTokenByHash(ctx, hash)
	if err != nil {
		return nil, s.dbErr(err)
	}
	now, err := s.databaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if !liveMCPToken(stored, stored.PrincipalID, now) {
		return nil, errUnauthenticated
	}
	observeCtx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	observation, _, err := s.observeActor(observeCtx, stored.PrincipalID)
	if err != nil {
		return nil, err
	}
	var principal Principal
	denied := false
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		snapshot, err := s.writeObservation(ctx, q, stored.PrincipalID, observation)
		if errors.Is(err, errStaleObservation) {
			row, loadErr := q.GetPrincipalForUpdate(ctx, stored.PrincipalID)
			if loadErr != nil {
				return s.dbErr(loadErr)
			}
			snapshot, err = s.readSnapshot(ctx, q, row)
		}
		if err != nil {
			return err
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		decision := decideAccess(now, s.accessIssuer(snapshot), snapshot.policy, snapshot)
		principal = s.snapshotPrincipal(snapshot, decision.Role)
		if decision.Kind != accessOK || principal.BreakGlass {
			denied = true
			return nil // Keep authoritative revocation and its audit committed.
		}
		proof := mcpAccess{service: s, actor: principal.ID, hash: hash, proposals: stored.ProposalsAllowed, clientTag: stored.Label}
		if err := s.checkMCPToken(ctx, q, proof); err != nil {
			if errors.Is(err, ErrAuthorizationDenied) || errors.Is(err, ErrAuthorizationExpired) {
				denied = true
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, errUnauthenticated
	}
	return context.WithValue(WithPrincipal(ctx, principal), mcpAccessKey{}, mcpAccess{
		service: s, actor: principal.ID, hash: hash, proposals: stored.ProposalsAllowed, clientTag: stored.Label,
	}), nil
}

func liveMCPToken(token identitydb.McpToken, actor uuid.UUID, now time.Time) bool {
	created, createdOK := timeFrom(token.CreatedAt)
	expires, expiresOK := timeFrom(token.ExpiresAt)
	return token.PrincipalID == actor && !token.RevokedAt.Valid && createdOK && expiresOK && !now.Before(created) && now.Before(expires)
}

// checkMCPAccess runs only under the normal policy/principal authorization locks.
// Settings locks and credential row locks prevent disable/revoke from racing a
// downstream transaction commit. Non-MCP worker contexts remain unchanged.
func (s *Service) checkMCPAccess(ctx context.Context, q *identitydb.Queries, actor uuid.UUID) error {
	proof, ok := ctx.Value(mcpAccessKey{}).(mcpAccess)
	if !ok {
		return nil
	}
	if proof.service != s || proof.actor != actor {
		return ErrAuthorizationDenied
	}
	enabled, err := q.LockMCPEnabled(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if !enabled {
		return ErrAuthorizationDenied
	}
	if len(proof.hash) == 0 {
		return s.checkAuthenticatedSession(ctx, q, actor, true)
	}
	return s.checkMCPToken(ctx, q, proof)
}

func (s *Service) checkMCPToken(ctx context.Context, q *identitydb.Queries, proof mcpAccess) error {
	row, err := q.GetPrincipalByID(ctx, proof.actor)
	if err != nil {
		return s.authorizationStoreError(err)
	}
	snapshot, err := s.readSnapshot(ctx, q, row)
	if err != nil {
		return err
	}
	now, err := s.authorizationTime(ctx, q)
	if err != nil {
		return err
	}
	if decideAccess(now, s.accessIssuer(snapshot), snapshot.policy, snapshot).Kind != accessOK || snapshot.BreakGlass {
		return ErrAuthorizationDenied
	}
	token, err := q.LockMCPTokenByHash(ctx, proof.hash)
	if err != nil {
		return s.authorizationStoreError(err)
	}
	if !liveMCPToken(token, proof.actor, now) || token.ProposalsAllowed != proof.proposals || token.Label != proof.clientTag {
		return ErrAuthorizationDenied
	}
	if cutoff, valid := timeFrom(row.LifecycleNotBefore); valid && !token.CreatedAt.Time.After(cutoff) {
		return ErrAuthorizationDenied
	}
	return nil
}

// AuditMCP durably records an attempt before transport parsing or tool dispatch.
// A write error must prevent the caller from invoking the domain API.
func (s *Service) AuditMCP(ctx context.Context, method, tool string) error {
	return s.auditMCP(ctx, method, tool, "attempt")
}

// AuditMCPResult records the closed-vocabulary success, denied or failed outcome.
func (s *Service) AuditMCPResult(ctx context.Context, method, tool, outcome string) error {
	if outcome == "attempt" {
		return ErrAuthorizationDenied
	}
	return s.auditMCP(ctx, method, tool, outcome)
}

func (s *Service) auditMCP(ctx context.Context, method, tool, outcome string) error {
	proof, ok := ctx.Value(mcpAccessKey{}).(mcpAccess)
	principal, present := PrincipalFromContext(ctx)
	if s == nil || !ok || !present || proof.service != s || proof.actor != principal.ID {
		return ErrAuthorizationDenied
	}
	record := &authv1.MCPAuditRecord{Method: method, Tool: tool, ClientTag: proof.clientTag, Outcome: outcome}
	if err := s.rules.Validate(record); err != nil {
		return ErrAuthorizationDenied
	}
	details, err := json.Marshal(map[string]string{"method": method, "tool": tool, "client_tag": proof.clientTag, "outcome": outcome})
	if err != nil {
		return err
	}
	// Result audit survives request cancellation, but never waits indefinitely.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.dbErr(identitydb.New(s.pool).InsertAuditEvent(auditCtx, identitydb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &principal.ID, Action: auditkind.MCPAttempt.String(), ResourceID: "mcp", Details: details,
	}))
}

// revokePrincipalCredentials follows the existing principal-before-credential
// lock order and atomically terminates both session and dedicated token access.
func (s *Service) revokePrincipalCredentials(ctx context.Context, q *identitydb.Queries, actor uuid.UUID) (int64, error) {
	count, err := q.RevokePrincipalSessions(ctx, actor)
	if err != nil {
		return 0, err
	}
	if err := q.RevokePrincipalMCPTokens(ctx, actor); err != nil {
		return 0, err
	}
	return count, nil
}
