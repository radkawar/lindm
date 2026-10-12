package identity

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

// Every process restart ends emergency sessions, so changed local policy cannot
// inherit authority established under a previous configuration.
func (s *Service) terminateEmergencySessions(ctx context.Context) error {
	ids, err := identitydb.New(s.pool).ListBreakGlassPrincipals(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	for _, id := range ids {
		if err = s.withTx(ctx, func(q *identitydb.Queries) error {
			principal, err := q.GetPrincipalForUpdate(ctx, id)
			if err != nil {
				return s.dbErr(err)
			}
			count, err := q.RevokeBreakGlassSessions(ctx, id)
			if err != nil {
				return s.dbErr(err)
			}
			if count == 0 {
				return nil
			}
			if err = s.bumpLocalAuthorization(ctx, q, id, principal.AuthorizationRole); err != nil {
				return s.dbErr(err)
			}
			return s.insertSystemAudit(ctx, q, &id, auditkind.IdentityBreakGlassTerminated, principalResource(id), "authentication service restarted; emergency policy re-established")
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) emergencyAudit(ctx context.Context, id uuid.UUID, action auditkind.Kind, reason, systemContext string) error {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	// No actor FK acquisition here: worker denials may hold the principal lock in
	// an outer transaction which must remain free to roll back. Immutable actor ID
	// remains in resource_id, and the audit independently commits the denial.
	if systemContext != "" {
		return s.insertSystemAudit(auditCtx, identitydb.New(s.pool), nil, action, principalResource(id), systemContext)
	}
	return s.insertAudit(auditCtx, identitydb.New(s.pool), nil, action, principalResource(id), reason)
}

type emergencyResponse struct {
	http.ResponseWriter
	status int
}

func (w *emergencyResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *emergencyResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *emergencyResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}
