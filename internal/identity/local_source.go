package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/identity/identitydb"
)

type localSource struct{ pool *pgxpool.Pool }

var _ DirectorySource = (*localSource)(nil)

func (l *localSource) Observe(ctx context.Context, subject uuid.UUID) (directoryObservation, error) {
	account, err := identitydb.New(l.pool).GetLocalAccount(ctx, subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return directoryObservation{}, nil
	}
	if err != nil {
		return directoryObservation{}, errStore
	}
	return directoryObservation{Found: true, UserID: account.ID, DisplayName: account.Username, Enabled: account.Enabled, Direct: true}, nil
}

func deploymentLocalIssuer(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	id, err := identitydb.New(pool).GetDeploymentID(ctx)
	if err != nil {
		return "", errStore
	}
	return "urn:lindm:local:" + id.String(), nil
}

func (s *Service) readLocalSnapshot(ctx context.Context, q *identitydb.Queries, row identitydb.Principal) (directorySnapshot, error) {
	account, err := q.GetLocalAccount(ctx, row.ID)
	if err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	now, err := s.authorizationTime(ctx, q)
	if err != nil {
		return directorySnapshot{}, err
	}
	enabled := account.Enabled && (s.localPrimary || (account.BreakGlass && account.Role == RoleOwner && s.breakGlass != nil))
	return directorySnapshot{PrincipalID: row.ID, Issuer: row.Issuer, Subject: row.Subject,
		DisplayName: account.Username, Enabled: enabled, Observed: true, ObservedAt: now,
		Qualified: row.Subject == row.ID.String(), AuthorizationVersion: row.AuthorizationVersion,
		AuthorizationRole: account.Role, Local: true, BreakGlass: !s.localPrimary}, nil
}

func (s *Service) accessIssuer(snapshot directorySnapshot) string {
	if snapshot.Local {
		return s.localIssuer
	}
	return s.issuer
}

func (s *Service) snapshotPrincipal(snapshot directorySnapshot, role string) Principal {
	p := Principal{ID: snapshot.PrincipalID, Issuer: snapshot.Issuer, Subject: snapshot.Subject,
		DisplayName: snapshot.DisplayName, Role: role, BreakGlass: snapshot.BreakGlass}
	if p.BreakGlass {
		p.AllowedPermissions = s.breakGlass.GetAllowedPermissions()
	}
	return p
}

func (s *Service) observePrincipal(ctx context.Context, issuer string, subject uuid.UUID) (directoryObservation, error) {
	if issuer != s.localIssuer {
		return s.observeDirectory(ctx, subject)
	}
	acquired, err := s.databaseTime(ctx)
	if err != nil {
		return directoryObservation{}, err
	}
	observation, err := (&localSource{pool: s.pool}).Observe(ctx, subject)
	observation.AcquiredAt = acquired
	return observation, err
}
