package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"lindm/internal/identity/identitydb"
)

type sessionRecord struct {
	PrincipalID    uuid.UUID
	Idle           time.Time
	Absolute       time.Time
	Revoked        bool
	BreakGlass     bool
	IncidentReason string
}

type authWrite struct {
	display          string
	enabled          bool
	deactivated      bool
	source           string
	deactivatedAt    time.Time
	observed         bool
	observedAt       time.Time
	connector        string
	upstreamProvider string
	upstreamSubject  string
	brokerIssuer     string
	brokerSubject    string
	groups           []string
	revoke           bool
	auditAction      string
	auditReason      string
	conflict         bool
}

func (s *Service) withTx(ctx context.Context, fn func(*identitydb.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(identitydb.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return s.dbErr(err)
	}
	return nil
}

func (s *Service) dbErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFound
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		slog.Error("identity database error", "code", pgErr.Code, "constraint", pgErr.ConstraintName)
		if pgErr.Code == "23505" {
			return errUnique
		}
		return errStore
	}
	slog.Error("identity database error")
	return errStore
}

func (s *Service) getSession(ctx context.Context, hash []byte) (sessionRecord, error) {
	row, err := identitydb.New(s.pool).GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return sessionRecord{}, s.dbErr(err)
	}
	idle, idleOK := timeFrom(row.IdleExpiresAt)
	absolute, absoluteOK := timeFrom(row.AbsoluteExpiresAt)
	if !idleOK || !absoluteOK {
		return sessionRecord{}, errUnauthenticated
	}
	_, revoked := timeFrom(row.RevokedAt)
	return sessionRecord{PrincipalID: row.PrincipalID, Idle: idle, Absolute: absolute, Revoked: revoked, BreakGlass: row.BreakGlass, IncidentReason: row.IncidentReason}, nil
}

func (s *Service) touch(ctx context.Context, cookie string) error {
	_, err := identitydb.New(s.pool).TouchSession(ctx, sessionHash(cookie))
	return s.dbErr(err)
}

func (s *Service) loadSnapshot(ctx context.Context, id uuid.UUID) (directorySnapshot, error) {
	q := identitydb.New(s.pool)
	row, err := q.GetPrincipalByID(ctx, id)
	if err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	return s.readSnapshot(ctx, q, row)
}

func (s *Service) readSnapshot(ctx context.Context, q *identitydb.Queries, row identitydb.Principal) (directorySnapshot, error) {
	if row.Issuer == s.localIssuer {
		return s.readLocalSnapshot(ctx, q, row)
	}
	lin, err := q.GetLineageByPrincipalID(ctx, row.ID)
	if err != nil {
		mapped := s.dbErr(err)
		if !errors.Is(mapped, errNotFound) {
			return directorySnapshot{}, mapped
		}
		lin = identitydb.PrincipalLineage{}
	}
	groups, err := q.ListPrincipalGroupPaths(ctx, row.ID)
	if err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	return s.snapshotFrom(row, lin, groups), nil
}

func (s *Service) writeObservation(ctx context.Context, q *identitydb.Queries, principalID uuid.UUID, obs directoryObservation) (directorySnapshot, error) {
	row, err := q.GetPrincipalForUpdate(ctx, principalID)
	if err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	if row.Issuer == s.localIssuer {
		return s.readLocalSnapshot(ctx, q, row)
	}
	existing, err := q.GetLineageForUpdate(ctx, principalID)
	missing := false
	if err != nil {
		mapped := s.dbErr(err)
		if !errors.Is(mapped, errNotFound) {
			return directorySnapshot{}, mapped
		}
		missing = true
	}
	if !observationNewer(obs.AcquiredAt, row.DirectoryObservedAt) {
		return directorySnapshot{}, errStaleObservation
	}
	prevAt, prevDeactivated := timeFrom(row.DeactivatedAt)
	display := row.DisplayName
	if obs.Found && obs.DisplayName != "" {
		display = obs.DisplayName
	}
	w := authWrite{
		display:       display,
		source:        row.DeactivationSource,
		deactivated:   prevDeactivated,
		deactivatedAt: prevAt,
	}
	switch {
	case !obs.Found:
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.source, w.deactivatedAt = s.tombstone(row.DeactivationSource, prevAt, prevDeactivated, w.observedAt)
		w.deactivated = true
		w.revoke = true
		w.auditAction = auditDisabled
		w.auditReason = reasonAbsent
	case !obs.Direct || obs.UserID.String() != row.Subject:
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.revoke = true
		w.auditAction = auditLineageDenied
		w.auditReason = reasonUnqualified
		if row.DeactivationSource == deactivationSCIM {
			w.deactivated = true
		}
	case !obs.Enabled:
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.source, w.deactivatedAt = s.tombstone(row.DeactivationSource, prevAt, prevDeactivated, w.observedAt)
		w.deactivated = true
		w.revoke = true
		s.copyLineage(&w, existing, missing, row)
		if !prevDeactivated {
			w.auditAction = auditDisabled
			w.auditReason = reasonDisabled
		}
	default:
		if row.Issuer != s.issuer || row.Subject != obs.UserID.String() || (!missing && s.lineageConflict(existing, s.issuer, obs.UserID.String())) {
			w.conflict = true
			w.enabled = false
			w.observed = true
			w.observedAt = obs.AcquiredAt
			w.revoke = true
			w.auditAction = auditLineageDenied
			w.auditReason = reasonConflict
			break
		}
		w.connector = s.connector()
		w.upstreamProvider = row.Issuer
		w.upstreamSubject = row.Subject
		w.observed = true
		w.observedAt = obs.AcquiredAt
		if row.DeactivationSource == deactivationSCIM {
			w.enabled = true
			w.deactivated = true
			w.source = deactivationSCIM
			w.revoke = true
			w.auditAction = auditLineageDenied
			w.auditReason = reasonTombstone
			break
		}
		if prevDeactivated {
			w.auditAction = auditReactivated
			w.auditReason = reasonReactivated
		}
		w.enabled = true
		w.deactivated = false
		w.source = ""
		w.deactivatedAt = time.Time{}
		w.groups = obs.Groups
	}

	observedStamp := pgStamp(w.observedAt, w.observed && !w.conflict)
	deactivatedStamp := pgStamp(w.deactivatedAt, w.deactivated)
	if err := q.UpdatePrincipalAuthState(ctx, identitydb.UpdatePrincipalAuthStateParams{
		DisplayName:         w.display,
		DirectoryEnabled:    w.enabled,
		DirectoryObservedAt: observedStamp,
		DeactivatedAt:       deactivatedStamp,
		DeactivationSource:  w.source,
		ID:                  row.ID,
	}); err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	if err := s.persistLineage(ctx, q, row.ID, missing, existing, w); err != nil {
		return directorySnapshot{}, err
	}
	if err := q.DeletePrincipalGroups(ctx, row.ID); err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	qualified := w.observed && !w.conflict && s.qualifiedLineage(row.Issuer, row.Subject, w.connector, w.upstreamProvider, w.upstreamSubject, w.brokerIssuer, w.brokerSubject)
	if w.enabled && !w.deactivated && qualified {
		for _, g := range w.groups {
			if err := q.InsertPrincipalGroup(ctx, identitydb.InsertPrincipalGroupParams{
				PrincipalID: row.ID,
				GroupPath:   g,
			}); err != nil {
				return directorySnapshot{}, s.dbErr(err)
			}
		}
	} else {
		w.groups = nil
	}
	nextRole := ""
	if w.enabled && !w.deactivated && qualified {
		nextRole = effectiveRole(row.PinnedRole, w.groups, s.adminGroups)
	}
	authorizationVersion, err := s.persistAuthorization(ctx, q, row, nextRole)
	if err != nil {
		return directorySnapshot{}, err
	}
	revoked := int64(0)
	if w.revoke {
		revoked, err = q.RevokePrincipalSessions(ctx, row.ID)
		if err != nil {
			return directorySnapshot{}, s.dbErr(err)
		}
	}
	if w.auditAction == "" && revoked > 0 {
		w.auditAction = auditDisabled
		w.auditReason = reasonDisabled
	}
	if w.auditAction != "" && (w.auditAction != auditDisabled || !prevDeactivated || revoked > 0) {
		if err := s.insertAudit(ctx, q, &row.ID, w.auditAction, principalResource(row.ID), w.auditReason); err != nil {
			return directorySnapshot{}, err
		}
	}
	return directorySnapshot{
		PrincipalID:          row.ID,
		Issuer:               row.Issuer,
		Subject:              row.Subject,
		DisplayName:          w.display,
		PinnedRole:           row.PinnedRole,
		Enabled:              w.enabled && !w.conflict,
		Deactivated:          w.deactivated,
		DeactivationSource:   w.source,
		Observed:             w.observed,
		ObservedAt:           w.observedAt,
		Qualified:            qualified,
		Groups:               w.groups,
		AuthorizationVersion: authorizationVersion,
		AuthorizationRole:    nextRole,
	}, nil
}

func (s *Service) copyLineage(w *authWrite, existing identitydb.PrincipalLineage, missing bool, row identitydb.Principal) {
	if missing {
		w.connector = s.connector()
		w.upstreamProvider = row.Issuer
		w.upstreamSubject = row.Subject
		return
	}
	w.connector = existing.DirectoryConnector
	w.upstreamProvider = existing.UpstreamProvider
	w.upstreamSubject = existing.UpstreamSubject
	w.brokerIssuer = existing.BrokerIssuer
	w.brokerSubject = existing.BrokerSubject
}

func (s *Service) persistLineage(ctx context.Context, q *identitydb.Queries, id uuid.UUID, missing bool, existing identitydb.PrincipalLineage, w authWrite) error {
	if w.conflict && !missing {
		err := q.UpdateLineage(ctx, identitydb.UpdateLineageParams{
			BrokerIssuer:       existing.BrokerIssuer,
			BrokerSubject:      existing.BrokerSubject,
			UpstreamProvider:   existing.UpstreamProvider,
			UpstreamSubject:    existing.UpstreamSubject,
			DirectoryConnector: existing.DirectoryConnector,
			UpstreamObservedAt: pgtype.Timestamptz{},
			PrincipalID:        id,
		})
		return s.dbErr(err)
	}
	if w.conflict {
		return nil
	}
	stamp := pgStamp(w.observedAt, w.observed)
	if missing {
		return s.dbErr(q.InsertLineage(ctx, identitydb.InsertLineageParams{
			PrincipalID:        id,
			BrokerIssuer:       w.brokerIssuer,
			BrokerSubject:      w.brokerSubject,
			UpstreamProvider:   w.upstreamProvider,
			UpstreamSubject:    w.upstreamSubject,
			DirectoryConnector: w.connector,
			UpstreamObservedAt: stamp,
		}))
	}
	return s.dbErr(q.UpdateLineage(ctx, identitydb.UpdateLineageParams{
		BrokerIssuer:       w.brokerIssuer,
		BrokerSubject:      w.brokerSubject,
		UpstreamProvider:   w.upstreamProvider,
		UpstreamSubject:    w.upstreamSubject,
		DirectoryConnector: w.connector,
		UpstreamObservedAt: stamp,
		PrincipalID:        id,
	}))
}

func (s *Service) beginFlow(ctx context.Context, state, nonce, verifier, binding string) error {
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		if err := q.DeleteStaleAuthFlows(ctx); err != nil {
			return s.dbErr(err)
		}
		if err := q.PurgeConsumedVerifiers(ctx); err != nil {
			return s.dbErr(err)
		}
		n, err := q.CountOpenAuthFlows(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if n >= maxOpenAuthFlows {
			return errUnavailable
		}
		return s.dbErr(q.InsertAuthFlow(ctx, identitydb.InsertAuthFlowParams{
			StateHash:          stateHash(state),
			NonceHash:          nonceHash(nonce),
			CodeVerifier:       verifier,
			BrowserBindingHash: bindingHash(binding),
			RedirectUri:        s.redirectURI,
		}))
	})
}

func (s *Service) consumeFlow(ctx context.Context, state, binding string) ([]byte, string, error) {
	var nonce []byte
	var verifier string
	var mismatch bool
	err := s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.ConsumeAuthFlow(ctx, identitydb.ConsumeAuthFlowParams{
			StateHash:   stateHash(state),
			RedirectUri: s.redirectURI,
		})
		if err != nil {
			return s.dbErr(err)
		}
		if err := q.ClearAuthFlowVerifier(ctx, row.ID); err != nil {
			return s.dbErr(err)
		}
		nonce = append([]byte(nil), row.NonceHash...)
		verifier = row.CodeVerifier
		mismatch = hashesDiffer(row.BrowserBindingHash, bindingHash(binding))
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if mismatch || verifier == "" || len(nonce) != 32 {
		return nil, "", errUnauthenticated
	}
	return nonce, verifier, nil
}

// revokePrincipal revokes live sessions only when the locked principal still
// denies access. A snapshot from an earlier observation must not revoke a
// session created after a newer re-enable, or write a false disable audit.
// The principal FOR UPDATE is taken before the session update so the audit
// foreign key's KEY SHARE cannot deadlock with writeObservation.
func (s *Service) revokePrincipal(ctx context.Context, id uuid.UUID) error {
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.GetPrincipalForUpdate(ctx, id)
		if err != nil {
			return s.dbErr(err)
		}
		snap, err := s.readSnapshot(ctx, q, row)
		if err != nil {
			return err
		}
		dec := decideAccess(s.clock(), s.accessIssuer(snap), s.adminGroups, snap)
		if !dec.RevokeSessions {
			return nil
		}
		n, err := q.RevokePrincipalSessions(ctx, id)
		if err != nil {
			return s.dbErr(err)
		}
		if n == 0 || dec.AuditAction == "" {
			return nil
		}
		return s.insertAudit(ctx, q, &id, dec.AuditAction, principalResource(id), dec.AuditReason)
	})
}

// logout locks the principal before the session row. The audit insert takes
// KEY SHARE on the principal; doing that after the session update inverts
// writeObservation and deadlocks with an in-flight observation.
func (s *Service) logout(ctx context.Context, cookie string, principalID uuid.UUID) error {
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		if _, err := q.GetPrincipalForUpdate(ctx, principalID); err != nil {
			return s.dbErr(err)
		}
		session, err := q.GetSessionByTokenHash(ctx, sessionHash(cookie))
		if err != nil {
			return s.dbErr(err)
		}
		n, err := q.RevokeSessionByTokenHash(ctx, sessionHash(cookie))
		if err != nil {
			return s.dbErr(err)
		}
		if n == 0 {
			return errNotFound
		}
		if session.BreakGlass {
			account, err := q.GetLocalAccount(ctx, principalID)
			if err != nil {
				return s.dbErr(err)
			}
			if err := q.BumpLocalAuthorization(ctx, identitydb.BumpLocalAuthorizationParams{ID: principalID, AuthorizationRole: account.Role}); err != nil {
				return s.dbErr(err)
			}
			return s.insertAudit(ctx, q, &principalID, "identity.break_glass_terminated", principalResource(principalID), session.IncidentReason)
		}
		return s.insertAudit(ctx, q, &principalID, auditLogout, principalResource(principalID), "")
	})
}

func (s *Service) insertAudit(ctx context.Context, q *identitydb.Queries, actor *uuid.UUID, action, resource, reason string) error {
	if !boundedText(action, 1, 128) || !boundedText(resource, 1, 512) || !boundedText(reason, 0, 512) {
		return errStore
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{
		ID:         id,
		ActorID:    actor,
		Action:     action,
		ResourceID: resource,
		Reason:     reason,
	}))
}

func (s *Service) snapshotFrom(row identitydb.Principal, lin identitydb.PrincipalLineage, groups []string) directorySnapshot {
	observedAt, observed := timeFrom(lin.UpstreamObservedAt)
	_, deactivated := timeFrom(row.DeactivatedAt)
	return directorySnapshot{
		PrincipalID:          row.ID,
		Issuer:               row.Issuer,
		Subject:              row.Subject,
		DisplayName:          row.DisplayName,
		PinnedRole:           row.PinnedRole,
		Enabled:              row.DirectoryEnabled,
		Deactivated:          deactivated,
		DeactivationSource:   row.DeactivationSource,
		Observed:             observed,
		ObservedAt:           observedAt,
		Qualified:            observed && s.qualifiedLineage(row.Issuer, row.Subject, lin.DirectoryConnector, lin.UpstreamProvider, lin.UpstreamSubject, lin.BrokerIssuer, lin.BrokerSubject),
		Groups:               groups,
		AuthorizationVersion: row.AuthorizationVersion,
		AuthorizationRole:    row.AuthorizationRole,
	}
}

func (s *Service) lineageConflict(existing identitydb.PrincipalLineage, issuer, subject string) bool {
	if existing.DirectoryConnector == "" && existing.UpstreamSubject == "" && existing.BrokerSubject == "" {
		return false
	}
	if existing.BrokerIssuer != "" || existing.BrokerSubject != "" {
		return true
	}
	if existing.DirectoryConnector != "" && existing.DirectoryConnector != s.connector() {
		return true
	}
	if existing.UpstreamSubject != "" && existing.UpstreamSubject != subject {
		return true
	}
	if existing.UpstreamProvider != "" && existing.UpstreamProvider != issuer {
		return true
	}
	return false
}

func (s *Service) tombstone(source string, at time.Time, hasAt bool, now time.Time) (string, time.Time) {
	if source == deactivationSCIM && hasAt {
		return deactivationSCIM, at
	}
	if source == s.connector() && hasAt {
		return s.connector(), at
	}
	return s.connector(), now
}

func principalResource(id uuid.UUID) string {
	return "principal/" + id.String()
}

func boundedText(s string, min, max int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}

func pgStamp(t time.Time, ok bool) pgtype.Timestamptz {
	if !ok || t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true, InfinityModifier: pgtype.Finite}
}

func timeFrom(ts pgtype.Timestamptz) (time.Time, bool) {
	if !ts.Valid || ts.InfinityModifier != pgtype.Finite {
		return time.Time{}, false
	}
	return ts.Time, true
}

func observationNewer(acquired time.Time, stored pgtype.Timestamptz) bool {
	if acquired.IsZero() {
		return false
	}
	previous, ok := timeFrom(stored)
	if !ok {
		return true
	}
	return acquired.After(previous)
}

func (s *Service) databaseTime(ctx context.Context) (time.Time, error) {
	var ts pgtype.Timestamptz
	if err := s.pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&ts); err != nil {
		return time.Time{}, s.dbErr(err)
	}
	acquired, ok := timeFrom(ts)
	if !ok {
		return time.Time{}, errStore
	}
	return acquired, nil
}

func (s *Service) observeDirectory(ctx context.Context, subject uuid.UUID) (directoryObservation, error) {
	acquired, err := s.databaseTime(ctx)
	if err != nil {
		return directoryObservation{}, err
	}
	obs, err := s.directory.Observe(ctx, subject)
	if err != nil {
		return directoryObservation{}, err
	}
	obs.AcquiredAt = acquired
	return obs, nil
}

func (s *Service) persistAuthorization(ctx context.Context, q *identitydb.Queries, row identitydb.Principal, nextRole string) (int64, error) {
	if row.AuthorizationRole == nextRole {
		return row.AuthorizationVersion, nil
	}
	version, err := q.SetPrincipalAuthorization(ctx, identitydb.SetPrincipalAuthorizationParams{
		ID: row.ID, ExpectedVersion: row.AuthorizationVersion, AuthorizationRole: nextRole,
	})
	if err != nil {
		return 0, s.dbErr(err)
	}
	if err := s.insertAudit(ctx, q, &row.ID, auditAuthorizationChanged, principalResource(row.ID), authorizationChangeReason(row.AuthorizationRole, nextRole)); err != nil {
		return 0, err
	}
	return version, nil
}

func authorizationChangeReason(prev, next string) string {
	switch {
	case next == RoleAdmin && prev != RoleAdmin:
		return reasonAdminGranted
	case prev == RoleAdmin && next != RoleAdmin:
		return reasonAdminRemoved
	case next == RoleOwner && prev != RoleOwner:
		return "owner authorization granted"
	case prev == RoleOwner && next != RoleOwner:
		return "owner authorization removed"
	default:
		return "authorization changed"
	}
}
