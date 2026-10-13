package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

type sessionRecord struct {
	PrincipalID    uuid.UUID
	Idle           time.Time
	Absolute       time.Time
	Revoked        bool
	BreakGlass     bool
	IncidentReason string
	Kind           string
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
	auditAction      auditkind.Kind
	auditReason      string
	conflict         bool
}

func (s *Service) withTx(ctx context.Context, fn func(*identitydb.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	if err := s.lockPolicy(ctx, q); err != nil {
		return err
	}
	if err := fn(q); err != nil {
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
	return sessionRecord{PrincipalID: row.PrincipalID, Idle: idle, Absolute: absolute, Revoked: revoked, BreakGlass: row.BreakGlass, IncidentReason: row.IncidentReason, Kind: row.Kind}, nil
}

func (s *Service) touch(ctx context.Context, cookie string) error {
	_, err := identitydb.New(s.pool).TouchSession(ctx, sessionHash(cookie))
	return s.dbErr(err)
}

func (s *Service) loadSnapshot(ctx context.Context, id uuid.UUID) (directorySnapshot, error) {
	var snapshot directorySnapshot
	err := s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.GetPrincipalForUpdate(ctx, id)
		if err != nil {
			return s.dbErr(err)
		}
		snapshot, err = s.readSnapshot(ctx, q, row)
		return err
	})
	return snapshot, err
}

func (s *Service) readSnapshot(ctx context.Context, q *identitydb.Queries, row identitydb.Principal) (directorySnapshot, error) {
	policy, err := s.currentPolicy(ctx, q)
	if err != nil {
		return directorySnapshot{}, err
	}
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
	snapshot := s.snapshotFrom(row, lin, groups)
	snapshot.policy = policy
	return snapshot, nil
}

func (s *Service) writeObservation(ctx context.Context, q *identitydb.Queries, principalID uuid.UUID, obs directoryObservation) (directorySnapshot, error) {
	row, err := q.GetPrincipalForUpdate(ctx, principalID)
	if err != nil {
		return directorySnapshot{}, s.dbErr(err)
	}
	if row.Issuer == s.localIssuer {
		return s.readLocalSnapshot(ctx, q, row)
	}
	policy, err := s.currentPolicy(ctx, q)
	if err != nil {
		return directorySnapshot{}, err
	}
	if cutoff, valid := timeFrom(row.LifecycleNotBefore); valid && !obs.AcquiredAt.After(cutoff) {
		return directorySnapshot{}, errStaleObservation
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
	_, prevDeactivated := timeFrom(row.DeactivatedAt)
	w := s.planObservation(row, existing, missing, obs)

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
	if w.conflict {
		// Losing qualification clears freshness, not ordering: an older in-flight
		// authoritative read must not restore grants after this denial.
		if err := q.AdvancePrincipalObservationFence(ctx, identitydb.AdvancePrincipalObservationFenceParams{ID: row.ID, ObservedAt: pgStamp(obs.AcquiredAt, true)}); err != nil {
			return directorySnapshot{}, s.dbErr(err)
		}
	}
	if err := s.persistLineage(ctx, q, row.ID, missing, existing, w); err != nil {
		return directorySnapshot{}, err
	}
	qualified := w.observed && !w.conflict && s.qualifiedLineage(row.Issuer, row.Subject, w.connector, w.upstreamProvider, w.upstreamSubject, w.brokerIssuer, w.brokerSubject)
	granted := w.enabled && !w.deactivated && qualified
	if !granted {
		w.groups = nil
	}
	if err := s.replacePrincipalGroups(ctx, q, row.ID, w.groups); err != nil {
		return directorySnapshot{}, err
	}
	nextRole := ""
	if granted {
		nextRole = effectiveRole(row.PinnedRole, w.groups, policy)
	}
	var bindings []*authv1.RoleBinding
	if nextRole != "" {
		bindings = policy.bindings(row.PinnedRole, w.groups)
	}
	digest, err := bindingsDigest(bindings)
	if err != nil {
		return directorySnapshot{}, err
	}
	authorizationVersion, err := s.persistAuthorization(ctx, q, row, nextRole, digest)
	if err != nil {
		return directorySnapshot{}, err
	}
	if err := s.revokeAndAudit(ctx, q, row.ID, w, prevDeactivated); err != nil {
		return directorySnapshot{}, err
	}
	return directorySnapshot{
		policy:               policy,
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
		ServiceAccount:       row.ServiceAccount,
	}, nil
}

// planObservation decides the principal's next directory state, lineage,
// session revocation and audit from a fresh observation. It writes nothing.
func (s *Service) planObservation(row identitydb.Principal, existing identitydb.PrincipalLineage, missing bool, obs directoryObservation) authWrite {
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
	if s.broker != nil {
		s.copyLineage(&w, existing, missing, row)
		w.conflict = !obs.Found || !obs.Direct || !s.broker.qualified(obs.Lineage, row.Subject) ||
			(!missing && !obs.Lineage.matches(existing))
		if !w.conflict {
			w.connector = obs.Lineage.Connector
			w.upstreamProvider = obs.Lineage.UpstreamProvider
			w.upstreamSubject = obs.Lineage.UpstreamSubject
			w.brokerIssuer = obs.Lineage.BrokerIssuer
			w.brokerSubject = obs.Lineage.BrokerSubject
		}
	}
	switch {
	case w.conflict:
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.revoke = true
		w.auditAction = auditkind.IdentityLineageDenied
		w.auditReason = reasonConflict
	case !obs.Found:
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.source, w.deactivatedAt = s.tombstone(row.DeactivationSource, prevAt, prevDeactivated, w.observedAt)
		w.deactivated = true
		w.revoke = true
		w.auditAction = auditkind.IdentityDisabled
		w.auditReason = reasonAbsent
	case !obs.Direct || obs.UserID != row.Subject:
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.revoke = true
		w.auditAction = auditkind.IdentityLineageDenied
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
		if s.broker == nil {
			s.copyLineage(&w, existing, missing, row)
		}
		if !prevDeactivated {
			w.auditAction = auditkind.IdentityDisabled
			w.auditReason = reasonDisabled
		}
	default:
		s.planEnabledObservation(&w, row, existing, missing, obs, prevDeactivated)
	}
	return w
}

// planEnabledObservation handles a direct, enabled observation of the principal's
// own subject: a lineage conflict or SCIM tombstone still denies it; otherwise it
// (re)activates with the observed groups.
func (s *Service) planEnabledObservation(w *authWrite, row identitydb.Principal, existing identitydb.PrincipalLineage, missing bool, obs directoryObservation, prevDeactivated bool) {
	if row.Issuer != s.issuer || row.Subject != obs.UserID || (!missing && s.lineageConflict(existing, s.issuer, obs.UserID)) {
		w.conflict = true
		w.enabled = false
		w.observed = true
		w.observedAt = obs.AcquiredAt
		w.revoke = true
		w.auditAction = auditkind.IdentityLineageDenied
		w.auditReason = reasonConflict
		return
	}
	if s.broker == nil {
		w.connector = s.connector()
		w.upstreamProvider = row.Issuer
		w.upstreamSubject = row.Subject
	}
	w.observed = true
	w.observedAt = obs.AcquiredAt
	if row.DeactivationSource == deactivationSCIM {
		w.enabled = true
		w.deactivated = true
		w.source = deactivationSCIM
		w.revoke = true
		w.auditAction = auditkind.IdentityLineageDenied
		w.auditReason = reasonTombstone
		return
	}
	if prevDeactivated {
		w.auditAction = auditkind.IdentityReactivated
		w.auditReason = reasonReactivated
	}
	w.enabled = true
	w.deactivated = false
	w.source = ""
	w.deactivatedAt = time.Time{}
	w.groups = obs.Groups
}

// replacePrincipalGroups replaces the stored directory groups with groups, which
// is empty unless the observation grants access.
func (s *Service) replacePrincipalGroups(ctx context.Context, q *identitydb.Queries, id uuid.UUID, groups []string) error {
	// A routine fresh observation usually repeats the stored groups; rewriting
	// them would lengthen every observation's exclusive principal lock.
	current, err := q.ListPrincipalGroupPaths(ctx, id)
	if err != nil {
		return s.dbErr(err)
	}
	slices.Sort(current) // database collation order may differ from byte order
	if slices.Equal(current, slices.Sorted(slices.Values(groups))) {
		return nil
	}
	if err := q.DeletePrincipalGroups(ctx, id); err != nil {
		return s.dbErr(err)
	}
	for _, g := range groups {
		if err := q.InsertPrincipalGroup(ctx, identitydb.InsertPrincipalGroupParams{
			PrincipalID: id,
			GroupPath:   g,
		}); err != nil {
			return s.dbErr(err)
		}
	}
	return nil
}

// revokeAndAudit revokes sessions when the plan requires it and records the
// planned audit event; revocation alone is audited as a disable.
func (s *Service) revokeAndAudit(ctx context.Context, q *identitydb.Queries, id uuid.UUID, w authWrite, prevDeactivated bool) error {
	revoked := int64(0)
	if w.revoke {
		var err error
		revoked, err = s.revokePrincipalCredentials(ctx, q, id)
		if err != nil {
			return s.dbErr(err)
		}
	}
	if w.auditAction == (auditkind.Kind{}) && revoked > 0 {
		w.auditAction = auditkind.IdentityDisabled
		w.auditReason = reasonDisabled
	}
	if w.auditAction != (auditkind.Kind{}) && (w.auditAction != auditkind.IdentityDisabled || !prevDeactivated || revoked > 0) {
		return s.insertSystemAudit(ctx, q, &id, w.auditAction, principalResource(id), w.auditReason)
	}
	return nil
}

func (s *Service) copyLineage(w *authWrite, existing identitydb.PrincipalLineage, missing bool, row identitydb.Principal) {
	if missing {
		if s.broker != nil {
			return
		}
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
		dec := decideAccess(s.clock(), s.accessIssuer(snap), snap.policy, snap)
		if !dec.RevokeSessions {
			return nil
		}
		n, err := s.revokePrincipalCredentials(ctx, q, id)
		if err != nil {
			return s.dbErr(err)
		}
		if n == 0 || dec.AuditAction == (auditkind.Kind{}) {
			return nil
		}
		return s.insertSystemAudit(ctx, q, &id, dec.AuditAction, principalResource(id), dec.AuditReason)
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
			if err := s.bumpLocalAuthorization(ctx, q, principalID, account.Role); err != nil {
				return s.dbErr(err)
			}
			return s.insertAudit(ctx, q, &principalID, auditkind.IdentityBreakGlassTerminated, principalResource(principalID), session.IncidentReason)
		}
		return s.insertAudit(ctx, q, &principalID, auditkind.IdentityLogout, principalResource(principalID), "")
	})
}

func (s *Service) insertAudit(ctx context.Context, q *identitydb.Queries, actor *uuid.UUID, action auditkind.Kind, resource, reason string) error {
	if action == (auditkind.Kind{}) || !boundedText(resource, 1, 512) || !boundedText(reason, 0, 512) {
		return errStore
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{
		ID:         id,
		ActorID:    actor,
		Action:     action.String(),
		ResourceID: resource,
		Reason:     reason,
	}))
}

// insertSystemAudit records generated context, not an operator-authored reason.
func (s *Service) insertSystemAudit(ctx context.Context, q *identitydb.Queries, actor *uuid.UUID, action auditkind.Kind, resource, context string) error {
	details, err := json.Marshal(map[string]string{"context": context})
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: resource, Details: details,
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
		ServiceAccount:       row.ServiceAccount,
	}
}

func (s *Service) lineageConflict(existing identitydb.PrincipalLineage, issuer, subject string) bool {
	if s.broker != nil {
		return !s.qualifiedLineage(issuer, subject, existing.DirectoryConnector, existing.UpstreamProvider, existing.UpstreamSubject, existing.BrokerIssuer, existing.BrokerSubject)
	}
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
	connector := s.connector()
	if s.broker != nil {
		// Deactivation records the provider family; the immutable connector
		// instance and original issuer remain separately pinned in lineage.
		connector = connectorKeycloak
	}
	if source == connector && hasAt {
		return connector, at
	}
	return connector, now
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

func (s *Service) observeDirectory(ctx context.Context, subject string) (directoryObservation, error) {
	acquired, err := s.databaseTime(ctx)
	if err != nil {
		return directoryObservation{}, err
	}
	source := s.directory
	if google, ok := source.(*googleSource); ok {
		policy, err := s.currentPolicy(ctx, identitydb.New(s.pool))
		if err != nil {
			return directoryObservation{}, err
		}
		// Google queries configured immutable IDs rather than listing memberships.
		// Keep the source immutable while each observation captures the runtime set.
		current := *google
		current.groups = make([]string, 0, len(policy.groups))
		for group := range policy.groups {
			current.groups = append(current.groups, group)
		}
		source = &current
	}
	obs, err := source.Observe(ctx, subject)
	if err != nil {
		return directoryObservation{}, err
	}
	obs.AcquiredAt = acquired
	return obs, nil
}

func (s *Service) persistAuthorization(ctx context.Context, q *identitydb.Queries, row identitydb.Principal, nextRole string, digest []byte) (int64, error) {
	if row.AuthorizationRole == nextRole && bytes.Equal(row.AuthorizationDigest, digest) {
		return row.AuthorizationVersion, nil
	}
	version, err := q.SetPrincipalAuthorization(ctx, identitydb.SetPrincipalAuthorizationParams{
		ID: row.ID, ExpectedVersion: row.AuthorizationVersion, AuthorizationRole: nextRole, AuthorizationDigest: digest,
	})
	if err != nil {
		return 0, s.dbErr(err)
	}
	if err := s.insertSystemAudit(ctx, q, &row.ID, auditkind.IdentityAuthorizationChanged, principalResource(row.ID), authorizationChangeReason(row.AuthorizationRole, nextRole)); err != nil {
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
