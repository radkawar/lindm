package identity

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"github.com/go-webauthn/webauthn/webauthn"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

// Service authenticates browser sessions and resolves current source authority.
// It does not run a background refresher.
type Service struct {
	pool          *pgxpool.Pool
	issuer        string
	entraTenant   uuid.UUID
	clientID      string
	publicOrigin  string
	redirectURI   string
	adminGroups   []string
	localIssuer   string
	localPrimary  bool
	breakGlass    *configv1.BreakGlassPolicy
	webauthn      *webauthn.WebAuthn
	dummyHash     string
	passwordSlots chan struct{}
	rules         protovalidate.Validator
	httpClient    *http.Client
	ownsClient    bool
	oauth         *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	directory     DirectorySource
	flights       flightGroup
	now           func() time.Time
}

type flight struct {
	wg  sync.WaitGroup
	val any
	err error
}

type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

func newService(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Service, error) {
	if pool == nil || (!cfg.Local && (cfg.ClientSecret == "" || cfg.DirectoryClientSecret == "")) {
		return nil, errInvalidConfig
	}
	origin, redirect, err := parsePublicURL(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	localIssuer, err := deploymentLocalIssuer(ctx, pool)
	if err != nil {
		return nil, err
	}
	webAuthn, err := localWebAuthn(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(
		&authv1.LocalLoginRequest{}, &authv1.LocalEnrollmentRequest{}, &authv1.WebAuthnFinishRequest{},
		&authv1.CreateAccountRequest{}, &authv1.UpdateAccountRequest{}, &authv1.ResetAccountRequest{}, &configv1.BreakGlassPolicy{}))
	if err != nil {
		return nil, err
	}
	if cfg.BreakGlass != nil {
		if err := rules.Validate(cfg.BreakGlass); err != nil {
			return nil, err
		}
	}
	if cfg.Local {
		s := &Service{pool: pool, issuer: localIssuer, localIssuer: localIssuer,
			localPrimary: true, publicOrigin: origin, redirectURI: redirect,
			breakGlass: cfg.BreakGlass, webauthn: webAuthn, dummyHash: dummyPasswordHash(), now: time.Now, rules: rules}
		s.directory = &localSource{pool: pool}
		s.passwordSlots = make(chan struct{}, 2)
		if err := s.checkOwnerAuthenticationMode(ctx); err != nil {
			return nil, err
		}
		if err := s.terminateEmergencySessions(ctx); err != nil {
			return nil, err
		}
		return s, nil
	}
	var entraTenant uuid.UUID
	if cfg.EntraTenantID != "" {
		issuer, err := EntraIssuer(cfg.EntraTenantID)
		if err != nil || cfg.Issuer != issuer || strings.EqualFold(cfg.ClientID, cfg.DirectoryClientID) {
			return nil, errInvalidConfig
		}
		entraTenant, err = uuid.Parse(cfg.EntraTenantID)
		if err != nil {
			return nil, errInvalidConfig
		}
	}
	groups := append([]string(nil), cfg.AdminGroups...)
	if entraTenant != uuid.Nil {
		for i, group := range groups {
			id, err := uuid.Parse(group)
			if err != nil || id == uuid.Nil {
				return nil, errInvalidConfig
			}
			groups[i] = id.String()
		}
	}
	httpClient := cfg.HTTPClient
	owns := false
	if httpClient == nil {
		httpClient = defaultHTTPClient()
		owns = true
	}
	discoverCtx := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(discoverCtx, cfg.Issuer)
	if err != nil {
		slog.Warn("identity issuer discovery failed")
		var mismatch *oidc.IssuerMismatchError
		if errors.As(err, &mismatch) {
			return nil, errInvalidConfig
		}
		return nil, ErrDirectoryUnavailable
	}
	endpoint := provider.Endpoint()
	if !strings.HasPrefix(endpoint.AuthURL, "https://") || !strings.HasPrefix(endpoint.TokenURL, "https://") {
		return nil, errInvalidConfig
	}
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	s := &Service{
		pool:          pool,
		issuer:        cfg.Issuer,
		entraTenant:   entraTenant,
		clientID:      cfg.ClientID,
		publicOrigin:  origin,
		redirectURI:   redirect,
		adminGroups:   groups,
		localIssuer:   localIssuer,
		breakGlass:    cfg.BreakGlass,
		webauthn:      webAuthn,
		dummyHash:     dummyPasswordHash(),
		rules:         rules,
		passwordSlots: make(chan struct{}, 2),
		httpClient:    httpClient,
		ownsClient:    owns,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  redirect,
			Endpoint:     endpoint,
			Scopes:       []string{oidc.ScopeOpenID},
		},
		verifier: provider.VerifierContext(oidc.ClientContext(context.Background(), httpClient), &oidc.Config{ClientID: cfg.ClientID}),
		now:      time.Now,
	}
	if entraTenant != uuid.Nil {
		s.oauth.Scopes = append(s.oauth.Scopes, "profile")
		s.directory, err = newEntraSource(ctx, "https://graph.microsoft.com/v1.0", cfg.DirectoryClientID, cfg.DirectoryClientSecret, endpoint.TokenURL, httpClient, s.clock)
	} else {
		s.directory, err = newKeycloakSource(ctx, cfg.Issuer, cfg.DirectoryClientID, cfg.DirectoryClientSecret, endpoint.TokenURL, httpClient, s.clock)
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkOwnerAuthenticationMode(ctx); err != nil {
		return nil, err
	}
	if err := s.terminateEmergencySessions(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases idle connections if this service created its HTTP client.
// It does not stop a background task; there is none.
func (s *Service) Close() error {
	if s != nil && s.ownsClient {
		s.httpClient.CloseIdleConnections()
	}
	return nil
}

func (s *Service) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *Service) resolve(ctx context.Context, cookie string) (Principal, accessDecision, error) {
	sess, err := s.getSession(ctx, sessionHash(cookie))
	if errors.Is(err, errNotFound) || errors.Is(err, errUnauthenticated) {
		return Principal{}, accessDecision{Kind: accessUnauthenticated}, nil
	}
	if err != nil {
		return Principal{}, accessDecision{}, err
	}
	now := s.clock()
	if s.localPrimary || sess.BreakGlass {
		now, err = s.databaseTime(ctx)
		if err != nil {
			return Principal{}, accessDecision{}, err
		}
	}
	if sess.Revoked || !now.Before(sess.Idle) || !now.Before(sess.Absolute) {
		if sess.BreakGlass {
			if !sess.Revoked {
				if err := s.logout(ctx, cookie, sess.PrincipalID); err != nil && !errors.Is(err, errNotFound) {
					return Principal{}, accessDecision{}, err
				}
			}
			if err := s.emergencyAudit(ctx, sess.PrincipalID, "identity.break_glass_denied", "emergency session expired or revoked"); err != nil {
				return Principal{}, accessDecision{}, err
			}
		}
		return Principal{}, accessDecision{Kind: accessUnauthenticated}, nil
	}
	snap, err := s.loadSnapshot(ctx, sess.PrincipalID)
	if err != nil {
		return Principal{}, accessDecision{}, err
	}
	if snap.Local && sess.BreakGlass != snap.BreakGlass {
		if err := s.logout(ctx, cookie, sess.PrincipalID); err != nil && !errors.Is(err, errNotFound) {
			return Principal{}, accessDecision{}, err
		}
		if err := s.emergencyAudit(ctx, sess.PrincipalID, "identity.break_glass_denied", "session authentication mode changed"); err != nil {
			return Principal{}, accessDecision{}, err
		}
		return Principal{}, accessDecision{Kind: accessUnauthenticated}, nil
	}
	if !snap.Local && needsRefresh(now, snap) {
		subjectID, parseErr := uuid.Parse(snap.Subject)
		var refreshed directorySnapshot
		var refreshErr error
		if parseErr != nil {
			refreshErr = errDirectoryResponse
		} else {
			refreshed, refreshErr = s.refreshPrincipal(ctx, snap.PrincipalID, subjectID)
		}
		if refreshErr != nil {
			snap.RefreshFailed = true
		} else {
			snap = refreshed
		}
	}
	dec := decideAccess(s.clock(), s.accessIssuer(snap), s.adminGroups, snap)
	// snap may predate a re-enable. Revocation rechecks under the principal lock.
	if dec.RevokeSessions {
		if err := s.revokePrincipal(ctx, snap.PrincipalID); err != nil {
			return Principal{}, accessDecision{}, err
		}
	}
	if dec.Kind != accessOK {
		return Principal{}, dec, nil
	}
	principal := s.snapshotPrincipal(snap, dec.Role)
	principal.CSRFToken = csrfToken(cookie)
	principal.IncidentReason = sess.IncidentReason
	return principal, dec, nil
}

func (s *Service) refreshPrincipal(ctx context.Context, id, subject uuid.UUID) (directorySnapshot, error) {
	v, err := s.flights.Do("principal:"+id.String(), func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryFetchTimeout)
		defer cancel()
		obs, err := s.observeDirectory(fctx, subject)
		if err != nil {
			return directorySnapshot{}, err
		}
		var snap directorySnapshot
		err = s.withTx(fctx, func(q *identitydb.Queries) error {
			var werr error
			snap, werr = s.writeObservation(fctx, q, id, obs)
			return werr
		})
		if errors.Is(err, errStaleObservation) {
			return s.loadSnapshot(fctx, id)
		}
		if err != nil {
			return directorySnapshot{}, err
		}
		return snap, nil
	})
	if err != nil {
		return directorySnapshot{}, err
	}
	snap, ok := v.(directorySnapshot)
	if !ok {
		return directorySnapshot{}, errStore
	}
	return snap, nil
}

// BootstrapOwner binds the first owner once. Repeating it for that same
// issuer and subject succeeds. A different principal returns ErrOwnerInitialized.
func (s *Service) BootstrapOwner(ctx context.Context, issuer, subject string) error {
	if issuer != s.issuer {
		return ErrIssuerMismatch
	}
	userID, err := uuid.Parse(subject)
	if err != nil || userID == uuid.Nil {
		return ErrSubjectUnqualified
	}
	subject = userID.String()
	switch same, err := s.sameInitializedOwner(ctx, issuer, subject); {
	case err != nil:
		return err
	case same:
		return nil
	}
	obs, err := s.observeDirectory(ctx, userID)
	if err != nil {
		return ErrDirectoryUnavailable
	}
	if !obs.Found || !obs.Enabled || !obs.Direct || obs.UserID != userID {
		return ErrSubjectUnqualified
	}
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		dep, err := q.LockDeploymentIdentity(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if dep.OwnerPrincipalID != nil || dep.InitializedAt.Valid {
			return s.ownerReplay(ctx, q, dep, issuer, subject)
		}
		principalID, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		row, err := q.UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{
			ID:          principalID,
			Issuer:      s.issuer,
			Subject:     subject,
			DisplayName: obs.DisplayName,
		})
		if err != nil {
			mapped := s.dbErr(err)
			if errors.Is(mapped, errUnique) {
				return ErrOwnerInitialized
			}
			return mapped
		}
		snap, err := s.writeObservation(ctx, q, row.ID, obs)
		if errors.Is(err, errStaleObservation) {
			return ErrSubjectUnqualified
		}
		if err != nil {
			return err
		}
		if !snap.Qualified || !snap.Enabled || snap.Deactivated || snap.Issuer != s.issuer || snap.Subject != subject {
			return ErrSubjectUnqualified
		}
		n, err := q.PinOwnerRole(ctx, row.ID)
		if err != nil {
			mapped := s.dbErr(err)
			if errors.Is(mapped, errUnique) {
				return ErrOwnerInitialized
			}
			return mapped
		}
		if n != 1 {
			return ErrOwnerInitialized
		}
		marked, err := q.MarkDeploymentInitialized(ctx, &row.ID)
		if err != nil {
			mapped := s.dbErr(err)
			if errors.Is(mapped, errUnique) {
				return ErrOwnerInitialized
			}
			return mapped
		}
		if marked != 1 {
			return ErrOwnerInitialized
		}
		return s.insertAudit(ctx, q, &row.ID, auditOwnerBootstrapped, principalResource(row.ID), reasonInitialOwner)
	})
}

// InitializedOwner reports the pinned owner after bootstrap has completed.
// ok is false only when no owner is bound. A database error is not uninitialized.
func (s *Service) InitializedOwner(ctx context.Context) (issuer, subject string, ok bool, err error) {
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		dep, err := q.LockDeploymentIdentity(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if dep.OwnerPrincipalID == nil && !dep.InitializedAt.Valid {
			return nil
		}
		if dep.OwnerPrincipalID == nil || !dep.InitializedAt.Valid {
			return errStore
		}
		row, err := q.GetPrincipalByID(ctx, *dep.OwnerPrincipalID)
		if err != nil {
			return s.dbErr(err)
		}
		issuer, subject, ok = row.Issuer, row.Subject, true
		return nil
	})
	return issuer, subject, ok, err
}

func (s *Service) sameInitializedOwner(ctx context.Context, issuer, subject string) (bool, error) {
	var same bool
	err := s.withTx(ctx, func(q *identitydb.Queries) error {
		dep, err := q.LockDeploymentIdentity(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if dep.OwnerPrincipalID == nil && !dep.InitializedAt.Valid {
			return nil
		}
		match, err := s.ownerMatches(ctx, q, dep, issuer, subject)
		if err != nil {
			return err
		}
		same = match
		if !match {
			return ErrOwnerInitialized
		}
		return nil
	})
	return same, err
}

func (s *Service) ownerReplay(ctx context.Context, q *identitydb.Queries, dep identitydb.DeploymentIdentity, issuer, subject string) error {
	match, err := s.ownerMatches(ctx, q, dep, issuer, subject)
	if err != nil || match {
		return err
	}
	return ErrOwnerInitialized
}

func (s *Service) ownerMatches(ctx context.Context, q *identitydb.Queries, dep identitydb.DeploymentIdentity, issuer, subject string) (bool, error) {
	if dep.OwnerPrincipalID == nil || !dep.InitializedAt.Valid {
		return false, ErrOwnerInitialized
	}
	row, err := q.GetPrincipalByID(ctx, *dep.OwnerPrincipalID)
	if err != nil {
		return false, s.dbErr(err)
	}
	return row.Issuer == issuer && row.Subject == subject && row.PinnedRole == RoleOwner, nil
}

func (s *Service) denyAbsent(ctx context.Context, subject uuid.UUID, obs directoryObservation) error {
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.GetPrincipalByIssuerSubject(ctx, identitydb.GetPrincipalByIssuerSubjectParams{
			Issuer:  s.issuer,
			Subject: subject.String(),
		})
		if err != nil {
			mapped := s.dbErr(err)
			if errors.Is(mapped, errNotFound) {
				return s.insertAudit(ctx, q, nil, auditLoginDenied, "subject/"+subject.String(), reasonAbsent)
			}
			return mapped
		}
		_, err = s.writeObservation(ctx, q, row.ID, obs)
		return err
	})
}

func (s *Service) completeLogin(ctx context.Context, subject uuid.UUID, obs directoryObservation) (string, bool, error) {
	cookie, err := randomToken()
	if err != nil {
		return "", false, err
	}
	denied := false
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		principalID, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		row, err := q.UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{
			ID:          principalID,
			Issuer:      s.issuer,
			Subject:     subject.String(),
			DisplayName: obs.DisplayName,
		})
		if err != nil {
			return s.dbErr(err)
		}
		snap, err := s.writeObservation(ctx, q, row.ID, obs)
		if err != nil {
			return err
		}
		dec := decideAccess(s.clock(), s.issuer, s.adminGroups, snap)
		actor := row.ID
		if dec.Kind != accessOK {
			denied = true
			reason := dec.AuditReason
			if reason == "" {
				reason = reasonUnqualified
			}
			return s.insertAudit(ctx, q, &actor, auditLoginDenied, principalResource(row.ID), reason)
		}
		if err := q.InsertSession(ctx, identitydb.InsertSessionParams{
			TokenHash:   sessionHash(cookie),
			PrincipalID: row.ID,
		}); err != nil {
			return s.dbErr(err)
		}
		return s.insertAudit(ctx, q, &actor, auditLogin, principalResource(row.ID), "")
	})
	if err != nil {
		return "", false, err
	}
	if denied {
		return "", true, nil
	}
	return cookie, false, nil
}

func (g *flightGroup) Do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*flight)
	}
	if existing, ok := g.m[key]; ok {
		g.mu.Unlock()
		existing.wg.Wait()
		return existing.val, existing.err
	}
	f := &flight{}
	f.wg.Add(1)
	g.m[key] = f
	g.mu.Unlock()
	defer func() {
		if rec := recover(); rec != nil {
			f.err = errStore
			f.wg.Done()
			g.mu.Lock()
			delete(g.m, key)
			g.mu.Unlock()
			panic(rec)
		}
	}()
	f.val, f.err = fn()
	f.wg.Done()
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return f.val, f.err
}

func defaultHTTPClient() *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	var tr *http.Transport
	if ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	tr.TLSHandshakeTimeout = 5 * time.Second
	tr.ResponseHeaderTimeout = 10 * time.Second
	tr.ExpectContinueTimeout = time.Second
	tr.IdleConnTimeout = 90 * time.Second
	tr.MaxIdleConns = 32
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: httpsOnlyRedirect, Transport: tr}
}

func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Scheme != "https" {
		return errInvalidConfig
	}
	return nil
}
