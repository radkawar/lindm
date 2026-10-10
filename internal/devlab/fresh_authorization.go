package devlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

// CheckFreshAuthorization exercises the public identity API against the already
// running fixture. It neither starts services nor touches shared principals,
// groups or application schemas. The same check runs in TestIntegration.
func CheckFreshAuthorization(ctx context.Context, repoRoot string, evidence io.Writer) error {
	return locked(ctx, repoRoot, func(root string) error {
		return checkFreshAuthorization(ctx, root, evidence)
	})
}

func checkFreshAuthorization(ctx context.Context, root string, evidence io.Writer) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	dir := FixturePath(root)
	if err := validateFixture(dir); err != nil {
		return err
	}
	if err := requireKeycloakFixture(dir); err != nil {
		return err
	}
	tlsConfig, err := trustClient(dir)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	secrets := make(map[string]string, 4)
	for _, name := range []string{"migration-database-url", "console-secret", "directory-secret", "lab-admin-secret"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read protected fresh-check input %s failed", name)
		}
		secrets[name] = strings.TrimSpace(string(data))
		clear(data)
		if secrets[name] == "" {
			return fmt.Errorf("protected fresh-check input %s is empty", name)
		}
	}
	database, err := testdb.New(ctx, secrets["migration-database-url"])
	if err != nil {
		return err
	}
	defer func() {
		err := database.Close()
		if err == nil {
			_, err = fmt.Fprintf(evidence, "fresh-authorization cleanup schema=%s removed\n", database.Schema())
		}
		resultErr = errors.Join(resultErr, err)
	}()
	if _, err := fmt.Fprintf(evidence, "fresh-authorization owned schema=%s; issuer=%s; deadline=2m; directory=lindm-directory (read-only); mutation=lindm-lab-admin\n", database.Schema(), issuer); err != nil {
		return err
	}
	var role, schema, protocol string
	var encrypted bool
	if err := database.Pool.QueryRow(ctx, "SELECT current_user, current_schema(), ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&role, &schema, &encrypted, &protocol); err != nil {
		return err
	}
	if role != "lindm_migrator" || schema != database.Schema() || !encrypted || protocol != "TLSv1.3" {
		return errors.New("fresh-check database did not use its isolated schema, migration role and TLS 1.3")
	}
	fixture := &freshDirectoryFixture{client: client, secret: secrets["lab-admin-secret"], name: "lindm-fresh-" + uuid.NewString()}
	defer func() { resultErr = errors.Join(resultErr, fixture.close(ctx, evidence)) }()
	if _, err := fmt.Fprintf(evidence, "fresh-authorization owned Keycloak name=%s\n", fixture.name); err != nil {
		return err
	}
	if err := fixture.authenticate(ctx); err != nil {
		return err
	}
	fixture.groupID, err = fixture.create(ctx, "groups")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(evidence, "fresh-authorization owned group=%s path=/%s\n", fixture.groupID, fixture.name); err != nil {
		return err
	}
	fixture.userID, err = fixture.create(ctx, "users")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(evidence, "fresh-authorization owned user=%s\n", fixture.userID); err != nil {
		return err
	}
	if err := fixture.membership(ctx, true); err != nil {
		return err
	}
	service, err := identity.New(ctx, database.Pool, identity.Config{
		Issuer: issuer, ClientID: "lindm-console", ClientSecret: secrets["console-secret"],
		DirectoryClientID: "lindm-directory", DirectoryClientSecret: secrets["directory-secret"],
		PublicURL: consoleOrigin, HTTPClient: client,
		Policy: &authv1.AuthorizationPolicy{
			Roles:         []*authv1.RoleDefinition{{Name: "lab-operator", Permissions: []string{string(identity.PermissionManageEnrollment), string(identity.PermissionReadFleet)}}},
			GroupBindings: []*authv1.GroupBinding{{Group: "/" + fixture.name, Role: "lab-operator", Scopes: []*authv1.DeviceScope{{Labels: []string{"lab-owned"}, DeviceIds: []string{fixture.userID}}}}},
		},
	})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, service.Close()) }()
	actorID := uuid.New()
	// Seed only the immutable local binding. Enabled state, lineage, groups,
	// display name and authorization version must come from actual Keycloak reads.
	if _, err := database.Pool.Exec(ctx, "INSERT INTO principals (id, issuer, subject) VALUES ($1, $2, $3)", actorID, issuer, fixture.userID); err != nil {
		return err
	}
	if _, err := database.Pool.Exec(ctx, "CREATE TABLE fresh_authorization_effects (label text PRIMARY KEY)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(evidence, "fresh-authorization owned actor=%s permission=%s\n", actorID, identity.PermissionManageEnrollment); err != nil {
		return err
	}
	return exerciseFreshAuthorization(ctx, service, database.Pool, actorID, fixture, evidence)
}

type freshAuthorizationState struct {
	version  uint64
	role     string
	display  string
	enabled  bool
	observed time.Time
	now      time.Time
}

func readFreshAuthorizationState(ctx context.Context, pool *pgxpool.Pool, actorID uuid.UUID) (freshAuthorizationState, error) {
	var state freshAuthorizationState
	var version int64
	err := pool.QueryRow(ctx, "SELECT authorization_version, authorization_role, display_name, directory_enabled, directory_observed_at, clock_timestamp() FROM principals WHERE id = $1", actorID).Scan(&version, &state.role, &state.display, &state.enabled, &state.observed, &state.now)
	if err != nil {
		return state, err
	}
	if version <= 0 {
		return state, errors.New("fresh-check persisted authorization version is not positive")
	}
	state.version = uint64(version)
	return state, nil
}

func exerciseFreshAuthorization(ctx context.Context, service *identity.Service, pool *pgxpool.Pool, actorID uuid.UUID, fixture *freshDirectoryFixture, evidence io.Writer) error {
	allowed := func(stage string, wantVersion uint64) (*identity.Authorization, error) {
		authorization, err := service.AuthorizeFresh(ctx, actorID, identity.PermissionManageEnrollment)
		if err != nil {
			return nil, fmt.Errorf("fresh-check %s authorization: %w", stage, err)
		}
		state, err := readFreshAuthorizationState(ctx, pool, actorID)
		if err != nil {
			return nil, err
		}
		if authorization == nil || authorization.ActorID() != actorID || authorization.Version() != state.version || state.role != "lab-operator" || !state.enabled || (wantVersion != 0 && state.version != wantVersion) {
			return nil, fmt.Errorf("fresh-check %s did not persist the expected allowed version", stage)
		}
		principal := authorization.Principal()
		unrestricted, scopes := identity.DeviceScopes(principal, identity.PermissionManageEnrollment)
		if unrestricted || len(scopes) != 1 || len(scopes[0].GetLabels()) != 1 || scopes[0].GetLabels()[0] != "lab-owned" || len(scopes[0].GetDeviceIds()) != 1 || scopes[0].GetDeviceIds()[0] != fixture.userID {
			return nil, fmt.Errorf("fresh-check %s lost the custom role's exact device scope", stage)
		}
		if identity.Authorize(principal, identity.PermissionManageAccounts) || identity.Authorize(principal, identity.PermissionRevokeDevice) {
			return nil, fmt.Errorf("fresh-check %s widened the custom role's explicit permissions", stage)
		}
		if !authorization.ExpiresAt().After(state.now) || authorization.ExpiresAt().After(state.observed.Add(30*time.Second)) {
			return nil, fmt.Errorf("fresh-check %s approval deadline exceeds the observed 30s bound or is expired", stage)
		}
		if _, err := fmt.Fprintf(evidence, "fresh-authorization %s allowed version=%d expiry-bound=30s\n", stage, authorization.Version()); err != nil {
			return nil, err
		}
		return authorization, nil
	}
	denied := func(stage string, previous *identity.Authorization, since time.Time, enabled bool) (uint64, error) {
		authorization, err := service.AuthorizeFresh(ctx, actorID, identity.PermissionManageEnrollment)
		if authorization != nil || !errors.Is(err, identity.ErrAuthorizationDenied) {
			return 0, fmt.Errorf("fresh-check %s must deny without directory fallback: %w", stage, errors.Join(err, errors.New("unexpected authorization result")))
		}
		state, err := readFreshAuthorizationState(ctx, pool, actorID)
		if err != nil {
			return 0, err
		}
		elapsed := time.Since(since)
		if state.version != previous.Version()+1 || state.role != "" || state.enabled != enabled {
			return 0, fmt.Errorf("fresh-check %s denial did not commit the expected revocation/version", stage)
		}
		if elapsed >= 30*time.Second || !state.now.Before(previous.ExpiresAt()) {
			return 0, fmt.Errorf("fresh-check %s missed the within-cache30s proof window", stage)
		}
		if err := rejectFreshFence(ctx, service, pool, previous, false); err != nil {
			return 0, fmt.Errorf("fresh-check %s stale fence: %w", stage, err)
		}
		if _, err := fmt.Fprintf(evidence, "fresh-authorization %s denied version=%d elapsed=%s stale-fence=denied\n", stage, state.version, elapsed.Round(time.Millisecond)); err != nil {
			return 0, err
		}
		return state.version, nil
	}
	first, err := allowed("membership", 0)
	if err != nil {
		return err
	}
	if err := mutateWithFreshFence(ctx, service, pool, first, "initial-commit", true); err != nil {
		return err
	}
	if _, err := allowed("unchanged-refresh", first.Version()); err != nil {
		return err
	}
	if err := fixture.updateUser(ctx, map[string]any{"firstName": "Fresh", "lastName": "Renamed"}); err != nil {
		return err
	}
	removalStart := time.Now()
	beforeRemoval, err := allowed("display-refresh", first.Version())
	if err != nil {
		return err
	}
	state, err := readFreshAuthorizationState(ctx, pool, actorID)
	if err != nil {
		return err
	}
	if state.display != "Fresh Renamed" {
		return errors.New("fresh-check did not observe the actual Keycloak display change")
	}
	if err := fixture.membership(ctx, false); err != nil {
		return err
	}
	removedVersion, err := denied("group-removal", beforeRemoval, removalStart, true)
	if err != nil {
		return err
	}
	if err := fixture.membership(ctx, true); err != nil {
		return err
	}
	disableStart := time.Now()
	regranted, err := allowed("regrant", removedVersion+1)
	if err != nil {
		return err
	}
	if err := rejectFreshFence(ctx, service, pool, beforeRemoval, true); err != nil {
		return fmt.Errorf("fresh-check regrant revived an old fence: %w", err)
	}
	if err := fixture.updateUser(ctx, map[string]any{"enabled": false}); err != nil {
		return err
	}
	disabledVersion, err := denied("disable", regranted, disableStart, false)
	if err != nil {
		return err
	}
	if err := fixture.updateUser(ctx, map[string]any{"enabled": true}); err != nil {
		return err
	}
	reenabled, err := allowed("re-enable", disabledVersion+1)
	if err != nil {
		return err
	}
	if err := rejectFreshFence(ctx, service, pool, regranted, true); err != nil {
		return fmt.Errorf("fresh-check re-enable revived an old fence: %w", err)
	}
	if err := mutateWithFreshFence(ctx, service, pool, reenabled, "rolled-back", false); err != nil {
		return err
	}
	if err := mutateWithFreshFence(ctx, service, pool, reenabled, "final-commit", true); err != nil {
		return err
	}
	var committed, rolledBack int
	if err := pool.QueryRow(ctx, "SELECT count(*) FILTER (WHERE label IN ('initial-commit', 'final-commit')), count(*) FILTER (WHERE label NOT IN ('initial-commit', 'final-commit')) FROM fresh_authorization_effects").Scan(&committed, &rolledBack); err != nil {
		return err
	}
	if committed != 2 || rolledBack != 0 {
		return errors.New("fresh-check protected mutations did not preserve commit/rollback boundaries")
	}
	_, err = fmt.Fprintf(evidence, "fresh-authorization fenced-mutations committed=%d denied-or-rolled-back=0 old-fences-after-regrant=denied; shared users/groups/public schema untouched\n", committed)
	return err
}

func rollbackFreshTransaction(tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func rejectFreshFence(ctx context.Context, service *identity.Service, pool *pgxpool.Pool, authorization *identity.Authorization, changed bool) (resultErr error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackFreshTransaction(tx)) }()
	err = service.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment)
	if errors.Is(err, identity.ErrAuthorizationChanged) || (!changed && errors.Is(err, identity.ErrAuthorizationDenied)) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("expected version/role fence rejection, not expiry or infrastructure failure: %w", err)
	}
	return errors.New("stale authorization fence unexpectedly accepted")
}

func mutateWithFreshFence(ctx context.Context, service *identity.Service, pool *pgxpool.Pool, authorization *identity.Authorization, label string, commit bool) (resultErr error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackFreshTransaction(tx)) }()
	if err := service.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return fmt.Errorf("fresh-check valid mutation fence: %w", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO fresh_authorization_effects (label) VALUES ($1)", label); err != nil {
		return err
	}
	if commit {
		return tx.Commit(ctx)
	}
	return nil
}
