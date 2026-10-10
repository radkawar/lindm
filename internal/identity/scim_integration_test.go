//go:build integration

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

// This source is only the credential administrator's test authority. Every SCIM
// request, SQL constraint, lifecycle transaction and worker fence below is real;
// these tests do not claim qualification of an upstream directory service.
type scimAdministratorSource struct{}

func (scimAdministratorSource) Observe(_ context.Context, subject string) (directoryObservation, error) {
	return directoryObservation{Found: true, UserID: subject, Enabled: true, Direct: true, Groups: []string{"/admins"}}, nil
}

type scimFixture struct {
	s          *Service
	ctx        context.Context
	conn       *pgx.Conn
	config     *configv1.SCIMConfig
	cookie     string
	token      string
	otherToken string
	subject    string
}

func newSCIMFixture(t *testing.T) scimFixture {
	t.Helper()
	s, ctx, conn := integrationService(t)
	var err error
	s.rules, err = protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	s.publicOrigin = localTestOrigin
	s.directory = scimAdministratorSource{}
	subject := "immutable-provider-object:017"
	cfg := &configv1.SCIMConfig{Connectors: []*configv1.SCIMConnector{
		{Id: "primary", Correlations: []*configv1.SCIMCorrelation{{ProviderId: "provider-017", Issuer: s.issuer, Subject: subject}}},
		{Id: "other", Correlations: []*configv1.SCIMCorrelation{{ProviderId: "provider-018", Issuer: s.issuer, Subject: "immutable-provider-object:018"}}},
	}}
	if err = s.configureSCIM(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ownerSubject := uuid.New()
	owner := insertObservedPrincipal(t, ctx, s, ownerSubject)
	if _, err = conn.Exec(ctx, "UPDATE principals SET pinned_role='owner' WHERE id=$1", owner.ID); err != nil {
		t.Fatal(err)
	}
	if err = applyAuthorizationObservation(ctx, s, owner.ID, directoryObs(ownerSubject, authorizationDatabaseTime(t, ctx, s), true)); err != nil {
		t.Fatal(err)
	}
	fixture := scimFixture{s: s, ctx: ctx, conn: conn, config: cfg, cookie: insertLiveSession(t, ctx, s, owner.ID), subject: subject}
	fixture.token = fixture.rotate(t, "primary")
	fixture.otherToken = fixture.rotate(t, "other")
	return fixture
}

func (f scimFixture) rotate(t *testing.T, id string) string {
	t.Helper()
	response := authAccountRequest(t, f.s, http.MethodPost, "/auth/scim/credentials/rotate", f.cookie, &authv1.RotateSCIMCredentialRequest{ConnectorId: id})
	if response.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", response.Code, response.Body.String())
	}
	issued := &authv1.SCIMCredential{}
	if err := protojson.Unmarshal(response.Body.Bytes(), issued); err != nil {
		t.Fatal(err)
	}
	if issued.GetConnectorId() != id || len(issued.GetBearerToken()) != 43 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid or cacheable credential response")
	}
	return issued.GetBearerToken()
}

func scimRequest(s *Service, method, path, token, etag string, body any) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			response := httptest.NewRecorder()
			response.WriteHeader(http.StatusInternalServerError)
			return response
		}
	}
	request := httptest.NewRequest(method, localTestOrigin+scimBase+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/scim+json")
	request.Header.Set("Authorization", "Bearer "+token)
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	return response
}

func scimResponse(t *testing.T, response *httptest.ResponseRecorder, status int) scimDocument {
	t.Helper()
	if response.Code != status {
		t.Fatalf("SCIM status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status == http.StatusNoContent {
		return nil
	}
	var doc scimDocument
	if err := json.Unmarshal(response.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func scimUser(externalID, username string, active bool) scimDocument {
	return scimDocument{"schemas": []any{scimCore + "User"}, "externalId": externalID, "userName": username, "active": active, "emails": []any{map[string]any{"value": username}}}
}

func scimPatch(path string, value any) scimDocument {
	return scimDocument{"schemas": []any{scimMessages + "PatchOp"}, "Operations": []any{map[string]any{"op": "replace", "path": path, "value": value}}}
}

func TestSCIMImmutableCorrelationCredentialsAndIsolation(t *testing.T) {
	f := newSCIMFixture(t)
	unknown := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("not-configured", "recycled@example.test", true))
	scimResponse(t, unknown, http.StatusBadRequest)
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "recycled@example.test", true))
	user := scimResponse(t, created, http.StatusCreated)
	id, ok := user["id"].(string)
	if !ok {
		t.Fatal("SCIM user lacks string id")
	}
	var issuer, subject string
	if err := f.conn.QueryRow(f.ctx, `SELECT p.issuer,p.subject FROM scim_resources r JOIN principals p ON p.id=r.principal_id WHERE r.id=$1`, id).Scan(&issuer, &subject); err != nil {
		t.Fatal(err)
	}
	if issuer != f.s.issuer || subject != f.subject {
		t.Fatal("correlation was not exact configured immutable identity")
	}
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users/"+id, f.otherToken, "", nil), http.StatusNotFound)
	scimResponse(t, scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "new@example.test", true)), http.StatusConflict)
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, created.Header().Get("ETag"), scimPatch("externalId", "provider-018")), http.StatusBadRequest)
	renamed := scimRequest(f.s, http.MethodPut, "Users/"+id, f.token, created.Header().Get("ETag"), scimUser("provider-017", "renamed@example.test", true))
	scimResponse(t, renamed, http.StatusOK)
	filtered := scimResponse(t, scimRequest(f.s, http.MethodGet, "Users?filter="+url.QueryEscape(`userName eq "renamed@example.test"`), f.token, "", nil), http.StatusOK)
	if filtered["totalResults"] != float64(1) {
		t.Fatal("renamed userName equality filter failed")
	}
	filtered = scimResponse(t, scimRequest(f.s, http.MethodGet, "Users?filter="+url.QueryEscape(`externalId eq "provider-017"`), f.token, "", nil), http.StatusOK)
	if filtered["totalResults"] != float64(1) {
		t.Fatal("immutable externalId equality filter failed")
	}
	if err := f.conn.QueryRow(f.ctx, `SELECT p.subject FROM scim_resources r JOIN principals p ON p.id=r.principal_id WHERE r.id=$1`, id).Scan(&subject); err != nil || subject != f.subject {
		t.Fatalf("rename rebound identity: %s %v", subject, err)
	}
	fresh := f.rotate(t, "primary")
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", f.token, "", nil), http.StatusUnauthorized)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", fresh, "", nil), http.StatusOK)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", f.cookie, "", nil), http.StatusUnauthorized)
	var digest []byte
	if err := f.conn.QueryRow(f.ctx, "SELECT credential_hash FROM scim_connectors WHERE id='primary'").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, domainHash(scimCredentialDomain, fresh)) || bytes.Equal(digest, []byte(fresh)) {
		t.Fatal("credential is not hash-only")
	}
	// Configuration removal revokes credentials permanently; re-adding does not
	// resurrect a previously issued bearer, even with the same fingerprint.
	if err := f.s.configureSCIM(f.ctx, &configv1.SCIMConfig{Connectors: f.config.Connectors[1:]}); err != nil {
		t.Fatal(err)
	}
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", fresh, "", nil), http.StatusUnauthorized)
	if err := f.s.configureSCIM(f.ctx, f.config); err != nil {
		t.Fatal(err)
	}
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", fresh, "", nil), http.StatusUnauthorized)
}

func TestSCIMTombstoneReactivationAndWorkerFence(t *testing.T) {
	f := newSCIMFixture(t)
	createAuthorizationEffects(t, f.ctx, f.conn)
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", false))
	user := scimResponse(t, created, http.StatusCreated)
	id, ok := user["id"].(string)
	if !ok {
		t.Fatal("SCIM user lacks string id")
	}
	var actor uuid.UUID
	if err := f.conn.QueryRow(f.ctx, "SELECT principal_id FROM scim_resources WHERE id=$1", id).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	observe := func() directoryObservation {
		return directoryObservation{Found: true, UserID: f.subject, Direct: true, Enabled: true, Groups: []string{"/admins"}, AcquiredAt: authorizationDatabaseTime(t, f.ctx, f.s)}
	}
	if _, denied, err := f.s.completeLogin(f.ctx, f.subject, observe()); err != nil || !denied {
		t.Fatalf("tombstone failed to deny stale login claims: denied=%v err=%v", denied, err)
	}
	stale := observe()
	activated := scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, created.Header().Get("ETag"), scimPatch("active", true))
	scimResponse(t, activated, http.StatusOK)
	snapshot, err := f.s.loadSnapshot(f.ctx, actor)
	if err != nil || snapshot.Deactivated || snapshot.Observed || snapshot.Enabled || len(snapshot.Groups) != 0 || snapshot.AuthorizationRole != "" {
		t.Fatalf("SCIM reactivation granted authority: %+v %v", snapshot, err)
	}
	if err := applyAuthorizationObservation(f.ctx, f.s, actor, stale); !errors.Is(err, errStaleObservation) {
		t.Fatalf("pre-reactivation observation crossed lifecycle fence: %v", err)
	}
	if err := applyAuthorizationObservation(f.ctx, f.s, actor, observe()); err != nil {
		t.Fatal(err)
	}
	grant := authorizationFromSnapshot(t, f.ctx, f.s, actor)
	cookie := insertLiveSession(t, f.ctx, f.s, actor)
	assertAuthorizationEffect(t, f.ctx, f.conn, f.s, grant, nil)
	disabled := scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, activated.Header().Get("ETag"), scimPatch("active", false))
	scimResponse(t, disabled, http.StatusOK)
	var revoked bool
	if err := f.conn.QueryRow(f.ctx, "SELECT revoked_at IS NOT NULL FROM sessions WHERE token_hash=$1", sessionHash(cookie)).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("SCIM did not revoke session transactionally: %v %v", revoked, err)
	}
	assertAuthorizationEffect(t, f.ctx, f.conn, f.s, grant, ErrAuthorizationChanged)
	if err := applyAuthorizationObservation(f.ctx, f.s, actor, observe()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = f.s.loadSnapshot(f.ctx, actor)
	if err != nil || !snapshot.Deactivated || snapshot.AuthorizationRole != "" || len(snapshot.Groups) != 0 {
		t.Fatalf("directory resurrected SCIM tombstone: %+v %v", snapshot, err)
	}
	deleted := scimRequest(f.s, http.MethodDelete, "Users/"+id, f.token, disabled.Header().Get("ETag"), nil)
	scimResponse(t, deleted, http.StatusNoContent)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users/"+id, f.token, "", nil), http.StatusNotFound)
	recreated := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "new-name@example.test", true))
	reprovisioned := scimResponse(t, recreated, http.StatusCreated)
	if reprovisioned["id"] != id {
		t.Fatal("reprovisioning replaced immutable resource binding")
	}
	snapshot, err = f.s.loadSnapshot(f.ctx, actor)
	if err != nil || snapshot.Observed || snapshot.AuthorizationRole != "" {
		t.Fatalf("reprovisioning manufactured freshness: %+v %v", snapshot, err)
	}
	if err := applyAuthorizationObservation(f.ctx, f.s, actor, observe()); err != nil {
		t.Fatal(err)
	}
	assertAuthorizationEffect(t, f.ctx, f.conn, f.s, grant, ErrAuthorizationChanged)
}

func TestSCIMETagMembershipAndConcurrentUpdates(t *testing.T) {
	f := newSCIMFixture(t)
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", true))
	user := scimResponse(t, created, http.StatusCreated)
	id, ok := user["id"].(string)
	if !ok {
		t.Fatal("SCIM user lacks string id")
	}
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, "", scimPatch("active", false)), http.StatusPreconditionRequired)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var workers sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		workers.Add(1)
		go func(name string) {
			defer workers.Done()
			<-start
			results <- scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, created.Header().Get("ETag"), scimPatch("displayName", name))
		}(name)
	}
	close(start)
	workers.Wait()
	close(results)
	statuses := map[int]int{}
	for result := range results {
		statuses[result.Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusPreconditionFailed] != 1 {
		t.Fatalf("concurrent stale writes committed: %v", statuses)
	}
	groupBody := scimDocument{"schemas": []any{scimCore + "Group"}, "externalId": "group-1", "displayName": "/admins", "members": []any{map[string]any{"value": id}}}
	createdGroup := scimRequest(f.s, http.MethodPost, "Groups", f.token, "", groupBody)
	group := scimResponse(t, createdGroup, http.StatusCreated)
	groupID := scimField[string](t, group, "id")
	var grants int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM principal_groups g JOIN scim_resources r ON r.principal_id=g.principal_id WHERE r.id=$1`, id).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("SCIM membership became authorization: count=%d err=%v", grants, err)
	}
	foreign := scimRequest(f.s, http.MethodPost, "Users", f.otherToken, "", scimUser("provider-018", "other@example.test", true))
	foreignUser := scimResponse(t, foreign, http.StatusCreated)
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Groups/"+groupID, f.token, createdGroup.Header().Get("ETag"), scimPatch("members", []any{map[string]any{"value": foreignUser["id"]}})), http.StatusBadRequest)
	remove := scimDocument{"schemas": []any{scimMessages + "PatchOp"}, "Operations": []any{map[string]any{"op": "remove", "path": fmt.Sprintf(`members[value eq "%s"]`, id)}}}
	removed := scimRequest(f.s, http.MethodPatch, "Groups/"+groupID, f.token, createdGroup.Header().Get("ETag"), remove)
	updated := scimResponse(t, removed, http.StatusOK)
	if len(scimField[[]any](t, updated, "members")) != 0 {
		t.Fatal("filtered member removal failed")
	}
	oversized := make([]any, scimMaxMembers+1)
	for i := range oversized {
		oversized[i] = map[string]any{"value": id}
	}
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Groups/"+groupID, f.token, removed.Header().Get("ETag"), scimPatch("members", oversized)), http.StatusBadRequest)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users?count=0", f.token, "", nil), http.StatusOK)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users?startIndex=1000002", f.token, "", nil), http.StatusBadRequest)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users?filter="+url.QueryEscape(`userName co "user"`), f.token, "", nil), http.StatusBadRequest)
	for _, path := range []string{"ServiceProviderConfig", "Schemas", "ResourceTypes", "Schemas/" + scimCore + "User", "ResourceTypes/Group"} {
		scimResponse(t, scimRequest(f.s, http.MethodGet, path, f.token, "", nil), http.StatusOK)
	}
}

func TestSCIMLifecycleSerializesInFlightObservationAndWorker(t *testing.T) {
	for _, operation := range []string{"observation", "worker"} {
		t.Run(operation, func(t *testing.T) {
			f := newSCIMFixture(t)
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			createAuthorizationEffects(t, ctx, f.conn)
			created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", true))
			user := scimResponse(t, created, http.StatusCreated)
			var actor uuid.UUID
			if err := f.conn.QueryRow(ctx, "SELECT principal_id FROM scim_resources WHERE id=$1", user["id"]).Scan(&actor); err != nil {
				t.Fatal(err)
			}
			observation := directoryObservation{Found: true, UserID: f.subject, Direct: true, Enabled: true, Groups: []string{"/admins"}, AcquiredAt: authorizationDatabaseTime(t, ctx, f.s)}
			if err := applyAuthorizationObservation(ctx, f.s, actor, observation); err != nil {
				t.Fatal(err)
			}
			grant := authorizationFromSnapshot(t, ctx, f.s, actor)
			observation.AcquiredAt = authorizationDatabaseTime(t, ctx, f.s)
			tx, err := f.conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			q := identitydb.New(tx)
			if _, err := q.GetPrincipalForUpdate(ctx, actor); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			if operation == "observation" {
				go func() { result <- applyAuthorizationObservation(ctx, f.s, actor, observation) }()
			} else {
				go func() { result <- commitAuthorizedEffect(ctx, f.s, grant, uuid.New(), PermissionRevokeDevice) }()
			}
			waitForAuthorizationBlock(t, ctx, f.s, int32(f.conn.PgConn().PID()), result)
			if err := f.s.scimLifecycle(ctx, q, actor, false); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			want := errStaleObservation
			if operation == "worker" {
				want = ErrAuthorizationChanged
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("in-flight %s crossed SCIM fence: %v, want %v", operation, err, want)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestSCIMLifecycleFailureRollsBackResourceAndRevocation(t *testing.T) {
	f := newSCIMFixture(t)
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", true))
	user := scimResponse(t, created, http.StatusCreated)
	id := scimField[string](t, user, "id")
	var actor uuid.UUID
	if err := f.conn.QueryRow(f.ctx, "SELECT principal_id FROM scim_resources WHERE id=$1", id).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if err := applyAuthorizationObservation(f.ctx, f.s, actor, directoryObservation{Found: true, UserID: f.subject, Direct: true, Enabled: true, Groups: []string{"/admins"}, AcquiredAt: authorizationDatabaseTime(t, f.ctx, f.s)}); err != nil {
		t.Fatal(err)
	}
	cookie := insertLiveSession(t, f.ctx, f.s, actor)
	if _, err := f.conn.Exec(f.ctx, `CREATE FUNCTION scim_test_reject_audit() RETURNS trigger AS $$
	BEGIN
	  IF NEW.action = 'identity.scim_lifecycle' THEN RAISE EXCEPTION 'forced SCIM audit failure'; END IF;
	  RETURN NEW;
	END $$ LANGUAGE plpgsql;
	CREATE TRIGGER scim_test_reject_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION scim_test_reject_audit()`); err != nil {
		t.Fatal(err)
	}
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, created.Header().Get("ETag"), scimPatch("active", false)), http.StatusServiceUnavailable)
	current := scimRequest(f.s, http.MethodGet, "Users/"+id, f.token, "", nil)
	document := scimResponse(t, current, http.StatusOK)
	if document["active"] != true || current.Header().Get("ETag") != created.Header().Get("ETag") {
		t.Fatal("failed lifecycle transaction changed resource or ETag")
	}
	var active bool
	if err := f.conn.QueryRow(f.ctx, `SELECT s.revoked_at IS NULL AND p.deactivated_at IS NULL AND p.authorization_role='admin'
	FROM sessions s JOIN principals p ON p.id=s.principal_id WHERE s.token_hash=$1`, sessionHash(cookie)).Scan(&active); err != nil || !active {
		t.Fatalf("failed lifecycle transaction partially revoked authority: active=%v err=%v", active, err)
	}
}

func TestSCIMDeleteInvalidatesContainingGroupETag(t *testing.T) {
	f := newSCIMFixture(t)
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", true))
	user := scimResponse(t, created, http.StatusCreated)
	id := scimField[string](t, user, "id")
	groupCreated := scimRequest(f.s, http.MethodPost, "Groups", f.token, "", scimDocument{
		"schemas": []any{scimCore + "Group"}, "displayName": "provisioned", "members": []any{map[string]any{"value": id}},
	})
	group := scimResponse(t, groupCreated, http.StatusCreated)
	groupID := scimField[string](t, group, "id")
	scimResponse(t, scimRequest(f.s, http.MethodDelete, "Users/"+id, f.token, created.Header().Get("ETag"), nil), http.StatusNoContent)
	current := scimRequest(f.s, http.MethodGet, "Groups/"+groupID, f.token, "", nil)
	group = scimResponse(t, current, http.StatusOK)
	if len(scimField[[]any](t, group, "members")) != 0 || current.Header().Get("ETag") == groupCreated.Header().Get("ETag") {
		t.Fatal("user deletion did not remove membership and invalidate group ETag")
	}
	scimResponse(t, scimRequest(f.s, http.MethodPatch, "Groups/"+groupID, f.token, groupCreated.Header().Get("ETag"), scimPatch("displayName", "stale")), http.StatusPreconditionFailed)
	scimResponse(t, scimRequest(f.s, http.MethodDelete, "Groups/"+groupID, f.token, current.Header().Get("ETag"), nil), http.StatusNoContent)
}

func TestSCIMConfigurationCannotRebindOrAmbiguouslyCorrelate(t *testing.T) {
	f := newSCIMFixture(t)
	remapped := &configv1.SCIMConfig{Connectors: []*configv1.SCIMConnector{
		{Id: "primary", Correlations: []*configv1.SCIMCorrelation{{ProviderId: "provider-017", Issuer: f.s.issuer, Subject: "replacement-subject"}}},
	}}
	if err := f.s.configureSCIM(f.ctx, remapped); err == nil {
		t.Fatal("configuration rebound an immutable correlation")
	}
	ambiguous := &configv1.SCIMConfig{Connectors: []*configv1.SCIMConnector{
		f.config.Connectors[0],
		{Id: "replacement", Correlations: []*configv1.SCIMCorrelation{{ProviderId: "different-provider", Issuer: f.s.issuer, Subject: f.subject}}},
	}}
	if err := f.s.configureSCIM(f.ctx, ambiguous); err == nil {
		t.Fatal("two connectors claimed the same issuer/subject")
	}
	// Both rejected startup transactions leave existing scoped credentials intact.
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", f.token, "", nil), http.StatusOK)
	scimResponse(t, scimRequest(f.s, http.MethodGet, "Users", f.otherToken, "", nil), http.StatusOK)
}

func TestSCIMRotationFencesAlreadyWaitingOldBearer(t *testing.T) {
	f := newSCIMFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	created := scimRequest(f.s, http.MethodPost, "Users", f.token, "", scimUser("provider-017", "user@example.test", true))
	user := scimResponse(t, created, http.StatusCreated)
	id := scimField[string](t, user, "id")
	tx, err := f.conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	if _, err := q.LockSCIMConnector(ctx, "primary"); err != nil {
		t.Fatal(err)
	}
	pending := make(chan error, 1)
	go func() {
		result := scimRequest(f.s, http.MethodPatch, "Users/"+id, f.token, created.Header().Get("ETag"), scimPatch("active", false))
		if result.Code != http.StatusUnauthorized {
			pending <- fmt.Errorf("old bearer accepted after rotation: status %d", result.Code)
			return
		}
		pending <- nil
	}()
	waitForAuthorizationBlock(t, ctx, f.s, int32(f.conn.PgConn().PID()), pending)
	replacement, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RotateSCIMCredential(ctx, identitydb.RotateSCIMCredentialParams{ID: "primary", CredentialHash: domainHash(scimCredentialDomain, replacement)}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pending:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	current := scimRequest(f.s, http.MethodGet, "Users/"+id, replacement, "", nil)
	resource := scimResponse(t, current, http.StatusOK)
	if resource["active"] != true || current.Header().Get("ETag") != created.Header().Get("ETag") {
		t.Fatal("old bearer changed resource after rotation committed")
	}
}

// scimField returns a typed SCIM response field or fails the test.
func scimField[T any](t *testing.T, document map[string]any, key string) T {
	t.Helper()
	value, ok := document[key].(T)
	if !ok {
		t.Fatalf("SCIM response field %q has unexpected type %T", key, document[key])
	}
	return value
}
