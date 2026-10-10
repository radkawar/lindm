package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"lindm/internal/identity/identitydb"
)

func TestBrokerSourceIntersectsOriginalAuthority(t *testing.T) {
	brokerID, originalID := uuid.NewString(), uuid.NewString()
	var state atomic.Int32
	var originalReads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			if _, err := fmt.Fprint(w, `{"access_token":"directory-token","token_type":"Bearer","expires_in":300}`); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer directory-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		isOriginal := strings.HasPrefix(r.URL.Path, "/admin/realms/original/")
		if isOriginal {
			originalReads.Add(1)
			if state.Load() == 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		var body string
		switch r.URL.Path {
		case "/admin/realms/broker/users/" + brokerID:
			body = fmt.Sprintf(`{"id":%q,"username":"renamed-import","enabled":%t}`, brokerID, state.Load() != 4)
		case "/admin/realms/broker/users/" + brokerID + "/federated-identity":
			subject := originalID
			if state.Load() == 5 {
				subject = uuid.NewString()
			}
			body = fmt.Sprintf(`[{"identityProvider":"saml","userId":%q}]`, subject)
			if state.Load() == 6 {
				body = `[]`
			}
			if state.Load() == 7 {
				body = fmt.Sprintf(`[{"identityProvider":"saml","userId":%q},{"identityProvider":"other","userId":%q}]`, subject, subject)
			}
		case "/admin/realms/broker/users/" + brokerID + "/groups":
			body = `[{"path":"/admins"},{"path":"/broker-only"}]`
			if state.Load() == 8 {
				body = `[]`
			}
		case "/admin/realms/original/users/" + originalID:
			body = fmt.Sprintf(`{"id":%q,"username":"same-recycled-email","enabled":%t}`, originalID, state.Load() != 2)
		case "/admin/realms/original/users/" + originalID + "/federated-identity":
			body = `[]`
		case "/admin/realms/original/users/" + originalID + "/groups":
			body = `[{"path":"/admins"},{"path":"/upstream-only"}]`
			if state.Load() == 1 {
				body = `[]`
			}
		default:
			t.Errorf("unexpected directory path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := fmt.Fprint(w, body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	newSource := func(realm string) *keycloakSource {
		source, err := newKeycloakSource(t.Context(), server.URL+"/realms/"+realm, "directory", "secret", server.URL+"/token", server.Client(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	source := &brokerSource{issuer: server.URL + "/realms/broker", upstreamIssuer: server.URL + "/realms/original", alias: "saml", connector: "original-keycloak", broker: newSource("broker"), upstream: newSource("original")}
	proof := &brokerLineage{BrokerIssuer: source.issuer, BrokerSubject: brokerID, UpstreamProvider: source.upstreamIssuer, UpstreamSubject: originalID, Connector: source.connector}
	for _, tc := range []struct {
		name                           string
		state                          int32
		enabled, direct, grant, failed bool
	}{
		{"intersection", 0, true, true, true, false},
		{"original-group-removal", 1, true, true, false, false},
		{"original-disable", 2, false, true, false, false},
		{"healthy-broker-original-outage", 3, false, false, false, true},
		{"broker-disable", 4, false, true, false, false},
		{"immutable-remap", 5, false, false, false, false},
		{"missing-link", 6, false, false, false, false},
		{"ambiguous-link", 7, false, false, false, false},
		{"broker-group-removal", 8, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state.Store(tc.state)
			before := originalReads.Load()
			observation, err := source.ObserveLogin(t.Context(), brokerID, proof)
			if (err != nil) != tc.failed || observation.Enabled != tc.enabled || observation.Direct != tc.direct {
				t.Fatalf("observation=%+v error=%v", observation, err)
			}
			if tc.grant {
				if len(observation.Groups) != 1 || observation.Groups[0] != "/admins" {
					t.Fatalf("union widened authority: %+v", observation)
				}
			} else if len(observation.Groups) != 0 {
				t.Fatalf("denied source retained groups: %+v", observation)
			}
			if !observation.AcquiredAt.IsZero() {
				t.Fatal("broker supplied freshness instead of database acquisition time")
			}
			if tc.state <= 4 && originalReads.Load() == before {
				t.Fatal("healthy broker substituted for original directory read")
			}
		})
	}
}

func TestBrokerLineageRequiresExactConfiguredImmutableSubjects(t *testing.T) {
	brokerID, originalID := uuid.NewString(), "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	source := &brokerSource{issuer: "https://idp.example/realms/broker", upstreamIssuer: "https://idp.example/realms/original", alias: "configured-saml", connector: "original"}
	proof := brokerLineage{BrokerIssuer: source.issuer, BrokerSubject: brokerID, UpstreamProvider: source.upstreamIssuer, UpstreamSubject: originalID, Connector: source.connector}
	if !source.qualified(&proof, brokerID) {
		t.Fatal("exact lineage rejected")
	}
	for _, mutate := range []func(*brokerLineage){
		func(p *brokerLineage) { p.BrokerIssuer = "https://other.example" },
		func(p *brokerLineage) { p.BrokerSubject = uuid.NewString() },
		func(p *brokerLineage) { p.UpstreamProvider = "different-alias" },
		func(p *brokerLineage) { p.UpstreamSubject = "recycled@example.test" },
		func(p *brokerLineage) { p.UpstreamSubject = strings.ToUpper(originalID) },
		func(p *brokerLineage) { p.Connector = "different-connector" },
	} {
		changed := proof
		mutate(&changed)
		if source.qualified(&changed, brokerID) {
			t.Fatalf("accepted changed lineage %+v", changed)
		}
		if _, err := source.ObserveLogin(context.Background(), brokerID, &changed); err == nil {
			t.Fatal("unqualified lineage reached directory access")
		}
	}
	if source.qualified(nil, brokerID) {
		t.Fatal("missing signed lineage accepted")
	}
}

func TestBrokerUsesCommonFreshnessBound(t *testing.T) {
	issuer, subject, original := "https://broker.example/realms/company", uuid.NewString(), uuid.NewString()
	service := &Service{issuer: issuer, broker: &brokerSource{issuer: issuer, upstreamIssuer: "https://upstream.example/realms/company", alias: "saml", connector: "original"}}
	now := time.Now()
	row := identitydb.Principal{Issuer: issuer, Subject: subject, DirectoryEnabled: true}
	lineage := identitydb.PrincipalLineage{BrokerIssuer: issuer, BrokerSubject: subject, UpstreamProvider: service.broker.upstreamIssuer, UpstreamSubject: original, DirectoryConnector: "original", UpstreamObservedAt: pgStamp(now, true)}
	snapshot := service.snapshotFrom(row, lineage, []string{"/admins"})
	policy := mappedPolicy(t, "/admins")
	if decideAccess(now, issuer, policy, snapshot).Kind != accessOK || !needsRefresh(now.Add(30*time.Second), snapshot) {
		t.Fatal("broker did not reuse the 30-second refresh contract")
	}
	if decideAccess(now.Add(60*time.Second+time.Nanosecond), issuer, policy, snapshot).Kind == accessOK {
		t.Fatal("healthy broker imported grant masked stale upstream authority")
	}
	snapshot.RefreshFailed = true
	if decideAccess(now, issuer, policy, snapshot).Kind == accessOK {
		t.Fatal("healthy broker imported grant masked failed upstream read")
	}
}
