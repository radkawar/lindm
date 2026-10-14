// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"lindm/internal/identity/identitydb"
)

func TestBrokerLineagePersistsAndRejectsSubjectRemapping(t *testing.T) {
	service, ctx, conn := integrationService(t)
	service.broker = &brokerSource{pool: service.pool, issuer: service.issuer, upstreamIssuer: "https://upstream.example/realms/company", alias: "saml", connector: "original-keycloak"}
	service.directory = service.broker
	subject, original := uuid.NewString(), uuid.NewString()
	if _, err := service.broker.Observe(ctx, subject); !errors.Is(err, ErrSubjectUnqualified) {
		t.Fatalf("unbound broker principal accepted: %v", err)
	}
	proof := &brokerLineage{BrokerIssuer: service.issuer, BrokerSubject: subject, UpstreamProvider: service.broker.upstreamIssuer, UpstreamSubject: original, Connector: "original-keycloak"}
	base, err := service.databaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observation := directoryObservation{Found: true, UserID: subject, Enabled: true, Direct: true, Groups: []string{"/admins"}, Lineage: proof, AcquiredAt: base}
	cookie, denied, err := service.completeLogin(ctx, subject, observation)
	if err != nil || denied || cookie == "" {
		t.Fatalf("broker login denied=%v error=%v", denied, err)
	}
	q := identitydb.New(service.pool)
	row, err := q.GetPrincipalByIssuerSubject(ctx, identitydb.GetPrincipalByIssuerSubjectParams{Issuer: service.issuer, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := q.GetLineageByPrincipalID(ctx, row.ID)
	if err != nil || !proof.matches(lineage) || !lineage.UpstreamObservedAt.Valid {
		t.Fatalf("persisted lineage=%+v error=%v", lineage, err)
	}
	for i, stage := range []string{"disabled", "reenabled", "remapped", "issuer-remapped", "broker-only"} {
		observation.AcquiredAt = base.Add(time.Duration(i+1) * time.Millisecond)
		observation.Enabled = stage != "disabled"
		observation.Direct = stage != "broker-only"
		service.broker.upstreamIssuer = proof.UpstreamProvider
		switch stage {
		case "remapped":
			changed := *proof
			changed.UpstreamSubject = uuid.NewString()
			observation.Lineage = &changed
		case "issuer-remapped":
			changed := *proof
			changed.UpstreamProvider = "https://different-upstream.example/realms/company"
			service.broker.upstreamIssuer = changed.UpstreamProvider
			observation.Lineage = &changed
		default:
			observation.Lineage = proof
		}
		if err := service.withTx(ctx, func(q *identitydb.Queries) error {
			_, err := service.writeObservation(ctx, q, row.ID, observation)
			return err
		}); err != nil {
			t.Fatalf("%s write: %v", stage, err)
		}
		lineage, err = q.GetLineageByPrincipalID(ctx, row.ID)
		if err != nil || !proof.matches(lineage) {
			t.Fatalf("%s changed immutable lineage=%+v error=%v", stage, lineage, err)
		}
		if (stage == "remapped" || stage == "issuer-remapped" || stage == "broker-only") && lineage.UpstreamObservedAt.Valid {
			t.Fatalf("%s advanced upstream freshness from broker import", stage)
		}
		if stage == "disabled" {
			var source string
			if err := conn.QueryRow(ctx, "SELECT deactivation_source FROM principals WHERE id=$1", row.ID).Scan(&source); err != nil {
				t.Fatal(err)
			}
			if source != connectorKeycloak {
				t.Fatalf("broker disable tombstone source=%q", source)
			}
		}
		var revoked bool
		if err := conn.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM sessions WHERE principal_id=$1", row.ID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if !revoked {
			t.Fatalf("%s retained old browser session", stage)
		}
	}
}

func TestBrokerLineageCannotBeClaimedByAnotherBrokerSubject(t *testing.T) {
	service, ctx, conn := integrationService(t)
	service.broker = &brokerSource{pool: service.pool, issuer: service.issuer, upstreamIssuer: "https://upstream.example/realms/company", alias: "saml", connector: "original-keycloak"}
	original := uuid.NewString()
	for i := range 2 {
		subject := uuid.NewString()
		at, err := service.databaseTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cookie, denied, err := service.completeLogin(ctx, subject, directoryObservation{Found: true, UserID: subject, Enabled: true, Direct: true, Groups: []string{"/admins"}, AcquiredAt: at,
			Lineage: &brokerLineage{BrokerIssuer: service.issuer, BrokerSubject: subject, UpstreamProvider: service.broker.upstreamIssuer, UpstreamSubject: original, Connector: "original-keycloak"}})
		if i == 0 && (err != nil || denied || cookie == "") {
			t.Fatalf("first immutable binding: %v", err)
		}
		if i == 1 && err == nil && !denied {
			t.Fatal("same upstream identity accepted a second broker subject")
		}
	}
	var sessions int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE revoked_at IS NULL").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("duplicate upstream binding created %d sessions", sessions)
	}
}

func TestBrokerConflictFencesOlderAuthoritativeObservation(t *testing.T) {
	service, ctx, _ := integrationService(t)
	service.broker = &brokerSource{pool: service.pool, issuer: service.issuer, upstreamIssuer: "https://upstream.example/realms/company", alias: "saml", connector: "original-keycloak"}
	subject := uuid.NewString()
	proof := &brokerLineage{BrokerIssuer: service.issuer, BrokerSubject: subject, UpstreamProvider: service.broker.upstreamIssuer, UpstreamSubject: uuid.NewString(), Connector: service.broker.connector}
	base, err := service.databaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial := directoryObservation{Found: true, UserID: subject, Enabled: true, Direct: true, Groups: []string{"/admins"}, Lineage: proof, AcquiredAt: base}
	if _, denied, err := service.completeLogin(ctx, subject, initial); err != nil || denied {
		t.Fatalf("initial authority: denied=%v err=%v", denied, err)
	}
	row, err := identitydb.New(service.pool).GetPrincipalByIssuerSubject(ctx, identitydb.GetPrincipalByIssuerSubjectParams{Issuer: service.issuer, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	denial := initial
	denial.Direct = false
	denial.AcquiredAt = base.Add(2 * time.Millisecond)
	if err := applyAuthorizationObservation(ctx, service, row.ID, denial); err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{time.Millisecond, 2 * time.Millisecond} {
		delayed := initial
		delayed.AcquiredAt = base.Add(age)
		if err := applyAuthorizationObservation(ctx, service, row.ID, delayed); !errors.Is(err, errStaleObservation) {
			t.Fatalf("older/equal observation restored conflict authority: %v", err)
		}
		if _, denied, err := service.completeLogin(ctx, subject, delayed); !errors.Is(err, errStaleObservation) || denied {
			t.Fatalf("delayed login restored conflict authority: denied=%v err=%v", denied, err)
		}
	}
	snapshot, err := service.loadSnapshot(ctx, row.ID)
	if err != nil || snapshot.Observed || snapshot.Enabled || len(snapshot.Groups) != 0 {
		t.Fatalf("conflict regained stale authority: %+v %v", snapshot, err)
	}
	fresh := initial
	fresh.AcquiredAt = base.Add(3 * time.Millisecond)
	if err := applyAuthorizationObservation(ctx, service, row.ID, fresh); err != nil {
		t.Fatalf("newer original authority could not recover: %v", err)
	}
}
