//go:build integration

package integrations

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/identity"
	"lindm/internal/integrations/integrationdb"
	"lindm/internal/testdb"
)

type integrationFixture struct {
	service *Service
	pool    *pgxpool.Pool
	conn    *pgx.Conn
	ctx     context.Context
	actor   identity.Principal
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	pool, conn := testdb.Open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	t.Cleanup(cancel)
	auth, err := identity.New(ctx, pool, identity.Config{Local: true, PublicURL: "https://admin.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := auth.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := New(pool, auth, bytes.Repeat([]byte{0x72}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	var deployment uuid.UUID
	if err = conn.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity WHERE id").Scan(&deployment); err != nil {
		t.Fatal(err)
	}
	issuer := "urn:lindm:local:" + deployment.String()
	if _, err = conn.Exec(ctx, "INSERT INTO principals(id,issuer,subject,authorization_role,directory_enabled) VALUES ($1,$2,$3,'owner',true)", id, issuer, id.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "INSERT INTO local_accounts(id,username,role) VALUES ($1,$2,'owner')", id, "integration-"+id.String()); err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{ID: id, Issuer: issuer, Subject: id.String(), Role: identity.RoleOwner}
	return &integrationFixture{service: s, pool: pool, conn: conn, ctx: identity.WithPrincipal(ctx, actor), actor: actor}
}
func (f *integrationFixture) target(t *testing.T, kind int32, endpoint, ca string, secret []byte) integrationdb.IntegrationDestination {
	t.Helper()
	id := uuid.New()
	encrypted := []byte{}
	if kind == 1 {
		encrypted = f.service.aead.Seal(nil, nil, secret, id[:])
	}
	row, err := integrationdb.New(f.pool).CreateDestination(f.ctx, integrationdb.CreateDestinationParams{ID: id, DisplayName: "Integration receiver", Kind: kind, Endpoint: endpoint, PinnedCaPem: ca, Enabled: true, SecretCiphertext: encrypted})
	if err != nil {
		t.Fatal(err)
	}
	return row
}
func (f *integrationFixture) event(t *testing.T, resource string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.conn.Exec(f.ctx, "INSERT INTO audit_events(id,action,resource_id,reason) VALUES($1,'device.result',$2,'super-secret-free-form-reason')", id, resource); err != nil {
		t.Fatal(err)
	}
	return id
}
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
