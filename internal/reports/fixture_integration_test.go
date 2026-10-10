//go:build integration

package reports

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func reportFixture(t *testing.T) (*Service, context.Context, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool, _ := testdb.Open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	t.Cleanup(cancel)
	identities, err := identity.New(ctx, pool, identity.Config{Local: true, PublicURL: "https://reports.example.test", HTTPClient: &http.Client{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := identities.Close(); err != nil {
			t.Error(err)
		}
	})
	enrollment, err := identities.BootstrapLocalOwner(ctx, "report-owner")
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, identities, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture covers RPC business authorization against real local identity
	// and PostgreSQL; it does not claim a browser session/WebAuthn ceremony.
	ctx = identity.WithPrincipal(ctx, identity.Principal{ID: enrollment.AccountID, Role: identity.RoleOwner})
	return service, ctx, pool, enrollment.AccountID
}

func downloadArtifact(t *testing.T, s *Service, ctx context.Context, id string) ([]byte, *integrationsv1.ReportSignedManifest) {
	t.Helper()
	var content bytes.Buffer
	var envelope *integrationsv1.ReportSignedManifest
	for index := uint32(0); ; {
		response, err := s.DownloadReportArtifact(ctx, connect.NewRequest(&integrationsv1.DownloadReportArtifactRequest{ArtifactId: id, ChunkIndex: index}))
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Msg.GetData()) > chunkBytes {
			t.Fatal("unbounded report chunk")
		}
		if _, err := content.Write(response.Msg.GetData()); err != nil {
			t.Fatal(err)
		}
		envelope = response.Msg.GetSignedManifest()
		if response.Msg.GetFinished() {
			break
		}
		if response.Msg.GetNextChunkIndex() != index+1 {
			t.Fatal("non-contiguous chunk index")
		}
		index++
	}
	return content.Bytes(), envelope
}
