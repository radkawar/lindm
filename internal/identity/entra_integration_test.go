//go:build integration

package identity

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// This test uses real PostgreSQL and a TLS Graph fixture, not a live Entra tenant.
func TestEntraPersistedRevocationAndWorkerFences(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	tenant, subject, group := uuid.New(), uuid.New(), uuid.New()
	issuer, err := EntraIssuer(tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	svc.issuer, svc.entraTenant, svc.adminGroups = issuer, tenant, []string{group.String()}
	var state atomic.Int32
	source, _ := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if state.Load() == 4 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, subject.String()) {
			if state.Load() == 3 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeGraphJSON(t, w, fmt.Sprintf(`{"id":%q,"accountEnabled":%t}`, subject, state.Load() != 2))
		} else if state.Load() == 1 {
			writeGraphJSON(t, w, `{"value":[]}`)
		} else {
			writeGraphJSON(t, w, fmt.Sprintf(`{"value":[{"id":%q}]}`, group))
		}
	})
	svc.directory = source
	row := insertObservedPrincipal(t, ctx, svc, subject)
	createAuthorizationEffects(t, ctx, conn)
	grant, err := svc.AuthorizeFresh(ctx, row.ID, PermissionRevokeDevice)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)
	for _, step := range []int32{1, 2, 3, 4} {
		state.Store(step)
		if next, err := svc.AuthorizeFresh(ctx, row.ID, PermissionRevokeDevice); err == nil || next != nil {
			t.Fatalf("state %d granted fresh authority", step)
		}
		if step != 4 {
			if err := commitAuthorizedEffect(ctx, svc, grant, uuid.New(), PermissionRevokeDevice); err == nil {
				t.Fatalf("state %d accepted old worker approval", step)
			}
		}
		if step == 2 || step == 3 {
			snapshot, err := svc.loadSnapshot(ctx, row.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !snapshot.Deactivated || snapshot.DeactivationSource != connectorEntra || snapshot.AuthorizationRole != "" {
				t.Fatalf("Entra denial not persisted: %+v", snapshot)
			}
		}
		state.Store(0)
		fresh, err := svc.AuthorizeFresh(ctx, row.ID, PermissionRevokeDevice)
		if err != nil {
			t.Fatal(err)
		}
		if step != 4 && fresh.version <= grant.version {
			t.Fatal("authority restoration revived an old version")
		}
		grant = fresh
	}
}
