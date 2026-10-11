//go:build linux && integration

package vmlab

import (
	"context"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
	"lindm/internal/testdb"
)

// Only the isolated session clock is aged. Login, denial, independent approval,
// grant/device revocation and logout all use the real server's public routes.
func TestNativeCleanupRenewsExpiredOwnerWithoutChangingActor(t *testing.T) {
	binary, repository := os.Getenv("LINDM_NATIVE_SERVER_BINARY"), os.Getenv("LINDM_NATIVE_REPOSITORY")
	if binary == "" || repository == "" {
		t.Fatal("requires LINDM_NATIVE_SERVER_BINARY and LINDM_NATIVE_REPOSITORY; use go run ./cmd/dev test-integration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := fixture.ConfigureDeviceActions(ctx); err != nil {
		t.Fatal(err)
	}
	control, err := openVMControlPlane(ctx, repository, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := control.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	bootstrap, err := control.BootstrapMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clear(bootstrap.GrantSecret)
	pool, _ := testdb.Open(t)
	config := pool.Config().ConnConfig.Copy()
	config.Database = fixture.DatabaseName
	config.RuntimeParams["search_path"] = "public"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	deviceID := uuid.NewString()
	if _, err := connection.Exec(ctx, "INSERT INTO devices(id,state,enrolled_at) VALUES($1,'pending',now())", deviceID); err != nil {
		t.Fatal(err)
	}
	if err := control.TrackDevice(deviceID); err != nil {
		t.Fatal(err)
	}
	original, openOwner := control.session, control.openOwner
	control.openOwner = func(ctx context.Context) (*devlab.OwnerSession, error) {
		fresh, err := openOwner(ctx)
		if err == nil {
			fresh.AccountID = uuid.NewString()
		}
		return fresh, err
	}
	if err := control.refreshOwner(ctx); err == nil || control.session != original {
		t.Fatal("cleanup accepted a changed owner identity")
	}
	control.openOwner = openOwner
	changed, err := connection.Exec(ctx, "UPDATE sessions SET created_at=created_at-interval '31 minutes', last_seen_at=last_seen_at-interval '31 minutes', idle_expires_at=idle_expires_at-interval '31 minutes', absolute_expires_at=absolute_expires_at-interval '31 minutes' WHERE principal_id=$1 AND revoked_at IS NULL", original.AccountID)
	if err != nil || changed.RowsAffected() < 1 {
		t.Fatalf("expire owned cleanup session: rows=%d err=%v", changed.RowsAffected(), err)
	}
	if _, err := original.Admin.ListEnrollmentGrants(ctx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expired owner was not refused: %v", err)
	}
	if err := control.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if control.session == original || control.session.AccountID != original.AccountID {
		t.Fatal("cleanup did not authenticate the same owner afresh")
	}
	var grantRevoked bool
	if err := connection.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM enrollment_grants WHERE id=$1", bootstrap.GrantID).Scan(&grantRevoked); err != nil || !grantRevoked {
		t.Fatalf("owned grant not revoked: %v", err)
	}
	var state string
	if err := connection.QueryRow(ctx, "SELECT state FROM devices WHERE id=$1", deviceID).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("owned device not revoked: state=%s err=%v", state, err)
	}
	approval := control.devices[deviceID].approval
	if approval.GetRequesterId() != original.AccountID || approval.GetApproverId() == "" || approval.GetApproverId() == original.AccountID {
		t.Fatal("cleanup lost the independent approval identity")
	}
}
