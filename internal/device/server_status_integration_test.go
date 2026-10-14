// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
)

func TestServerStatusRequiresFreshUnrestrictedAuthority(t *testing.T) {
	f := newProvisioningFixture(t)
	reads := 0
	f.service.ServerStatus = func() *adminv1.GetServerStatusResponse {
		reads++
		return &adminv1.GetServerStatusResponse{Version: "status-test", Checks: []*adminv1.ServerStatusCheck{{Component: "backups", State: adminv1.ServerStatusState_SERVER_STATUS_STATE_UNKNOWN}}}
	}
	response, err := f.service.GetServerStatus(f.ownerCtx, connect.NewRequest(&adminv1.GetServerStatusRequest{}))
	if err != nil || response == nil || response.Header().Get("Cache-Control") != "no-store" || reads != 1 {
		t.Fatalf("authorized status read: response=%v reads=%d err=%v", response, reads, err)
	}
	auditor := insertPrincipal(t, t.Context(), f.conn, identity.RoleAuditor)
	response, err = f.service.GetServerStatus(identity.WithPrincipal(t.Context(), auditor), connect.NewRequest(&adminv1.GetServerStatusRequest{}))
	if response != nil || connect.CodeOf(err) != connect.CodePermissionDenied || reads != 1 {
		t.Fatal("unauthorized caller reached status evidence")
	}
	if _, err := f.conn.Exec(t.Context(), `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, f.owner.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	response, err = f.service.GetServerStatus(f.ownerCtx, connect.NewRequest(&adminv1.GetServerStatusRequest{}))
	if response != nil || connect.CodeOf(err) != connect.CodePermissionDenied || reads != 1 {
		t.Fatalf("persisted narrowed grant exposed global status: %v %v", response, err)
	}
}
