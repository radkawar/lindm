// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// The production lindmd loader rejects search_path overrides, so these tests use
// the maintained disposable database fixture rather than testdb's schema pool.
// Sessions are always issued by real password/WebAuthn or code/PKCE HTTPS login.
// SQL changes only the clock boundary, never authentication authority.
func TestNativeApprovalFreshAuthentication(t *testing.T) {
	t.Run("local", func(t *testing.T) { testNativeApprovalFreshAuthentication(t, false) })
	t.Run("directory", func(t *testing.T) { testNativeApprovalFreshAuthentication(t, true) })
}

func testNativeApprovalFreshAuthentication(t *testing.T, directory bool) {
	t.Helper()
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	open := OpenLocalAuthorityFixture
	if directory {
		open = OpenAuthorityFixture
	}
	fixture, err := open(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	cfg := fixture.database.admin.Copy()
	cfg.Database = fixture.DatabaseName
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	scenarios := []string{"idle_expiry"}
	if !directory {
		scenarios = append(scenarios, "revoke_restore")
	}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			approver, err := OpenApprovalSession(ctx, repository, fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := approver.Close(context.WithoutCancel(ctx)); err != nil {
					t.Error(err)
				}
			}()
			deviceID := uuid.NewString()
			if _, err := conn.Exec(ctx, "INSERT INTO devices(id,state,enrolled_at) VALUES($1,'pending',now())", deviceID); err != nil {
				t.Fatal(err)
			}
			request := &adminv1.CreateApprovalRequest{LifetimeSeconds: 300, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: deviceID, Reason: "disposable stale approver regression"}}}
			created, err := owner.Admin.CreateApproval(ctx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			decision := &adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independent stale session regression"}
			sessionCount := func() int {
				t.Helper()
				var count int
				if err := conn.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE principal_id=$1", approver.session.AccountID).Scan(&count); err != nil {
					t.Fatal(err)
				}
				return count
			}
			before := sessionCount()
			if scenario == "idle_expiry" {
				changed, err := conn.Exec(ctx, "UPDATE sessions SET created_at=created_at-interval '31 minutes', last_seen_at=last_seen_at-interval '31 minutes', idle_expires_at=idle_expires_at-interval '31 minutes', absolute_expires_at=absolute_expires_at-interval '31 minutes' WHERE principal_id=$1 AND revoked_at IS NULL", approver.session.AccountID)
				if err != nil || changed.RowsAffected() != 1 {
					t.Fatalf("expire owned approver session: rows=%d err=%v", changed.RowsAffected(), err)
				}
			} else {
				if err := fixture.RevokeAccount(ctx, approver.session.AccountID); err != nil {
					t.Fatal(err)
				}
				// A real fresh login cannot bypass an actually disabled account.
				if _, err := approver.session.ApproveApproval(ctx, connect.NewRequest(decision)); err == nil {
					t.Fatal("disabled approver authenticated")
				}
				if err := fixture.RestoreAccount(ctx, approver.session.AccountID); err != nil {
					t.Fatal(err)
				}
			}
			// Deterministically reproduce the original unauthenticated decision.
			if _, err := approver.session.Admin.ApproveApproval(ctx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("stale session was not denied: %v", err)
			}
			approved, err := approver.Approve(ctx, owner, request)
			if err != nil {
				t.Fatalf("fresh two-human approval: %v", err)
			}
			if approved.GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED || approved.GetRequesterId() != owner.AccountID || approved.GetApproverId() != approver.session.AccountID || approved.GetRequesterId() == approved.GetApproverId() || sessionCount() != before+1 {
				t.Fatal("approval did not bind a fresh independent authenticated human")
			}
			// The same shared helper used by native reveal/destructive/enrollment
			// callers also starts a fresh session on the next decision.
			before = sessionCount()
			request.GetRevokeDevice().RequestId = uuid.NewString()
			created, err = owner.Admin.CreateApproval(ctx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			decision.ApprovalId = created.Msg.GetApproval().GetId()
			decisionResponse, err := approver.session.ApproveApproval(ctx, connect.NewRequest(decision))
			if err != nil {
				t.Fatal(err)
			}
			if sessionCount() != before+1 {
				t.Fatal("subsequent approval reused its session")
			}
			request.GetRevokeDevice().ApprovalId = decisionResponse.Msg.GetApproval().GetId()
			if _, err := owner.Admin.RevokeDevice(ctx, connect.NewRequest(request.GetRevokeDevice())); err != nil {
				t.Fatalf("consume fresh independent approval: %v", err)
			}
		})
	}
}
