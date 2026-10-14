// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
)

func custodyRequest(digest string) *connect.Request[adminv1.ConfirmRecoveryKeyCustodyRequest] {
	return connect.NewRequest(&adminv1.ConfirmRecoveryKeyCustodyRequest{ExpectedConfirmationDigest: digest, ConfirmOffServerCustody: true})
}

func TestRecoveryCustodyRequiresActualOwnerNewScopedUVAndCurrentExportSet(t *testing.T) {
	f := newSecretFixture(t)
	digest := strings.Repeat("a", 64)
	exports := []*adminv1.RecoveryKeyCustodyExport{{Kind: adminv1.RecoveryKeyCustodyExportKind_RECOVERY_KEY_CUSTODY_EXPORT_KIND_CANONICAL_AUTHORITY, Path: "/var/lib/lindmd-operations/recovery-custody.age", Sha256: strings.Repeat("d", 64)}}
	f.svc.ServerStatus = func() *adminv1.GetServerStatusResponse {
		return &adminv1.GetServerStatusResponse{Version: "integration"}
	}
	f.svc.RecoveryKeyCustody = func() (*adminv1.RecoveryKeyCustody, error) {
		return &adminv1.RecoveryKeyCustody{State: adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING, ConfirmationDigest: digest, RecordedAt: timestamppb.New(time.Now().Add(-time.Hour)), Exports: exports}, nil
	}
	read := func(ctx context.Context) *adminv1.RecoveryKeyCustody {
		t.Helper()
		response, err := f.svc.GetServerStatus(ctx, connect.NewRequest(&adminv1.GetServerStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetRecoveryKeyCustody()
	}
	assertDenied := func(ctx context.Context, target, reason string) {
		t.Helper()
		_, err := f.svc.ConfirmRecoveryKeyCustody(ctx, custodyRequest(target))
		if connect.CodeOf(err) != connect.CodePermissionDenied || rpcReason(err) != reason {
			t.Fatalf("custody denial: %v", err)
		}
	}
	assertDenied(f.ownerCtx, digest, "recent_step_up_required")
	assertDenied(f.browser.context, digest, "recent_step_up_required") // real setup/login UV is not a new scoped ceremony
	admin := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
	assertDenied(identity.WithPrincipal(t.Context(), admin), digest, "permission_denied")
	invitedOwner := insertPrincipal(t, t.Context(), f.conn, identity.RoleOwner)
	assertDenied(identity.WithPrincipal(t.Context(), invitedOwner), digest, "permission_denied")
	if current := read(f.ownerCtx); current.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING || !current.CanConfirm {
		t.Fatal("actual owner lost persistent custody task")
	}
	if current := read(identity.WithPrincipal(t.Context(), invitedOwner)); current.CanConfirm {
		t.Fatal("invited owner-role account gained deployment-owner custody authority")
	}
	f.browser.reverify("")
	assertDenied(f.browser.context, digest, "recent_step_up_required") // generic password + UV still lacks this target
	f.browser.reverify(exports[0].Sha256)                              // a genuine ceremony for one file cannot acknowledge the composite set
	assertDenied(f.browser.context, digest, "recent_step_up_required")
	proof := f.browser.reverify(digest)
	confirmed, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(digest))
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Msg.GetCustody().GetState() != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_CONFIRMED || confirmed.Msg.GetCustody().GetConfirmedAt() == nil {
		t.Fatal("real scoped owner UV did not record the attestation")
	}
	assertDenied(proof, digest, "recent_step_up_required") // consumed stamp cannot be replayed
	if current := read(f.ownerCtx); current.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_CONFIRMED || current.CanConfirm {
		t.Fatal("current export-set owner confirmation was not durable")
	}
	digest = strings.Repeat("c", 64)
	exports = append(exports, &adminv1.RecoveryKeyCustodyExport{Kind: adminv1.RecoveryKeyCustodyExportKind_RECOVERY_KEY_CUSTODY_EXPORT_KIND_FRESH_DATABASE, Path: "/var/lib/lindmd-operations/database-custody/" + strings.Repeat("e", 64) + "/identities.age", Sha256: strings.Repeat("f", 64), LocalPresent: true})
	if current := read(f.ownerCtx); current.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING || current.ConfirmedAt != nil || !current.CanConfirm || len(current.Exports) != 2 || current.Exports[0].Sha256 != strings.Repeat("d", 64) {
		t.Fatal("source-only attestation cleared fresh target database custody")
	}
	assertDenied(proof, digest, "recent_step_up_required")
	proof = f.browser.reverify(digest)
	if _, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(digest)); err != nil {
		t.Fatal(err)
	}
	var confirmations, audit int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM recovery_key_custody_confirmations").Scan(&confirmations); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action='recovery_custody.confirmed'").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if confirmations != 2 || audit != 2 {
		t.Fatalf("attestation/audit/replay counts: %d/%d", confirmations, audit)
	}
}

func TestRecoveryCustodyRotationDuringAckRollsBackAuditAndScopeConsumption(t *testing.T) {
	f := newSecretFixture(t)
	original, rotated := strings.Repeat("a", 64), strings.Repeat("b", 64)
	calls := 0
	f.svc.RecoveryKeyCustody = func() (*adminv1.RecoveryKeyCustody, error) {
		calls++
		digest := original
		if calls > 1 {
			digest = rotated
		}
		return &adminv1.RecoveryKeyCustody{State: adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING, ConfirmationDigest: digest}, nil
	}
	proof := f.browser.reverify(original)
	if _, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(original)); rpcReason(err) != "recovery_custody_changed" {
		t.Fatalf("rotation failed to fence attestation: %v", err)
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM recovery_key_custody_confirmations)+(SELECT count(*) FROM audit_events WHERE action='recovery_custody.confirmed')").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rotated target left an attestation or delivery-producing audit")
	}
	f.svc.RecoveryKeyCustody = func() (*adminv1.RecoveryKeyCustody, error) {
		return &adminv1.RecoveryKeyCustody{State: adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING, ConfirmationDigest: original}, nil
	}
	if _, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(original)); err != nil {
		t.Fatalf("rolled-back attestation consumed the actual scoped UV stamp: %v", err)
	}
}

func TestRecoveryCustodyRevokedScopedBrowserProofCannotMutate(t *testing.T) {
	f := newSecretFixture(t)
	digest := strings.Repeat("a", 64)
	f.svc.RecoveryKeyCustody = func() (*adminv1.RecoveryKeyCustody, error) {
		return &adminv1.RecoveryKeyCustody{State: adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING, ConfirmationDigest: digest}, nil
	}
	proof := f.browser.reverify(digest)
	if _, err := f.pool.Exec(t.Context(), "UPDATE sessions SET revoked_at=clock_timestamp() WHERE principal_id=$1", f.owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(digest)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked scoped session mutated: %v", err)
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM recovery_key_custody_confirmations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("revoked browser recorded custody")
	}
}
