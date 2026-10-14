// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/durationpb"

	configv1 "lindm/gen/lindm/config/v1"
)

func unrestrictedApprover(_ context.Context, _ pgx.Tx, principal Principal, permission Permission, _ uuid.UUID) (bool, error) {
	unrestricted, _ := DeviceScopes(principal, permission)
	return unrestricted, nil
}

// TestOtherApproverStandingDirectoryAndBreakGlass covers external-directory
// deployments: a break-glass account never counts as an approver, even with an
// emergency allowlist that would let it approve; a directory administrator
// counts from their last observation, however old, until that observation
// disables them.
func TestOtherApproverStandingDirectoryAndBreakGlass(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	var deployment uuid.UUID
	if err := conn.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity WHERE id").Scan(&deployment); err != nil {
		t.Fatal(err)
	}
	svc.localIssuer = "urn:lindm:local:" + deployment.String()
	svc.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionRevealSecrets), string(PermissionManageApprovals)}, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
	base := authorizationDatabaseTime(t, ctx, svc).Add(-time.Hour)
	observe := func(subject uuid.UUID, id uuid.UUID, at time.Time, enabled bool) {
		t.Helper()
		if err := applyAuthorizationObservation(ctx, svc, id, directoryObs(subject, at, enabled)); err != nil {
			t.Fatal(err)
		}
	}
	requesterSubject := uuid.New()
	requester := insertObservedPrincipal(t, ctx, svc, requesterSubject)
	observe(requesterSubject, requester.ID, base, true)
	available := func(want bool) {
		t.Helper()
		got, err := svc.OtherApproverAvailable(ctx, requester.ID, PermissionRevealSecrets, uuid.Nil, unrestrictedApprover)
		if err != nil || got != want {
			t.Fatalf("other approver available = %t (%v), want %t", got, err, want)
		}
	}
	available(false)

	emergency := uuid.New()
	if _, err := conn.Exec(ctx, "INSERT INTO principals (id, issuer, subject, authorization_role, directory_enabled) VALUES ($1, $2, $3, 'owner', true)", emergency, svc.localIssuer, emergency.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO local_accounts (id, username, role, break_glass) VALUES ($1, 'emergency', 'owner', true)", emergency); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO local_credentials (credential_id, account_id, credential_json) VALUES ($1, $2, '{}')", emergency[:], emergency); err != nil {
		t.Fatal(err)
	}
	snapshot, err := svc.loadSnapshot(ctx, emergency)
	if err != nil {
		t.Fatal(err)
	}
	if principal := svc.snapshotPrincipal(snapshot, snapshotRole(snapshot.policy, snapshot)); !snapshot.Enabled || !snapshot.BreakGlass || !Authorize(principal, PermissionManageApprovals) || !Authorize(principal, PermissionRevealSecrets) {
		t.Fatalf("emergency fixture would not otherwise qualify: %+v", snapshot)
	}
	available(false)

	otherSubject := uuid.New()
	other := insertObservedPrincipal(t, ctx, svc, otherSubject)
	observe(otherSubject, other.ID, base.Add(time.Second), true)
	available(true)
	observe(otherSubject, other.ID, base.Add(2*time.Second), false)
	available(false)
}
