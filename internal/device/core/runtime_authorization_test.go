package core

import (
	"slices"
	"testing"

	"lindm/internal/identity"
)

// escrow.reveal_approval_required gates recovery key, secret and local admin
// password reveals; the policy editor must show exactly those as configured.
func TestConfiguredApprovalPermissionsFollowRevealApproval(t *testing.T) {
	if got := configuredApprovalPermissions(false); len(got) != 0 {
		t.Fatalf("reveal approval off reported %v", got)
	}
	got := configuredApprovalPermissions(true)
	want := []string{string(identity.PermissionReadRecoveryKeys), string(identity.PermissionRevealSecrets)}
	if !slices.Equal(got, want) {
		t.Fatalf("reveal approval on reported %v, want %v", got, want)
	}
}
