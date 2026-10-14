// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"strings"
	"testing"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestRecoveryCustodyFreshPolicyCannotReuseEarlierScopedUV(t *testing.T) {
	f := newSecretFixture(t)
	digest := strings.Repeat("a", 64)
	proof := f.browser.reverify(digest)
	if _, err := f.conn.Exec(t.Context(), `UPDATE local_accounts SET scope_binding='{"scopes":[{"deviceIds":["11111111-1111-4111-8111-111111111111"]}]}'::jsonb WHERE id=$1`, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	// A revoked global grant must fail before even reading root custody metadata.
	f.svc.RecoveryKeyCustody = func() (*adminv1.RecoveryKeyCustody, error) {
		t.Fatal("narrowed actor read privileged custody metadata")
		return nil, nil
	}
	if _, err := f.svc.ConfirmRecoveryKeyCustody(proof, custodyRequest(digest)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("earlier scoped UV bypassed current global grant: %v", err)
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM recovery_key_custody_confirmations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("narrowed actor recorded custody")
	}
}
