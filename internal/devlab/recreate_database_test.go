// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRecreationTargetConfinesDestruction(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgresql://lindm_migrator@localhost:15432/lindm?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	name, err := recreationTarget(cfg)
	if err != nil || name != "lindm" {
		t.Fatalf("target = %q, %v", name, err)
	}
	for _, database := range []string{"postgres", "template1", "lindm_authority_abc", "testdb", "lindm; DROP DATABASE postgres", ""} {
		other := cfg.Copy()
		other.Database = database
		if _, err := recreationTarget(other); err == nil {
			t.Errorf("accepted database %q", database)
		}
	}
	insecure := cfg.Copy()
	insecure.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if _, err := recreationTarget(insecure); err == nil {
		t.Fatal("accepted unverified TLS")
	}
}

func TestRecreateRequiresConsentBeforeFixtureAccess(t *testing.T) {
	if err := RecreateDatabase(context.Background(), t.TempDir(), false); err == nil {
		t.Fatal("destruction accepted without consent")
	}
}
