// SPDX-License-Identifier: Apache-2.0
//go:build linux && integration

package server

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"lindm/internal/auditkind"
	devicecore "lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/testdb"
)

func TestBundledReleaseConcurrentActivationIsAtomicAndIdempotent(t *testing.T) {
	pool, _ := testdb.Open(t)
	manifest, identity, _ := bundledSeriesFixture()
	manifest.SourceDateEpoch = time.Now().Add(-time.Hour).Unix()
	service := &devicecore.Service{Pool: pool}
	native := &nativeRepositories{bundledRelease: manifest}
	var group sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		group.Go(func() { failures <- activateBundledRelease(t.Context(), service, native, identity) })
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	q := devicedb.New(pool)
	rows, err := q.ListReleasedAgentSeries(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("initial series missing or duplicated: %v", err)
	}
	if !devicecore.ReleaseSupported(rows, identity.Version, 1, identity.Version, 1, time.Now()) {
		t.Fatal("authenticated current agent cannot receive executable work")
	}
	var audits int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action=$1", auditkind.ReleaseSeriesRegister.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("activation did not commit one audit: %d, %v", audits, err)
	}
	before := append([]devicedb.ReleasedAgentSeries(nil), rows...)
	manifest.Version, identity.Version = "0.2.9", "0.2.9"
	if err := activateBundledRelease(t.Context(), service, native, identity); err != nil {
		t.Fatal(err)
	}
	rows, err = q.ListReleasedAgentSeries(t.Context())
	if err != nil || !reflect.DeepEqual(rows, before) {
		t.Fatalf("patch update rewrote release history: %v", err)
	}
}

func TestBundledReleaseNewMinorAnnouncesPriorRetirement(t *testing.T) {
	pool, _ := testdb.Open(t)
	q := devicedb.New(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for minor := int32(0); minor < 4; minor++ {
		if err := q.PutReleasedAgentSeries(t.Context(), devicedb.PutReleasedAgentSeriesParams{Major: 0, Minor: minor, ReleasedAt: devicecore.Timestamptz(now.Add(-120 * 24 * time.Hour)), SupportUntil: devicecore.Timestamptz(now.Add(time.Hour)), MinimumProtocol: 1, MaximumProtocol: 1}); err != nil {
			t.Fatal(err)
		}
	}
	manifest, identity, _ := bundledSeriesFixture()
	manifest.Version, identity.Version = "0.4.0", "0.4.0"
	manifest.SourceDateEpoch = now.Add(-time.Minute).Unix()
	if err := activateBundledRelease(t.Context(), &devicecore.Service{Pool: pool}, &nativeRepositories{bundledRelease: manifest}, identity); err != nil {
		t.Fatal(err)
	}
	rows, err := q.ListReleasedAgentSeries(t.Context())
	if err != nil || len(rows) != 5 {
		t.Fatalf("new minor was not committed: %v", err)
	}
	for _, row := range rows {
		if row.Minor >= 1 && row.SupportUntil.Time.Before(now.Add(90*24*time.Hour)) {
			t.Fatalf("minor %d was displaced without ninety-day notice", row.Minor)
		}
		if row.Minor == 0 && !row.SupportUntil.Time.Equal(now.Add(time.Hour)) {
			t.Fatal("unrelated older retirement history changed")
		}
	}
}

func TestBundledReleaseAuditFailureRollsBackCompatibility(t *testing.T) {
	pool, _ := testdb.Open(t)
	if _, err := pool.Exec(t.Context(), "CREATE FUNCTION refuse_installed_release_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned integration audit refusal'; END $$; CREATE TRIGGER refuse_installed_release_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION refuse_installed_release_audit()"); err != nil {
		t.Fatal(err)
	}
	manifest, identity, _ := bundledSeriesFixture()
	manifest.SourceDateEpoch = time.Now().Add(-time.Hour).Unix()
	if err := activateBundledRelease(t.Context(), &devicecore.Service{Pool: pool}, &nativeRepositories{bundledRelease: manifest}, identity); err == nil {
		t.Fatal("failed audit allowed release activation")
	}
	rows, err := devicedb.New(pool).ListReleasedAgentSeries(t.Context())
	if err != nil || len(rows) != 0 {
		t.Fatalf("failed activation leaked a compatibility row: %v", err)
	}
}
