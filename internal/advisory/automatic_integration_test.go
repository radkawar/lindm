// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/device/devicedb"
	"lindm/internal/testdb"
)

func TestAutomaticInventoryActivationAndIndependentInitialSchedule(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{RefreshEnabled: true, AutomaticInventoryFeeds: true}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if due, err := s.dueSources(t.Context()); err != nil || len(due) != 0 {
		t.Fatalf("empty installation downloaded unneeded distributions: %v %v", due, err)
	}
	ubuntu := seedInventory(t, pool, "ubuntu", "24.04", &inventoryv1.Package{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.2", SourceName: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.2", Architecture: "amd64", Manager: "dpkg"})
	for _, product := range []struct{ id, version string }{{"unknown-linux", "9"}, {"linuxmint", "22.3"}, {"rocky", "9"}} {
		seedInventory(t, pool, product.id, product.version, &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "x86_64", Manager: "rpm"})
	}
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err := advisorydb.New(pool).ListAdvisoryFeeds(t.Context())
	if err != nil || len(rows) != 1 || rows[0].Distro != "ubuntu" || rows[0].Release != "24.04" || rows[0].Architecture != "amd64" {
		t.Fatalf("automatic selection: %v %v", rows, err)
	}
	initial, err := s.dueSources(t.Context())
	if err != nil || len(initial) != 1 || initial[0].GetProgressTimeoutSeconds() != 3600 {
		t.Fatalf("initial activation not immediately due with archive idle bound: %v %v", initial, err)
	}
	q := advisorydb.New(pool)
	if err := q.FailAdvisoryFeed(t.Context(), advisorydb.FailAdvisoryFeedParams{ID: rows[0].ID, AttemptedAt: timestamp(time.Now()), Error: "refresh_failed", ConfigBytes: rows[0].ConfigBytes}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evaluate(t.Context(), ubuntu); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: ubuntu.String()}, true, []byte("[]"))
	if err != nil || findings.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || !findings.GetFreshness().GetRefreshFailed() {
		t.Fatalf("activation or failed attempt fabricated findings: %v %v", findings, err)
	}
	rhel := seedInventory(t, pool, "rhel", "9.8", &inventoryv1.Package{Name: "openssl-libs", Version: "1:3.0.7-27.el9_4", Architecture: "x86_64", Manager: "rpm"})
	details, err := proto.Marshal(&inventoryv1.NativeDetails{Platform: &inventoryv1.PlatformDetails{
		Cpe:            &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "cpe:/o:redhat:enterprise_linux:9::baseos"},
		ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		Repositories:   &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Ids: []string{"rhel-9-for-x86_64-baseos-rpms"}, Backend: "dnf"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET details=$2 WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", rhel, details)
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	due, err := s.dueSources(t.Context())
	if err != nil || len(due) != 1 || due[0].GetDistro() != "rhel" || due[0].GetRelease() != "9.8" || due[0].GetPlatformStream() != "standard" {
		t.Fatalf("new RHEL source waited behind Ubuntu retry interval: %v %v", due, err)
	}
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET details=''::bytea,advisory_registry_revision=''::bytea WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", rhel)
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err = q.ListAdvisoryFeeds(t.Context())
	if err != nil || len(rows) != 1 || rows[0].Distro != "ubuntu" {
		t.Fatalf("uncorroborated RHEL acquired standard coverage: %v %v", rows, err)
	}
}

func TestAutomaticDebianMaintainedPrimaryExportActivatesAfterInventory(t *testing.T) {
	for _, version := range []string{"12", "13"} {
		t.Run(version, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{RefreshEnabled: true, AutomaticInventoryFeeds: true}, http.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
			device := seedInventory(t, pool, "debian", version, &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "amd64", Manager: "dpkg"})
			if err := s.reconcileFeeds(t.Context()); err != nil {
				t.Fatal(err)
			}
			sources, err := s.dueSources(t.Context())
			if err != nil || len(sources) != 1 || sources[0].GetDistro() != "debian" || sources[0].GetRelease() != version || sources[0].GetArchitecture() != "amd64" || sources[0].GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP {
				t.Fatalf("maintained Debian primary export was not immediately eligible: %v %v", sources, err)
			}
			if _, err := s.Evaluate(t.Context(), device); err != nil {
				t.Fatal(err)
			}
			findings, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: device.String()}, true, []byte("[]"))
			if err != nil || findings.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
				t.Fatalf("source activation fabricated unpublished vendor findings: %v %v", findings, err)
			}
		})
	}
}

type refusingFeedTransport struct{ calls atomic.Int32 }

func (r *refusingFeedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, errors.New("unexpected advisory egress")
}

func TestAutomaticDisabledMaintenanceMakesNoEgress(t *testing.T) {
	pool, _ := testdb.Open(t)
	transport := new(refusingFeedTransport)
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{AutomaticInventoryFeeds: true}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	seedInventory(t, pool, "ubuntu", "24.04", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "amd64", Manager: "dpkg"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunMaintenance(ctx) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		feeds, err := s.Feeds(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(feeds.Feeds) == 1 {
			if feeds.Feeds[0].GetRefreshEnabled() || feeds.Feeds[0].GetRefreshing() {
				t.Fatal("offline configured feed was presented as downloading")
			}
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("maintenance did not reconcile enrolled inventory")
		}
	}
	cancel()
	if err := <-done; err != nil || transport.calls.Load() != 0 {
		t.Fatalf("disabled maintenance egress: %d %v", transport.calls.Load(), err)
	}
}

func TestAutomaticSelectionPreservesExplicitSource(t *testing.T) {
	pool, _ := testdb.Open(t)
	_, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	seedInventory(t, pool, "ubuntu", "24.04", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "amd64", Manager: "dpkg"})
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{AutomaticInventoryFeeds: true, Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	sources, err := s.configuredSources(t.Context())
	if err != nil || len(sources) != 1 || !proto.Equal(sources[0], source) {
		t.Fatalf("explicit source replaced by automatic source: %v %v", sources, err)
	}
}

func TestRefreshMetadataRequiresLiveExactConfigurationLease(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	q := advisorydb.New(pool)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	generation := uuid.New()
	started := time.Now().UTC().Truncate(time.Microsecond)
	if err := q.StartAdvisoryGeneration(t.Context(), advisorydb.StartAdvisoryGenerationParams{FeedID: source.Id, Generation: generation, StartedAt: timestamp(started), ConfigBytes: encoded}); err != nil {
		t.Fatal(err)
	}
	feeds, err := s.Feeds(t.Context())
	if err != nil || len(feeds.Feeds) != 1 || !feeds.Feeds[0].GetRefreshing() || !feeds.Feeds[0].GetRefreshStartedAt().AsTime().Equal(started) || feeds.Feeds[0].GetFresh() || feeds.Feeds[0].GetRefreshEnabled() {
		t.Fatalf("live manual lease metadata: %v %v", feeds, err)
	}
	id := seedInventory(t, pool, "ubuntu", "24.04", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "amd64", Manager: "dpkg"})
	findings, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil || !findings.GetFreshness().GetRefreshing() || findings.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatalf("live download changed evaluation authority: %v %v", findings, err)
	}
	for _, state := range []string{"wrong-config", "expired", "retired"} {
		switch state {
		case "wrong-config":
			mustExec(t, t.Context(), pool, "UPDATE advisory_generation_cleanup SET config_bytes='wrong'::bytea WHERE generation=$1", generation)
		case "expired":
			mustExec(t, t.Context(), pool, "UPDATE advisory_generation_cleanup SET config_bytes=$2,cleanup_after=clock_timestamp()-interval '1 second' WHERE generation=$1", generation, encoded)
		case "retired":
			if err := q.QueueAdvisoryGenerationCleanup(t.Context(), advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: source.Id, Generation: generation}); err != nil {
				t.Fatal(err)
			}
		}
		feeds, err = s.Feeds(t.Context())
		if err != nil || feeds.Feeds[0].GetRefreshing() || feeds.Feeds[0].GetRefreshStartedAt() != nil {
			t.Fatalf("%s lease advertised active work: %v %v", state, feeds, err)
		}
	}
}

func TestAutomaticArchitectureSpecificExportsRemainDisjoint(t *testing.T) {
	pool, _ := testdb.Open(t)
	seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "x86_64", Manager: "rpm"})
	arm := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "aarch64", Manager: "rpm"})
	mustExec(t, t.Context(), pool, "UPDATE devices SET architecture='aarch64' WHERE id=$1", arm)
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET architecture_value='aarch64' WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", arm)
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{AutomaticInventoryFeeds: true}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := s.configuredSources(t.Context())
	if err != nil || len(sources) != 2 || sources[0].GetArchitecture() == sources[1].GetArchitecture() || sources[0].GetUrl() == sources[1].GetUrl() {
		t.Fatalf("architecture-specific exports collapsed or borrowed coverage: %v %v", sources, err)
	}
}

func TestAutomaticProjectionProgressesPastCohortAndFencesChangedObservation(t *testing.T) {
	pool, _ := testdb.Open(t)
	for range 257 {
		seedInventory(t, pool, "unknown-linux", "24.04", &inventoryv1.Package{Name: "fixture", Version: "1", Architecture: "amd64", Manager: "dpkg"})
	}
	var device, generation uuid.UUID
	if err := pool.QueryRow(t.Context(), "SELECT d.id,e.id FROM devices d JOIN enrollment_generations e ON e.id=d.current_generation_id ORDER BY e.id DESC LIMIT 1").Scan(&device, &generation); err != nil {
		t.Fatal(err)
	}
	mustExec(t, t.Context(), pool, "UPDATE devices SET os_id='ubuntu' WHERE id=$1", device)
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET os_id_value='ubuntu' WHERE generation_id=$1", generation)
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{AutomaticInventoryFeeds: true}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.configuredSources(t.Context())
	if err != nil || len(first) != 0 {
		t.Fatalf("first bounded batch did not stop before last cohort member: %v %v", first, err)
	}
	var resolved int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM host_observations WHERE advisory_registry_revision=$1", s.automaticRevision).Scan(&resolved); err != nil || resolved != 256 {
		t.Fatalf("observation resolution batch = %d %v", resolved, err)
	}
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	sources, err := s.configuredSources(t.Context())
	if err != nil || len(sources) != 1 || sources[0].GetDistro() != "ubuntu" {
		t.Fatalf("later eligible product starved behind resolved cohort: %v %v", sources, err)
	}
	dq := devicedb.New(pool)
	host, err := dq.GetHostObservation(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("controlled new observation with unavailable OS identity"))
	if err := dq.UpsertHostObservation(t.Context(), devicedb.UpsertHostObservationParams{
		GenerationID: generation, Sequence: host.Sequence + 1,
		StartedAt: host.StartedAt, FinishedAt: host.FinishedAt, ReceivedAt: host.ReceivedAt, Digest: digest[:],
		BootIDStatus: 2, HostnameStatus: 2, OsIDStatus: 2,
		OsVersionStatus: 1, OsVersionValue: "24.04", ArchitectureStatus: 1, ArchitectureValue: "x86_64",
		KernelReleaseStatus: 2, HardwareVendorStatus: 2, HardwareModelStatus: 2, HardwareSerialStatus: 2,
		Details: []byte{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := advisorydb.New(pool).ResolveAutomaticAdvisoryIdentity(t.Context(), advisorydb.ResolveAutomaticAdvisoryIdentityParams{
		GenerationID: generation, Sequence: host.Sequence,
		AdvisoryRegistryRevision: s.automaticRevision, AdvisoryEligible: true, AdvisoryPlatformStream: "standard",
	}); err != nil {
		t.Fatal(err)
	}
	var revision []byte
	var eligible bool
	var stream string
	if err := pool.QueryRow(t.Context(), "SELECT advisory_registry_revision,advisory_eligible,advisory_platform_stream FROM host_observations WHERE generation_id=$1", generation).Scan(&revision, &eligible, &stream); err != nil || len(revision) != 0 || eligible || stream != "" {
		t.Fatalf("new observation retained or accepted old projection: %x %t %q %v", revision, eligible, stream, err)
	}
	if err := s.reconcileFeeds(t.Context()); err != nil {
		t.Fatal(err)
	}
	sources, err = s.configuredSources(t.Context())
	if err != nil || len(sources) != 0 {
		t.Fatalf("failed current host identity retained automatic coverage: %v %v", sources, err)
	}
}

func TestMalformedRHELIdentityCannotBlockOtherAutomaticFeeds(t *testing.T) {
	pool, _ := testdb.Open(t)
	details, err := proto.Marshal(&inventoryv1.NativeDetails{Platform: &inventoryv1.PlatformDetails{
		Cpe:            &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "cpe:/o:redhat:enterprise_linux:9::baseos"},
		ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		Repositories:   &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Ids: []string{"rhel-9-for-x86_64-baseos-rpms"}, Backend: "dnf"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"9.", "9.8a", "9." + strings.Repeat("1", 65)} {
		device := seedInventory(t, pool, "rhel", version, &inventoryv1.Package{Name: "openssl-libs", Version: "1:3.0.7-27.el9_4", Architecture: "x86_64", Manager: "rpm"})
		mustExec(t, t.Context(), pool, "UPDATE host_observations SET details=$2 WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", device, details)
	}
	seedInventory(t, pool, "ubuntu", "24.04", &inventoryv1.Package{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.2", Architecture: "amd64", Manager: "dpkg"})
	cfg := &configv1.AdvisoryConfig{RefreshEnabled: true, AutomaticInventoryFeeds: true}
	for range 2 {
		s, err := New(t.Context(), pool, cfg, http.DefaultClient)
		if err != nil {
			t.Fatalf("untrusted RHEL identity blocked service construction: %v", err)
		}
		sources, err := s.dueSources(t.Context())
		if err != nil || len(sources) != 1 || sources[0].GetDistro() != "ubuntu" || sources[0].GetRelease() != "24.04" {
			t.Fatalf("malformed identity blocked or acquired feed authority: %v %v", sources, err)
		}
		var rejected int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM host_observations WHERE os_id_value='rhel' AND advisory_registry_revision=$1 AND NOT advisory_eligible AND advisory_platform_stream=''", s.automaticRevision).Scan(&rejected); err != nil || rejected != 3 {
			t.Fatalf("malformed identities poisoned durable discovery instead of resolving ineligible: %d %v", rejected, err)
		}
	}
}
