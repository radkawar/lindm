// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"google.golang.org/protobuf/proto"

	"lindm/db"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestPublishProfileRevisionWithExpandedResourceDependencies(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	publishExpandedDependencies(t, f)
	// Isolate migration 57 without executing later irreversible Down migrations.
	// Keep the business tables intact, as in db's migration Down tests.
	if _, err := f.pool.Exec(t.Context(), `
		DELETE FROM goose_db_version WHERE version_id > 57;
		UPDATE lindm_schema_compatibility
		SET minimum_runtime_version=51,
		    migration_versions=(SELECT array_agg(version_id ORDER BY version_id) FROM goose_db_version WHERE version_id > 0 AND is_applied);
	`); err != nil {
		t.Fatal(err)
	}
	before, err := db.Preflight(t.Context(), f.pool)
	if err != nil {
		t.Fatal(err)
	}
	provider := profileDependencyMigrationProvider(t, f)
	if _, err := provider.DownTo(t.Context(), 56); err == nil || !strings.Contains(err.Error(), "retained expanded profile dependencies") {
		t.Fatalf("Down discarded typed dependencies: %v", err)
	}
	after, err := db.Preflight(t.Context(), f.pool)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("refused Down changed schema admission: before=%+v after=%+v err=%v", before, after, err)
	}
	assertExpandedDependencies(t, f)
}

func TestPublishExpandedDependenciesAfterForwardMigration(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	// Recreate the already-applied lab predecessor, not a destructive Down.
	// Remove later history too: migration 57 must be pending above Current,
	// and the later contract migrations still require fenced application.
	if _, err := f.pool.Exec(t.Context(), `
		ALTER TABLE profile_dependencies DROP CONSTRAINT profile_dependencies_dependency_kind_check;
		ALTER TABLE profile_dependencies ADD CONSTRAINT profile_dependencies_dependency_kind_check CHECK (dependency_kind BETWEEN 1 AND 20);
		DELETE FROM goose_db_version WHERE version_id >= 57;
		UPDATE lindm_schema_compatibility
		SET minimum_runtime_version=51,
		    migration_versions=(SELECT array_agg(version_id ORDER BY version_id) FROM goose_db_version WHERE version_id > 0 AND is_applied);
	`); err != nil {
		t.Fatal(err)
	}
	status, err := db.Preflight(t.Context(), f.pool)
	if err != nil || status.Current != 56 || status.Target != 59 || status.Online || status.Compatible || !reflect.DeepEqual(status.Pending, []int64{57, 58, 59}) {
		t.Fatalf("dependency expansion preflight=%+v err=%v", status, err)
	}
	provider := profileDependencyMigrationProvider(t, f)
	if _, err := provider.UpTo(t.Context(), 57); err != nil {
		t.Fatal(err)
	}
	status, err = db.Preflight(t.Context(), f.pool)
	if err != nil || status.Current != 57 || !reflect.DeepEqual(status.Pending, []int64{58, 59}) {
		t.Fatalf("dependency expansion history=%+v err=%v", status, err)
	}
	publishExpandedDependencies(t, f)
}

func profileDependencyMigrationProvider(t *testing.T, f *dispatchFixture) *goose.Provider {
	t.Helper()
	migration, err := os.ReadFile("../../db/migrations/00057_profile_dependency_kinds.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(f.pool)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fstest.MapFS{
		"00057_profile_dependency_kinds.sql": &fstest.MapFile{Data: migration},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func publishExpandedDependencies(t *testing.T, f *dispatchFixture) {
	t.Helper()
	dependencies := []*resourcev1.ResourceDesiredState{
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/modprobe.d/99-lindm-blocklist.conf"}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: "/etc/modprobe.d/99-lindm-blocklist.conf", Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage"}}}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "kernel.kptr_restrict"}, State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: "kernel.kptr_restrict", Value: "2"}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "drop-in/aaa-dependent.service"}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_DropIn{DropIn: &resourcev1.ServiceDropIn{Unit: "aaa-dependent.service", CpuWeight: proto.Uint32(100)}}}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}, State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true}}},
	}
	service := proto.CloneOf(f.revision.GetSpec().GetResources()[0])
	// Select the dependent service by identity, independent of canonical ordering.
	for _, item := range f.revision.GetSpec().GetResources() {
		if item.GetDesired().GetRef().GetCanonicalKey() == "aaa-dependent.service" {
			service = proto.CloneOf(item)
		}
	}
	service.DependsOn = nil
	resources := []*policyv1.ProfileResource{service}
	for _, desired := range dependencies {
		resources = append(resources, dispatchProfileResource(desired))
		service.DependsOn = append(service.DependsOn, &policyv1.ResourceDependency{Ref: proto.CloneOf(desired.GetRef()), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED})
	}
	publishDispatchResources(t, f, resources...)
	assertExpandedDependencies(t, f)
	for _, item := range f.revision.GetSpec().GetResources() {
		if item.GetResourceId() == service.GetResourceId() && !proto.Equal(item, service) {
			t.Fatal("published service lost its typed dependency edges")
		}
	}
}

func assertExpandedDependencies(t *testing.T, f *dispatchFixture) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM profile_dependencies WHERE revision_id=$1 AND dependency_kind BETWEEN 21 AND 24", f.revision.GetRevisionId()).Scan(&count); err != nil || count != 4 {
		t.Fatalf("expanded dependency edges persisted=%d err=%v", count, err)
	}
}
