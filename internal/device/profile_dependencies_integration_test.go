// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"os"
	"strings"
	"testing"

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
	sqlDB := stdlib.OpenDBFromPool(f.pool)
	defer func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	}()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 56); err == nil || !strings.Contains(err.Error(), "retained expanded profile dependencies") {
		t.Fatalf("Down discarded typed dependencies: %v", err)
	}
	if err := db.Check(t.Context(), f.pool); err != nil {
		t.Fatalf("refused Down changed schema admission: %v", err)
	}
	assertExpandedDependencies(t, f)
}

func TestPublishExpandedDependenciesAfterForwardMigration(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	// Recreate the already-applied lab predecessor, not a destructive Down.
	if _, err := f.pool.Exec(t.Context(), `
		ALTER TABLE profile_dependencies DROP CONSTRAINT profile_dependencies_dependency_kind_check;
		ALTER TABLE profile_dependencies ADD CONSTRAINT profile_dependencies_dependency_kind_check CHECK (dependency_kind BETWEEN 1 AND 20);
		DELETE FROM goose_db_version WHERE version_id=57;
		UPDATE lindm_schema_compatibility SET migration_versions=array_remove(migration_versions,57::bigint);
	`); err != nil {
		t.Fatal(err)
	}
	status, err := db.Preflight(t.Context(), f.pool)
	if err != nil || !status.Online || status.Compatible || len(status.Pending) != 1 || status.Pending[0] != 57 {
		t.Fatalf("dependency expansion preflight=%+v err=%v", status, err)
	}
	if err := db.Migrate(t.Context(), f.pool); err != nil {
		t.Fatal(err)
	}
	publishExpandedDependencies(t, f)
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
