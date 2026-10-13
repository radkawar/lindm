//go:build integration

package device

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func suggest(t *testing.T, svc *Service, ctx context.Context, req *adminv1.SuggestValuesRequest) *adminv1.SuggestValuesResponse {
	t.Helper()
	res, err := svc.SuggestValues(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("SuggestValues(%v): %v", req, err)
	}
	return res.Msg
}

func suggestionValues(res *adminv1.SuggestValuesResponse) []string {
	values := make([]string, len(res.GetSuggestions()))
	for i, item := range res.GetSuggestions() {
		values[i] = item.GetValue()
	}
	return values
}

func wantSuggestions(t *testing.T, res *adminv1.SuggestValuesResponse, next string, values ...string) {
	t.Helper()
	if got := suggestionValues(res); !slices.Equal(got, values) || res.GetNextAfter() != next {
		t.Fatalf("suggestions %q next %q, want %q next %q", got, res.GetNextAfter(), values, next)
	}
}

func fleetReader(t *testing.T, f *enrolledFixture, perm identity.Permission, deviceIDs ...string) context.Context {
	t.Helper()
	reader, _ := identity.PrincipalFromContext(f.ownerCtx)
	reader.Role = identity.RoleAuditor
	binding := &authv1.RoleBinding{Permissions: []string{string(perm)}}
	if len(deviceIDs) > 0 {
		binding.Scopes = []*authv1.DeviceScope{{DeviceIds: deviceIDs}}
	}
	reader.Bindings = []*authv1.RoleBinding{binding}
	return identity.WithPrincipal(f.ctx, reader)
}

func TestSuggestValuesPackagesReadCurrentSnapshotsWithinScope(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	pkg := adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_NAME
	f.publishPackages(t, 1, "retiredpkg")
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	f.publishPackages(t, 2, "python3", "Zlib", "PyQt5", "bash", "python3-yaml")

	first := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "PY", PageSize: 2})
	wantSuggestions(t, first, "python3", "PyQt5", "python3")
	if first.GetSuggestions()[0].GetCount() != 1 {
		t.Fatalf("package device count: %v", first.GetSuggestions()[0])
	}
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "PY", PageSize: 2, After: first.GetNextAfter()}), "", "python3-yaml")
	// A superseded snapshot is history, not a currently installed package.
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "retired"}), "")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "z"}), "", "Zlib")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "py", DeviceId: f.deviceID}), "", "PyQt5", "python3", "python3-yaml")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Manager: "rpm"}), "")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: pkg, Manager: "apt", Prefix: "b"}), "", "bash")
	managers := adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_MANAGER
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: managers, DeviceId: f.deviceID}), "", "apt")
	if _, err := f.svc.SuggestValues(f.ownerCtx, connect.NewRequest(&adminv1.SuggestValuesRequest{Field: managers})); connect.CodeOf(err) != connect.CodeInvalidArgument || rpcreason.Get(err) != "device_required" {
		t.Fatalf("fleet-wide managers admitted: %v", err)
	}

	other := uuid.NewString()
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,hostname,enrolled_at) VALUES($1,'pending','other',now())`, other); err != nil {
		t.Fatal(err)
	}
	scoped := fleetReader(t, f, identity.PermissionReadFleet, other)
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: pkg}), "")
	if _, err := f.svc.SuggestValues(scoped, connect.NewRequest(&adminv1.SuggestValuesRequest{Field: managers, DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope device packages exposed: %v", err)
	}
	// A device without a published snapshot has no package values, not an error.
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: managers, DeviceId: other}), "")
	visible := fleetReader(t, f, identity.PermissionReadFleet, f.deviceID)
	wantSuggestions(t, suggest(t, f.svc, visible, &adminv1.SuggestValuesRequest{Field: pkg, Prefix: "bash"}), "", "bash")
}

func TestSuggestValuesDeviceFieldsAreLiteralOrderedAndScoped(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for i, row := range [][3]string{{"Fedora", "44", "x86_64"}, {"fedora", "43", "aarch64"}, {"a%_b", "1", "x86_64"}, {"aXYb", "2", "riscv64"}} {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,hostname,enrolled_at,os_id,os_version,architecture) VALUES($1,'active','host',now(),$2,$3,$4)`, ids[i], row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	for _, label := range [][2]string{{ids[0], "lab:b"}, {ids[1], "Lab:a"}, {ids[2], "lab:b"}} {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_labels(device_id,label) VALUES($1,$2)`, label[0], label[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_release_reports(generation_id,session_epoch,agent_release,protocol_version,reported_at) VALUES($1,1,'1.4.0',2,now())
 		ON CONFLICT (generation_id) DO UPDATE SET agent_release=excluded.agent_release`, f.generation); err != nil {
		t.Fatal(err)
	}
	os := adminv1.SuggestionField_SUGGESTION_FIELD_OS_ID
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: os, Prefix: "F"}), "", "Fedora", "fedora")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: os, Prefix: "a%_"}), "", "a%_b")
	versions := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_OS_VERSION, OsId: "fedora"})
	wantSuggestions(t, versions, "", "43")
	if versions.GetSuggestions()[0].GetLabel() != "Fedora 43" {
		t.Fatalf("release label: %v", versions.GetSuggestions()[0])
	}
	// Registry names identify known OS IDs; an unknown spelling stays unnamed.
	named := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: os, Prefix: "f"})
	if named.GetSuggestions()[0].GetLabel() != "" || named.GetSuggestions()[1].GetLabel() != "Fedora" {
		t.Fatalf("os labels: %v", named.GetSuggestions())
	}
	if label := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_OS_VERSION, Prefix: "43"}).GetSuggestions()[0].GetLabel(); label != "" {
		t.Fatalf("unnarrowed version named %q", label)
	}
	arch := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_ARCHITECTURE, Prefix: "X86"})
	wantSuggestions(t, arch, "", "x86_64")
	if arch.GetSuggestions()[0].GetCount() != 2 {
		t.Fatalf("architecture device count: %v", arch.GetSuggestions()[0])
	}
	labels := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_DEVICE_LABEL, Prefix: "lab:"})
	wantSuggestions(t, labels, "", "Lab:a", "lab:b")
	if labels.GetSuggestions()[1].GetCount() != 2 {
		t.Fatalf("label device count: %v", labels.GetSuggestions()[1])
	}
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_AGENT_RELEASE}), "", "1.4.0")

	scoped := fleetReader(t, f, identity.PermissionReadFleet, ids[1])
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: os}), "", "fedora")
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_DEVICE_LABEL}), "", "Lab:a")
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_AGENT_RELEASE}), "")
	if _, err := f.svc.SuggestValues(scoped, connect.NewRequest(&adminv1.SuggestValuesRequest{Field: os, DeviceId: ids[0]})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope device narrowing exposed: %v", err)
	}
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: os, DeviceId: ids[0]}), "", "Fedora")

	for name, req := range map[string]*adminv1.SuggestValuesRequest{
		"os narrowing on os id":  {Field: os, OsId: "fedora"},
		"manager on labels":      {Field: adminv1.SuggestionField_SUGGESTION_FIELD_DEVICE_LABEL, Manager: "rpm"},
		"unspecified field":      {},
		"page above bound":       {Field: os, PageSize: 101},
		"device id not a uuid":   {Field: os, DeviceId: "host"},
		"device on directory":    {Field: adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP, DeviceId: ids[0]},
		"prefix above the bound": {Field: os, Prefix: string(make([]byte, 513))},
	} {
		if _, err := f.svc.SuggestValues(f.ownerCtx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSuggestValuesDirectoryGroupsNeedUnrestrictedAccountAuthority(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	for _, path := range []string{"/eng/linux", "/Eng/desktop", "/sales"} {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO principal_groups(principal_id,group_path) VALUES($1,$2)`, owner.ID, path); err != nil {
			t.Fatal(err)
		}
	}
	groups := adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP
	res := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: groups, Prefix: "/eng"})
	wantSuggestions(t, res, "", "/Eng/desktop", "/eng/linux")
	if res.GetSuggestions()[0].GetCount() != 1 {
		t.Fatalf("account count: %v", res.GetSuggestions()[0])
	}
	for name, ctx := range map[string]context.Context{
		"fleet reader":           fleetReader(t, f, identity.PermissionReadFleet),
		"scoped account manager": fleetReader(t, f, identity.PermissionManageAccounts, f.deviceID),
	} {
		if _, err := f.svc.SuggestValues(ctx, connect.NewRequest(&adminv1.SuggestValuesRequest{Field: groups})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s read directory groups: %v", name, err)
		}
	}
	wantSuggestions(t, suggest(t, f.svc, fleetReader(t, f, identity.PermissionManageAccounts), &adminv1.SuggestValuesRequest{Field: groups, Prefix: "/s"}), "", "/sales")
}

func TestSuggestValuesAdvisoriesReadLatestFindingSetsWithinScope(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	set := uuid.New()
	digest := make([]byte, 32)
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO advisory_finding_sets(id,feed_id,feed_revision,package_digest,state,reason,finding_digest,finding_count,critical_count,high_count,medium_count,low_count,other_count)
 		VALUES($1,'ubuntu-24.04',gen_random_uuid(),$2,'evaluated','',$2,3,0,2,1,0,0)`, set, digest); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO advisory_set_findings(set_id,finding_key,advisory_id,package_name,installed_version,fixed_version,architecture,severity,cves,source_url) VALUES
 		 ($1,gen_random_uuid(),'USN-7001-1','openssl','3.0','3.1','amd64','high','{CVE-2026-0002,CVE-2026-0001}',''),
 		 ($1,gen_random_uuid(),'USN-7001-1','libssl3','3.0','3.1','amd64','medium','{CVE-2026-0001}',''),
 		 ($1,gen_random_uuid(),'usn-6999-2','bash','5','6','amd64','high','{}','')`,
		`INSERT INTO advisory_set_advisories(set_id,advisory_id,severity,findings) VALUES ($1,'USN-7001-1','high',1),($1,'USN-7001-1','medium',1),($1,'usn-6999-2','high',1)`,
	} {
		if _, err := f.conn.Exec(f.ctx, statement, set); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO advisory_evaluations(device_id,id,evaluated_at,expires_at,state,reason,finding_digest,finding_set_id) VALUES($1,gen_random_uuid(),now(),now()+interval '1 hour','evaluated','',$2,$3)`, f.deviceID, digest, set); err != nil {
		t.Fatal(err)
	}
	advisories := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_ADVISORY_ID, Prefix: "usn-"})
	wantSuggestions(t, advisories, "", "usn-6999-2", "USN-7001-1")
	if advisories.GetSuggestions()[1].GetCount() != 1 {
		t.Fatalf("advisory with two severities counted twice: %v", advisories.GetSuggestions()[1])
	}
	cves := adminv1.SuggestionField_SUGGESTION_FIELD_CVE_ID
	page := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: cves, Prefix: "cve-2026", PageSize: 1})
	wantSuggestions(t, page, "CVE-2026-0001", "CVE-2026-0001")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: cves, Prefix: "cve-2026", PageSize: 1, After: page.GetNextAfter()}), "", "CVE-2026-0002")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: cves, DeviceId: f.deviceID}), "", "CVE-2026-0001", "CVE-2026-0002")
	scoped := fleetReader(t, f, identity.PermissionReadFleet, uuid.NewString())
	wantSuggestions(t, suggest(t, f.svc, scoped, &adminv1.SuggestValuesRequest{Field: cves}), "")
}

func TestSuggestValuesHostEvidenceFollowsLatestObservation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	report := hostObservation(f.generation, 1, "host-values")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.LocalUsers = &inventoryv1.LocalUsers{Status: success, Users: []*inventoryv1.LocalUser{
		{Uid: 0, Name: "root", Shell: "/bin/bash"},
		{Uid: 1000, Name: "Alice", Shell: "/bin/zsh"},
		{Uid: 1001, Name: "admin", Shell: "/bin/bash"},
	}}
	app := func(name string) *inventoryv1.Application {
		unavailable := &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		return &inventoryv1.Application{Name: name, Version: unavailable, Architecture: unavailable, Scope: unavailable}
	}
	report.Observation.Details.Flatpak = &inventoryv1.ApplicationDetails{Status: success, Applications: []*inventoryv1.Application{app("org.mozilla.firefox")}}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	users := adminv1.SuggestionField_SUGGESTION_FIELD_LOCAL_USER_NAME
	page := suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: users, PageSize: 2})
	wantSuggestions(t, page, "Alice", "admin", "Alice")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: users, PageSize: 2, After: page.GetNextAfter()}), "", "root")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_LOGIN_SHELL, Prefix: "/BIN/"}), "", "/bin/bash", "/bin/zsh")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_FLATPAK_APP, DeviceId: f.deviceID}), "", "org.mozilla.firefox")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_SNAP_NAME}), "")
	wantSuggestions(t, suggest(t, f.svc, fleetReader(t, f, identity.PermissionReadFleet, uuid.NewString()), &adminv1.SuggestValuesRequest{Field: users}), "")

	// The next observation replaces every kind; a failed collection is empty,
	// as the device page shows it, not the earlier accounts.
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	report.Sequence = 2
	report.Observation.Details.LocalUsers = &inventoryv1.LocalUsers{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED}
	report.Observation.Details.Flatpak = &inventoryv1.ApplicationDetails{Status: success, Applications: []*inventoryv1.Application{app("org.gnome.Calculator")}}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: users}), "")
	wantSuggestions(t, suggest(t, f.svc, f.ownerCtx, &adminv1.SuggestValuesRequest{Field: adminv1.SuggestionField_SUGGESTION_FIELD_FLATPAK_APP}), "", "org.gnome.Calculator")
}
