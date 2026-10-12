//go:build integration

package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/advisory"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func scopedReader(principal identity.Principal, scopes ...*authv1.DeviceScope) identity.Principal {
	principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadFleet)}, Scopes: scopes}}
	return principal
}

func TestDeviceScopeReadMatrix(t *testing.T) {
	f := newEnrolled(t, 0)
	f.publishPackages(t, 1, "visible-package")
	var err error
	f.svc.Advisories, err = advisory.New(f.ctx, f.svc.Pool, nil, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	readers := []struct {
		name string
		read func(context.Context, string) error
	}{
		{"GetDevice", func(ctx context.Context, id string) error {
			_, err := f.svc.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: id}))
			return err
		}},
		{"ListDevicePackages", func(ctx context.Context, id string) error {
			_, err := f.svc.ListDevicePackages(ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: id}))
			return err
		}},
		{"GetDeviceResourceState", func(ctx context.Context, id string) error {
			_, err := f.svc.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: id}))
			return err
		}},
		{"ListDeviceFindings", func(ctx context.Context, id string) error {
			_, err := f.svc.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: id}))
			return err
		}},
		{"GetDeviceActions", func(ctx context.Context, id string) error {
			_, err := f.svc.GetDeviceActions(ctx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: id}))
			return err
		}},
		{"ListDeviceStorageTargets", func(ctx context.Context, id string) error {
			_, err := f.svc.ListDeviceStorageTargets(ctx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: id, ActionKind: "sanitize"}))
			return err
		}},
	}
	for _, role := range []string{"owner", "admin", "operator", "helpdesk", "auditor"} {
		for _, reader := range readers {
			t.Run(role+"/"+reader.name, func(t *testing.T) {
				principal := owner
				principal.Role = role
				principal = scopedReader(principal, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
				if err := reader.read(identity.WithPrincipal(f.ctx, principal), f.deviceID); err != nil {
					t.Fatalf("in-scope device: %v", err)
				}
				principal = scopedReader(principal, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
				ctx := identity.WithPrincipal(f.ctx, principal)
				denied := reader.read(ctx, f.deviceID)
				missing := reader.read(ctx, uuid.NewString())
				if connect.CodeOf(denied) != connect.CodeNotFound || connect.CodeOf(missing) != connect.CodeNotFound || rpcReason(denied) != rpcReason(missing) {
					t.Fatalf("existence leaked: denied=%v missing=%v", denied, missing)
				}
			})
		}
	}
	principal := scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	ctx := identity.WithPrincipal(f.ctx, principal)
	first, err := f.svc.ListDevicePackages(ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	principal = scopedReader(principal, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
	if _, err := f.svc.ListDevicePackages(identity.WithPrincipal(f.ctx, principal), connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageToken: first.Msg.GetPageToken()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("saved package cursor bypassed revoked scope: %v", err)
	}
}

func TestGetDeviceReportsCallerPermissionsForThatDevice(t *testing.T) {
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	callerPermissions := func(principal identity.Principal) []string {
		t.Helper()
		response, err := f.svc.GetDevice(identity.WithPrincipal(f.ctx, principal), connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetCallerPermissions()
	}
	if got, want := callerPermissions(owner), identity.Permissions(owner); !slices.Equal(got, want) {
		t.Fatalf("owner caller permissions = %v, want %v", got, want)
	}
	here := &authv1.DeviceScope{DeviceIds: []string{f.deviceID}}
	elsewhere := &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}}
	helpdesk := owner
	helpdesk.Role = identity.RoleHelpdesk
	helpdesk.Bindings = []*authv1.RoleBinding{
		{Role: identity.RoleHelpdesk, Permissions: []string{string(identity.PermissionReadFleet), string(identity.PermissionManageEnrollment)}, Scopes: []*authv1.DeviceScope{here}},
		{Role: "restarter", Permissions: []string{string(identity.PermissionRunRemoteExecution)}, Scopes: []*authv1.DeviceScope{elsewhere}},
		{Role: "inventory", Permissions: []string{string(identity.PermissionManageInventory)}},
	}
	want := []string{string(identity.PermissionReadFleet), string(identity.PermissionManageEnrollment), string(identity.PermissionManageInventory)}
	if got := callerPermissions(helpdesk); !slices.Equal(got, want) {
		t.Fatalf("scoped caller permissions = %v, want %v (no grant scoped to another device)", got, want)
	}
}

func TestDeviceScopeFiltersBeforePagesAndCounts(t *testing.T) {
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	groupID := uuid.New()
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_groups(id,name) VALUES($1,'scope regression')`, groupID); err != nil {
		t.Fatal(err)
	}
	var want []string
	var all []string
	for i := range 8 {
		id := uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1))
		all = append(all, id.String())
		// Advisory totals count active devices, including ones with no usable
		// inventory. Keep both visible and hidden fixtures in that population.
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,$3,'scope-os')`, id, f.now.Add(-time.Minute), fmt.Sprintf("scope-%d", i)); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_labels(device_id,label) VALUES($1,'site-a'),($1,'workstation')`, id); err != nil {
				t.Fatal(err)
			}
			want = append(want, id.String())
		} else if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_labels(device_id,label) VALUES($1,'site-a')`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_group_memberships(group_id,device_id) VALUES($1,$2)`, groupID, id); err != nil {
			t.Fatal(err)
		}
	}
	slices.Reverse(want)
	principal := scopedReader(owner, &authv1.DeviceScope{Labels: []string{"site-a", "workstation"}, GroupIds: []string{groupID.String()}, DeviceIds: all})
	// A different permission's unrestricted grant must not broaden fleet reads.
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(identity.PermissionReadAudit)}})
	ctx := identity.WithPrincipal(f.ctx, principal)
	var got []string
	token := ""
	for page := range 5 {
		result, err := f.svc.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 2, PageToken: token, Filter: &adminv1.DeviceFilter{OsId: "scope-os"}}))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Msg.GetDevices()) != 2 {
			t.Fatalf("hidden rows consumed page capacity: page=%d count=%d", page, len(result.Msg.GetDevices()))
		}
		for _, row := range result.Msg.GetDevices() {
			got = append(got, row.GetId())
		}
		token = result.Msg.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if !slices.Equal(got, want) || token != "" {
		t.Fatalf("scope keyset pagination: got=%v want=%v continuation=%q", got, want, token)
	}
	unrestricted, scopes, err := core.DeviceScopeFilter(principal, identity.PermissionReadFleet)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM devices d WHERE device_scope_matches(d.id,$1,$2::jsonb)`, unrestricted, scopes).Scan(&count); err != nil || count != len(want) {
		t.Fatalf("scope count leaked rows: count=%d want=%d error=%v", count, len(want), err)
	}
	f.svc.Advisories, err = advisory.New(f.ctx, f.svc.Pool, nil, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := f.svc.ListAdvisorySummary(ctx, connect.NewRequest(&adminv1.ListAdvisorySummaryRequest{PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Msg.GetUnknownDevices()+summary.Msg.GetEvaluatedDevices() != uint64(len(want)) {
		t.Fatalf("advisory RPC totals exposed out-of-scope devices: %v", summary.Msg)
	}
	for _, format := range []adminv1.DeviceExportFormat{adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON, adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV} {
		response, err := f.svc.ExportDevices(ctx, connect.NewRequest(&adminv1.ExportDevicesRequest{Format: format, PageSize: 200}))
		if err != nil {
			t.Fatal(err)
		}
		if got := splitExportTokens(response.Msg.GetContent()); !slices.Equal(got, want) {
			t.Fatalf("export format %s scope: got=%v want=%v", format, got, want)
		}
	}
	// A scope containing an explicit ID is ORed with the conjunctive scope.
	principal.Bindings[0].Scopes = append(principal.Bindings[0].Scopes, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	if err := core.RequireDeviceScope(f.ctx, devicedb.New(f.svc.Pool), principal, identity.PermissionReadFleet, f.principal.DeviceID); err != nil {
		t.Fatalf("alternative scope was not ORed: %v", err)
	}
	// Nil scopes cannot turn malformed authority into a match-all grant.
	principal.Bindings[0].Scopes = []*authv1.DeviceScope{nil}
	if err := core.RequireDeviceScope(f.ctx, devicedb.New(f.svc.Pool), principal, identity.PermissionReadFleet, f.principal.DeviceID); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("nil scope admitted device: %v", err)
	}
}

func splitExportTokens(data []byte) []string {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(data, &rows) == nil {
		result := make([]string, 0, len(rows))
		for _, row := range rows {
			var id string
			if json.Unmarshal(row["id"], &id) == nil {
				result = append(result, id)
			}
		}
		return result
	}
	// CSV IDs are the first column and cannot contain delimiters.
	var result []string
	for _, line := range strings.Split(string(data), "\n") {
		id, _, _ := strings.Cut(line, ",")
		if id == "" || id == "id" {
			continue
		}
		result = append(result, id)
	}
	return result
}

func TestDeviceGroupMembershipFencesScopeAndReplay(t *testing.T) {
	f := newEnrolled(t, 0)
	groupID := uuid.NewString()
	request := &adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: groupID, Name: "managed scope", DeviceIds: []string{f.deviceID}, Reason: "test group authorization"}
	if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	principal := scopedReader(owner, &authv1.DeviceScope{GroupIds: []string{groupID}})
	tx, err := f.svc.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if _, err := core.LockDeviceScope(f.ctx, devicedb.New(tx), principal, identity.PermissionReadFleet, f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	remove := &adminv1.DeleteDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: groupID, Reason: "remove group scope"}
	blockedCtx, cancel := context.WithTimeout(f.ownerCtx, 200*time.Millisecond)
	_, err = f.svc.DeleteDeviceGroup(blockedCtx, connect.NewRequest(remove))
	cancel()
	if connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("group mutation did not wait for scope fence: %v", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DeleteDeviceGroup(f.ownerCtx, connect.NewRequest(remove)); err != nil {
		t.Fatal(err)
	}
	if err := core.RequireDeviceScope(f.ctx, devicedb.New(f.svc.Pool), principal, identity.PermissionReadFleet, f.principal.DeviceID); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted membership retained authority: %v", err)
	}
	if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact set replay failed: %v", err)
	}
	if err := core.RequireDeviceScope(f.ctx, devicedb.New(f.svc.Pool), principal, identity.PermissionReadFleet, f.principal.DeviceID); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("set replay recreated deleted authorization: %v", err)
	}
	request.Name = "changed replay"
	if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed group replay admitted: %v", err)
	}
}

func TestDeviceMutationUsesFreshCapturedScope(t *testing.T) {
	f := newEnrolled(t, 0)
	outside := uuid.New()
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at) VALUES($1,'pending',$2)`, outside, f.now); err != nil {
		t.Fatal(err)
	}
	// The request's cached admin display role is deliberately unrestricted.
	// Only the newly fetched directory binding restricts this mutation.
	authority, actor, directory := dispatchIdentity(t, f.svc.Pool, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	f.svc.Identity = authority
	ctx := identity.WithPrincipal(f.ctx, actor)
	request := &adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: outside.String(), Metadata: &adminv1.DeviceMetadata{Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "restricted-write"}}, Reason: "fresh scoped write"}
	if _, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("cached role bypassed fresh scope: %v", err)
	}
	request.DeviceId = uuid.NewString()
	if _, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing target differs from scoped denial: %v", err)
	}
	request.DeviceId = f.deviceID
	request.Metadata.Labels = []string{"execution-scope"}
	if _, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped inventory grant widened authorization labels: %v", err)
	}
	request.Metadata.Labels = nil
	if _, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(request)); err != nil {
		t.Fatalf("fresh in-scope mutation: %v", err)
	}
	assignment := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: outside.String(), Clear: true, Reason: "fresh scoped assignment"}
	if _, err := f.svc.SetResourceAssignment(ctx, connect.NewRequest(assignment)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("assignment cached role bypassed fresh scope: %v", err)
	}
	assignment.DeviceId = uuid.NewString()
	if _, err := f.svc.SetResourceAssignment(ctx, connect.NewRequest(assignment)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("assignment missing target differs from scoped denial: %v", err)
	}
	assignment.DeviceId = f.deviceID
	if _, err := f.svc.SetResourceAssignment(ctx, connect.NewRequest(assignment)); err != nil {
		t.Fatalf("fresh in-scope assignment: %v", err)
	}
	directory.membership(t, false)
	if _, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("exact request replay bypassed fresh membership revocation: %v", err)
	}
	if _, err := f.svc.SetResourceAssignment(ctx, connect.NewRequest(assignment)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("assignment replay bypassed fresh revocation: %v", err)
	}
	var outsideOwner string
	if err := f.conn.QueryRow(f.ctx, `SELECT coalesce(metadata->>'ownerText','') FROM devices WHERE id=$1`, outside).Scan(&outsideOwner); err != nil || outsideOwner != "" {
		t.Fatalf("denied target mutated: owner=%q error=%v", outsideOwner, err)
	}
}

func TestEveryAdminPermissionScopesTheTarget(t *testing.T) {
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	for name, policy := range adminAuthorizationCases() {
		if policy.permission == "" || policy.global {
			continue
		}
		for _, role := range policy.roles {
			t.Run(name+"/"+role, func(t *testing.T) {
				principal := owner
				principal.Role = role
				principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(policy.permission)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}}}
				q := devicedb.New(f.svc.Pool)
				if err := core.RequireDeviceScope(f.ctx, q, principal, policy.permission, f.principal.DeviceID); err != nil {
					t.Fatalf("in-scope permission: %v", err)
				}
				principal.Bindings[0].Scopes[0].DeviceIds = []string{uuid.NewString()}
				if err := core.RequireDeviceScope(f.ctx, q, principal, policy.permission, f.principal.DeviceID); connect.CodeOf(err) != connect.CodeNotFound {
					t.Fatalf("out-of-scope permission: %v", err)
				}
			})
		}
	}
}
