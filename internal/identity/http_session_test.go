// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
)

// The console derives navigation and global controls from these server-computed
// capabilities; it must never recompute them from a role table of its own.
func TestSessionReportsCapabilitiesPerRole(t *testing.T) {
	engineering := &authv1.DeviceScope{Labels: []string{"engineering"}}
	all := Permissions(Principal{Role: RoleOwner})
	admin := builtinPermissions(RoleAdmin)
	helpdesk := []string{string(PermissionReadFleet), string(PermissionManageEnrollment)}
	for _, test := range []struct {
		name         string
		principal    Principal
		permissions  []string
		unrestricted []string
	}{
		{"owner", Principal{Role: RoleOwner}, all, all},
		{"approver", Principal{Role: RoleAdmin, Bindings: []*authv1.RoleBinding{
			{Role: RoleAdmin, Permissions: admin},
		}}, admin, admin},
		{"scoped helpdesk", Principal{Role: RoleHelpdesk, Bindings: []*authv1.RoleBinding{
			{Role: RoleHelpdesk, Permissions: helpdesk, Scopes: []*authv1.DeviceScope{engineering}},
		}}, helpdesk, []string{}},
		{"scoped helpdesk with an unrestricted grant", Principal{Role: RoleHelpdesk, Bindings: []*authv1.RoleBinding{
			{Role: RoleHelpdesk, Permissions: helpdesk, Scopes: []*authv1.DeviceScope{engineering}},
			{Role: "reader", Permissions: []string{string(PermissionReadFleet)}},
		}}, helpdesk, []string{string(PermissionReadFleet)}},
		{"break-glass owner", Principal{Role: RoleOwner, BreakGlass: true, AllowedPermissions: []string{string(PermissionReadFleet), string(PermissionManageAccounts)}},
			[]string{string(PermissionReadFleet), string(PermissionManageAccounts)},
			[]string{string(PermissionReadFleet), string(PermissionManageAccounts)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.principal.ID = uuid.New()
			recorder := httptest.NewRecorder()
			writeSession(recorder, test.principal)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
			session := new(authv1.SessionPrincipal)
			if err := protojson.Unmarshal(recorder.Body.Bytes(), session); err != nil {
				t.Fatal(err)
			}
			if got := session.GetPermissions(); !slices.Equal(got, test.permissions) {
				t.Fatalf("permissions = %v, want %v", got, test.permissions)
			}
			if got := session.GetUnrestrictedPermissions(); !slices.Equal(got, test.unrestricted) {
				t.Fatalf("unrestricted permissions = %v, want %v", got, test.unrestricted)
			}
		})
	}
}
