// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/json"
	"slices"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
)

func TestApprovalRegistryCoversClosedPayloadAndActionOneofs(t *testing.T) {
	request := new(adminv1.CreateApprovalRequest).ProtoReflect()
	fields := request.Descriptor().Oneofs().ByName("payload").Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		payload := request.NewField(field).Message().Interface()
		if _, ok := payload.(*adminv1.CreateDeviceActionRequest); ok {
			continue
		}
		permission := approvalPermission(payload)
		if permission == "" || !slices.Contains(approvalInboxPermissions, permission) {
			t.Fatalf("approval arm %s has no inbox authorization", field.FullName())
		}
	}
	spec := new(agentv1.DeviceActionSpec)
	action := spec.ProtoReflect()
	fields = action.Descriptor().Oneofs().ByName("action").Fields()
	if fields.Len() != len(deviceActionPermissions) {
		t.Fatal("closed action registry and schema diverged")
	}
	for i := range fields.Len() {
		field := fields.Get(i)
		action.Set(field, action.NewField(field))
		permission := approvalPermission(&adminv1.CreateDeviceActionRequest{Spec: spec})
		if permission == "" || !slices.Contains(approvalInboxPermissions, permission) {
			t.Fatalf("device action arm %s has no inbox authorization", field.FullName())
		}
	}
}

func TestApprovalRequiredScopesRetainIndependentReadGrant(t *testing.T) {
	target := "11111111-1111-4111-8111-111111111111"
	principal := Principal{Role: RoleOwner, Bindings: []*authv1.RoleBinding{{Permissions: []string{string(PermissionManageInventory), string(PermissionManageApprovals)}}}}
	required, err := approvalRequiredScopes(principal, PermissionManageInventory)
	if err != nil || len(required) != 1 || required[0].Unrestricted || string(required[0].Scopes) != "[]" {
		t.Fatalf("missing fleet-read grant was broadened: %v %v", required, err)
	}
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{target}}}})
	required, err = approvalRequiredScopes(principal, PermissionManageInventory)
	if err != nil || len(required) != 1 || required[0].Unrestricted {
		t.Fatalf("scoped read was broadened by unrestricted management: %v %v", required, err)
	}
	var scopes []struct {
		DeviceIDs []string `json:"device_ids"`
	}
	if err := json.Unmarshal(required[0].Scopes, &scopes); err != nil || len(scopes) != 1 || len(scopes[0].DeviceIDs) != 1 || scopes[0].DeviceIDs[0] != target {
		t.Fatalf("independent read scope changed: %s %v", required[0].Scopes, err)
	}
	principal.Bindings[1].Scopes = nil
	required, err = approvalRequiredScopes(principal, PermissionManageInventory)
	if err != nil || !required[0].Unrestricted {
		t.Fatalf("unrestricted read was lost: %v %v", required, err)
	}
}
