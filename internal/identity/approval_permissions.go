// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

// These closed registries drive binding/decision authorization and both inbox
// queries. Adding an action cannot require a second visibility allow-list.
var approvalPayloadPermissions = map[protoreflect.FullName]Permission{
	"lindm.admin.v1.ApprovePendingEnrollmentRequest":      PermissionManageEnrollment,
	"lindm.admin.v1.CreateRecoveryEnrollmentGrantRequest": PermissionRevokeDevice,
	"lindm.admin.v1.RevokeDeviceRequest":                  PermissionRevokeDevice,
	"lindm.admin.v1.SetResourceAssignmentRequest":         PermissionAssignResources,
	"lindm.admin.v1.ActivateTargetPreviewRequest":         PermissionAssignResources,
	"lindm.admin.v1.StartRolloutRequest":                  PermissionAssignResources,
	"lindm.admin.v1.UpdateExecutionAuthorityRequest":      PermissionManageExecutionTrust,
	"lindm.admin.v1.RevealRecoveryKeyRequest":             PermissionReadRecoveryKeys,
	"lindm.admin.v1.RevealSecretRequest":                  PermissionRevealSecrets,
	"lindm.admin.v1.RevealLocalAdminPasswordRequest":      PermissionRevealSecrets,
	"lindm.admin.v1.AcceptAdvisoryFindingRequest":         PermissionManageAdvisoryExceptions,
	"lindm.admin.v1.AuthorizeUnattendedAssistanceRequest": PermissionAssistanceUnattended,
}
var deviceActionPermissions = map[protoreflect.Name]Permission{
	"escrow_rotate":      PermissionManageEncryption,
	"tpm2_bind":          PermissionManageEncryption,
	"lock_sessions":      PermissionLockDevice,
	"release_lock":       PermissionReleaseLockDevice,
	"quarantine":         PermissionQuarantineDevice,
	"release_quarantine": PermissionQuarantineDevice,
	"crypto_erase":       PermissionExecuteDestructive,
	"sanitize":           PermissionExecuteDestructive,
	"restart":            PermissionRunRemoteExecution,
	"shutdown":           PermissionRunRemoteExecution,
	"refresh_inventory":  PermissionManageInventory,
	// Server-minted from a managed policy; the policy actor's secrets.manage authority.
	"local_admin_password_rotate": PermissionManageSecrets,
	"patch_now":                   PermissionRunRemoteExecution,
}

// Supplemental grants retain their own scope intersection in both decisions and
// display projections; the primary permission alone is not sufficient authority.
var approvalPermissionRequirements = map[Permission][]Permission{
	PermissionManageInventory: {PermissionReadFleet},
}

// approvalReviewerPermissions names an action whose second person needs an
// independent approve permission instead of the requester's action permission.
// The reviewer still needs approvals.manage and never equals the requester.
var approvalReviewerPermissions = map[Permission]Permission{
	PermissionAssistanceUnattended: PermissionApproveAssistanceUnattended,
}

func approvalReviewerPermission(permission Permission) Permission {
	if reviewer, ok := approvalReviewerPermissions[permission]; ok {
		return reviewer
	}
	return permission
}

// reviewer is the binding the second person is scoped against.
func (b approvalBinding) reviewer() approvalBinding {
	b.permission = approvalReviewerPermission(b.permission)
	return b
}

// approvalActionAudits names the domain audit an approval lifecycle event
// also records, in the same transaction as the generic approval event.
var approvalActionAudits = map[string]map[string]auditkind.Kind{
	"assistance.unattended": {"request": auditkind.AssistanceUnattendedRequest, "approved": auditkind.AssistanceUnattendedApprove, "rejected": auditkind.AssistanceUnattendedReject},
}

func (s *Service) insertApprovalActionAudit(ctx context.Context, q *identitydb.Queries, actor uuid.UUID, action, event string, approval uuid.UUID, device *uuid.UUID) error {
	name, ok := approvalActionAudits[action][event]
	if !ok {
		return nil
	}
	resource := approval.String()
	values := map[string]string{"approval": approval.String(), "result": event}
	if device != nil {
		resource = device.String()
		values["device"] = device.String()
	}
	details, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return s.dbErr(q.InsertAuditEvent(ctx, identitydb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor, Action: name.String(), ResourceID: resource, Details: details}))
}

// DeviceActionPermission returns no authority for an unknown or missing arm.
func DeviceActionPermission(spec *agentv1.DeviceActionSpec) Permission {
	if spec == nil {
		return ""
	}
	message := spec.ProtoReflect()
	field := message.WhichOneof(message.Descriptor().Oneofs().ByName("action"))
	if field == nil {
		return ""
	}
	return deviceActionPermissions[field.Name()]
}
func approvalPermission(message proto.Message) Permission {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ""
	}
	if request, ok := message.(*adminv1.CreateDeviceActionRequest); ok {
		return DeviceActionPermission(request.GetSpec())
	}
	return approvalPayloadPermissions[message.ProtoReflect().Descriptor().FullName()]
}

var approvalInboxPermissions = func() []Permission {
	permissions := make([]Permission, 0, len(approvalPayloadPermissions)+len(deviceActionPermissions))
	for _, permission := range approvalPayloadPermissions {
		permissions = append(permissions, permission)
	}
	for _, permission := range deviceActionPermissions {
		permissions = append(permissions, permission)
	}
	slices.Sort(permissions)
	return slices.Compact(permissions)
}()
