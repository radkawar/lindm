package identity

import (
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// These closed registries drive binding/decision authorization and both inbox
// queries. Adding an action cannot require a second visibility allow-list.
var approvalPayloadPermissions = map[protoreflect.FullName]Permission{
	"lindm.admin.v1.ApprovePendingEnrollmentRequest":      PermissionManageEnrollment,
	"lindm.admin.v1.CreateRecoveryEnrollmentGrantRequest": PermissionRevokeDevice,
	"lindm.admin.v1.RevokeDeviceRequest":                  PermissionRevokeDevice,
	"lindm.admin.v1.SetResourceAssignmentRequest":         PermissionAssignResources,
	"lindm.admin.v1.ActivateTargetPreviewRequest":         PermissionAssignResources,
	"lindm.admin.v1.UpdateExecutionAuthorityRequest":      PermissionManageExecutionTrust,
	"lindm.admin.v1.RevealRecoveryKeyRequest":             PermissionReadRecoveryKeys,
	"lindm.admin.v1.RevealSecretRequest":                  PermissionRevealSecrets,
	"lindm.admin.v1.RevealLocalAdminPasswordRequest":      PermissionRevealSecrets,
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
