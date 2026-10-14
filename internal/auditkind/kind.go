// SPDX-License-Identifier: Apache-2.0

// Package auditkind is the registry of audit event kinds: every action code the
// server writes to audit_events.action. Audit write helpers take a Kind, which
// only this package constructs, so All enumerates every kind a server can record
// and the console's human names (web/src/features/audit/action-names.json) are
// checked against it. The package does not write audit rows, assign search
// categories, or describe kinds for people.
package auditkind

// Kind is one recorded audit action code. The zero Kind is never valid.
type Kind struct{ code string }

// String returns the exact code stored in audit_events.action and the hash chain.
func (k Kind) String() string { return k.code }

// registry is appended to only while the package variables below initialize.
var registry []Kind

func kind(code string) Kind {
	k := Kind{code: code}
	registry = append(registry, k)
	return k
}

// All returns every registered kind in declaration order.
func All() []Kind { return append([]Kind(nil), registry...) }

// Strings returns the codes of kinds, for SQL array parameters.
func Strings(kinds ...Kind) []string {
	codes := make([]string, len(kinds))
	for i, k := range kinds {
		codes[i] = k.code
	}
	return codes
}

// HumanActionsExcluded lists kinds a person causes that are not decisions:
// signing in and out and reading the approvals inbox. The "Human actions"
// audit view and export selection omit them; "All actions" keeps them.
func HumanActionsExcluded() []Kind {
	return []Kind{ApprovalListed, IdentityLogin, IdentityCLILogin, IdentityLogout}
}

// Advisory evidence and exceptions.
var (
	AdvisoryExceptionAccepted = kind("advisory.exception.accepted")
	// Written once by migration 00019, never by a running server.
	AdvisoryExceptionMigrationRemoved = kind("advisory.exception.migration_removed")
	AdvisoryFeedIngested              = kind("advisory.feed.ingested")
	AdvisoryFindingsChanged           = kind("advisory.findings.changed")
)

// Two-person approvals.
var (
	ApprovalApproved  = kind("approval.approved")
	ApprovalConsumed  = kind("approval.consumed")
	ApprovalCreated   = kind("approval.created")
	ApprovalListed    = kind("approval.listed")
	ApprovalRejected  = kind("approval.rejected")
	ApprovalWithdrawn = kind("approval.withdrawn")
)

// Remote assistance sessions.
var (
	AssistanceAnswer        = kind("assistance.answer")
	AssistanceClipboard     = kind("assistance.clipboard")
	AssistanceCommandDenied = kind("assistance.command_denied")
	AssistanceConsent       = kind("assistance.consent")
	AssistanceDisplay       = kind("assistance.display")
	AssistanceEnd           = kind("assistance.end")
	AssistanceJoin          = kind("assistance.join")
	AssistanceMessage       = kind("assistance.message")
	AssistancePolicy        = kind("assistance.policy")
	AssistancePrompt        = kind("assistance.prompt")
	AssistanceRequest       = kind("assistance.request")
	AssistanceSpecialKeys   = kind("assistance.special_keys")
	AssistanceStart         = kind("assistance.start")
	AssistanceStop          = kind("assistance.stop")
)

// Device management capability policies: an administrator's scope change and
// the server's per-device signed issue.
var (
	CapabilityPolicyIssue = kind("capability_policy.issue")
	CapabilityPolicySet   = kind("capability_policy.set")
)

// Remote assistance file transfer.
var (
	AssistanceFileCancel   = kind("assistance.file.cancel")
	AssistanceFileComplete = kind("assistance.file.complete")
	AssistanceFileDeny     = kind("assistance.file.deny")
	AssistanceFileRequest  = kind("assistance.file.request")
)

// Remote assistance reconnect workflows and encrypted recordings.
var (
	AssistanceReconnectConsent = kind("assistance.reconnect.consent")
	AssistanceReconnectEnd     = kind("assistance.reconnect.end")
	AssistanceReconnectExpire  = kind("assistance.reconnect.expire")
	AssistanceReconnectRequest = kind("assistance.reconnect.request")
	AssistanceRecordingDelete  = kind("assistance.recording.delete")
	AssistanceRecordingRead    = kind("assistance.recording.read")
	// Written by the server's own retention maintenance, never by a person.
	AssistanceRecordingRetention = kind("assistance.recording.retention")
	AssistanceRecordingStart     = kind("assistance.recording.start")
	AssistanceRecordingStop      = kind("assistance.recording.stop")
)

// Remote assistance Tier 3: unattended access, password guidance, pointer and
// sound.
var (
	AssistanceAnnotationClear   = kind("assistance.annotation.clear")
	AssistanceAnnotationDisable = kind("assistance.annotation.disable")
	AssistanceAnnotationEnable  = kind("assistance.annotation.enable")
	AssistanceAudioConsent      = kind("assistance.audio.consent")
	AssistanceAudioMute         = kind("assistance.audio.mute")
	AssistanceAudioSource       = kind("assistance.audio.source")
	AssistanceAudioStop         = kind("assistance.audio.stop")
	AssistanceElevationPause    = kind("assistance.elevation.pause")
	AssistanceElevationRequest  = kind("assistance.elevation.request")
	AssistanceElevationResume   = kind("assistance.elevation.resume")
	AssistanceUnattendedApprove = kind("assistance.unattended.approve")
	// Activation of an approved access period by its requester.
	AssistanceUnattendedAuthorize = kind("assistance.unattended.authorize")
	AssistanceUnattendedEnroll    = kind("assistance.unattended.enroll")
	AssistanceUnattendedReject    = kind("assistance.unattended.reject")
	AssistanceUnattendedRequest   = kind("assistance.unattended.request")
	AssistanceUnattendedRevoke    = kind("assistance.unattended.revoke")
	AssistanceUnattendedStart     = kind("assistance.unattended.start")
	AssistanceUnattendedStop      = kind("assistance.unattended.stop")
)

// Written by the compliance_record_states database function.
var ComplianceStateChanged = kind("compliance.state.changed")

// An actual deployment owner's scoped attestation, not verified external storage.
var RecoveryCustodyConfirmed = kind("recovery_custody.confirmed")

// Deployment status transitions and bounded reminders, written by the status collector.
var (
	ServerStatusUnknown   = kind("server.status.unknown")
	ServerStatusAttention = kind("server.status.attention")
	ServerStatusFailed    = kind("server.status.failed")
	ServerStatusRecovered = kind("server.status.recovered")
	ServerStatusInactive  = kind("server.status.inactive")
)

// Device identity, lifecycle and groups.
var (
	DeviceActivate            = kind("device.activate")
	DeviceAgentUpdateReported = kind("device.agent_update.reported")
	DeviceEnroll              = kind("device.enroll")
	DeviceGroupDelete         = kind("device.group_delete")
	DeviceGroupSet            = kind("device.group_set")
	DeviceRecovered           = kind("device.recovered")
	DeviceRecoveryAuthorized  = kind("device.recovery_authorized")
	DeviceRecoveryHold        = kind("device.recovery_hold")
	DeviceRenew               = kind("device.renew")
	DeviceRevoke              = kind("device.revoke")
)

// Device actions. resource_id is the device action ID.
var (
	DeviceActionCreate             = kind("device_action.create")
	DeviceActionEscrowReceipt      = kind("device_action.escrow_receipt")
	DeviceActionEscrowStore        = kind("device_action.escrow_store")
	DeviceActionInventoryPublished = kind("device_action.inventory_published")
	DeviceActionRecoveryCheckpoint = kind("device_action.recovery_checkpoint")
	DeviceActionRecoveryHandoff    = kind("device_action.recovery_handoff")
	DeviceActionRecoveryResult     = kind("device_action.recovery_result")
	DeviceActionRecoveryStart      = kind("device_action.recovery_start")
	DeviceActionResult             = kind("device_action.result")
	DeviceActionStart              = kind("device_action.start")
	DeviceEncryptionKeyRegistered  = kind("device_encryption_key.registered")
)

// Enrollment.
var (
	EnrollmentOfflineAuthorization = kind("enrollment.offline_authorization")
	EnrollmentOfflineImport        = kind("enrollment.offline_import")
	EnrollmentOfflineResponse      = kind("enrollment.offline_response")
	EnrollmentGrantCreate          = kind("enrollment_grant.create")
	EnrollmentGrantRevoke          = kind("enrollment_grant.revoke")
	ProvisioningApprove            = kind("provisioning.approve")
	ProvisioningReserve            = kind("provisioning.reserve")
	ProvisioningTokenCreate        = kind("provisioning_token.create")
	ProvisioningTokenRevoke        = kind("provisioning_token.revoke")
)

// Execution authority (execution trust).
var (
	ExecutionAuthorityInitialize = kind("execution_authority.initialize")
	ExecutionAuthorityUpdate     = kind("execution_authority.update")
)

// Accounts, sign-in and organization access.
var (
	IdentityAuthorizationChanged = kind("identity.authorization_changed")
	IdentityAuthorizationUpdated = kind("identity.authorization_updated")
	// Written by server startup when the persisted policy names a retired permission.
	IdentityAuthorizationUpgraded = kind("identity.authorization_upgraded")
	IdentityBreakGlassActivated   = kind("identity.break_glass_activated")
	IdentityBreakGlassDenied      = kind("identity.break_glass_denied")
	IdentityBreakGlassTerminated  = kind("identity.break_glass_terminated")
	IdentityBreakGlassUsed        = kind("identity.break_glass_used")
	IdentityCLIApproved           = kind("identity.cli_approved")
	IdentityCLILogin              = kind("identity.cli_login")
	IdentityDisabled              = kind("identity.disabled")
	IdentityLineageDenied         = kind("identity.lineage_denied")
	IdentityLocalAccountCreated   = kind("identity.local_account_created")
	IdentityLocalAccountUpdated   = kind("identity.local_account_updated")
	IdentityLocalCredentialsReset = kind("identity.local_credentials_reset")
	IdentityLocalEnrolled         = kind("identity.local_enrolled")
	IdentityLocalLoginDenied      = kind("identity.local_login_denied")
	IdentityLocalMFADenied        = kind("identity.local_mfa_denied")
	IdentityLogin                 = kind("identity.login")
	IdentityLoginDenied           = kind("identity.login_denied")
	IdentityLogout                = kind("identity.logout")
	IdentityOwnerBootstrapped     = kind("identity.owner_bootstrapped")
	IdentityReactivated           = kind("identity.reactivated")
	IdentitySCIMCreated           = kind("identity.scim_created")
	IdentitySCIMCredentialRotated = kind("identity.scim_credential_rotated")
	IdentitySCIMDeleted           = kind("identity.scim_deleted")
	IdentitySCIMLifecycle         = kind("identity.scim_lifecycle")
	IdentitySCIMUpdated           = kind("identity.scim_updated")
	// In-page re-verification (password, then passkey) on a signed-in session.
	IdentityStepUp       = kind("identity.step_up")
	IdentityStepUpDenied = kind("identity.step_up_denied")
)

// Assistant access and credential management.
var (
	IdentityMCPSettingsChanged = kind("identity.mcp_settings_changed")
	IdentityMCPTokenIssued     = kind("identity.mcp_token_issued")
	IdentityMCPTokenRevoked    = kind("identity.mcp_token_revoked")
	MCPAttempt                 = kind("mcp.attempt")
)

// Event destinations (webhooks, syslog).
var (
	IntegrationDeliveryReplayed         = kind("integration.delivery.replayed")
	IntegrationDestinationCreated       = kind("integration.destination.created")
	IntegrationDestinationDeleted       = kind("integration.destination.deleted")
	IntegrationDestinationSecretRotated = kind("integration.destination.secret_rotated")
	IntegrationDestinationUpdated       = kind("integration.destination.updated")
)

// Inventory metadata. The code carries the admin RPC method name.
var (
	InventorySetAttributeDefinition = kind("inventory.SetAttributeDefinition")
	InventorySetDeviceMetadata      = kind("inventory.SetDeviceMetadata")
)

// Managed local administrator passwords.
var (
	LocalAdminEscrowStore       = kind("local_admin.escrow_store")
	LocalAdminPolicyRemoved     = kind("local_admin.policy_removed")
	LocalAdminPolicySet         = kind("local_admin.policy_set")
	LocalAdminReveal            = kind("local_admin.reveal")
	LocalAdminRotationRequested = kind("local_admin.rotation_requested")
)

// Offline bundles.
var OfflineBundleImported = kind("offline_bundle.imported")

// Written by the InsertProfileAudit query.
var ProfilePublish = kind("profile.publish")

// Recovery keys.
var RecoveryKeyReveal = kind("recovery_key.reveal")

// Agent releases.
var (
	ReleaseRolloutPublished = kind("release.rollout.published")
	ReleaseRolloutRequest   = kind("release.rollout.request")
	ReleaseSeriesRegister   = kind("release.series.register")
)

// Reports and audit exports.
var (
	ReportAuditExportCreated = kind("report.audit_export.created")
	ReportScheduleUpdated    = kind("report.schedule.updated")
)

// Typed resource actions and assignments.
var (
	ResourceActionMint              = kind("resource_action.mint")
	ResourceActionPreparationCancel = kind("resource_action.preparation_cancel")
	ResourceActionResult            = kind("resource_action.result")
	ResourceActionStart             = kind("resource_action.start")
	ResourceAssignmentAssign        = kind("resource_assignment.assign")
	ResourceAssignmentClear         = kind("resource_assignment.clear")
)

// Secrets.
var (
	SecretCreated   = kind("secret.created")
	SecretDeleted   = kind("secret.deleted")
	SecretDelivered = kind("secret.delivered")
	SecretReveal    = kind("secret.reveal")
	SecretRotated   = kind("secret.rotated")
)

// Targeting: groups, assignments, previews and rollouts. The code is also the
// idempotency receipt method.
var (
	TargetingAssignmentPut   = kind("targeting.assignment.put")
	TargetingGroupPut        = kind("targeting.group.put")
	TargetingPreviewActivate = kind("targeting.preview.activate")
	TargetingRolloutControl  = kind("targeting.rollout.control")
	TargetingRolloutPause    = kind("targeting.rollout.pause")
	TargetingRolloutPut      = kind("targeting.rollout.put")
	TargetingRolloutStart    = kind("targeting.rollout.start")
)
