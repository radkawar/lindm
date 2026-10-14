// SPDX-License-Identifier: Apache-2.0

// Package identity is the admin session boundary.
//
// Local login requires password plus WebAuthn; optional external login uses
// authorization-code PKCE. Authority comes from current local accounts or fresh
// directory observations, never login claims alone. Sessions are opaque and hashed
// at rest. Owner bootstrap is explicit, never claimed by the first login.
package identity

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

// Config is the process dependency injection for one configured issuer.
// It is not a serialized user-config schema.
type Config struct {
	Local                       bool
	BreakGlass                  *configv1.BreakGlassPolicy
	Issuer                      string
	EntraTenantID               string
	ClientID                    string
	ClientSecret                string
	DirectoryClientID           string
	DirectoryClientSecret       string
	Okta                        *configv1.OktaDirectory
	Google                      *configv1.GoogleDirectory
	DirectoryPrivateKeyPEM      []byte
	SCIM                        *configv1.SCIMConfig
	Broker                      *configv1.KeycloakBrokerUpstream
	BrokerDirectoryClientSecret string
	PublicURL                   string
	Policy                      *authv1.AuthorizationPolicy
	HTTPClient                  *http.Client
	// InitialOwnerExecution admits the configured signed initial delegation in
	// the same transaction as first-run owner/credential/session completion.
	InitialOwnerExecution func(context.Context, pgx.Tx, uuid.UUID) error
}

// Principal is the authenticated admin stored in the request context.
// GET /auth/session encodes authv1.SessionPrincipal, not this struct.
type Principal struct {
	policy             *authorizationPolicy
	ID                 uuid.UUID
	Issuer             string
	Subject            string
	DisplayName        string
	Role               string
	CSRFToken          string
	BreakGlass         bool
	IncidentReason     string
	AllowedPermissions []string
	Bindings           []*authv1.RoleBinding
	ServiceAccount     bool
}

// Permission is an authorization action. Unknown values are denied.
type Permission string

const (
	PermissionReadFleet                Permission = "fleet.read"
	PermissionManageEnrollment         Permission = "enrollment.manage"
	PermissionRevokeDevice             Permission = "device.revoke"
	PermissionReadAudit                Permission = "audit.read"
	PermissionManageExecutionTrust     Permission = "execution_trust.manage"
	PermissionManageProfiles           Permission = "profiles.manage"
	PermissionAssignResources          Permission = "resources.assign"
	PermissionManageAccounts           Permission = "accounts.manage"
	PermissionManageInventory          Permission = "inventory.manage"
	PermissionReadRecoveryKeys         Permission = "recovery_keys.read"
	PermissionRunRemoteExecution       Permission = "remote_execution.run"
	PermissionRunScripts               Permission = "scripts.run"
	PermissionExecuteDestructive       Permission = "destructive.execute"
	PermissionManageApprovals          Permission = "approvals.manage"
	PermissionManageIntegrations       Permission = "integrations.manage"
	PermissionManageReleaseUpdates     Permission = "release_updates.manage"
	PermissionManageAdvisoryExceptions Permission = "advisory_exceptions.manage"
	PermissionManageEncryption         Permission = "encryption.manage"
	PermissionLockDevice               Permission = "actions.lock"
	PermissionReleaseLockDevice        Permission = "actions.release-lock"
	PermissionQuarantineDevice         Permission = "actions.quarantine"
	PermissionManageSecrets            Permission = "secrets.manage"
	PermissionRevealSecrets            Permission = "secrets.reveal"
	// Control supplements view; neither capability grants nor control imply view.
	PermissionViewRemoteAssistance    Permission = "remote_assistance.view"
	PermissionControlRemoteAssistance Permission = "remote_assistance.control"
	PermissionManageAssistancePolicy  Permission = "remote_assistance.policy.manage"
	PermissionAssistanceClipboard     Permission = "remote_assistance.clipboard"
	PermissionAssistanceKeyboard      Permission = "remote_assistance.keyboard"
	PermissionAssistanceDisplay       Permission = "remote_assistance.display"
	PermissionAssistanceMessage       Permission = "remote_assistance.message"
	PermissionAssistanceFiles         Permission = "remote_assistance.files"
	PermissionAssistanceReconnect     Permission = "remote_assistance.reconnect"
	PermissionAssistanceRecord        Permission = "remote_assistance.record"
	// Recording retrieval and deletion are archive authority on their own
	// device scope; they never grant view, control or another live capability.
	PermissionReadAssistanceRecordings   Permission = "remote_assistance.recordings.read"
	PermissionDeleteAssistanceRecordings Permission = "remote_assistance.recordings.delete"
	// Unattended access is requested with one permission and approved by a
	// different person holding the independent approve permission.
	PermissionAssistanceUnattended        Permission = "remote_assistance.unattended"
	PermissionApproveAssistanceUnattended Permission = "remote_assistance.unattended.approve"
	PermissionAssistanceElevation         Permission = "remote_assistance.elevation_guidance"
	PermissionAssistanceAnnotate          Permission = "remote_assistance.annotate"
	PermissionAssistanceAudio             Permission = "remote_assistance.audio"

	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleHelpdesk = "helpdesk"
	RoleAuditor  = "auditor"
)

// Bootstrap and directory failures returned to the owner command.
// Local owner bootstrap is one-shot; external bootstrap permits exact replay.
var (
	ErrOwnerInitialized     = errors.New("identity: a different owner is already initialized")
	ErrIssuerMismatch       = errors.New("identity: issuer does not match configured issuer")
	ErrSubjectUnqualified   = errors.New("identity: subject is not an enabled direct user of the configured issuer")
	ErrDirectoryUnavailable = errors.New("identity: authoritative directory is unavailable")
)

type principalContextKey struct{}

// WithPrincipal stores p for PrincipalFromContext. It does not grant authority;
// Authorize still evaluates the resolved permission bindings.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext returns the principal stored by RequireSession or WithPrincipal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// New builds the selected authoritative source and compiles request validation.
// Local mode never contacts an identity provider.
func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Service, error) {
	return newService(ctx, pool, cfg)
}
