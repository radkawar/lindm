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
	"github.com/jackc/pgx/v5/pgxpool"

	configv1 "lindm/gen/lindm/config/v1"
)

// Config is the process dependency injection for one configured issuer.
// It is not a serialized user-config schema.
type Config struct {
	Local                 bool
	BreakGlass            *configv1.BreakGlassPolicy
	Issuer                string
	EntraTenantID         string
	ClientID              string
	ClientSecret          string
	DirectoryClientID     string
	DirectoryClientSecret string
	PublicURL             string
	AdminGroups           []string
	HTTPClient            *http.Client
}

// Principal is the authenticated admin stored in the request context.
// GET /auth/session encodes authv1.SessionPrincipal, not this struct.
type Principal struct {
	ID                 uuid.UUID
	Issuer             string
	Subject            string
	DisplayName        string
	Role               string
	CSRFToken          string
	BreakGlass         bool
	IncidentReason     string
	AllowedPermissions []string
}

// Permission is an authorization action. Unknown values are denied.
type Permission string

const (
	PermissionReadFleet            Permission = "fleet.read"
	PermissionManageEnrollment     Permission = "enrollment.manage"
	PermissionRevokeDevice         Permission = "device.revoke"
	PermissionReadAudit            Permission = "audit.read"
	PermissionManageExecutionTrust Permission = "execution_trust.manage"
	PermissionManageProfiles       Permission = "profiles.manage"
	PermissionAssignServices       Permission = "services.assign"
	PermissionManageAccounts       Permission = "accounts.manage"

	RoleOwner = "owner"
	RoleAdmin = "admin"
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
// Authorize still evaluates Role.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext returns the principal stored by RequireSession or WithPrincipal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// Authorize applies the role policy and intersects emergency grants with their
// explicit allowlist. Account management is owner-only; unknown permissions deny.
func Authorize(p Principal, perm Permission) bool {
	if p.BreakGlass {
		allowed := false
		for _, value := range p.AllowedPermissions {
			if value == string(perm) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	if perm == PermissionManageAccounts {
		return p.Role == RoleOwner
	}
	switch p.Role {
	case RoleOwner, RoleAdmin:
	default:
		return false
	}
	switch perm {
	case PermissionReadFleet, PermissionManageEnrollment, PermissionRevokeDevice, PermissionReadAudit, PermissionManageExecutionTrust, PermissionManageProfiles, PermissionAssignServices:
		return true
	default:
		return false
	}
}

// New builds the selected authoritative source and compiles request validation.
// Local mode never contacts an identity provider.
func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Service, error) {
	return newService(ctx, pool, cfg)
}
