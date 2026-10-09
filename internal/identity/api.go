// Package identity is the admin session boundary.
//
// Login uses authorization-code PKCE. Access after login is granted only from a
// fresh Keycloak Admin API snapshot, never from the login token alone. Sessions
// are opaque and hashed at rest. The first owner is bound by BootstrapOwner,
// not by the first successful login.
package identity

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config is the process dependency injection for one configured issuer.
// It is not a serialized user-config schema.
type Config struct {
	Issuer                string
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
	ID          uuid.UUID
	Issuer      string
	Subject     string
	DisplayName string
	Role        string
	CSRFToken   string
}

// Permission is an authorization action. Unknown values are denied.
type Permission string

const (
	PermissionReadFleet            Permission = "fleet.read"
	PermissionManageEnrollment     Permission = "enrollment.manage"
	PermissionRevokeDevice         Permission = "device.revoke"
	PermissionReadAudit            Permission = "audit.read"
	PermissionManageExecutionTrust Permission = "execution_trust.manage"

	RoleOwner = "owner"
	RoleAdmin = "admin"
)

// Bootstrap and directory failures returned to the local owner command.
// ErrOwnerInitialized means a different principal is already owner.
// The same issuer and subject is idempotent and returns nil.
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

// Authorize allows the implemented fleet permissions only for owner and admin.
// Every other role, including auditor, is denied. Owner and admin are equal
// for this slice; finer roles are not granted here.
func Authorize(p Principal, perm Permission) bool {
	switch p.Role {
	case RoleOwner, RoleAdmin:
	default:
		return false
	}
	switch perm {
	case PermissionReadFleet, PermissionManageEnrollment, PermissionRevokeDevice, PermissionReadAudit, PermissionManageExecutionTrust:
		return true
	default:
		return false
	}
}

// New builds a service. It discovers the issuer and rejects a directory
// credential that the issuer will not accept. There is no unauthenticated mode.
func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Service, error) {
	return newService(ctx, pool, cfg)
}
