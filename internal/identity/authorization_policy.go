package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

type authorizationPolicy struct {
	roles               map[string]*authv1.RoleBinding
	groups              map[string][]*authv1.RoleBinding
	names               []string
	approvalPermissions []string
	digest              []byte
}

func compilePolicy(cfg Config, rules protovalidate.Validator) (*authorizationPolicy, error) {
	definition := cfg.Policy
	if definition == nil {
		definition = &authv1.AuthorizationPolicy{}
	}
	if err := rules.Validate(definition); err != nil {
		return nil, fmt.Errorf("identity: authorization policy: %w", err)
	}
	definition = proto.CloneOf(definition)
	policy := &authorizationPolicy{roles: make(map[string]*authv1.RoleBinding), groups: make(map[string][]*authv1.RoleBinding), approvalPermissions: definition.GetApprovalRequiredPermissions()}
	for _, name := range []string{RoleOwner, RoleAdmin, RoleOperator, RoleHelpdesk, RoleAuditor} {
		policy.roles[name] = &authv1.RoleBinding{Role: name, Permissions: builtinPermissions(name)}
	}
	for _, role := range definition.GetRoles() {
		policy.roles[role.GetName()] = &authv1.RoleBinding{Role: role.GetName(), Permissions: role.GetPermissions()}
	}
	for _, binding := range definition.GetGroupBindings() {
		group := binding.GetGroup()
		if cfg.Local {
			return nil, fmt.Errorf("identity: local authority cannot include directory mappings")
		}
		if cfg.EntraTenantID != "" {
			id, err := uuid.Parse(group)
			if err != nil || id == uuid.Nil || id.String() != group {
				return nil, fmt.Errorf("identity: Entra mapping requires a canonical group object ID")
			}
		} else if cfg.Okta != nil || cfg.Google != nil {
			if strings.ContainsAny(group, "/@ \t\r\n") {
				return nil, fmt.Errorf("identity: directory mapping requires an immutable group ID")
			}
		} else if !strings.HasPrefix(group, "/") || group == "/" {
			return nil, fmt.Errorf("identity: Keycloak mapping requires an exact group path")
		}
		role := policy.roles[binding.GetRole()]
		if role == nil {
			return nil, fmt.Errorf("identity: unknown mapped role %q", binding.GetRole())
		}
		policy.groups[group] = append(policy.groups[group], &authv1.RoleBinding{Role: role.GetRole(), Permissions: role.GetPermissions(), Scopes: binding.GetScopes()})
	}
	for name := range policy.roles {
		policy.names = append(policy.names, name)
	}
	slices.Sort(policy.names)
	// Include source identity, emergency restrictions and built-in grants, not
	// credentials or display-only configuration. A policy edit fences every actor.
	fingerprint := &configv1.ServerConfig{Authorization: definition, BreakGlass: cfg.BreakGlass, Authentication: &configv1.AuthenticationConfig{}}
	switch {
	case cfg.Local:
		fingerprint.Authentication.Primary = &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}
	case cfg.EntraTenantID != "":
		fingerprint.Authentication.Primary = &configv1.AuthenticationConfig_Entra{Entra: &configv1.EntraDirectory{TenantId: cfg.EntraTenantID}}
	case cfg.Okta != nil:
		fingerprint.Authentication.Primary = &configv1.AuthenticationConfig_Okta{Okta: &configv1.OktaDirectory{Issuer: cfg.Issuer, OrgUrl: cfg.Okta.GetOrgUrl()}}
	case cfg.Google != nil:
		fingerprint.Authentication.Primary = &configv1.AuthenticationConfig_Google{Google: &configv1.GoogleDirectory{HostedDomain: cfg.Google.GetHostedDomain(), DelegatedSubject: cfg.Google.GetDelegatedSubject()}}
	default:
		fingerprint.Authentication.Primary = &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{Issuer: cfg.Issuer, Upstream: cfg.Broker}}
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(fingerprint)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, _ = hash.Write(encoded)
	for _, entry := range permissionTable {
		_, _ = fmt.Fprintf(hash, "\x00%s:%s", entry.permission, strings.Join(entry.roles, ","))
	}
	policy.digest = hash.Sum(nil)
	return policy, nil
}

func (p *authorizationPolicy) role(name string) *authv1.RoleBinding {
	if p != nil {
		return p.roles[name]
	}
	permissions := builtinPermissions(name)
	if len(permissions) == 0 {
		return nil
	}
	return &authv1.RoleBinding{Role: name, Permissions: permissions}
}

func (p *authorizationPolicy) bindings(pinned string, groups []string) []*authv1.RoleBinding {
	bindings := make([]*authv1.RoleBinding, 0)
	if pinned == RoleOwner {
		return append(bindings, p.role(RoleOwner))
	}
	if pinned != "" || p == nil {
		return bindings
	}
	for _, group := range groups {
		bindings = append(bindings, p.groups[group]...)
	}
	// Directory pages and group ordering cannot create spurious version changes.
	slices.SortStableFunc(bindings, func(a, b *authv1.RoleBinding) int { return strings.Compare(a.GetRole(), b.GetRole()) })
	return bindings
}

func effectiveRole(pinned string, groups []string, policy *authorizationPolicy) string {
	bindings := policy.bindings(pinned, groups)
	if len(bindings) == 0 {
		return ""
	}
	return bindings[0].GetRole()
}

func bindingsDigest(bindings []*authv1.RoleBinding) ([]byte, error) {
	// Canonicalize complete encoded bindings, including equal-role different scopes.
	if len(bindings) == 0 {
		return []byte{}, nil
	}
	encoded := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(binding)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, string(data))
	}
	slices.Sort(encoded)
	encoded = slices.Compact(encoded)
	hash := sha256.New()
	for _, value := range encoded {
		_, _ = fmt.Fprintf(hash, "%d:", len(value))
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil), nil
}

func (s *Service) activatePolicy(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	previous, err := q.LockAuthorizationPolicyUpdate(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if err := s.checkOwnerAuthenticationMode(ctx, q); err != nil {
		return err
	}
	if !bytes.Equal(previous, s.policy.digest) {
		if err := q.SetAuthorizationPolicy(ctx, s.policy.digest); err != nil {
			return s.dbErr(err)
		}
		if err := q.InvalidatePolicyAuthorizations(ctx); err != nil {
			return s.dbErr(err)
		}
	}
	return s.dbErr(tx.Commit(ctx))
}

func (s *Service) lockPolicy(ctx context.Context, q *identitydb.Queries) error {
	current, err := q.LockAuthorizationPolicy(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if s.policy == nil || !bytes.Equal(current, s.policy.digest) {
		return ErrAuthorizationChanged
	}
	return nil
}

func (s *Service) checkPolicy(ctx context.Context, q *identitydb.Queries) error {
	current, err := q.GetAuthorizationPolicy(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if s.policy == nil || !bytes.Equal(current, s.policy.digest) {
		return ErrAuthorizationChanged
	}
	return nil
}

// ApprovalRequired reports the concrete sensitive operations enabled by policy.
func (s *Service) ApprovalRequired(permission Permission) bool {
	return permission == PermissionRevokeDevice || permission == PermissionExecuteDestructive || s != nil && s.policy != nil && slices.Contains(s.policy.approvalPermissions, string(permission))
}
