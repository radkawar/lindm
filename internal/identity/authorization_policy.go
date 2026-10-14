// SPDX-License-Identifier: Apache-2.0

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
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
	"lindm/internal/permissionupgrade"
)

type authorizationPolicy struct {
	definition          *authv1.AuthorizationPolicy
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
	policy := &authorizationPolicy{definition: definition, roles: make(map[string]*authv1.RoleBinding), groups: make(map[string][]*authv1.RoleBinding), approvalPermissions: definition.GetApprovalRequiredPermissions()}
	for _, name := range []string{RoleOwner, RoleAdmin, RoleOperator, RoleHelpdesk, RoleAuditor} {
		policy.roles[name] = &authv1.RoleBinding{Role: name, Permissions: builtinPermissions(name)}
	}
	for _, role := range definition.GetRoles() {
		policy.roles[role.GetName()] = &authv1.RoleBinding{Role: role.GetName(), Permissions: role.GetPermissions()}
	}
	for _, binding := range definition.GetGroupBindings() {
		group := binding.GetGroup()
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
	// Reuse the configuration's source-dependent CEL rules. This is an authority
	// projection, not listener/credential configuration: validate its root rules
	// only; the complete policy itself was validated above.
	if err := rules.Validate(fingerprint, protovalidate.WithFilter(protovalidate.FilterFunc(func(_ protoreflect.Message, descriptor protoreflect.Descriptor) bool {
		return descriptor.FullName() == "lindm.config.v1.ServerConfig"
	}))); err != nil {
		return nil, fmt.Errorf("identity: authorization source: %w", err)
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
	previous, err := q.LockRuntimeAuthorizationUpdate(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if err := s.checkOwnerAuthenticationMode(ctx, q); err != nil {
		return err
	}
	if previous.Definition != nil {
		definition := new(authv1.AuthorizationPolicy)
		if err := proto.Unmarshal(previous.Definition, definition); err != nil {
			return s.dbErr(err)
		}
		changes := permissionupgrade.Policy(definition)
		policy, err := compilePolicy(s.policyConfiguration(definition), s.rules)
		if err != nil {
			return err
		}
		if len(changes) != 0 {
			if err := s.persistPermissionUpgrade(ctx, q, previous, policy, changes); err != nil {
				return err
			}
		}
		s.policy = policy
	}
	if !bytes.Equal(previous.Digest, s.policy.digest) {
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
	policy, err := s.currentPolicy(ctx, q)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, policy.digest) {
		return ErrAuthorizationChanged
	}
	return nil
}

// currentPolicy reads the database on every authority boundary. The cache only
// avoids recompiling an immutable definition; it never decides which revision wins.
func (s *Service) currentPolicy(ctx context.Context, q *identitydb.Queries) (*authorizationPolicy, error) {
	row, err := q.ReadRuntimeAuthorization(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	if s.policy != nil && bytes.Equal(row.Digest, s.policy.digest) {
		return s.policy, nil
	}
	if cached := s.runtimePolicy.Load(); cached != nil && bytes.Equal(row.Digest, cached.digest) {
		return cached, nil
	}
	if row.Definition == nil {
		return nil, ErrAuthorizationChanged
	}
	definition := new(authv1.AuthorizationPolicy)
	if err := proto.Unmarshal(row.Definition, definition); err != nil {
		return nil, errStore
	}
	policy, err := compilePolicy(s.policyConfiguration(definition), s.rules)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(row.Digest, policy.digest) {
		return nil, ErrAuthorizationChanged
	}
	s.runtimePolicy.Store(policy)
	return policy, nil
}

func (s *Service) policyConfiguration(definition *authv1.AuthorizationPolicy) Config {
	tenant := ""
	if s.entraTenant != uuid.Nil {
		tenant = s.entraTenant.String()
	}
	var broker *configv1.KeycloakBrokerUpstream
	if s.broker != nil {
		broker = s.policyBroker
	}
	return Config{Local: s.localPrimary, Issuer: s.issuer, EntraTenantID: tenant,
		Okta: s.okta, Google: s.google, Broker: broker, BreakGlass: s.breakGlass, Policy: definition}
}

// builtInApprovalPermissions always need an independent approver; policy can
// add permissions to this set but never remove these.
var builtInApprovalPermissions = []Permission{PermissionRevokeDevice, PermissionExecuteDestructive}

// ApprovalRequired describes the immutable authority snapshot. Mutation callers
// must fence its Authorization before relying on an optional approval decision.
func (p Principal) ApprovalRequired(permission Permission) bool {
	return slices.Contains(builtInApprovalPermissions, permission) || p.policy != nil && slices.Contains(p.policy.approvalPermissions, string(permission))
}

func runtimeAuthorizationState(definition *authv1.AuthorizationPolicy, revision int64, runtime bool) *adminv1.AuthorizationState {
	builtIn := make([]string, 0, len(builtInApprovalPermissions))
	for _, permission := range builtInApprovalPermissions {
		builtIn = append(builtIn, string(permission))
	}
	return &adminv1.AuthorizationState{Policy: proto.CloneOf(definition), Revision: uint64(revision), Runtime: runtime, BuiltInApprovalPermissions: builtIn}
}
