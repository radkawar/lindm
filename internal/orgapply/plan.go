package orgapply

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/policy"
)

// Plan reads product state without mutating it (including without creating target
// previews). Activation is resolved only after the planned catalog changes land.
func Plan(ctx context.Context, client adminv1connect.AdminServiceClient, spec *orgv1.Organization) (*ChangePlan, error) {
	if client == nil {
		return nil, errors.New("orgapply: admin client is required")
	}
	if err := Validate(spec); err != nil {
		return nil, err
	}
	p := &ChangePlan{spec: proto.CloneOf(spec)}
	for _, profile := range p.spec.GetProfiles() {
		normalized, _, err := policy.CanonicalSpec(ctx, profile.GetSpec())
		if err != nil {
			return nil, fmt.Errorf("canonicalize profile: %w", err)
		}
		profile.Spec = normalized
	}
	if err := p.groups(ctx, client); err != nil {
		return nil, err
	}
	revisions, changed, err := p.profiles(ctx, client)
	if err != nil {
		return nil, err
	}
	p.revisions = revisions
	if err := p.rollouts(ctx, client); err != nil {
		return nil, err
	}
	if err := p.assignments(ctx, client, revisions, changed); err != nil {
		return nil, err
	}
	if err := p.enrollment(ctx, client); err != nil {
		return nil, err
	}
	if err := p.exceptions(ctx, client); err != nil {
		return nil, err
	}
	for _, a := range p.spec.GetAccounts() {
		p.add("account", a.GetUsername(), "", "pending", "requires console session", a)
	}
	if p.spec.GetAuthorization() != nil {
		p.add("authorization", p.spec.GetName(), "", "unsupported", "requires server configuration; API cannot read or change authorization policy", nil)
	}
	return p, nil
}

func (p *ChangePlan) groups(ctx context.Context, client adminv1connect.AdminServiceClient) error {
	if len(p.spec.GetGroups()) > 0 {
		groups, err := pages(func(token string) ([]*adminv1.DeviceGroup, string, error) {
			r, e := client.ListDeviceGroups(ctx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 100, PageToken: token}))
			if e != nil {
				return nil, "", e
			}
			return r.Msg.GetGroups(), r.Msg.GetNextPageToken(), nil
		})
		if err != nil {
			return fmt.Errorf("list static groups: %w", err)
		}
		byID := make(map[string]*adminv1.DeviceGroup, len(groups))
		for _, g := range groups {
			byID[g.GetId()] = g
		}
		for _, g := range p.spec.GetGroups() {
			existing := byID[g.GetId()]
			if existing != nil && existing.GetName() == g.GetName() {
				p.add("group", g.GetName(), g.GetId(), "unchanged", "", nil)
				continue
			}
			if existing != nil {
				// This RPC replaces membership without CAS. Never risk restoring an old RBAC
				// membership snapshot merely to rename a declarative group.
				p.add("group", g.GetName(), g.GetId(), "unsupported", "name drift: static group API has no membership-safe compare-and-swap", nil)
				continue
			}
			p.add("group", g.GetName(), g.GetId(), "created", "", &adminv1.SetDeviceGroupRequest{GroupId: g.GetId(), Name: g.GetName(), Reason: reason(p.spec), CreateOnly: true})
		}
	}
	for _, g := range p.spec.GetDynamicGroups() {
		existing, err := client.GetDynamicGroup(ctx, connect.NewRequest(&adminv1.GetDynamicGroupRequest{GroupId: g.GetGroupId()}))
		if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
			return fmt.Errorf("get dynamic group: %w", err)
		}
		desired := proto.CloneOf(g)
		desired.Revision = 0
		var revision uint64
		status := "created"
		if err == nil {
			current := proto.CloneOf(existing.Msg.GetGroup())
			revision = current.GetRevision()
			current.Revision = 0
			if proto.Equal(current, desired) {
				p.add("dynamic_group", g.GetName(), g.GetGroupId(), "unchanged", "", nil)
				continue
			}
			status = "updated"
		}
		p.add("dynamic_group", g.GetName(), g.GetGroupId(), status, "", &adminv1.PutDynamicGroupRequest{Group: desired, ExpectedRevision: revision, Reason: reason(p.spec)})
	}
	return nil
}

func (p *ChangePlan) profiles(ctx context.Context, client adminv1connect.AdminServiceClient) (map[string]string, map[string]bool, error) {
	revisions := make(map[string]string, len(p.spec.GetProfiles()))
	changed := make(map[string]bool, len(p.spec.GetProfiles()))
	for _, profile := range p.spec.GetProfiles() {
		current, err := client.GetProfileRevision(ctx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: profile.GetId()}))
		if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
			return nil, nil, fmt.Errorf("get profile: %w", err)
		}
		request := &adminv1.PublishProfileRevisionRequest{ProfileId: profile.GetId(), Spec: profile.GetSpec(), Reason: reason(p.spec)}
		status := "created"
		if err == nil {
			revisions[profile.GetId()] = current.Msg.GetRevision().GetRevisionId()
			if proto.Equal(current.Msg.GetRevision().GetSpec(), profile.GetSpec()) {
				p.add("profile", profile.GetSpec().GetName(), profile.GetId(), "unchanged", "", nil)
				continue
			}
			request.ExpectedRevisionId = proto.String(revisions[profile.GetId()])
			status = "updated"
		}
		changed[profile.GetId()] = true
		p.add("profile", profile.GetSpec().GetName(), profile.GetId(), status, "", request)
	}
	return revisions, changed, nil
}

func (p *ChangePlan) rollouts(ctx context.Context, client adminv1connect.AdminServiceClient) error {
	if len(p.spec.GetRollouts()) == 0 {
		return nil
	}
	existing, err := pages(func(after string) ([]*adminv1.RolloutState, string, error) {
		r, e := client.ListRollouts(ctx, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100, AfterId: optional(after), ReadOnly: true}))
		if e != nil {
			return nil, "", e
		}
		next := ""
		if len(r.Msg.GetRollouts()) == 100 {
			next = r.Msg.GetRollouts()[99].GetRollout().GetRolloutId()
		}
		return r.Msg.GetRollouts(), next, nil
	})
	if err != nil {
		return fmt.Errorf("list rollouts: %w", err)
	}
	byID := make(map[string]*adminv1.RolloutState, len(existing))
	for _, r := range existing {
		byID[r.GetRollout().GetRolloutId()] = r
	}
	for _, r := range p.spec.GetRollouts() {
		old := byID[r.GetRolloutId()]
		if old != nil {
			if proto.Equal(old.GetRollout(), r) {
				p.add("rollout", r.GetRolloutId(), r.GetRolloutId(), "unchanged", "", nil)
			} else {
				p.add("rollout", r.GetRolloutId(), r.GetRolloutId(), "unsupported", "rollout specifications are immutable; use a new stable ID", nil)
			}
			continue
		}
		p.add("rollout", r.GetRolloutId(), r.GetRolloutId(), "created", "", &adminv1.PutRolloutRequest{Rollout: r, Reason: reason(p.spec)})
	}
	return nil
}

func (p *ChangePlan) assignments(ctx context.Context, client adminv1connect.AdminServiceClient, revisions map[string]string, changed map[string]bool) error {
	if len(p.spec.GetAssignments()) == 0 {
		return nil
	}
	existing, err := pages(func(after string) ([]*policyv1.TargetCandidate, string, error) {
		r, e := client.ListTargetAssignments(ctx, connect.NewRequest(&adminv1.ListTargetAssignmentsRequest{PageSize: 100, AfterId: optional(after)}))
		if e != nil {
			return nil, "", e
		}
		next := ""
		if len(r.Msg.GetAssignments()) == 100 {
			next = r.Msg.GetAssignments()[99].GetAssignment().GetAssignmentId()
		}
		return r.Msg.GetAssignments(), next, nil
	})
	if err != nil {
		return fmt.Errorf("list target assignments: %w", err)
	}
	byID := make(map[string]*policyv1.TargetCandidate, len(existing))
	for _, a := range existing {
		byID[a.GetAssignment().GetAssignmentId()] = a
	}
	for _, a := range p.spec.GetAssignments() {
		desired := proto.CloneOf(a.GetAssignment())
		desired.ProfileRevisionId = revisions[a.GetProfileId()]
		old := byID[desired.GetAssignmentId()]
		status := "created"
		var revision uint64
		if old != nil {
			revision = old.GetRevision()
			status = "updated"
			if !changed[a.GetProfileId()] && proto.Equal(old.GetAssignment(), desired) {
				p.add("assignment", desired.GetAssignmentId(), desired.GetAssignmentId(), "unchanged", "", nil)
				continue
			}
		}
		p.add("assignment", desired.GetAssignmentId(), desired.GetAssignmentId(), status, "activate matching devices after catalog changes", &adminv1.PutTargetAssignmentRequest{Assignment: desired, ExpectedRevision: revision, Reason: reason(p.spec)})
		p.operations[len(p.operations)-1].profileID = a.GetProfileId()
	}
	return nil
}

func (p *ChangePlan) enrollment(ctx context.Context, client adminv1connect.AdminServiceClient) error {
	if len(p.spec.GetProvisioningTokens()) > 0 {
		tokens, err := pages(func(token string) ([]*adminv1.ProvisioningToken, string, error) {
			r, e := client.ListProvisioningTokens(ctx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{PageSize: 200, PageToken: token}))
			if e != nil {
				return nil, "", e
			}
			return r.Msg.GetTokens(), r.Msg.GetNextPageToken(), nil
		})
		if err != nil {
			return fmt.Errorf("list provisioning tokens: %w", err)
		}
		byName := make(map[string]*adminv1.ProvisioningToken, len(tokens))
		revoked := make(map[string]*adminv1.ProvisioningToken)
		for _, t := range tokens {
			if t.GetRevokedAt() == nil {
				byName[t.GetName()] = t
			} else if old := revoked[t.GetName()]; old == nil || t.GetRevokedAt().AsTime().After(old.GetRevokedAt().AsTime()) || (t.GetRevokedAt().AsTime().Equal(old.GetRevokedAt().AsTime()) && t.GetTokenId() > old.GetTokenId()) {
				revoked[t.GetName()] = t
			}
		}
		for _, t := range p.spec.GetProvisioningTokens() {
			r := tokenTemplate(p.spec, t)
			old := byName[r.GetName()]
			if old == nil {
				p.add("provisioning_token", t.GetName(), "", "created", "", r)
				p.operations[len(p.operations)-1].predecessorID = revoked[r.GetName()].GetTokenId()
				continue
			}
			same := old.GetMaxUses() == r.GetMaxUses() && old.GetApprovalRequired() == r.GetApprovalRequired() && proto.Equal(old.GetMetadata(), r.GetMetadata()) && slices.Equal(old.GetGroupIds(), r.GetGroupIds()) && slices.Equal(old.GetProfileRevisionIds(), r.GetProfileRevisionIds())
			if old.GetCreatedAt() != nil && old.GetExpiresAt() != nil {
				same = same && old.GetExpiresAt().AsTime().Sub(old.GetCreatedAt().AsTime()).Seconds() == float64(r.GetLifetimeSeconds())
			}
			if same {
				p.add("provisioning_token", t.GetName(), old.GetTokenId(), "unchanged", "existing credential is never renewed or reissued", nil)
			} else {
				p.add("provisioning_token", t.GetName(), old.GetTokenId(), "unsupported", "immutable credential drift; revoke and choose a new name", nil)
			}
		}
	}
	if len(p.spec.GetGrants()) > 0 {
		grants, err := pages(func(token string) ([]*adminv1.EnrollmentGrant, string, error) {
			r, e := client.ListEnrollmentGrants(ctx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{PageSize: 200, PageToken: token}))
			if e != nil {
				return nil, "", e
			}
			return r.Msg.GetGrants(), r.Msg.GetNextPageToken(), nil
		})
		if err != nil {
			return fmt.Errorf("list enrollment grants: %w", err)
		}
		byName := make(map[string]*adminv1.EnrollmentGrant, len(grants))
		revoked := make(map[string]*adminv1.EnrollmentGrant)
		for _, g := range grants {
			if g.GetRevokedAt() == nil {
				byName[g.GetName()] = g
			} else if old := revoked[g.GetName()]; old == nil || g.GetRevokedAt().AsTime().After(old.GetRevokedAt().AsTime()) || (g.GetRevokedAt().AsTime().Equal(old.GetRevokedAt().AsTime()) && g.GetGrantId() > old.GetGrantId()) {
				revoked[g.GetName()] = g
			}
		}
		for _, g := range p.spec.GetGrants() {
			r := grantTemplate(p.spec, g)
			old := byName[r.GetName()]
			if old == nil {
				p.add("enrollment_grant", g.GetName(), "", "created", "", r)
				p.operations[len(p.operations)-1].predecessorID = revoked[r.GetName()].GetGrantId()
				continue
			}
			status, detail := "unchanged", "existing credential is never renewed or reissued"
			if old.GetCreatedAt() != nil && old.GetExpiresAt() != nil && old.GetExpiresAt().AsTime().Sub(old.GetCreatedAt().AsTime()).Seconds() != float64(r.GetLifetimeSeconds()) {
				status, detail = "unsupported", "immutable credential drift; revoke and choose a new name"
			}
			p.add("enrollment_grant", g.GetName(), old.GetGrantId(), status, detail, nil)
		}
	}
	return nil
}

// pages bounds retained remote state and detects a stuck server cursor. Page sizes
// are the product's own limits; the cap is an engine memory/operation limit.
func pages[T any](fetch func(string) ([]T, string, error)) ([]T, error) {
	var all []T
	token := ""
	for {
		items, next, err := fetch(token)
		if err != nil {
			return nil, err
		}
		if len(all)+len(items) > 10000 {
			return nil, errors.New("orgapply: catalog exceeds 10000 objects")
		}
		all = append(all, items...)
		if next == "" {
			return all, nil
		}
		if next == token {
			return nil, errors.New("orgapply: nonadvancing page cursor")
		}
		token = next
	}
}
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
