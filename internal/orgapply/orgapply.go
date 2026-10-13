// Package orgapply plans and applies declarative organizations through the product
// AdminService. It never accesses a database, retries mutations, logs secrets, or
// turns CLI credentials into browser authority. Omission never deletes objects.
package orgapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/permissionupgrade"
)

// Outcome reports control-plane state, not native execution or compliance.
type Outcome struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ChangePlan retains the immutable desired document and observed CAS versions.
// Create a fresh plan after a conflict; Apply never retries a mutation.
type ChangePlan struct {
	Outcomes        []Outcome `json:"outcomes"`
	spec            *orgv1.Organization
	operations      []operation
	revisions       map[string]string
	accountSnapshot []*authv1.LocalAccount
}

type operation struct {
	outcome       Outcome
	request       proto.Message
	profileID     string
	predecessorID string
	// reviewOnly starts a rollout only when the apply-time review finds devices
	// whose resolution differs from their current head.
	reviewOnly bool
}

// Secret is returned only on the original issuance response. Callers must write
// these to protected storage, never to ordinary output, logs, or a query cache.
type Secret struct {
	Kind      string                 `json:"kind"`
	Name      string                 `json:"name"`
	ID        string                 `json:"id"`
	Value     string                 `json:"secret"`
	ExpiresAt *timestamppb.Timestamp `json:"expires_at,omitempty"`
}

// Result excludes secrets from ordinary JSON serialization. A non-nil Result
// accompanies partial-apply errors so already-issued secrets can still be saved.
type Result struct {
	Outcomes []Outcome `json:"outcomes"`
	Secrets  []Secret  `json:"-"`
}

// AccountClient is deliberately separate from AdminService. Implementations use
// browser-kind sessions with the existing account endpoints and CSRF checks.
type AccountClient interface {
	// CheckSession fences continued browser authority between independent mutations.
	CheckSession(context.Context) error
	ListAccounts(context.Context) (*authv1.ListAccountsResponse, error)
	CreateAccount(context.Context, *authv1.CreateAccountRequest) (*authv1.AccountEnrollment, error)
	UpdateAccount(context.Context, *authv1.UpdateAccountRequest) error
}

// Options grants only the separately supplied browser account capability.
type Options struct {
	AccountClient AccountClient
}

// Decode rejects unknown fields and validates both the composition and completed
// API templates with the same buf.validate rules the server uses.
func Decode(data []byte) (*orgv1.Organization, error) {
	spec := new(orgv1.Organization)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, spec); err != nil {
		return nil, fmt.Errorf("decode organization: %w", err)
	}
	if err := Validate(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

// Validate completes only engine-owned fields before applying the reused product
// validators. No duplicated field-bound or policy validation lives in this engine.
func Validate(spec *orgv1.Organization) error {
	if spec == nil {
		return errors.New("orgapply: organization is required")
	}
	if err := rejectRetiredPermissions(spec.GetAuthorization()); err != nil {
		return err
	}
	if err := protovalidate.Validate(spec); err != nil {
		return fmt.Errorf("validate organization: %w", err)
	}
	const placeholder = "00000000-0000-4000-8000-000000000001"
	for _, a := range spec.GetAssignments() {
		r := proto.CloneOf(a.GetAssignment())
		r.ProfileRevisionId = a.GetProfileId()
		if err := protovalidate.Validate(r); err != nil {
			return fmt.Errorf("validate assignment: %w", err)
		}
	}
	for _, t := range spec.GetProvisioningTokens() {
		r := proto.CloneOf(t.GetRequest())
		r.RequestId = placeholder
		r.Reason = reason(spec)
		r.Name = enrollmentName(spec, t.GetName())
		if err := protovalidate.Validate(r); err != nil {
			return fmt.Errorf("validate provisioning token: %w", err)
		}
	}
	for _, g := range spec.GetGrants() {
		r := proto.CloneOf(g.GetRequest())
		r.RequestId = placeholder
		r.Reason = reason(spec)
		r.Name = enrollmentName(spec, g.GetName())
		if err := protovalidate.Validate(r); err != nil {
			return fmt.Errorf("validate enrollment grant: %w", err)
		}
	}
	for _, e := range spec.GetAdvisoryExceptions() {
		r := proto.CloneOf(e.GetRequest())
		r.RequestId = placeholder
		r.DeviceId = placeholder
		r.FindingId = placeholder
		if err := protovalidate.Validate(r); err != nil {
			return fmt.Errorf("validate advisory exception: %w", err)
		}
	}
	scopes := make(map[string]bool, len(spec.GetCapabilityPolicies()))
	for _, c := range spec.GetCapabilityPolicies() {
		r := proto.CloneOf(c.GetRequest())
		r.RequestId = placeholder
		r.Reason = reason(spec)
		if err := protovalidate.Validate(r); err != nil {
			return fmt.Errorf("validate capability policy: %w", err)
		}
		key := capabilityScopeKey(r.GetScope())
		if scopes[key] {
			return fmt.Errorf("validate capability policy: scope %s is declared twice", key)
		}
		scopes[key] = true
	}
	return nil
}

// rejectRetiredPermissions names the replacement for a permission an earlier
// release accepted. The server upgrades persisted and configured policies, but a
// declarative document is new input to the policy API, which rejects retired
// names; apply never rewrites the operator's source document.
func rejectRetiredPermissions(policy *authv1.AuthorizationPolicy) error {
	if policy == nil {
		return nil
	}
	changes := permissionupgrade.Policy(proto.CloneOf(policy))
	if len(changes) == 0 {
		return nil
	}
	legacy := changes[0].Legacy[0]
	current, _ := permissionupgrade.Replacement(legacy)
	return fmt.Errorf("validate organization: authorization %s names retired permission %s; replace it with %s, which together grant what it granted", changes[0].List, legacy, strings.Join(current, " and "))
}

func reason(spec *orgv1.Organization) string                      { return "Apply organization " + spec.GetName() }
func enrollmentName(spec *orgv1.Organization, name string) string { return spec.GetName() + "/" + name }

// requestID binds identity and the exact completed request, including observed CAS
// versions. Changing unrelated objects never changes a mutation's replay key.
func requestID(org, kind, id string, request proto.Message) (string, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("encode request identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("lindm.orgapply.v1\x00"+org+"\x00"+kind+"\x00"+id+"\x00"+hex.EncodeToString(sum[:]))).String(), nil
}

func (p *ChangePlan) add(kind, name, id, status, detail string, request proto.Message) {
	outcome := Outcome{Kind: kind, Name: name, ID: id, Status: status, Detail: detail}
	p.Outcomes = append(p.Outcomes, outcome)
	p.operations = append(p.operations, operation{outcome: outcome, request: request})
}

func tokenTemplate(spec *orgv1.Organization, t *orgv1.ProvisioningToken) *adminv1.CreateProvisioningTokenRequest {
	r := proto.CloneOf(t.GetRequest())
	r.Reason = reason(spec)
	r.Name = enrollmentName(spec, t.GetName())
	return r
}
func grantTemplate(spec *orgv1.Organization, g *orgv1.EnrollmentGrant) *adminv1.CreateEnrollmentGrantRequest {
	r := proto.CloneOf(g.GetRequest())
	r.Reason = reason(spec)
	r.Name = enrollmentName(spec, g.GetName())
	return r
}
