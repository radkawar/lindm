// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
)

// RuntimeAuthorizationEvidence contains only public observations, never cookies,
// bearer credentials, passwords, enrollment secrets or WebAuthn assertions.
type RuntimeAuthorizationEvidence struct {
	OwnerID         string                `json:"owner_id"`
	SecondHumanID   string                `json:"second_human_id"`
	DeviceID        string                `json:"device_id,omitempty"`
	InitialRevision uint64                `json:"initial_revision"`
	InitialRuntime  bool                  `json:"initial_runtime"`
	FinalRevision   uint64                `json:"final_revision"`
	Checks          []string              `json:"checks"`
	AuditEvents     []*adminv1.AuditEvent `json:"audit_events"`
	PolicySHA256    string                `json:"policy_sha256"`
}

// ApplyOrganization exercises the actual browser endpoint with this session's
// cookie jar, exact Origin and CSRF token. Callers must clear returned secrets.
func (s *OwnerSession) ApplyOrganization(ctx context.Context, request *orgv1.ApplyOrganizationRequest) (*orgv1.ApplyOrganizationResponse, error) {
	result := new(orgv1.ApplyOrganizationResponse)
	if err := s.localRequest(ctx, "/auth/organization/apply", request, result, http.StatusOK); err != nil {
		clearOrganizationSecrets(result)
		return nil, err
	}
	return result, nil
}

func clearOrganizationSecrets(result *orgv1.ApplyOrganizationResponse) {
	for _, secret := range result.GetSecrets() {
		secret.Secret = ""
	}
	if result != nil {
		result.Secrets = nil
	}
}

// ExerciseRuntimeAuthorization uses two real local human sessions and an owned
// disposable server. Device scope assertions require a real enrolled device ID;
// server-only integration tests leave it empty and make no native-device claim.
func ExerciseRuntimeAuthorization(ctx context.Context, fixture *AuthorityFixture, deviceID string) (_ *RuntimeAuthorizationEvidence, resultErr error) {
	if fixture == nil || fixture.local == nil || fixture.persistent || fixture.connected != nil || fixture.database == nil {
		return nil, errors.New("runtime authorization qualification requires a disposable local authority")
	}
	evidence := &RuntimeAuthorizationEvidence{DeviceID: deviceID}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return evidence, err
	}
	defer func() { resultErr = errors.Join(resultErr, owner.Close(context.WithoutCancel(ctx))) }()
	second, err := OpenApprovalSession(ctx, fixture.repository, fixture)
	if err != nil {
		return evidence, err
	}
	defer func() { resultErr = errors.Join(resultErr, second.Close(context.WithoutCancel(ctx))) }()
	evidence.OwnerID, evidence.SecondHumanID = owner.AccountID, second.session.AccountID
	if evidence.OwnerID == evidence.SecondHumanID {
		return evidence, errors.New("runtime qualification requires independent humans")
	}
	initial, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return evidence, err
	}
	evidence.InitialRevision = initial.Msg.GetAuthorization().GetRevision()
	evidence.InitialRuntime = initial.Msg.GetAuthorization().GetRuntime()
	policy := proto.CloneOf(initial.Msg.GetAuthorization().GetPolicy())
	if policy == nil {
		policy = new(authv1.AuthorizationPolicy)
	}
	policy.Roles = append(policy.Roles, &authv1.RoleDefinition{Name: "runtime-reader", Permissions: []string{"fleet.read"}})
	request := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: evidence.InitialRevision, Policy: policy, Reason: "qualify runtime authorization through actual human console session"}
	first, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request))
	if err != nil {
		return evidence, err
	}
	if !first.Msg.GetAuthorization().GetRuntime() || first.Msg.GetAuthorization().GetRevision() != evidence.InitialRevision+1 || !proto.Equal(first.Msg.GetAuthorization().GetPolicy(), policy) {
		return evidence, errors.New("runtime update did not replace bootstrap policy")
	}
	evidence.Checks = append(evidence.Checks, "runtime policy replacement")
	stale := proto.CloneOf(request)
	stale.RequestId = uuid.NewString()
	if _, err := second.session.Admin.UpdateAuthorization(ctx, connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeAborted {
		return evidence, fmt.Errorf("stale revision: expected aborted, got %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Reason = "different replay payload"
	if _, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		return evidence, fmt.Errorf("changed replay: expected already_exists, got %v", err)
	}
	evidence.Checks = append(evidence.Checks, "two-human compare-and-swap denial", "request identity payload binding")
	later := proto.CloneOf(policy)
	later.Roles = append(later.Roles, &authv1.RoleDefinition{Name: "runtime-audit", Permissions: []string{"audit.read"}})
	update, err := second.session.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: first.Msg.GetAuthorization().GetRevision(), Policy: later, Reason: "independent human advances runtime policy"}))
	if err != nil {
		return evidence, err
	}
	replay, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request))
	if err != nil {
		return evidence, err
	}
	if !proto.Equal(first.Msg, replay.Msg) {
		return evidence, errors.New("replay did not return exact historical authorization state")
	}
	evidence.Checks = append(evidence.Checks, "historical idempotent replay after a later update")
	if err := runtimeAuthorizationRestart(ctx, fixture, owner, update.Msg.GetAuthorization()); err != nil {
		return evidence, fmt.Errorf("runtime restart precedence: %w", err)
	}
	evidence.Checks = append(evidence.Checks, "restart preserves runtime authority over changed bootstrap config")
	if err := runtimeAuthorizationReplica(ctx, fixture, owner, update.Msg.GetAuthorization()); err != nil {
		return evidence, fmt.Errorf("runtime replica visibility: %w", err)
	}
	evidence.Checks = append(evidence.Checks, "second actual server observes and updates shared runtime authority")
	if err := runtimeAuthorizationScope(ctx, owner, second.session, deviceID); err != nil {
		return evidence, fmt.Errorf("runtime scope and session fences: %w", err)
	}
	evidence.Checks = append(evidence.Checks, "non-owner session revocation and owner-only policy mutation")
	if deviceID != "" {
		evidence.Checks = append(evidence.Checks, "enrolled-device scope allow then deny")
	}
	if err := runtimeAuthorizationOrganization(ctx, fixture, owner); err != nil {
		return evidence, fmt.Errorf("runtime organization apply: %w", err)
	}
	evidence.Checks = append(evidence.Checks, "reviewed browser organization accounts and shown-once secrets", "CLI runtime policy without account authority")
	current, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return evidence, err
	}
	evidence.FinalRevision = current.Msg.GetAuthorization().GetRevision()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(current.Msg.GetAuthorization().GetPolicy())
	if err != nil {
		return evidence, err
	}
	digest := sha256.Sum256(encoded)
	evidence.PolicySHA256 = hex.EncodeToString(digest[:])
	var matches int
	for token := ""; ; {
		page, err := owner.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 200, PageToken: token}))
		if err != nil {
			return evidence, fmt.Errorf("read public runtime audit events: %w", err)
		}
		for _, event := range page.Msg.GetEvents() {
			if event.GetAction() != "identity.authorization_updated" {
				continue
			}
			evidence.AuditEvents = append(evidence.AuditEvents, event)
			if event.GetReason() == request.GetReason() {
				if event.GetActorId() != owner.AccountID || event.GetResourceId() != "authorization" || event.GetDetails()["policy_sha256"] == "" {
					return evidence, errors.New("runtime audit lost actor, resource or policy digest")
				}
				matches++
				details := event.GetDetails()
				if details["previous_revision"] != fmt.Sprint(evidence.InitialRevision) || details["revision"] != fmt.Sprint(evidence.InitialRevision+1) || details["revoked_sessions"] != "0" {
					return evidence, errors.New("runtime audit revision or initial owner-session count is incorrect")
				}
			}
		}
		token = page.Msg.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if matches != 1 {
		return evidence, fmt.Errorf("runtime update/replay audit count: %d", matches)
	}
	evidence.Checks = append(evidence.Checks, "initial update has one audit event and historical replay adds none", "partial browser apply preserves committed outcomes and shown-once secrets", "CLI bearer rejected by browser-only account and organization endpoints")
	return evidence, nil
}
