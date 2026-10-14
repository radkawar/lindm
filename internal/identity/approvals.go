// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

var ErrApprovalRequired = errors.New("approval_required")
var ErrApprovalInvalid = errors.New("approval_invalid")

// ApprovalScope checks current target membership under the caller's transaction.
// The caller must lock policy and principals before invoking it.
type ApprovalScope func(context.Context, pgx.Tx, Principal, Permission, uuid.UUID) error

// ApprovalAdmission checks, in the decision transaction after principals and
// target scope are locked, that a pending request's bound evidence still holds.
// It runs only before an approval; rejection never depends on evidence.
type ApprovalAdmission func(context.Context, pgx.Tx, *adminv1.Approval) error

type approvalBinding struct {
	action     string
	permission Permission
	target     uuid.UUID
	mutation   string
	payload    []byte
	digest     [32]byte
}

func bindApproval(message proto.Message) (approvalBinding, error) {
	var b approvalBinding
	b.permission = approvalPermission(message)
	if b.permission == "" {
		return b, ErrApprovalInvalid
	}
	var payload proto.Message
	var err error
	switch request := message.(type) {
	case *adminv1.AcceptAdvisoryFindingRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("advisory_exception.accept", copy)
	case *adminv1.CreateRecoveryEnrollmentGrantRequest:
		return bindRecoveryApproval(request)
	case *adminv1.ApprovePendingEnrollmentRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("enrollment.approve", copy)
	case *adminv1.RevokeDeviceRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("device.revoke", copy)
	case *adminv1.SetResourceAssignmentRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("resources.assign", copy)
	case *adminv1.ActivateTargetPreviewRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = nil
		payload, err = b.bindDevice("resources.activate_preview", copy)
	case *adminv1.StartRolloutRequest:
		// One approval covers the whole reviewed rollout plan. It has no device
		// target, so both principals need unrestricted resources.assign scope.
		if request == nil {
			return b, ErrApprovalInvalid
		}
		b.action, b.mutation = "resources.rollout", request.GetRequestId()
		payload = request
	case *adminv1.UpdateExecutionAuthorityRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		b.action = "execution_trust.manage"
		payload = copy
	case *adminv1.CreateDeviceActionRequest:
		// Local-admin rotation is server-minted from a policy, never approved by hand.
		if request == nil || request.GetSpec() == nil || request.GetSpec().GetLocalAdminPasswordRotate() != nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("device.action", copy)
	case *adminv1.RevealRecoveryKeyRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("recovery_key.reveal", copy)
	case *adminv1.RevealSecretRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		// Secrets are deployment-global: no device target means unrestricted scope.
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		b.action, b.mutation = "secret.reveal", copy.GetRequestId()
		payload = copy
	case *adminv1.RevealLocalAdminPasswordRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("local_admin.reveal", copy)
	case *adminv1.AuthorizeUnattendedAssistanceRequest:
		if request == nil {
			return b, ErrApprovalInvalid
		}
		copy := proto.CloneOf(request)
		copy.ApprovalId = ""
		payload, err = b.bindDevice("assistance.unattended", copy)
	default:
		return b, ErrApprovalInvalid
	}
	if err != nil {
		return b, err
	}
	b.payload, err = (proto.MarshalOptions{Deterministic: true}).Marshal(payload)
	if err != nil {
		return b, fmt.Errorf("encode approval payload: %w", err)
	}
	b.digest = sha256.Sum256(b.payload)
	if b.mutation == "" {
		b.mutation = hex.EncodeToString(b.digest[:])
	}
	return b, nil
}

// deviceScopedRequest is an approvable request that targets one device.
type deviceScopedRequest interface {
	proto.Message
	GetRequestId() string
	GetDeviceId() string
}

// bindDevice binds action, the request's mutation ID and its device target, and
// returns the request as the approval payload.
func (b *approvalBinding) bindDevice(action string, request deviceScopedRequest) (proto.Message, error) {
	b.action, b.mutation = action, request.GetRequestId()
	id, err := uuid.Parse(request.GetDeviceId())
	if err != nil || id == uuid.Nil {
		return nil, ErrApprovalInvalid
	}
	b.target = id
	return request, nil
}

func approvalPayload(request *adminv1.CreateApprovalRequest) proto.Message {
	switch request.GetPayload().(type) {
	case *adminv1.CreateApprovalRequest_AcceptAdvisoryFinding:
		return request.GetAcceptAdvisoryFinding()
	case *adminv1.CreateApprovalRequest_ApprovePendingEnrollment:
		return request.GetApprovePendingEnrollment()
	case *adminv1.CreateApprovalRequest_RecoverDevice:
		return request.GetRecoverDevice()
	case *adminv1.CreateApprovalRequest_RevokeDevice:
		return request.GetRevokeDevice()
	case *adminv1.CreateApprovalRequest_SetResourceAssignment:
		return request.GetSetResourceAssignment()
	case *adminv1.CreateApprovalRequest_ActivateTargetPreview:
		return request.GetActivateTargetPreview()
	case *adminv1.CreateApprovalRequest_StartRollout:
		return request.GetStartRollout()
	case *adminv1.CreateApprovalRequest_UpdateExecutionAuthority:
		return request.GetUpdateExecutionAuthority()
	case *adminv1.CreateApprovalRequest_CreateDeviceAction:
		return request.GetCreateDeviceAction()
	case *adminv1.CreateApprovalRequest_RevealRecoveryKey:
		return request.GetRevealRecoveryKey()
	case *adminv1.CreateApprovalRequest_RevealSecret:
		return request.GetRevealSecret()
	case *adminv1.CreateApprovalRequest_RevealLocalAdminPassword:
		return request.GetRevealLocalAdminPassword()
	case *adminv1.CreateApprovalRequest_AuthorizeUnattendedAssistance:
		return request.GetAuthorizeUnattendedAssistance()
	default:
		return nil
	}
}

func (s *Service) approvalTransaction(ctx context.Context, fn func(pgx.Tx, *identitydb.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx, identitydb.New(tx)); err != nil {
		return err
	}
	return s.dbErr(tx.Commit(ctx))
}

// Inventory refresh requires independently scoped read and management authority.
// Both checks use the same fresh, transaction-fenced principal.
func scopeApproval(ctx context.Context, tx pgx.Tx, principal Principal, binding approvalBinding, scope ApprovalScope) error {
	if err := scope(ctx, tx, principal, binding.permission, binding.target); err != nil {
		return err
	}
	for _, permission := range approvalPermissionRequirements[binding.permission] {
		if !Authorize(principal, permission) {
			return ErrAuthorizationDenied
		}
		if err := scope(ctx, tx, principal, permission, binding.target); err != nil {
			return err
		}
	}
	return nil
}

// CreateApproval derives authority from the typed action, never a caller supplied permission.
func (s *Service) CreateApproval(ctx context.Context, actor uuid.UUID, request *adminv1.CreateApprovalRequest, scope ApprovalScope) (*adminv1.Approval, error) {
	if s == nil || scope == nil || request == nil {
		return nil, ErrApprovalInvalid
	}
	if err := s.rules.Validate(request); err != nil {
		return nil, ErrApprovalInvalid
	}
	binding, err := bindApproval(approvalPayload(request))
	if err != nil {
		return nil, err
	}
	authorization, err := s.AuthorizeFresh(ctx, actor, binding.permission)
	if err != nil {
		return nil, err
	}
	if authorization.Principal().ServiceAccount {
		return nil, ErrAuthorizationDenied
	}
	var projection approvalProjection
	err = s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		if err := s.LockAuthorization(ctx, tx, authorization, binding.permission); err != nil {
			return err
		}
		if err := scopeApproval(ctx, tx, authorization.Principal(), binding, scope); err != nil {
			return err
		}
		previous, lookupErr := q.GetApprovalForMutation(ctx, identitydb.GetApprovalForMutationParams{RequesterID: actor, Action: binding.action, MutationID: binding.mutation})
		if lookupErr == nil {
			if !approvalMatches(previous, actor, binding) || previous.ExpiresAt.Time.Sub(previous.CreatedAt.Time) != time.Duration(request.GetLifetimeSeconds())*time.Second {
				return ErrApprovalInvalid
			}
			if previous.RequesterVersion != int64(authorization.Version()) {
				return ErrAuthorizationChanged
			}
			projection, lookupErr = q.GetApprovalProjection(ctx, previous.ID)
			return s.dbErr(lookupErr)
		}
		if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return s.dbErr(lookupErr)
		}
		var target *uuid.UUID
		if binding.target != uuid.Nil {
			target = &binding.target
		}
		row, err := q.InsertApproval(ctx, identitydb.InsertApprovalParams{ID: uuid.New(), RequesterID: actor, RequesterVersion: int64(authorization.Version()), Action: binding.action, Permission: string(binding.permission), DeviceID: target, MutationID: binding.mutation, Payload: binding.payload, PayloadSha256: binding.digest[:], LifetimeSeconds: int32(request.GetLifetimeSeconds())})
		if err != nil {
			return s.dbErr(err)
		}
		if err := s.insertSystemAudit(ctx, q, &actor, auditkind.ApprovalCreated, row.ID.String(), binding.action); err != nil {
			return err
		}
		if err := s.insertApprovalActionAudit(ctx, q, actor, binding.action, "request", row.ID, row.DeviceID); err != nil {
			return err
		}
		projection, err = q.GetApprovalProjection(ctx, row.ID)
		return s.dbErr(err)
	})
	if err != nil {
		return nil, err
	}
	return approvalMessage(&projection, s.clock())
}

// ApprovalConsumption is an opaque fresh pair bound to one durable approval and mutation.
type ApprovalConsumption struct {
	service   *Service
	id        uuid.UUID
	binding   approvalBinding
	requester *Authorization
	approver  *Authorization
}

// Requester and Approver expose captured authority for signed action attestations;
// neither replaces LockAndConsumeApproval in the mutation transaction.
func (a *ApprovalConsumption) Requester() *Authorization {
	if a == nil {
		return nil
	}
	return a.requester
}
func (a *ApprovalConsumption) Approver() *Authorization {
	if a == nil {
		return nil
	}
	return a.approver
}

func approvalMatches(row identitydb.ApprovalRequest, actor uuid.UUID, binding approvalBinding) bool {
	target := uuid.Nil
	if row.DeviceID != nil {
		target = *row.DeviceID
	}
	return row.RequesterID == actor && row.Action == binding.action && row.Permission == string(binding.permission) && target == binding.target && row.MutationID == binding.mutation && bytes.Equal(row.PayloadSha256, binding.digest[:]) && bytes.Equal(row.Payload, binding.payload)
}

func (s *Service) freshApprovalPair(ctx context.Context, row identitydb.ApprovalRequest, approver uuid.UUID) (*ApprovalConsumption, error) {
	if approver == uuid.Nil || approver == row.RequesterID {
		return nil, ErrAuthorizationDenied
	}
	requester, err := s.AuthorizeFresh(ctx, row.RequesterID, Permission(row.Permission))
	if err != nil {
		return nil, err
	}
	reviewer, err := s.AuthorizeFresh(ctx, approver, approvalReviewerPermission(Permission(row.Permission)))
	if err != nil {
		return nil, err
	}
	if requester.Principal().ServiceAccount || reviewer.Principal().ServiceAccount || !Authorize(reviewer.Principal(), PermissionManageApprovals) {
		return nil, ErrAuthorizationDenied
	}
	if int64(requester.Version()) != row.RequesterVersion {
		return nil, ErrAuthorizationChanged
	}
	return &ApprovalConsumption{service: s, id: row.ID, requester: requester, approver: reviewer}, nil
}

// ApprovalForRequest finds the requester's retained approval bound to exactly
// this payload. It returns uuid.Nil when none exists yet. It only reads, on the
// caller's transaction when it holds one (a second pool connection under an
// open transaction can exhaust the pool): a background worker still consumes it
// through PrepareApprovalConsumption and LockAndConsumeApproval.
func (s *Service) ApprovalForRequest(ctx context.Context, db identitydb.DBTX, requester uuid.UUID, payload proto.Message) (uuid.UUID, adminv1.ApprovalState, error) {
	if s == nil {
		return uuid.Nil, adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, ErrApprovalInvalid
	}
	binding, err := bindApproval(payload)
	if err != nil {
		return uuid.Nil, adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, err
	}
	if db == nil {
		db = s.pool
	}
	row, err := identitydb.New(db).GetApprovalForMutation(ctx, identitydb.GetApprovalForMutationParams{RequesterID: requester, Action: binding.action, MutationID: binding.mutation})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, nil
	}
	if err != nil {
		return uuid.Nil, adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, s.dbErr(err)
	}
	if !approvalMatches(row, requester, binding) {
		return uuid.Nil, adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, ErrApprovalInvalid
	}
	state := adminv1.ApprovalState_APPROVAL_STATE_PENDING
	switch row.State {
	case "approved":
		state = adminv1.ApprovalState_APPROVAL_STATE_APPROVED
	case "rejected":
		state = adminv1.ApprovalState_APPROVAL_STATE_REJECTED
	case "consumed":
		state = adminv1.ApprovalState_APPROVAL_STATE_CONSUMED
	case "withdrawn":
		state = adminv1.ApprovalState_APPROVAL_STATE_WITHDRAWN
	}
	if (row.State == "pending" || row.State == "approved") && !s.clock().Before(row.ExpiresAt.Time) {
		state = adminv1.ApprovalState_APPROVAL_STATE_EXPIRED
	}
	return row.ID, state, nil
}

// PrepareApprovalConsumption performs external refreshes before any mutation locks.
func (s *Service) PrepareApprovalConsumption(ctx context.Context, actor uuid.UUID, id uuid.UUID, payload proto.Message) (*ApprovalConsumption, error) {
	if s == nil || id == uuid.Nil {
		return nil, ErrApprovalRequired
	}
	if err := s.rules.Validate(payload); err != nil {
		return nil, ErrApprovalInvalid
	}
	binding, err := bindApproval(payload)
	if err != nil {
		return nil, err
	}
	row, err := identitydb.New(s.pool).GetApproval(ctx, id)
	if err != nil {
		return nil, ErrApprovalInvalid
	}
	if !approvalMatches(row, actor, binding) || row.ApproverID == nil || (row.State != "approved" && row.State != "consumed") {
		return nil, ErrApprovalInvalid
	}
	pair, err := s.freshApprovalPair(ctx, row, *row.ApproverID)
	if err != nil {
		return nil, err
	}
	if int64(pair.approver.Version()) != row.ApproverVersion {
		return nil, ErrAuthorizationChanged
	}
	pair.binding = binding
	return pair, nil
}

func (s *Service) lockApprovalPair(ctx context.Context, tx pgx.Tx, pair *ApprovalConsumption, scope ApprovalScope) error {
	if pair == nil || pair.service != s || scope == nil {
		return ErrApprovalInvalid
	}
	first, second := pair.requester, pair.approver
	if bytes.Compare(first.actorID[:], second.actorID[:]) > 0 {
		first, second = second, first
	}
	if err := s.LockAuthorization(ctx, tx, first, first.permission); err != nil {
		return err
	}
	if err := s.LockAuthorization(ctx, tx, second, second.permission); err != nil {
		return err
	}
	if pair.requester.Principal().ServiceAccount || pair.approver.Principal().ServiceAccount || !Authorize(pair.approver.Principal(), PermissionManageApprovals) {
		return ErrAuthorizationDenied
	}
	if err := scopeApproval(ctx, tx, pair.requester.Principal(), pair.binding, scope); err != nil {
		return err
	}
	if err := scopeApproval(ctx, tx, pair.approver.Principal(), pair.binding.reviewer(), scope); err != nil {
		return err
	}
	return scope(ctx, tx, pair.approver.Principal(), PermissionManageApprovals, pair.binding.target)
}

// LockAndConsumeApproval holds policy, ordered principal, target, then approval
// locks. Consumption commits atomically with the caller's exact idempotent mutation.
// Calling again for that same mutation is safe; expiry and versions still fence it.
func (s *Service) LockAndConsumeApproval(ctx context.Context, tx pgx.Tx, pair *ApprovalConsumption, scope ApprovalScope) error {
	if err := s.lockApprovalPair(ctx, tx, pair, scope); err != nil {
		return err
	}
	q := identitydb.New(tx)
	row, err := q.LockApproval(ctx, pair.id)
	if err != nil {
		return ErrApprovalInvalid
	}
	now, err := s.authorizationTime(ctx, q)
	if err != nil {
		return err
	}
	if !row.ExpiresAt.Valid || !now.Before(row.ExpiresAt.Time) {
		return ErrAuthorizationExpired
	}
	if !approvalMatches(row, pair.requester.ActorID(), pair.binding) || row.ApproverID == nil || *row.ApproverID != pair.approver.ActorID() || row.RequesterVersion != int64(pair.requester.Version()) || row.ApproverVersion != int64(pair.approver.Version()) {
		return ErrAuthorizationChanged
	}
	if row.State == "consumed" {
		return nil
	}
	if row.State != "approved" {
		return ErrApprovalInvalid
	}
	count, err := q.ConsumeApproval(ctx, row.ID)
	if err != nil {
		return s.dbErr(err)
	}
	if count != 1 {
		return ErrAuthorizationExpired
	}
	actor := pair.requester.ActorID()
	return s.insertSystemAudit(ctx, q, &actor, auditkind.ApprovalConsumed, row.ID.String(), row.Action)
}

func (s *Service) DecideApproval(ctx context.Context, actor, id uuid.UUID, approve bool, reason string, scope ApprovalScope, admit ApprovalAdmission) (*adminv1.Approval, error) {
	if s == nil || scope == nil || admit == nil {
		return nil, ErrApprovalInvalid
	}
	validation := &adminv1.ApproveApprovalRequest{ApprovalId: id.String(), Reason: reason}
	if err := s.rules.Validate(validation); err != nil {
		return nil, ErrApprovalInvalid
	}
	row, err := identitydb.New(s.pool).GetApproval(ctx, id)
	if err != nil {
		return nil, ErrApprovalInvalid
	}
	pair, err := s.freshApprovalPair(ctx, row, actor)
	if err != nil {
		return nil, err
	}
	pair.binding = approvalBinding{action: row.Action, permission: Permission(row.Permission)}
	if row.DeviceID != nil {
		pair.binding.target = *row.DeviceID
	}
	state, action := "rejected", auditkind.ApprovalRejected
	if approve {
		state, action = "approved", auditkind.ApprovalApproved
	}
	var projection approvalProjection
	err = s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		if err := s.lockApprovalPair(ctx, tx, pair, scope); err != nil {
			return err
		}
		current, err := q.LockApproval(ctx, id)
		if err != nil {
			return ErrApprovalInvalid
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		if !now.Before(current.ExpiresAt.Time) {
			return ErrAuthorizationExpired
		}
		if current.RequesterVersion != int64(pair.requester.Version()) {
			return ErrAuthorizationChanged
		}
		if current.State != "pending" {
			if current.State == state && current.ApproverID != nil && *current.ApproverID == actor && current.ApproverVersion == int64(pair.approver.Version()) && current.DecisionReason == reason {
				projection, err = q.GetApprovalProjection(ctx, current.ID)
				return s.dbErr(err)
			}
			return ErrApprovalInvalid
		}
		if approve {
			pending, err := approvalMessage(&approvalProjection{ApprovalRequest: current}, now)
			if err != nil {
				return err
			}
			if err := admit(ctx, tx, pending); err != nil {
				return err
			}
		}
		_, err = q.DecideApproval(ctx, identitydb.DecideApprovalParams{ID: id, State: state, ApproverID: &actor, ApproverVersion: int64(pair.approver.Version()), DecisionReason: reason})
		if err != nil {
			return s.dbErr(err)
		}
		if err := s.insertAudit(ctx, q, &actor, action, id.String(), reason); err != nil {
			return err
		}
		if err := s.insertApprovalActionAudit(ctx, q, actor, current.Action, state, id, current.DeviceID); err != nil {
			return err
		}
		projection, err = q.GetApprovalProjection(ctx, id)
		return s.dbErr(err)
	})
	if err != nil {
		return nil, err
	}
	return approvalMessage(&projection, s.clock())
}

// WithdrawApproval lets the requester close their own pending request. It
// needs no approval authority: withdrawal only removes the request's power,
// is never a decision, and records no approver. An exact retry is idempotent.
func (s *Service) WithdrawApproval(ctx context.Context, actor, id uuid.UUID, reason string) (*adminv1.Approval, error) {
	if s == nil {
		return nil, ErrApprovalInvalid
	}
	if err := s.rules.Validate(&adminv1.WithdrawApprovalRequest{ApprovalId: id.String(), Reason: reason}); err != nil {
		return nil, ErrApprovalInvalid
	}
	var projection approvalProjection
	err := s.approvalTransaction(ctx, func(tx pgx.Tx, q *identitydb.Queries) error {
		current, err := q.LockApproval(ctx, id)
		if err != nil {
			return ErrApprovalInvalid
		}
		if current.RequesterID != actor {
			return ErrAuthorizationDenied
		}
		if current.State == "withdrawn" && current.DecisionReason == reason {
			projection, err = q.GetApprovalProjection(ctx, id)
			return s.dbErr(err)
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		if !now.Before(current.ExpiresAt.Time) {
			return ErrAuthorizationExpired
		}
		if current.State != "pending" {
			return ErrApprovalInvalid
		}
		if _, err := q.WithdrawApproval(ctx, identitydb.WithdrawApprovalParams{ID: id, RequesterID: actor, Reason: reason}); err != nil {
			return s.dbErr(err)
		}
		if err := s.insertAudit(ctx, q, &actor, auditkind.ApprovalWithdrawn, id.String(), reason); err != nil {
			return err
		}
		projection, err = q.GetApprovalProjection(ctx, id)
		return s.dbErr(err)
	})
	if err != nil {
		return nil, err
	}
	return approvalMessage(&projection, s.clock())
}

// approvalProjection is read only after fresh authorization and target scope
// checks. Names and hostname are joined live, never cached on approval requests.
type approvalProjection = identitydb.GetApprovalProjectionRow

func approvalMessage(projection *approvalProjection, now time.Time) (*adminv1.Approval, error) {
	row := &projection.ApprovalRequest
	out := &adminv1.Approval{Id: row.ID.String(), RequesterId: row.RequesterID.String(), Action: row.Action, Permission: row.Permission, PayloadSha256: row.PayloadSha256, CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), DecisionReason: row.DecisionReason, RequesterDisplayName: projection.RequesterDisplayName, ApproverDisplayName: projection.ApproverDisplayName, DeviceHostname: projection.DeviceHostname}
	if row.DeviceID != nil {
		out.DeviceId = row.DeviceID.String()
	}
	if row.ApproverID != nil {
		out.ApproverId = row.ApproverID.String()
	}
	switch row.State {
	case "pending":
		out.State = adminv1.ApprovalState_APPROVAL_STATE_PENDING
	case "approved":
		out.State = adminv1.ApprovalState_APPROVAL_STATE_APPROVED
	case "rejected":
		out.State = adminv1.ApprovalState_APPROVAL_STATE_REJECTED
	case "consumed":
		out.State = adminv1.ApprovalState_APPROVAL_STATE_CONSUMED
	case "withdrawn":
		out.State = adminv1.ApprovalState_APPROVAL_STATE_WITHDRAWN
	default:
		return nil, ErrApprovalInvalid
	}
	if (row.State == "pending" || row.State == "approved") && !now.Before(row.ExpiresAt.Time) {
		out.State = adminv1.ApprovalState_APPROVAL_STATE_EXPIRED
	}
	var payload proto.Message
	switch row.Action {
	case "advisory_exception.accept":
		request := &adminv1.AcceptAdvisoryFindingRequest{}
		payload = request
		out.Payload = &adminv1.Approval_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}
	case "enrollment.approve":
		request := &adminv1.ApprovePendingEnrollmentRequest{}
		payload = request
		out.Payload = &adminv1.Approval_ApprovePendingEnrollment{ApprovePendingEnrollment: request}
	case "device.recover":
		request := &adminv1.CreateRecoveryEnrollmentGrantRequest{}
		payload = request
		out.Payload = &adminv1.Approval_RecoverDevice{RecoverDevice: request}
	case "device.revoke":
		request := &adminv1.RevokeDeviceRequest{}
		payload = request
		out.Payload = &adminv1.Approval_RevokeDevice{RevokeDevice: request}
	case "resources.assign":
		request := &adminv1.SetResourceAssignmentRequest{}
		payload = request
		out.Payload = &adminv1.Approval_SetResourceAssignment{SetResourceAssignment: request}
	case "resources.activate_preview":
		request := &adminv1.ActivateTargetPreviewRequest{}
		payload = request
		out.Payload = &adminv1.Approval_ActivateTargetPreview{ActivateTargetPreview: request}
	case "resources.rollout":
		request := &adminv1.StartRolloutRequest{}
		payload = request
		out.Payload = &adminv1.Approval_StartRollout{StartRollout: request}
	case "execution_trust.manage":
		request := &adminv1.UpdateExecutionAuthorityRequest{}
		payload = request
		out.Payload = &adminv1.Approval_UpdateExecutionAuthority{UpdateExecutionAuthority: request}
	case "device.action":
		request := &adminv1.CreateDeviceActionRequest{}
		payload = request
		out.Payload = &adminv1.Approval_CreateDeviceAction{CreateDeviceAction: request}
	case "recovery_key.reveal":
		request := &adminv1.RevealRecoveryKeyRequest{}
		payload = request
		out.Payload = &adminv1.Approval_RevealRecoveryKey{RevealRecoveryKey: request}
	case "secret.reveal":
		request := &adminv1.RevealSecretRequest{}
		payload = request
		out.Payload = &adminv1.Approval_RevealSecret{RevealSecret: request}
	case "local_admin.reveal":
		request := &adminv1.RevealLocalAdminPasswordRequest{}
		payload = request
		out.Payload = &adminv1.Approval_RevealLocalAdminPassword{RevealLocalAdminPassword: request}
	case "assistance.unattended":
		request := &adminv1.AuthorizeUnattendedAssistanceRequest{}
		payload = request
		out.Payload = &adminv1.Approval_AuthorizeUnattendedAssistance{AuthorizeUnattendedAssistance: request}
	default:
		return nil, ErrApprovalInvalid
	}
	if err := proto.Unmarshal(row.Payload, payload); err != nil {
		return nil, fmt.Errorf("decode approval payload: %w", err)
	}
	return out, nil
}
