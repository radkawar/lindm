package device

import (
	"bytes"
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// Every provisioning mutation locks principal(s), token, receipt, then device.
// Prelock approval principals before taking the token: the approval service's
// normal scope check takes the device lock and must not invert this ordering.
func (s *Service) lockProvisioningPair(ctx context.Context, tx pgx.Tx, first, second *identity.Authorization) error {
	if second != nil {
		a, b := first.ActorID(), second.ActorID()
		if bytes.Compare(a[:], b[:]) > 0 {
			first, second = second, first
		}
	}
	if err := s.identity.LockAuthorization(ctx, tx, first, identity.PermissionManageEnrollment); err != nil {
		return executionError(err)
	}
	if second != nil {
		if err := s.identity.LockAuthorization(ctx, tx, second, identity.PermissionManageEnrollment); err != nil {
			return executionError(err)
		}
	}
	return nil
}

func (s *Service) ApprovePendingEnrollment(ctx context.Context, req *connect.Request[adminv1.ApprovePendingEnrollmentRequest]) (*connect.Response[adminv1.ApprovePendingEnrollmentResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_pending_enrollment")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	id, _ := uuid.Parse(req.Msg.GetTransactionId())
	q := devicedb.New(s.pool)
	receipt, err := q.GetProvisioningEnrollment(ctx, id)
	if err != nil {
		return nil, mapErr(notFoundIfMissing(err))
	}
	token, err := q.GetProvisioningToken(ctx, receipt.TokenID)
	if err != nil {
		return nil, mapErr(err)
	}
	expected := pendingEnrollmentPayload(token, receipt)
	expected.ApprovalId = req.Msg.GetApprovalId()
	if token.CreatedBy != actor.ID || receipt.ApprovalID == nil || expected.GetApprovalId() != receipt.ApprovalID.String() || !proto.Equal(expected, req.Msg) {
		return nil, approvalError(identity.ErrApprovalInvalid)
	}
	authorization, assignment, err := s.provisioningAuthorization(ctx, token)
	if err != nil {
		return nil, mapErr(err)
	}
	pair, err := s.identity.PrepareApprovalConsumption(ctx, actor.ID, *receipt.ApprovalID, req.Msg)
	if err != nil {
		return nil, approvalError(err)
	}
	if err := provisioningAssignmentAuthority(pair.Approver().Principal(), assignment); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockProvisioningPair(ctx, tx, pair.Requester(), pair.Approver()); err != nil {
		return nil, err
	}
	q = devicedb.New(tx)
	token, err = q.LockProvisioningToken(ctx, token.ID)
	if err != nil {
		return nil, mapErr(err)
	}
	receipt, err = q.LockProvisioningEnrollment(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.approvalScope); err != nil {
		return nil, approvalError(err)
	}
	if receipt.State != "ready" {
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := provisioningTokenUsable(token, now); err != nil {
			return nil, err
		}
		if receipt.State != "pending_approval" || !now.Before(receipt.ExpiresAt.Time) {
			return nil, approvalError(identity.ErrApprovalInvalid)
		}
		device, err := q.GetDeviceForUpdate(ctx, receipt.DeviceID)
		if err != nil {
			return nil, mapErr(err)
		}
		if device.State != statePending || device.CurrentGenerationID == nil || *device.CurrentGenerationID != receipt.GenerationID {
			return nil, mapErr(errDeviceRevoked)
		}
		csr, err := parseDeviceCSR(receipt.CsrPem)
		if err != nil {
			return nil, mapErr(errInternalState)
		}
		issued, err := s.storeCertificate(ctx, q, receipt.DeviceID, receipt.GenerationID, csr.PublicKey, now)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := s.activateProvisioningProfile(ctx, tx, token, receipt, assignment); err != nil {
			return nil, mapErr(err)
		}
		changed, err := q.CompleteProvisioningEnrollment(ctx, devicedb.CompleteProvisioningEnrollmentParams{TransactionID: id, CertificateID: &issued.ID})
		if err != nil {
			return nil, mapErr(err)
		}
		if changed != 1 {
			return nil, mapErr(errInternalState)
		}
		if err := insertAudit(ctx, q, &actor.ID, "provisioning.approve", receipt.DeviceID.String(), req.Msg.GetReason()); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.approvalScope); err != nil {
		return nil, approvalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.ApprovePendingEnrollmentResponse{}), nil
}

func (s *Service) GetPendingEnrollments(ctx context.Context, req *connect.Request[adminv1.GetPendingEnrollmentsRequest]) (*connect.Response[adminv1.GetPendingEnrollmentsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_argument")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.GetPageSize())
	q := devicedb.New(s.pool)
	rows, err := q.ListPendingProvisioningEnrollments(ctx, devicedb.ListPendingProvisioningEnrollmentsParams{AfterID: after, RowLimit: limit + 1})
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.GetPendingEnrollmentsResponse)
	var budget responsePageBudget
	for _, row := range rows {
		token, err := q.GetProvisioningToken(ctx, row.TokenID)
		if err != nil {
			return nil, mapErr(err)
		}
		assignment, err := provisioningAssignment(token)
		if err != nil {
			return nil, mapErr(err)
		}
		item := &adminv1.PendingEnrollment{TransactionId: row.TransactionID.String(), TokenId: row.TokenID.String(), DeviceId: row.DeviceID.String(), EnrollmentGeneration: row.GenerationID.String(), InstallationId: row.InstallationID.String(), CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), State: row.State, Metadata: assignment.GetMetadata()}
		if row.ApprovalID != nil {
			item.ApprovalId = row.ApprovalID.String()
			decision, err := q.ProvisioningApprovalState(ctx, *row.ApprovalID)
			if err != nil {
				return nil, mapErr(err)
			}
			if decision.State == "rejected" {
				item.State = "rejected"
			}
		}
		if item.State == "pending_approval" && !s.now().Before(row.ExpiresAt.Time) {
			item.State = "expired"
		}
		fits, err := budget.take(item)
		if err != nil {
			return nil, mapErr(err)
		}
		if len(response.Enrollments) == int(limit) || !fits {
			if len(response.Enrollments) == 0 {
				return nil, mapErr(errInternalState)
			}
			id, _ := uuid.Parse(response.Enrollments[len(response.Enrollments)-1].TransactionId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Enrollments = append(response.Enrollments, item)
	}
	return noStore(response), nil
}
