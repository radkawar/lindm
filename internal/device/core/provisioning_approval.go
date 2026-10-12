package core

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
	if err := s.Identity.LockAuthorization(ctx, tx, first, identity.PermissionManageEnrollment); err != nil {
		return ExecutionError(err)
	}
	if second != nil {
		if err := s.Identity.LockAuthorization(ctx, tx, second, identity.PermissionManageEnrollment); err != nil {
			return ExecutionError(err)
		}
	}
	return nil
}

func (s *Service) ApprovePendingEnrollment(ctx context.Context, req *connect.Request[adminv1.ApprovePendingEnrollmentRequest]) (*connect.Response[adminv1.ApprovePendingEnrollmentResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_pending_enrollment")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	id, _ := uuid.Parse(req.Msg.GetTransactionId())
	q := devicedb.New(s.Pool)
	receipt, err := q.GetProvisioningEnrollment(ctx, id)
	if err != nil {
		return nil, MapErr(NotFoundIfMissing(err))
	}
	token, err := q.GetProvisioningToken(ctx, receipt.TokenID)
	if err != nil {
		return nil, MapErr(err)
	}
	expected := pendingEnrollmentPayload(token, receipt)
	expected.ApprovalId = req.Msg.GetApprovalId()
	if token.CreatedBy != actor.ID || receipt.ApprovalID == nil || expected.GetApprovalId() != receipt.ApprovalID.String() || !proto.Equal(expected, req.Msg) {
		return nil, ApprovalError(identity.ErrApprovalInvalid)
	}
	authorization, assignment, err := s.provisioningAuthorization(ctx, token)
	if err != nil {
		return nil, MapErr(err)
	}
	pair, err := s.Identity.PrepareApprovalConsumption(ctx, actor.ID, *receipt.ApprovalID, req.Msg)
	if err != nil {
		return nil, ApprovalError(err)
	}
	if err := provisioningAssignmentAuthority(pair.Approver().Principal(), assignment); err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockProvisioningPair(ctx, tx, pair.Requester(), pair.Approver()); err != nil {
		return nil, err
	}
	q = devicedb.New(tx)
	token, err = q.LockProvisioningToken(ctx, token.ID)
	if err != nil {
		return nil, MapErr(err)
	}
	receipt, err = q.LockProvisioningEnrollment(ctx, id)
	if err != nil {
		return nil, MapErr(err)
	}
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, pair, s.ApprovalScope); err != nil {
		return nil, ApprovalError(err)
	}
	if receipt.State != "ready" {
		now, err := DispatchClock(ctx, q)
		if err != nil {
			return nil, MapErr(err)
		}
		if err := provisioningTokenUsable(token, now); err != nil {
			return nil, err
		}
		if receipt.State != "pending_approval" || !now.Before(receipt.ExpiresAt.Time) {
			return nil, ApprovalError(identity.ErrApprovalInvalid)
		}
		device, err := q.GetDeviceForUpdate(ctx, receipt.DeviceID)
		if err != nil {
			return nil, MapErr(err)
		}
		if device.State != StatePending || device.CurrentGenerationID == nil || *device.CurrentGenerationID != receipt.GenerationID {
			return nil, MapErr(ErrDeviceRevoked)
		}
		csr, err := ParseDeviceCSR(receipt.CsrPem)
		if err != nil {
			return nil, MapErr(ErrInternalState)
		}
		issued, err := s.storeCertificate(ctx, q, receipt.DeviceID, receipt.GenerationID, csr.PublicKey, now)
		if err != nil {
			return nil, MapErr(err)
		}
		if err := s.activateProfile(ctx, tx, token, receipt, assignment); err != nil {
			return nil, MapErr(err)
		}
		changed, err := q.CompleteProvisioningEnrollment(ctx, devicedb.CompleteProvisioningEnrollmentParams{TransactionID: id, CertificateID: &issued.ID})
		if err != nil {
			return nil, MapErr(err)
		}
		if changed != 1 {
			return nil, MapErr(ErrInternalState)
		}
		if err := InsertAudit(ctx, q, &actor.ID, "provisioning.approve", receipt.DeviceID.String(), req.Msg.GetReason()); err != nil {
			return nil, MapErr(err)
		}
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, ExecutionError(err)
	}
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, pair, s.ApprovalScope); err != nil {
		return nil, ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&adminv1.ApprovePendingEnrollmentResponse{}), nil
}

func (s *Service) GetPendingEnrollments(ctx context.Context, req *connect.Request[adminv1.GetPendingEnrollmentsRequest]) (*connect.Response[adminv1.GetPendingEnrollmentsResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := PageLimit(req.Msg.GetPageSize())
	q := devicedb.New(s.Pool)
	rows, err := q.ListPendingProvisioningEnrollments(ctx, devicedb.ListPendingProvisioningEnrollmentsParams{AfterID: after, RowLimit: limit + 1})
	if err != nil {
		return nil, MapErr(err)
	}
	response := new(adminv1.GetPendingEnrollmentsResponse)
	var budget ResponsePageBudget
	for _, row := range rows {
		token, err := q.GetProvisioningToken(ctx, row.TokenID)
		if err != nil {
			return nil, MapErr(err)
		}
		assignment, err := provisioningAssignment(token)
		if err != nil {
			return nil, MapErr(err)
		}
		item := &adminv1.PendingEnrollment{TransactionId: row.TransactionID.String(), TokenId: row.TokenID.String(), DeviceId: row.DeviceID.String(), EnrollmentGeneration: row.GenerationID.String(), InstallationId: row.InstallationID.String(), CreatedAt: timestamppb.New(row.CreatedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), State: row.State, Metadata: assignment.GetMetadata()}
		if row.ApprovalID != nil {
			item.ApprovalId = row.ApprovalID.String()
			decision, err := q.ProvisioningApprovalState(ctx, *row.ApprovalID)
			if err != nil {
				return nil, MapErr(err)
			}
			// Approved is still not enrolled: the requester must run the
			// approved payload. Report it so the console doesn't keep asking
			// for an approval that was already given.
			switch {
			case decision.State == "rejected":
				item.State = "rejected"
			case !s.Now().Before(row.ExpiresAt.Time) || !s.Now().Before(decision.ExpiresAt.Time):
				item.State = "expired"
			case decision.State == "approved":
				item.State = "approved"
			}
		} else if !s.Now().Before(row.ExpiresAt.Time) {
			item.State = "expired"
		}
		fits, err := budget.Take(item)
		if err != nil {
			return nil, MapErr(err)
		}
		if len(response.Enrollments) == int(limit) || !fits {
			if len(response.Enrollments) == 0 {
				return nil, MapErr(ErrInternalState)
			}
			id, _ := uuid.Parse(response.Enrollments[len(response.Enrollments)-1].TransactionId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Enrollments = append(response.Enrollments, item)
	}
	return NoStore(response), nil
}
