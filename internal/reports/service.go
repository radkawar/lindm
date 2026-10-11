// Package reports owns bounded durable report artifacts and independently signed
// audit exports. It does not establish archive signing-key trust or retain reports
// past their configured expiry; audit chain evidence itself is append-only.
package reports

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	integrationsv1connect "lindm/gen/lindm/integrations/v1/integrationsv1connect"
	"lindm/internal/identity"
	"lindm/internal/reports/reportdb"
	"lindm/internal/rpcreason"
)

const maxArtifactBytes = 32 * 1024 * 1024
const maxReportRows = 100000
const chunkBytes = 256 * 1024

// AdminHandler must be mounted behind identity.RequireSession.
func (s *Service) AdminHandler() (string, http.Handler) {
	path, handler := integrationsv1connect.NewReportServiceHandler(s,
		connect.WithReadMaxBytes(64*1024), connect.WithSendMaxBytes(1024*1024))
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r)
	})
}

// Service has constructor-only dependencies and no process-local job ownership.
// Run may operate concurrently in multiple server replicas against one database.
type Service struct {
	pool         *pgxpool.Pool
	identity     *identity.Service
	validator    protovalidate.Validator
	signer       crypto.Signer
	algorithm    string
	publicKey    []byte
	fingerprint  [sha256.Size]byte
	certificates [][]byte
	signMu       sync.Mutex
}

var _ integrationsv1connect.ReportServiceHandler = (*Service)(nil)

func New(pool *pgxpool.Pool, identities *identity.Service, signer crypto.Signer, certificates [][]byte) (*Service, error) {
	if pool == nil || identities == nil || signer == nil {
		return nil, errors.New("reports: pool, identity and signer are required")
	}
	algorithm, err := signingAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal report public key: %w", err)
	}
	chain := make([][]byte, len(certificates))
	for i, encoded := range certificates {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, fmt.Errorf("parse report certificate: %w", err)
		}
		if i == 0 && !bytes.Equal(certificate.RawSubjectPublicKeyInfo, public) {
			return nil, errors.New("reports: certificate does not match signer")
		}
		chain[i] = bytes.Clone(encoded)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(
		&integrationsv1.CreateAuditExportRequest{}, &integrationsv1.UpsertReportScheduleRequest{},
		&integrationsv1.ListReportSchedulesRequest{}, &integrationsv1.ListReportArtifactsRequest{},
		&integrationsv1.DownloadReportArtifactRequest{},
	))
	if err != nil {
		return nil, fmt.Errorf("compile report validation: %w", err)
	}
	return &Service{pool: pool, identity: identities, validator: validator, signer: signer,
		algorithm: algorithm, publicKey: public, fingerprint: sha256.Sum256(public), certificates: chain}, nil
}

func reportError(err error) error {
	if err == nil {
		return nil
	}
	var rpc *connect.Error
	if errors.As(err, &rpc) {
		return rpc
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeNotFound, "report_not_found")
	}
	if errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrAuthorizationExpired) {
		return rpcreason.Error(connect.CodePermissionDenied, "report_authorization_denied")
	}
	var database *pgconn.PgError
	if errors.As(err, &database) && database.Code == "23505" {
		return rpcreason.Error(connect.CodeAlreadyExists, "report_conflict")
	}
	return rpcreason.Error(connect.CodeUnavailable, "report_store_unavailable")
}

func (s *Service) require(ctx context.Context, request proto.Message) (identity.Principal, error) {
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return identity.Principal{}, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	unrestricted, _ := identity.DeviceScopes(principal, identity.PermissionManageIntegrations)
	if !unrestricted {
		return identity.Principal{}, rpcreason.Error(connect.CodePermissionDenied, "unrestricted_integrations_required")
	}
	if err := s.validator.Validate(request); err != nil {
		return identity.Principal{}, rpcreason.Error(connect.CodeInvalidArgument, "invalid_report_request")
	}
	return principal, nil
}

func rollback(tx pgx.Tx, ctx context.Context, result *error) {
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		*result = errors.Join(*result, err)
	}
}

func (s *Service) mutate(ctx context.Context, request proto.Message, requestID string, response proto.Message, operation func(*reportdb.Queries, uuid.UUID) error) (result error) {
	principal, err := s.require(ctx, request)
	if err != nil {
		return err
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, principal.ID, identity.PermissionManageIntegrations)
	if err != nil {
		return err
	}
	unrestricted, _ := identity.DeviceScopes(authorization.Principal(), identity.PermissionManageIntegrations)
	if !unrestricted {
		return rpcreason.Error(connect.CodePermissionDenied, "unrestricted_integrations_required")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(request.ProtoReflect().Descriptor().FullName()))
	_, _ = digest.Write(encoded)
	requestHash := digest.Sum(nil)
	id, err := uuid.Parse(requestID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx, ctx, &result)
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageIntegrations); err != nil {
		return err
	}
	q := reportdb.New(tx)
	receipt, err := q.GetReportMutation(ctx, reportdb.GetReportMutationParams{ActorID: principal.ID, RequestID: id})
	if err == nil {
		if !bytes.Equal(receipt.RequestHash, requestHash) {
			return rpcreason.Error(connect.CodeAlreadyExists, "request_id_reused")
		}
		if err := proto.Unmarshal(receipt.Response, response); err != nil {
			return err
		}
		if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageIntegrations); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := operation(q, principal.ID); err != nil {
		return err
	}
	encoded, err = proto.Marshal(response)
	if err != nil {
		return err
	}
	if err := q.InsertReportMutation(ctx, reportdb.InsertReportMutationParams{ActorID: principal.ID, RequestID: id, RequestHash: requestHash, Response: encoded}); err != nil {
		return err
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageIntegrations); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scheduleMessage(row reportdb.ReportSchedule) *integrationsv1.ReportSchedule {
	return &integrationsv1.ReportSchedule{Id: row.ID.String(), Name: row.Name,
		Kind: integrationsv1.ReportKind(row.Kind), Format: integrationsv1.ReportFormat(row.Format),
		IntervalSeconds: uint32(row.IntervalSeconds), RetentionDays: uint32(row.RetentionDays),
		Enabled: row.Enabled, Revision: uint64(row.Revision), NextRunAt: timestamppb.New(row.NextRunAt.Time)}
}

func artifactMessage(row reportdb.ReportArtifact) (*integrationsv1.ReportArtifact, error) {
	artifact := &integrationsv1.ReportArtifact{Id: row.ID.String(), Kind: integrationsv1.ReportKind(row.Kind),
		Format: integrationsv1.ReportFormat(row.Format), State: row.State, CreatedAt: timestamppb.New(row.CreatedAt.Time),
		ExpiresAt: timestamppb.New(row.ExpiresAt.Time), ByteCount: uint64(row.ByteCount), RowCount: uint64(row.RowCount),
		ChunkCount: uint32(row.ChunkCount), FailureReason: row.FailureReason}
	if row.ScheduleID != nil {
		artifact.ScheduleId = row.ScheduleID.String()
	}
	if len(row.SignedManifest) != 0 {
		artifact.SignedManifest = &integrationsv1.ReportSignedManifest{}
		if err := proto.Unmarshal(row.SignedManifest, artifact.SignedManifest); err != nil {
			return nil, err
		}
	}
	return artifact, nil
}

func pageArguments(after string, size uint32) (uuid.UUID, int32, error) {
	id := uuid.Nil
	var err error
	if after != "" {
		id, err = uuid.Parse(after)
	}
	if size == 0 {
		size = 50
	}
	return id, int32(size), err
}

func (s *Service) UpsertReportSchedule(ctx context.Context, request *connect.Request[integrationsv1.UpsertReportScheduleRequest]) (*connect.Response[integrationsv1.UpsertReportScheduleResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	response := &integrationsv1.UpsertReportScheduleResponse{}
	err := s.mutate(ctx, request.Msg, request.Msg.GetRequestId(), response, func(q *reportdb.Queries, actor uuid.UUID) error {
		input := request.Msg.GetSchedule()
		id, err := uuid.Parse(input.GetId())
		if err != nil {
			return err
		}
		var row reportdb.ReportSchedule
		if input.GetRevision() == 0 {
			row, err = q.CreateReportSchedule(ctx, reportdb.CreateReportScheduleParams{ID: id, ActorID: actor,
				Name: input.GetName(), Kind: int16(input.GetKind()), Format: int16(input.GetFormat()),
				IntervalSeconds: int32(input.GetIntervalSeconds()), RetentionDays: int32(input.GetRetentionDays()), Enabled: input.GetEnabled()})
		} else {
			row, err = q.UpdateReportSchedule(ctx, reportdb.UpdateReportScheduleParams{ID: id, ActorID: actor,
				Name: input.GetName(), Kind: int16(input.GetKind()), Format: int16(input.GetFormat()),
				IntervalSeconds: int32(input.GetIntervalSeconds()), RetentionDays: int32(input.GetRetentionDays()), Enabled: input.GetEnabled(), ExpectedRevision: int64(input.GetRevision())})
			if errors.Is(err, pgx.ErrNoRows) {
				return rpcreason.Error(connect.CodeAborted, "report_schedule_revision_changed")
			}
		}
		if err != nil {
			return err
		}
		response.Schedule = scheduleMessage(row)
		return q.InsertReportAudit(ctx, reportdb.InsertReportAuditParams{ActorID: &actor, Action: "report.schedule.updated", ResourceID: id.String(), Reason: request.Msg.GetReason()})
	})
	if err != nil {
		return nil, reportError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) CreateAuditExport(ctx context.Context, request *connect.Request[integrationsv1.CreateAuditExportRequest]) (*connect.Response[integrationsv1.CreateAuditExportResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	response := &integrationsv1.CreateAuditExportResponse{}
	err := s.mutate(ctx, request.Msg, request.Msg.GetRequestId(), response, func(q *reportdb.Queries, actor uuid.UUID) error {
		row, err := createAuditArtifact(ctx, q, request.Msg, actor)
		if err != nil {
			return err
		}
		response.Artifact, err = artifactMessage(row)
		if err != nil {
			return err
		}
		return q.InsertReportAudit(ctx, reportdb.InsertReportAuditParams{ActorID: &actor, Action: "report.audit_export.created", ResourceID: row.ID.String(), Reason: request.Msg.GetReason()})
	})
	if err != nil {
		return nil, reportError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) ListReportSchedules(ctx context.Context, request *connect.Request[integrationsv1.ListReportSchedulesRequest]) (*connect.Response[integrationsv1.ListReportSchedulesResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.require(ctx, request.Msg); err != nil {
		return nil, err
	}
	after, size, err := pageArguments(request.Msg.GetAfterId(), request.Msg.GetPageSize())
	if err != nil {
		return nil, reportError(err)
	}
	rows, err := reportdb.New(s.pool).ListReportSchedules(ctx, reportdb.ListReportSchedulesParams{AfterID: after, RowLimit: size + 1})
	if err != nil {
		return nil, reportError(err)
	}
	response := &integrationsv1.ListReportSchedulesResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		response.NextAfterId = rows[len(rows)-1].ID.String()
	}
	for _, row := range rows {
		response.Schedules = append(response.Schedules, scheduleMessage(row))
	}
	return connect.NewResponse(response), nil
}

func (s *Service) ListReportArtifacts(ctx context.Context, request *connect.Request[integrationsv1.ListReportArtifactsRequest]) (*connect.Response[integrationsv1.ListReportArtifactsResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.require(ctx, request.Msg); err != nil {
		return nil, err
	}
	after, size, err := pageArguments(request.Msg.GetAfterId(), request.Msg.GetPageSize())
	if err != nil {
		return nil, reportError(err)
	}
	rows, err := reportdb.New(s.pool).ListReportArtifacts(ctx, reportdb.ListReportArtifactsParams{AfterID: after, RowLimit: size + 1})
	if err != nil {
		return nil, reportError(err)
	}
	response := &integrationsv1.ListReportArtifactsResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		response.NextAfterId = rows[len(rows)-1].ID.String()
	}
	for _, row := range rows {
		artifact, err := artifactMessage(row)
		if err != nil {
			return nil, reportError(err)
		}
		response.Artifacts = append(response.Artifacts, artifact)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) DownloadReportArtifact(ctx context.Context, request *connect.Request[integrationsv1.DownloadReportArtifactRequest]) (*connect.Response[integrationsv1.DownloadReportArtifactResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.require(ctx, request.Msg); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(request.Msg.GetArtifactId())
	if err != nil {
		return nil, reportError(err)
	}
	q := reportdb.New(s.pool)
	row, err := q.GetReportArtifact(ctx, id)
	if err != nil {
		return nil, reportError(err)
	}
	if row.State != "published" {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "report_not_published")
	}
	index := int32(request.Msg.GetChunkIndex())
	if index >= row.ChunkCount && (index != 0 || row.ChunkCount != 0) {
		return nil, rpcreason.Error(connect.CodeOutOfRange, "report_chunk_out_of_range")
	}
	artifact, err := artifactMessage(row)
	if err != nil {
		return nil, reportError(err)
	}
	response := &integrationsv1.DownloadReportArtifactResponse{SignedManifest: artifact.GetSignedManifest(), Finished: index+1 >= row.ChunkCount}
	if row.ChunkCount > 0 {
		response.Data, err = q.DownloadReportChunk(ctx, reportdb.DownloadReportChunkParams{ArtifactID: id, ChunkIndex: index})
		if err != nil {
			return nil, reportError(err)
		}
	}
	if !response.Finished {
		response.NextChunkIndex = uint32(index + 1)
	}
	return connect.NewResponse(response), nil
}
