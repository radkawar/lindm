package reports

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/identity"
	"lindm/internal/reports/reportdb"
)

var errReportLimit = errors.New("reports: artifact size or row limit exceeded")
var errLeaseLost = errors.New("reports: artifact lease lost")

// Run is a replicated job that reconciles durable schedules, work and retention
// until cancellation. Schedules, artifacts and retention are claimed with SKIP
// LOCKED row leases. Every attempt has a 20-second generation bound inside a
// 60-second database lease. Generation uses one repeatable-read snapshot and
// atomically publishes chunks; crashes roll back chunks and another replica can
// reclaim an expired lease. Store failure returns to the job supervisor.
func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.workOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("reports: reconciliation failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) workOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := reportdb.New(s.pool)
	if _, err := q.PruneReportArtifacts(ctx); err != nil {
		return err
	}
	if _, err := q.QueueDueReport(ctx, reportdb.QueueDueReportParams{LeaseToken: uuid.New(), ArtifactID: uuid.New()}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	job, err := q.ClaimReportArtifact(ctx, uuid.New())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, job.ActorID, identity.PermissionManageIntegrations)
	if err == nil {
		unrestricted, _ := identity.DeviceScopes(authorization.Principal(), identity.PermissionManageIntegrations)
		if !unrestricted {
			err = identity.ErrAuthorizationDenied
		}
	}
	if err == nil {
		err = s.generate(ctx, job, authorization)
	}
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	reason := "report_generation_failed"
	if errors.Is(err, errReportLimit) {
		reason = "report_limit_exceeded"
	}
	if errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrAuthorizationExpired) {
		reason = "report_authorization_denied"
	}
	if job.LeaseToken == nil {
		return errLeaseLost
	}
	_, failErr := q.FailReportArtifact(ctx, reportdb.FailReportArtifactParams{ID: job.ID, LeaseToken: *job.LeaseToken, FailureReason: reason})
	return failErr
}

func (s *Service) generate(ctx context.Context, job reportdb.ReportArtifact, authorization *identity.Authorization) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer rollback(tx, ctx, &result)
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageIntegrations); err != nil {
		return err
	}
	if job.LeaseToken == nil {
		return errLeaseLost
	}
	q := reportdb.New(tx)
	job, err = q.LockReportArtifact(ctx, reportdb.LockReportArtifactParams{ID: job.ID, LeaseToken: *job.LeaseToken})
	if err != nil {
		return err
	}
	if err := s.buildArtifact(ctx, q, job); err != nil {
		return err
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageIntegrations); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// buildArtifact is the transaction-owned persistence boundary. Its caller must
// hold both the principal authorization fence and artifact lease row lock.
func (s *Service) buildArtifact(ctx context.Context, q *reportdb.Queries, job reportdb.ReportArtifact) error {
	writer := &chunkWriter{ctx: ctx, q: q, artifact: job.ID, buffer: make([]byte, 0, chunkBytes), hash: sha256.New()}
	var count uint64
	var err error
	var selection *auditv1.AuditFilter
	switch integrationsv1.ReportKind(job.Kind) {
	case integrationsv1.ReportKind_REPORT_KIND_AUDIT:
		count, err = writeAudit(ctx, q, writer, job)
	case integrationsv1.ReportKind_REPORT_KIND_AUDIT_SELECTION:
		selection = &auditv1.AuditFilter{}
		if err := proto.Unmarshal(job.AuditFilter, selection); err != nil {
			return err
		}
		if err := s.validator.Validate(selection); err != nil {
			return err
		}
		count, err = writeAuditSelection(ctx, q, writer, job, selection)
	default:
		count, err = writeDomainReport(ctx, q, writer, integrationsv1.ReportKind(job.Kind), integrationsv1.ReportFormat(job.Format))
	}
	if err != nil {
		return err
	}
	if err := writer.flush(); err != nil {
		return err
	}
	manifest := &integrationsv1.ReportManifest{ArtifactId: job.ID.String(), Kind: integrationsv1.ReportKind(job.Kind), Format: integrationsv1.ReportFormat(job.Format),
		CreatedAt: timestamppb.New(job.CreatedAt.Time), ByteCount: uint64(writer.total), RowCount: count, ContentSha256: writer.hash.Sum(nil)}
	if manifest.GetKind() == integrationsv1.ReportKind_REPORT_KIND_AUDIT {
		manifest.ChainId = job.ChainID.String()
		manifest.AfterSequence = uint64(job.AfterSequence)
		manifest.AfterHash = job.AfterHash
		manifest.FinalSequence = uint64(job.FinalSequence)
		manifest.FinalHash = job.FinalHash
		manifest.CapturedHeadSequence = uint64(job.CapturedHeadSequence)
		manifest.CapturedHeadHash = job.CapturedHeadHash
	}
	if selection != nil {
		manifest.AuditFilter = selection
		manifest.ChainId = job.ChainID.String()
		manifest.CapturedHeadSequence = uint64(job.CapturedHeadSequence)
		manifest.CapturedHeadHash = job.CapturedHeadHash
	}
	signed, err := s.signManifest(manifest)
	if err != nil {
		return err
	}
	if job.LeaseToken == nil {
		return errLeaseLost
	}
	affected, err := q.PublishReportArtifact(ctx, reportdb.PublishReportArtifactParams{ID: job.ID, LeaseToken: *job.LeaseToken,
		ByteCount: int64(writer.total), RowCount: int64(count), ChunkCount: writer.chunks, SignedManifest: signed})
	if err != nil {
		return err
	}
	if affected != 1 {
		return errLeaseLost
	}
	return nil
}

type chunkWriter struct {
	ctx      context.Context
	q        *reportdb.Queries
	artifact uuid.UUID
	buffer   []byte
	hash     hash.Hash
	total    int
	chunks   int32
}

func (w *chunkWriter) Write(data []byte) (int, error) {
	if len(data) > maxArtifactBytes-w.total {
		return 0, errReportLimit
	}
	length := len(data)
	for len(data) > 0 {
		n := min(len(data), chunkBytes-len(w.buffer))
		w.buffer = append(w.buffer, data[:n]...)
		data = data[n:]
		w.total += n
		if len(w.buffer) == chunkBytes {
			if err := w.flush(); err != nil {
				return length - len(data), err
			}
		}
	}
	return length, nil
}

func (w *chunkWriter) WriteString(data string) (int, error) {
	if len(data) > maxArtifactBytes-w.total {
		return 0, errReportLimit
	}
	length := len(data)
	for len(data) > 0 {
		n := min(len(data), chunkBytes-len(w.buffer))
		w.buffer = append(w.buffer, data[:n]...)
		data = data[n:]
		w.total += n
		if len(w.buffer) == chunkBytes {
			if err := w.flush(); err != nil {
				return length - len(data), err
			}
		}
	}
	return length, nil
}

func (w *chunkWriter) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	if err := w.q.InsertReportChunk(w.ctx, reportdb.InsertReportChunkParams{ArtifactID: w.artifact, ChunkIndex: w.chunks, Data: w.buffer}); err != nil {
		return err
	}
	_, _ = w.hash.Write(w.buffer)
	w.chunks++
	w.buffer = w.buffer[:0]
	return nil
}

func writeAudit(ctx context.Context, q *reportdb.Queries, writer io.Writer, job reportdb.ReportArtifact) (uint64, error) {
	after := job.AfterSequence
	var count uint64
	for after < job.FinalSequence {
		rows, err := q.PageAuditRows(ctx, reportdb.PageAuditRowsParams{AfterSequence: after, FinalSequence: job.FinalSequence})
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			return 0, errors.New("reports: missing audit evidence")
		}
		for _, row := range rows {
			if row.Sequence != after+1 {
				return 0, errors.New("reports: audit evidence discontinuity")
			}
			encoded, err := protojson.Marshal(&integrationsv1.AuditChainRecord{Sequence: uint64(row.Sequence), PreviousHash: row.PreviousHash, RowHash: row.RowHash, Payload: row.Payload})
			if err != nil {
				return 0, err
			}
			encoded = append(encoded, '\n')
			if _, err := writer.Write(encoded); err != nil {
				return 0, err
			}
			count++
			if count > maxReportRows {
				return 0, errReportLimit
			}
			after = row.Sequence
		}
	}
	return count, nil
}

func reportColumns(kind integrationsv1.ReportKind) []string {
	switch kind {
	case integrationsv1.ReportKind_REPORT_KIND_INVENTORY:
		return []string{"device_id", "hostname", "state", "os_id", "os_version", "architecture", "enrolled_at", "last_seen_at", "host_received_at", "snapshot_received_at", "published_sequence"}
	case integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE:
		return []string{"device_id", "assignment_id", "resource_id", "unit_name", "reason", "last_verified_at", "observed_at", "state"}
	case integrationsv1.ReportKind_REPORT_KIND_FINDINGS:
		return []string{"finding_id", "device_id", "advisory_id", "package_name", "installed_version", "fixed_version", "architecture", "severity", "state", "evaluated_at", "inventory_at"}
	default:
		return nil
	}
}

func writeDomainReport(ctx context.Context, q *reportdb.Queries, writer io.Writer, kind integrationsv1.ReportKind, format integrationsv1.ReportFormat) (uint64, error) {
	columns := reportColumns(kind)
	if columns == nil {
		return 0, errors.New("reports: unsupported report kind")
	}
	var count uint64
	var csvWriter *csv.Writer
	switch format {
	case integrationsv1.ReportFormat_REPORT_FORMAT_CSV:
		csvWriter = csv.NewWriter(writer)
		if err := csvWriter.Write(columns); err != nil {
			return 0, err
		}
	case integrationsv1.ReportFormat_REPORT_FORMAT_JSON:
		if _, err := io.WriteString(writer, "["); err != nil {
			return 0, err
		}
	default:
		return 0, errors.New("reports: unsupported report format")
	}
	emit := func(record string) error {
		if count == maxReportRows {
			return errReportLimit
		}
		if csvWriter != nil {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(record), &fields); err != nil {
				return err
			}
			values := make([]string, len(columns))
			for i, column := range columns {
				raw := fields[column]
				if len(raw) == 0 || string(raw) == "null" {
					continue
				}
				if raw[0] == '"' {
					if err := json.Unmarshal(raw, &values[i]); err != nil {
						return err
					}
				} else {
					values[i] = string(raw)
				}
				// CSV is for human spreadsheet use. Neutralize formula cells;
				// JSON preserves exact source values for machine ingestion.
				if strings.ContainsAny(values[i][:min(1, len(values[i]))], "=+-@\t\r") {
					values[i] = "'" + values[i]
				}
			}
			if err := csvWriter.Write(values); err != nil {
				return err
			}
		} else {
			if count > 0 {
				if _, err := io.WriteString(writer, ","); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(writer, record); err != nil {
				return err
			}
		}
		count++
		return nil
	}
	cursor := ""
	for {
		last, size, err := reportPage(ctx, q, kind, cursor, emit)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			break
		}
		cursor = last
	}
	if csvWriter != nil {
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return 0, err
		}
	} else {
		if _, err := io.WriteString(writer, "]\n"); err != nil {
			return 0, err
		}
	}
	return count, nil
}

func reportPage(ctx context.Context, q *reportdb.Queries, kind integrationsv1.ReportKind, cursor string, emit func(string) error) (string, int, error) {
	after := uuid.Nil
	if cursor != "" && kind != integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE && kind != integrationsv1.ReportKind_REPORT_KIND_FINDINGS {
		var err error
		after, err = uuid.Parse(cursor)
		if err != nil {
			return "", 0, err
		}
	}
	switch kind {
	case integrationsv1.ReportKind_REPORT_KIND_INVENTORY:
		rows, err := q.InventoryReportRows(ctx, after)
		if err != nil {
			return "", 0, err
		}
		for _, row := range rows {
			if err := emit(row.Record); err != nil {
				return "", 0, err
			}
			cursor = row.Cursor
		}
		return cursor, len(rows), nil
	case integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE:
		rows, err := q.ComplianceReportRows(ctx, cursor)
		if err != nil {
			return "", 0, err
		}
		for _, row := range rows {
			if err := emit(row.Record); err != nil {
				return "", 0, err
			}
			cursor = row.Cursor
		}
		return cursor, len(rows), nil
	case integrationsv1.ReportKind_REPORT_KIND_FINDINGS:
		// Finding keys are shared by devices bound to one finding set, so the
		// cursor is the (device, finding) pair.
		afterDevice, afterFinding := uuid.Nil, uuid.Nil
		if cursor != "" {
			device, finding, ok := strings.Cut(cursor, "/")
			var deviceErr, findingErr error
			afterDevice, deviceErr = uuid.Parse(device)
			afterFinding, findingErr = uuid.Parse(finding)
			if !ok || deviceErr != nil || findingErr != nil {
				return "", 0, errors.New("reports: invalid findings cursor")
			}
		}
		rows, err := q.FindingsReportRows(ctx, reportdb.FindingsReportRowsParams{AfterDevice: afterDevice, AfterID: afterFinding})
		if err != nil {
			return "", 0, err
		}
		for _, row := range rows {
			if err := emit(row.Record); err != nil {
				return "", 0, err
			}
			cursor = row.Cursor
		}
		return cursor, len(rows), nil
	default:
		return "", 0, errors.New("reports: unsupported report kind")
	}
}
