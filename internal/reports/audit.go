// SPDX-License-Identifier: Apache-2.0

package reports

import (
	"bytes"
	"context"
	"crypto/sha256"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/auditfilter"
	"lindm/internal/reports/reportdb"
	"lindm/internal/rpcreason"
)

func createAuditArtifact(ctx context.Context, q *reportdb.Queries, request *integrationsv1.CreateAuditExportRequest, actor uuid.UUID) (reportdb.ReportArtifact, error) {
	head, err := q.GetAuditHead(ctx)
	if err != nil {
		return reportdb.ReportArtifact{}, err
	}
	if request.GetFilter() != nil {
		selection, err := auditfilter.Normalize(request.GetFilter())
		if err != nil {
			return reportdb.ReportArtifact{}, rpcreason.Error(connect.CodeInvalidArgument, "invalid_argument")
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(selection.Filter)
		if err != nil {
			return reportdb.ReportArtifact{}, err
		}
		// An empty protobuf is a present all-events selection, not SQL NULL.
		if encoded == nil {
			encoded = []byte{}
		}
		return q.CreateAuditSelectionArtifact(ctx, reportdb.CreateAuditSelectionArtifactParams{
			ID: uuid.New(), ActorID: actor, RetentionDays: int32(request.GetRetentionDays()),
			CapturedHeadSequence: head.Sequence, CapturedHeadHash: head.RowHash, ChainID: head.ChainID,
			AuditFilter: encoded, AuditMaxEvents: int32(request.GetMaxEvents()),
		})
	}
	after := int64(request.GetAfterSequence())
	if after > head.Sequence {
		return reportdb.ReportArtifact{}, rpcreason.Error(connect.CodeFailedPrecondition, "audit_checkpoint_ahead")
	}
	previous := make([]byte, sha256.Size)
	if after > 0 {
		row, err := q.GetAuditRow(ctx, after)
		if err != nil {
			return reportdb.ReportArtifact{}, err
		}
		previous = row.RowHash
	}
	if !bytes.Equal(previous, request.GetAfterHash()) {
		return reportdb.ReportArtifact{}, rpcreason.Error(connect.CodeFailedPrecondition, "audit_checkpoint_mismatch")
	}
	final := head.Sequence
	if final-after > int64(request.GetMaxEvents()) {
		final = after + int64(request.GetMaxEvents())
	}
	finalHash := previous
	if final > after {
		row, err := q.GetAuditRow(ctx, final)
		if err != nil {
			return reportdb.ReportArtifact{}, err
		}
		finalHash = row.RowHash
	}
	return q.CreateAuditArtifact(ctx, reportdb.CreateAuditArtifactParams{ID: uuid.New(), ActorID: actor,
		RetentionDays: int32(request.GetRetentionDays()), AfterSequence: after, AfterHash: previous,
		FinalSequence: final, FinalHash: finalHash, CapturedHeadSequence: head.Sequence, CapturedHeadHash: head.RowHash, ChainID: head.ChainID})
}
