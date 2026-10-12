package reports

import (
	"context"
	"io"

	"google.golang.org/protobuf/encoding/protojson"

	auditv1 "lindm/gen/lindm/audit/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/auditfilter"
	"lindm/internal/reports/reportdb"
)

func writeAuditSelection(ctx context.Context, q *reportdb.Queries, writer io.Writer, job reportdb.ReportArtifact, filter *auditv1.AuditFilter) (uint64, error) {
	selection, err := auditfilter.Normalize(filter)
	if err != nil {
		return 0, err
	}
	params := reportdb.PageAuditSelectionParams{
		SnapshotSequence: job.CapturedHeadSequence,
		ActorID:          selection.ActorID, TargetDeviceID: selection.TargetDeviceID,
		ActionCategory: int16(selection.Filter.GetActionCategory()),
		OccurredFrom:   selection.OccurredFrom, OccurredUntil: selection.OccurredUntil,
		HumanExcludedActions: selection.HumanExcludedActions,
	}
	var count uint64
	for {
		rows, err := q.PageAuditSelection(ctx, params)
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			return count, nil
		}
		for _, row := range rows {
			if count >= uint64(job.AuditMaxEvents) {
				return 0, errReportLimit
			}
			encoded, err := protojson.Marshal(&integrationsv1.AuditChainRecord{
				Sequence: uint64(row.Sequence), PreviousHash: row.PreviousHash, RowHash: row.RowHash, Payload: row.Payload,
			})
			if err != nil {
				return 0, err
			}
			if _, err := writer.Write(append(encoded, '\n')); err != nil {
				return 0, err
			}
			count++
		}
		last := rows[len(rows)-1]
		params.CursorID = &last.EventID
		params.CursorOccurredAt = last.OccurredAt
	}
}
