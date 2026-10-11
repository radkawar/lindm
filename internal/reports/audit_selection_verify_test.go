package reports

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
)

func TestAuditSelectionVerifierRejectsNoncanonicalFilterTimestamps(t *testing.T) {
	manifest := &integrationsv1.ReportManifest{
		ChainId:          "5b1dcd2c-b257-4da4-a16e-57458454eefe",
		Format:           integrationsv1.ReportFormat_REPORT_FORMAT_JSONL,
		CapturedHeadHash: make([]byte, sha256.Size),
		AuditFilter:      &auditv1.AuditFilter{},
	}
	if err := verifyAuditSelection(bytes.NewReader(nil), manifest); err != nil {
		t.Fatalf("valid empty selection: %v", err)
	}
	for name, stamp := range map[string]*timestamppb.Timestamp{
		"negative nanos": {Nanos: -1},
		"excess nanos":   {Nanos: 1000000000},
	} {
		t.Run(name, func(t *testing.T) {
			for _, filter := range []*auditv1.AuditFilter{
				{OccurredFrom: stamp},
				{OccurredUntil: stamp},
			} {
				manifest.AuditFilter = filter
				if err := verifyAuditSelection(bytes.NewReader(nil), manifest); err == nil {
					t.Fatal("noncanonical timestamp accepted in selection manifest")
				}
			}
		})
	}
}
