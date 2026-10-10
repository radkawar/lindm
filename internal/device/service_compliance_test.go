package device

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
)

func TestServiceComplianceFreshnessBoundary(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	head := devicedb.ResourceAssignment{ReconcileIntervalSeconds: 300}
	for _, test := range []struct {
		name       string
		age        time.Duration
		remediated bool
		want       adminv1.ResourceCompliance
	}{
		{"fresh read-only", time.Minute, false, adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT},
		{"fresh remediation", time.Minute, true, adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED},
		{"just before stale", 10*time.Minute - time.Nanosecond, false, adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT},
		{"stale boundary", 10 * time.Minute, false, adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE},
		{"stale remediation", 10 * time.Minute, true, adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := devicedb.ResourceAssignmentResource{LastVerifiedAt: timestamptz(now.Add(-test.age)), DriftRemediated: test.remediated}
			state := &adminv1.ResourceState{Disposition: adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS}
			if got := serviceResourceCompliance(row, state, head, now); got != test.want {
				t.Fatalf("compliance=%s want=%s", got, test.want)
			}
			state.LatestAction = &adminv1.ServiceActionSummary{StartAuthorizedAt: timestamppb.New(now)}
			if got := serviceResourceCompliance(row, state, head, now); got != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION {
				t.Fatalf("known drift masked by previous evidence: %s", got)
			}
		})
	}
}
