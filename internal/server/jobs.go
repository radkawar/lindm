package server

import (
	"lindm/internal/advisory"
	"lindm/internal/device"
	"lindm/internal/integrations"
	"lindm/internal/jobs"
	"lindm/internal/reports"
)

// Advisory lock keys of exclusive jobs are a deployment-wide contract between
// concurrently running releases during a rolling upgrade. Never renumber or
// reuse a key; retire it with its job.
const (
	jobKeySnapshotCleanup     int64 = 0x6c696e646d000001
	jobKeyAdvisoryMaintenance int64 = 0x6c696e646d000002
	jobKeyAdvisoryEvaluation  int64 = 0x6c696e646d000003
	jobKeyComplianceDeadlines int64 = 0x6c696e646d000004
)

// backgroundJobs is the complete inventory of control-plane background work.
// Exclusive jobs run on one instance; replicated jobs fence row leases. Request
// handlers own no background goroutines.
func backgroundJobs(devices *device.Service, advisories *advisory.Service, deliveries *integrations.Service, reporting *reports.Service) []jobs.Job {
	inventory := []jobs.Job{
		{Name: "snapshot-cleanup", Key: jobKeySnapshotCleanup, Mode: jobs.Exclusive, Run: devices.RunSnapshotCleanup},
		{Name: "advisory-maintenance", Key: jobKeyAdvisoryMaintenance, Mode: jobs.Exclusive, Run: advisories.RunMaintenance},
		{Name: "advisory-evaluation", Key: jobKeyAdvisoryEvaluation, Mode: jobs.Exclusive, Run: advisories.RunEvaluations},
		// Each instance keeps its own read-only unrestricted fleet aggregate.
		{Name: "fleet-summary", Mode: jobs.Replicated, Run: devices.RunFleetSummary},
	}
	if deliveries != nil {
		inventory = append(inventory,
			jobs.Job{Name: "compliance-deadlines", Key: jobKeyComplianceDeadlines, Mode: jobs.Exclusive, Run: deliveries.RunComplianceDeadlines},
			jobs.Job{Name: "integration-deliveries", Mode: jobs.Replicated, Run: deliveries.RunDeliveries},
		)
	}
	if reporting != nil {
		inventory = append(inventory, jobs.Job{Name: "reports", Mode: jobs.Replicated, Run: reporting.Run})
	}
	return inventory
}
