package server

import (
	"lindm/internal/advisory"
	"lindm/internal/device"
	"lindm/internal/integrations"
	"lindm/internal/jobs"
	"lindm/internal/reports"
	"lindm/internal/targeting"
)

// Advisory lock keys of exclusive jobs are a deployment-wide contract between
// concurrently running releases during a rolling upgrade. Never renumber or
// reuse a key; retire it with its job. Retired: 0x6c696e646d000003 (exclusive
// advisory evaluation, now replicated with row claims).
const (
	jobKeySnapshotCleanup     int64 = 0x6c696e646d000001
	jobKeyAdvisoryMaintenance int64 = 0x6c696e646d000002
	jobKeyComplianceDeadlines int64 = 0x6c696e646d000004
	jobKeyRolloutPromoter     int64 = 0x6c696e646d000005
)

// backgroundJobs is the complete inventory of control-plane background work.
// Exclusive jobs run on one instance; replicated jobs fence row leases. Request
// handlers own no background goroutines.
func backgroundJobs(devices, consoleDevices *device.Service, advisories *advisory.Service, deliveries *integrations.Service, reporting *reports.Service, promoter *targeting.Promoter) []jobs.Job {
	inventory := []jobs.Job{
		{Name: "snapshot-cleanup", Key: jobKeySnapshotCleanup, Mode: jobs.Exclusive, Run: devices.RunSnapshotCleanup},
		{Name: "advisory-maintenance", Key: jobKeyAdvisoryMaintenance, Mode: jobs.Exclusive, Run: advisories.RunMaintenance},
		// Every instance claims disjoint batches of pending devices.
		{Name: "advisory-evaluation", Mode: jobs.Replicated, Run: advisories.RunEvaluations},
		{Name: "rollout-promoter", Key: jobKeyRolloutPromoter, Mode: jobs.Exclusive, Run: promoter.Run},
		// Each instance keeps its own read-only unrestricted fleet aggregate,
		// read on the console pool that serves it.
		{Name: "fleet-summary", Mode: jobs.Replicated, Run: consoleDevices.RunFleetSummary},
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
