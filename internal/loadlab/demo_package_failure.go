// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/rpcreason"
)

// demoPackageAdmissionWait bounds waiting for the server to admit the next
// package report: it admits one per device every five minutes, measured from
// the device's last package publication.
const demoPackageAdmissionWait = 6 * time.Minute

// packageFailureInBackground seeds the refused package scan state on devices
// after an interactive seed returned, then releases them and the owner session
// it inherited. Stopping the console first cancels it without error; any
// other failure is reported at once and returned from DemoPresence.Stop.
func (s *demoSeed) packageFailureInBackground(presence context.Context, devices []*simulatedDevice) (resultErr error) {
	defer func() {
		for _, d := range devices {
			d.close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, s.owner.Close(cleanup))
	}()
	ctx, cancel := context.WithTimeout(presence, demoEvaluationWait+demoPackageAdmissionWait+2*time.Minute)
	defer cancel()
	for _, d := range devices {
		if err := s.denyPackageScan(ctx, d); err != nil {
			if presence.Err() != nil {
				return nil
			}
			err = fmt.Errorf("background demo refused package scan on %s: %w", d.demo.hostname, err)
			if s.progress.out != nil {
				_, _ = fmt.Fprintf(s.progress.out, "demo seed: %v\n", err)
			}
			return err
		}
	}
	if s.progress.out != nil {
		_, _ = fmt.Fprintf(s.progress.out, "demo seed +%s: background refused package scan state ready\n", time.Since(s.progress.start).Round(time.Second))
	}
	return nil
}

// denyPackageScan leaves d's real-feed findings standing on a device that is
// no longer fully checked. After the server's own evaluation reports an
// affected or accepted finding, the host reports a later package collection its collector
// was refused (PERMISSION_DENIED: the failure the native lifecycle lane
// induces with a systemd InaccessiblePaths drop-in on the package database
// tool). The server keeps the last successful snapshot and its findings and
// marks the device's evaluation package_collection_failed, so /advisories
// shows those advisories as found on a device not fully checked. The seed
// fails rather than omit that state.
func (s *demoSeed) denyPackageScan(ctx context.Context, d *simulatedDevice) error {
	wait, cancel := context.WithTimeout(ctx, demoEvaluationWait)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		// An active exception changes a finding to ACCEPTED, not to absent.
		finding, freshness, err := s.demoFinding(wait, d, true)
		if finding != nil {
			break
		}
		select {
		case <-wait.Done():
			return errors.Join(fmt.Errorf("wait for an affected or accepted finding on %s before its refused package scan (last freshness %v %q): %w", d.demo.hostname, freshness.GetState(), freshness.GetReason(), wait.Err()), err)
		case <-ticker.C:
		}
	}
	if err := s.reportRefusedPackageScan(ctx, d); err != nil {
		return err
	}
	wait, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		freshness, found, err := s.uncheckedExposure(wait, d)
		if err == nil && found {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.Join(fmt.Errorf("wait for advisories found on %s while not fully checked (last freshness %v %q): %w", d.demo.hostname, freshness.GetState(), freshness.GetReason(), wait.Err()), err)
		case <-ticker.C:
		}
	}
}

// reportRefusedPackageScan reports one failed collection through the agent's
// own ReportPackageAttempt protocol, retrying only the definitive
// rate_limited rejection until the server's admission interval has passed.
func (s *demoSeed) reportRefusedPackageScan(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, demoPackageAdmissionWait)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	d.packageSequence++
	for {
		now := stamp()
		response, err := d.client.ReportPackageAttempt(ctx, connect.NewRequest(&devicev1.ReportPackageAttemptRequest{EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, Sequence: d.packageSequence, StartedAt: now, FinishedAt: now, Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, Backend: d.demo.backend}))
		if err == nil {
			if response.Msg.GetAcceptedSequence() != d.packageSequence {
				return fmt.Errorf("%s refused package scan: accepted sequence %d, want %d", d.demo.hostname, response.Msg.GetAcceptedSequence(), d.packageSequence)
			}
			return nil
		}
		if rpcreason.Get(err) != "rate_limited" {
			return fmt.Errorf("report %s refused package scan: %w", d.demo.hostname, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("report %s refused package scan: %w", d.demo.hostname, errors.Join(ctx.Err(), err))
		case <-ticker.C:
		}
	}
}

// uncheckedExposure reports whether the server shows d's findings as UNKNOWN
// because its package scan failed, and counts at least one advisory as found
// on a device not fully checked.
func (s *demoSeed) uncheckedExposure(ctx context.Context, d *simulatedDevice) (*adminv1.AdvisoryFreshness, bool, error) {
	findings, err := s.owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: d.id, PageSize: 1}))
	if err != nil {
		return nil, false, fmt.Errorf("list %s findings: %w", d.demo.hostname, err)
	}
	freshness := findings.Msg.GetFreshness()
	if freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || freshness.GetReason() != "package_collection_failed" || len(findings.Msg.GetFindings()) == 0 {
		return freshness, false, nil
	}
	request := &adminv1.ListAdvisorySummaryRequest{PageSize: 200}
	for {
		summary, err := s.owner.Admin.ListAdvisorySummary(ctx, connect.NewRequest(request))
		if err != nil {
			return freshness, false, fmt.Errorf("list advisory summary: %w", err)
		}
		for _, advisory := range summary.Msg.GetAdvisories() {
			if advisory.GetUnknownDevices() > 0 {
				return freshness, true, nil
			}
		}
		request.PageToken = summary.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return freshness, false, nil
		}
	}
}
