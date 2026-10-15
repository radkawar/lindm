// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"lindm/internal/deploylab"
	"lindm/internal/platform"
)

const deployInitialFindingsMeasurement = "signed_installer_invocation_to_first_observed_qualifying_managed_inventory_evaluation_including_install_and_enrollment"
const deployLaterFindingsMeasurement = "stage_management_start_to_first_observed_qualifying_managed_inventory_evaluation"

// VMDeployFindingsProof joins a visible authenticated browser assessment to the
// exact native durable evaluation. SQL is observation only, never feed setup,
// refresh, inventory submission or an alternative management authorization path.
type VMDeployFindingsProof struct {
	Stage                           string                      `json:"stage"`
	StartedAt                       time.Time                   `json:"started_at"`
	ObservedAt                      time.Time                   `json:"observed_at"`
	ElapsedMilliseconds             int64                       `json:"elapsed_milliseconds"`
	DurationMeaning                 string                      `json:"duration_meaning"`
	DeviceID                        string                      `json:"device_id"`
	ManagedActionID                 string                      `json:"managed_action_id"`
	ManagedSnapshotID               string                      `json:"managed_snapshot_id"`
	SnapshotID                      string                      `json:"snapshot_id"`
	InventorySequence               uint64                      `json:"inventory_sequence"`
	PackageCount                    uint64                      `json:"package_count"`
	FeedID                          string                      `json:"feed_id"`
	SourceSHA256                    string                      `json:"source_sha256"`
	EvaluatedAt                     time.Time                   `json:"evaluated_at"`
	EvaluationState                 string                      `json:"evaluation_state"`
	RefreshToEvaluationMilliseconds *int64                      `json:"observed_refresh_start_to_evaluation_milliseconds,omitempty"`
	Findings                        *deploylab.FindingsEvidence `json:"findings"`
}

func deployAdvisoryExpectations(release *platform.Release, imageVersion, architecture string) ([]deploylab.AdvisorySource, error) {
	var sources []deploylab.AdvisorySource
	for _, feed := range release.Advisory.Feeds {
		source, err := vmAdvisoryFeedSource(release, imageVersion, architecture, feed, "observation-only")
		if err != nil {
			return nil, err
		}
		sources = append(sources, deploylab.AdvisorySource{Distro: source.Distro, Release: source.Release, SourceURL: source.Url, PlatformStream: source.PlatformStream})
	}
	if len(sources) == 0 {
		return nil, errors.New("deploy: registry_vendor_advisory_source_missing")
	}
	return sources, nil
}

func observeDeployFindings(ctx context.Context, guest *guestVM, request deploylab.BrowserRequest, browser *deploylab.BrowserEvidence, stage string, started time.Time) (*VMDeployFindingsProof, error) {
	if err := deploylab.ValidateBrowserEvidence(request, browser); err != nil {
		return nil, err
	}
	for _, value := range []string{request.DeviceID, request.ManagedActionID, browser.Findings.SnapshotID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return nil, errors.New("deploy: invalid_native_findings_identity")
		}
	}
	// The local peer connection reads a single nonsecret record inside a read-only
	// transaction. Separate installed/upgrade/restore gates still prove runtime
	// verify-full SCRAM-PLUS and denied migration/DDL authority.
	sql := fmt.Sprintf(`BEGIN READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL TIME ZONE 'UTC';
SELECT json_build_object(
 'device_id',d.id,'managed_action_id',a.id,'managed_snapshot_id',ms.id,
 'snapshot_id',s.id,'inventory_sequence',s.sequence,'package_count',s.package_count,
 'feed_id',e.feed_id,'source_sha256',encode(f.source_sha256,'hex'),
 'evaluated_at',e.evaluated_at,'evaluation_state',e.state)
FROM devices d
JOIN enrollment_generations g ON g.id=d.current_generation_id
JOIN package_snapshots s ON s.id=g.current_snapshot_id AND s.generation_id=g.id AND s.device_id=d.id
JOIN package_attempts pa ON pa.generation_id=g.id AND pa.snapshot_id=s.id AND pa.status=1
JOIN host_observations h ON h.generation_id=g.id
JOIN advisory_evaluations e ON e.device_id=d.id AND e.snapshot_id=s.id AND e.host_received_at=d.host_received_at
JOIN advisory_feeds f ON f.id=e.feed_id AND f.revision=e.feed_revision
JOIN device_actions a ON a.id='%s'::uuid AND a.device_id=d.id AND a.generation_id=g.id
JOIN package_snapshots ms ON ms.generation_id=g.id AND ms.device_id=d.id AND ms.sequence=a.inventory_package_sequence
WHERE d.id='%s'::uuid AND s.id='%s'::uuid AND d.state='active' AND g.state='active'
 AND s.state='committed' AND s.package_count>0 AND s.sequence>=ms.sequence
 AND a.capability='device.refresh-inventory.v1' AND a.closed_reason='result' AND NOT a.outcome_unknown
 AND a.start_authorized_at IS NOT NULL AND a.inventory_host_sequence>0
 AND a.inventory_host_received_at>=a.start_authorized_at AND h.sequence>=a.inventory_host_sequence
 AND ms.state IN ('committed','superseded') AND ms.committed_at>=a.start_authorized_at
 AND f.enabled AND f.complete_snapshot AND f.error='' AND f.advisory_count>0
 AND f.expires_at>clock_timestamp() AND e.expires_at>clock_timestamp()
 AND e.state IN ('evaluated','partial');
COMMIT;
`, request.ManagedActionID, request.DeviceID, browser.Findings.SnapshotID)
	command := "runuser -u postgres -- psql -X -Atq -v ON_ERROR_STOP=1 -h " + nativeQuote(guest.release.Server.PostgreSQLSocketDirectory) + " -p " + nativeQuote(guest.release.Server.PostgreSQLPort) + " -d lindm"
	body, err := serverGuestCommand(ctx, guest, "observe published managed inventory advisory evaluation", command, strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	defer clear(body)
	proof := &VMDeployFindingsProof{Stage: stage, StartedAt: started, ObservedAt: browser.Findings.ObservedAt, Findings: browser.Findings, DurationMeaning: deployLaterFindingsMeasurement}
	if stage == "installed" {
		proof.DurationMeaning = deployInitialFindingsMeasurement
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(proof); err != nil {
		return nil, errors.New("deploy: matching_native_findings_evaluation_missing")
	}
	proof.ElapsedMilliseconds = proof.ObservedAt.Sub(started).Milliseconds()
	if refresh := proof.Findings.RefreshStartedAt; refresh != nil && !proof.EvaluatedAt.Before(*refresh) {
		elapsed := proof.EvaluatedAt.Sub(*refresh).Milliseconds()
		proof.RefreshToEvaluationMilliseconds = &elapsed
	}
	if err := validateDeployFindingsProof(request, proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func validateDeployFindingsProof(request deploylab.BrowserRequest, proof *VMDeployFindingsProof) error {
	if proof == nil || proof.Findings == nil || proof.DeviceID != request.DeviceID || proof.ManagedActionID != request.ManagedActionID || proof.ManagedSnapshotID == "" || proof.SnapshotID != proof.Findings.SnapshotID || proof.InventorySequence != proof.Findings.InventorySequence || proof.PackageCount == 0 || proof.FeedID != proof.Findings.FeedID || proof.SourceSHA256 != proof.Findings.SourceSHA256 || proof.EvaluatedAt.IsZero() || proof.EvaluatedAt.Before(proof.Findings.InventoryAt) || proof.StartedAt.IsZero() || !proof.ObservedAt.Equal(proof.Findings.ObservedAt) || proof.ElapsedMilliseconds < 0 || proof.ElapsedMilliseconds != proof.ObservedAt.Sub(proof.StartedAt).Milliseconds() {
		return errors.New("deploy: native_findings_evaluation_does_not_match_browser_managed_inventory")
	}
	switch proof.Findings.State {
	case "ADVISORY_FINDING_STATE_AFFECTED", "ADVISORY_FINDING_STATE_ACCEPTED", "ADVISORY_FINDING_STATE_CLEAR", "ADVISORY_FINDING_STATE_PARTIAL":
	default:
		return errors.New("deploy: native_findings_evaluation_is_unknown")
	}
	partial := proof.Findings.State == "ADVISORY_FINDING_STATE_PARTIAL"
	if (partial && proof.EvaluationState != "partial") || (!partial && proof.EvaluationState != "evaluated") {
		return errors.New("deploy: native_findings_coverage_state_mismatch")
	}
	return nil
}

func validateDeployFindingsStages(deviceID string, proofs []*VMDeployFindingsProof) error {
	if len(proofs) != 3 {
		return errors.New("deploy: installed_upgraded_restored_findings_proof_missing")
	}
	for index, stage := range []string{"installed", "upgraded", "restored"} {
		proof := proofs[index]
		if proof == nil || proof.Stage != stage || proof.DeviceID != deviceID {
			return errors.New("deploy: original_device_findings_lifecycle_mismatch")
		}
		request := deploylab.BrowserRequest{DeviceID: deviceID, ManagedActionID: proof.ManagedActionID}
		if err := validateDeployFindingsProof(request, proof); err != nil {
			return err
		}
		for _, earlier := range proofs[:index] {
			if proof.ManagedActionID == earlier.ManagedActionID || !proof.EvaluatedAt.After(earlier.EvaluatedAt) {
				return errors.New("deploy: restored_or_upgraded_findings_reused_old_managed_work")
			}
		}
	}
	return nil
}
