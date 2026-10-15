// SPDX-License-Identifier: Apache-2.0

package deploylab

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	InitialFindingsWait    = 90 * time.Minute
	SubsequentFindingsWait = 15 * time.Minute
)

// AdvisorySource is an expected registry vendor identity, not feed configuration.
// The lab never supplies it to the server or invokes acquisition operations.
type AdvisorySource struct {
	Distro         string `json:"distro"`
	Release        string `json:"release"`
	SourceURL      string `json:"source_url"`
	PlatformStream string `json:"platform_stream"`
}

type FindingCounts struct {
	Open     uint64 `json:"open"`
	Critical uint64 `json:"critical"`
	High     uint64 `json:"high"`
	Medium   uint64 `json:"medium"`
	Low      uint64 `json:"low"`
	Unrated  uint64 `json:"unrated"`
	Accepted uint64 `json:"accepted"`
}

// FindingsEvidence contains only public facts from real browser-issued reads.
// EvaluatedAt is deliberately absent: the API does not expose that timestamp;
// the native observer must obtain it from the matching durable evaluation.
type FindingsEvidence struct {
	SnapshotID         string         `json:"snapshot_id"`
	InventorySequence  uint64         `json:"inventory_sequence"`
	FeedID             string         `json:"feed_id"`
	Source             AdvisorySource `json:"source"`
	SourceSHA256       string         `json:"source_sha256"`
	FeedCheckedAt      time.Time      `json:"feed_checked_at"`
	FeedExpiresAt      time.Time      `json:"feed_expires_at"`
	AdvisoryCount      uint64         `json:"advisory_count"`
	InventoryAt        time.Time      `json:"inventory_at"`
	InventoryExpiresAt time.Time      `json:"inventory_expires_at"`
	ObservedAt         time.Time      `json:"observed_at"`
	State              string         `json:"state"`
	Reason             string         `json:"reason"`
	UncoveredPackages  uint64         `json:"uncovered_packages"`
	CompleteCoverage   bool           `json:"complete_coverage"`
	Totals             FindingCounts  `json:"totals"`
	RefreshStartedAt   *time.Time     `json:"refresh_started_at,omitempty"`
}

type FindingsWaitEvidence struct {
	LastObservedAt   time.Time `json:"last_observed_at"`
	Reason           string    `json:"reason,omitempty"`
	EvaluationReason string    `json:"evaluation_reason,omitempty"`
	EvaluationState  string    `json:"evaluation_state,omitempty"`
	FeedError        string    `json:"feed_error,omitempty"`
}

// BrowserTimeout preserves short ordinary phases while allowing a real cold
// vendor publication. The extra five minutes cover sign-in and evidence capture.
func BrowserTimeout(request BrowserRequest) time.Duration {
	if request.Phase == "findings" && request.FindingsWaitMilliseconds > 0 && request.FindingsWaitMilliseconds <= InitialFindingsWait.Milliseconds() {
		return time.Duration(request.FindingsWaitMilliseconds)*time.Millisecond + 5*time.Minute
	}
	return 10 * time.Minute
}

func ValidateFindingsEvidence(request BrowserRequest, evidence *BrowserEvidence) error {
	f := evidence.Findings
	if request.DeviceID == "" || evidence.DeviceID != request.DeviceID || request.ManagedActionID == "" || !evidence.PasswordAndPasskey || f == nil {
		return errors.New("deploy: findings did not prove authenticated same-device managed inventory")
	}
	id, err := uuid.Parse(f.SnapshotID)
	digest, digestErr := hex.DecodeString(f.SourceSHA256)
	if err != nil || id.String() != f.SnapshotID || f.InventorySequence == 0 || f.FeedID == "" || digestErr != nil || len(digest) != 32 || hex.EncodeToString(digest) != f.SourceSHA256 || f.AdvisoryCount == 0 {
		return errors.New("deploy: findings did not identify a real published vendor feed and inventory snapshot")
	}
	matched := false
	for _, source := range request.AdvisorySources {
		matched = matched || source == f.Source
	}
	if !matched {
		return errors.New("deploy: findings source does not match the platform registry vendor identity")
	}
	if f.ObservedAt.IsZero() || f.FeedCheckedAt.IsZero() || f.InventoryAt.IsZero() || f.FeedCheckedAt.After(f.ObservedAt) || f.InventoryAt.After(f.ObservedAt) || !f.FeedExpiresAt.After(f.ObservedAt) || !f.InventoryExpiresAt.After(f.ObservedAt) {
		return errors.New("deploy: findings feed or inventory is missing or stale")
	}
	switch f.State {
	case "ADVISORY_FINDING_STATE_AFFECTED", "ADVISORY_FINDING_STATE_ACCEPTED", "ADVISORY_FINDING_STATE_CLEAR":
		if !f.CompleteCoverage || f.UncoveredPackages != 0 {
			return errors.New("deploy: findings hid partial vendor coverage")
		}
	case "ADVISORY_FINDING_STATE_PARTIAL":
		if f.CompleteCoverage || f.UncoveredPackages == 0 || f.Reason == "" {
			return errors.New("deploy: partial findings did not retain their coverage limitation")
		}
	default:
		return errors.New("deploy: findings evaluation is unknown or not completed")
	}
	if f.Totals.Open != f.Totals.Critical+f.Totals.High+f.Totals.Medium+f.Totals.Low+f.Totals.Unrated {
		return errors.New("deploy: findings totals are inconsistent")
	}
	return nil
}
