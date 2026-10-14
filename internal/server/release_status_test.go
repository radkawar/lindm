// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"lindm/internal/serverops"
)

func TestOfflineReleaseStatusUsesAuthenticatedCurrentComparison(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		change      func(*serverops.ReleaseFeedHealth)
		readError   error
		wantState   int32
		wantSummary string
	}{
		{name: "unreadable", readError: errors.New("private-release-path-password"), wantState: int32(statusUnknown)},
		{name: "unverified", change: func(h *serverops.ReleaseFeedHealth) { h.Verified = false }, wantState: int32(statusUnknown)},
		{name: "missing import", change: func(h *serverops.ReleaseFeedHealth) { h.ImportedAt = time.Time{} }, wantState: int32(statusUnknown)},
		{name: "different installed binary", change: func(h *serverops.ReleaseFeedHealth) { h.InstalledVersion = "0.9.0" }, wantState: int32(statusUnknown), wantSummary: "no current installed-release comparison"},
		{name: "expired", change: func(h *serverops.ReleaseFeedHealth) { h.ExpiresAt = now }, wantState: int32(statusAttention), wantSummary: "has expired"},
		{name: "new release", wantState: int32(statusAttention), wantSummary: "newer server release"},
		{name: "security update", change: func(h *serverops.ReleaseFeedHealth) {
			h.SecurityUpdate = true
			h.AdvisoryIDs = []string{"CVE-2026-12345"}
		}, wantState: int32(statusAttention), wantSummary: "server security update"},
		{name: "new bundle without notice", change: func(h *serverops.ReleaseFeedHealth) { h.ExpiresAt = time.Time{} }, wantState: int32(statusAttention), wantSummary: "security-notice freshness is unknown"},
		{name: "same release without notice", change: func(h *serverops.ReleaseFeedHealth) {
			h.AvailableVersion = h.InstalledVersion
			h.UpdateAvailable = false
			h.ExpiresAt = time.Time{}
		}, wantState: int32(statusUnknown), wantSummary: "no current server security notice"},
		{name: "current within imported notice", change: func(h *serverops.ReleaseFeedHealth) {
			h.AvailableVersion = h.InstalledVersion
			h.UpdateAvailable = false
		}, wantState: int32(statusOK), wantSummary: "This authenticated import offers no newer release"},
		{name: "clock ahead", change: func(h *serverops.ReleaseFeedHealth) { h.ImportedAt = now.Add(2 * time.Minute) }, wantState: int32(statusUnknown)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := serverops.ReleaseFeedHealth{ImportedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), InstalledVersion: "1.0.0", AvailableVersion: "1.1.0", UpdateAvailable: true, Verified: true}
			if tc.change != nil {
				tc.change(&health)
			}
			check := releaseFeedStatus(now, "1.0.0", func() (serverops.ReleaseFeedHealth, error) { return health, tc.readError })
			if int32(check.State) != tc.wantState || !strings.Contains(check.Summary, tc.wantSummary) || check.NextAction == "" {
				t.Fatalf("incorrect release evidence: %v", check)
			}
			if strings.Contains(check.Summary, "password") || strings.Contains(check.Detail, "password") {
				t.Fatal("release reader diagnostic leaked")
			}
			if health.Verified && tc.readError == nil && !health.ImportedAt.IsZero() && !check.EvidenceAt.AsTime().Equal(health.ImportedAt) {
				t.Fatal("polling advanced import evidence time")
			}
		})
	}
}

func TestReleaseAlertIdentityIgnoresPollingButChangesWithNotice(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	check := statusCheck("server_release_feed", statusAttention, "Security update available", "Review the signed notice", now)
	check.Detail = "Installed release: 1.0.0; imported release: 1.1.0; security update: true; advisories: CVE-2026-12345"
	first := statusEvidenceKey(check)
	check.ObservedAt = timestamppb.New(now.Add(time.Minute))
	check.EvidenceAt = timestamppb.New(now.Add(time.Minute))
	if statusEvidenceKey(check) != first || len(first) != 64 {
		t.Fatal("polling changed a release notification identity")
	}
	check.Detail += ", CVE-2026-12346"
	if statusEvidenceKey(check) == first {
		t.Fatal("a distinct security notice would remain quiet until the old reminder deadline")
	}
	check.Component = "backups"
	if statusEvidenceKey(check) != "" {
		t.Fatal("ordinary check details changed notification cadence")
	}
}
