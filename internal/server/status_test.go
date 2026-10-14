// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/serverops"
)

func TestStatusObservationMissingStaleAndIsolation(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	monitor, err := newStatusMonitor(nil, "", false, func(context.Context, time.Time) []*adminv1.ServerStatusCheck {
		return []*adminv1.ServerStatusCheck{statusCheck("database", statusOK, "connection-secret", "path-secret", now)}
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	initial := monitor.snapshot()
	if initial.ObservedAt != nil || len(initial.Checks) != len(statusComponents) {
		t.Fatal("missing initial evidence was fabricated")
	}
	for _, check := range initial.Checks {
		if check.State != statusUnknown || check.ObservedAt != nil {
			t.Fatal("unchecked component claims evidence")
		}
	}
	monitor.collect(t.Context())
	one := monitor.snapshot()
	one.Checks[0].Summary = "changed by caller"
	if monitor.snapshot().Checks[0].Summary != "connection-secret" {
		t.Fatal("caller mutated cached evidence")
	}
	recorder := httptest.NewRecorder()
	monitor.metrics(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	if strings.Contains(body, "secret") || !strings.Contains(body, `lindm_server_status_state{component="database"} 2`) {
		t.Fatalf("unsafe or missing metric: %s", body)
	}
	now = now.Add(3 * time.Minute)
	stale := monitor.snapshot()
	if stale.Checks[0].State != statusUnknown || stale.ObservedAt.AsTime().Equal(now) {
		t.Fatal("stale monitor masquerades as a current successful check")
	}
}

func TestCertificateStatusExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want adminv1.ServerStatusState
	}{
		{"missing", nil, statusUnknown},
		{"current", &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(31 * 24 * time.Hour)}, statusOK},
		{"renew", &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}, statusAttention},
		{"expired", &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now}, statusFailed},
		{"future", &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}, statusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := certificateStatus("https_certificate", tc.cert, now)
			if check.State != tc.want || check.NextAction == "" {
				t.Fatalf("state/action: %v", check)
			}
			if tc.cert != nil && !check.ExpiresAt.AsTime().Equal(tc.cert.NotAfter) {
				t.Fatal("certificate expiry changed")
			}
		})
	}
}

func TestBackupEvidenceNeverClaimsRestore(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	identity := serverops.BackupIdentity{DeploymentID: "11111111-1111-4111-8111-111111111111", PublicURL: "https://control.invalid", DevicePublicURL: "https://devices.invalid", ConfigSHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name   string
		health serverops.BackupHealth
		err    error
		want   adminv1.ServerStatusState
	}{
		{"unreadable", serverops.BackupHealth{}, errors.New("private-path-and-password"), statusUnknown},
		{"empty", serverops.BackupHealth{}, nil, statusUnknown},
		{"failed", serverops.BackupHealth{LastFailure: "backup_failed"}, nil, statusFailed},
		{"unencrypted", serverops.BackupHealth{LastCompleted: now, Verified: true}, nil, statusFailed},
		{"unverified", serverops.BackupHealth{LastCompleted: now, Encrypted: true}, nil, statusFailed},
		{"complete", serverops.BackupHealth{LastCompleted: now.Add(-time.Hour), Encrypted: true, Verified: true}, nil, statusOK},
		{"stale", serverops.BackupHealth{LastCompleted: now.Add(-2 * time.Hour), Encrypted: true, Verified: true}, nil, statusAttention},
		{"future", serverops.BackupHealth{LastCompleted: now.Add(time.Hour), Encrypted: true, Verified: true}, nil, statusAttention},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.health.Identity = identity
			check := backupStatus(now, identity, func() (serverops.BackupHealth, error) { return tc.health, tc.err })
			if check.State != tc.want || strings.Contains(check.Summary, "password") || strings.Contains(check.Detail, "password") {
				t.Fatalf("bad backup projection: %v", check)
			}
			if tc.want == statusOK && !strings.Contains(check.Summary, "restore remains unproven") {
				t.Fatal("archive completion falsely claims a restore drill")
			}
			if !tc.health.LastCompleted.IsZero() && !check.EvidenceAt.AsTime().Equal(tc.health.LastCompleted) {
				t.Fatal("backup evidence time advanced on polling")
			}
		})
	}
}

func TestBackupStatusRejectsForeignAndUnboundEvidence(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	expected := serverops.BackupIdentity{DeploymentID: "11111111-1111-4111-8111-111111111111", PublicURL: "https://control.invalid", DevicePublicURL: "https://devices.invalid", ConfigSHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name   string
		change func(*serverops.BackupIdentity)
	}{
		{"legacy unbound", func(i *serverops.BackupIdentity) { *i = serverops.BackupIdentity{} }},
		{"different deployment", func(i *serverops.BackupIdentity) { i.DeploymentID = "22222222-2222-4222-8222-222222222222" }},
		{"different console origin", func(i *serverops.BackupIdentity) { i.PublicURL = "https://other-control.invalid" }},
		{"different device origin", func(i *serverops.BackupIdentity) { i.DevicePublicURL = "https://other-devices.invalid" }},
		{"different configuration", func(i *serverops.BackupIdentity) { i.ConfigSHA256 = strings.Repeat("b", 64) }},
		{"missing configuration", func(i *serverops.BackupIdentity) { i.ConfigSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := serverops.BackupHealth{Identity: expected, LastCompleted: now, Encrypted: true, Verified: true, Artifact: "other-site-secret.tar.age"}
			tc.change(&health.Identity)
			for _, failure := range []string{"", "other-site-private-failure"} {
				health.LastFailure = failure
				check := backupStatus(now, expected, func() (serverops.BackupHealth, error) { return health, nil })
				if check.State != statusUnknown || check.EvidenceAt != nil || check.ExpiresAt != nil || check.Detail != "" {
					t.Fatalf("foreign backup evidence appeared in this deployment: %v", check)
				}
				if check.NextAction == "" || strings.Contains(check.Summary, "other-site") {
					t.Fatal("identity mismatch exposed foreign data or omitted recovery action")
				}
			}
		})
	}
}
