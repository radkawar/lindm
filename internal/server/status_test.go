// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
	"lindm/internal/serverops"
)

func TestDatabaseStatusChannelBinding(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, component := range []string{"database", "admin_database"} {
		for _, tc := range []struct {
			name   string
			prefer bool
			err    error
			want   adminv1.ServerStatusState
		}{
			{"require", false, nil, statusOK},
			{"prefer", true, nil, statusAttention},
			{"require failed", false, errors.New("private-driver-message"), statusFailed},
			{"prefer failed", true, errors.New("private-driver-message"), statusFailed},
		} {
			t.Run(component+"/"+tc.name, func(t *testing.T) {
				calls := 0
				check := databaseStatus(t.Context(), func(ctx context.Context) error {
					calls++
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 2*time.Second {
						t.Fatal("database probe has no bounded deadline")
					}
					return tc.err
				}, component, tc.prefer, now)
				if calls != 1 || check.Component != component || check.State != tc.want || !check.ObservedAt.AsTime().Equal(now) {
					t.Fatalf("incorrect database observation: %v", check)
				}
				if tc.err != nil {
					if check.EvidenceAt != nil || check.Summary != "The database connection did not answer." || strings.Contains(check.NextAction, "prefer") {
						t.Fatalf("binding warning concealed connection failure: %v", check)
					}
				} else {
					if !check.EvidenceAt.AsTime().Equal(now) {
						t.Fatal("successful connection lost its evidence time")
					}
					if tc.prefer {
						if !strings.Contains(check.Summary, "SCRAM-PLUS channel binding may downgrade") ||
							!strings.Contains(check.NextAction, "channel_binding=require") ||
							!strings.Contains(check.NextAction, "explicit choice for a pooler") {
							t.Fatalf("missing downgrade warning or operator action: %v", check)
						}
					} else if strings.Contains(check.Summary, "downgrade") || check.NextAction != "This connection needs no action." {
						t.Fatalf("strict binding produced a warning: %v", check)
					}
				}
				if strings.Contains(check.String(), "private-driver-message") {
					t.Fatal("status exposed the driver error")
				}
			})
		}
	}
}

func TestDatabaseBindingWarningPreservesUnknownAndPersists(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	probe := func(ctx context.Context, at time.Time) []*adminv1.ServerStatusCheck {
		checks := make([]*adminv1.ServerStatusCheck, 0, 2)
		for _, component := range []string{"database", "admin_database"} {
			checks = append(checks, databaseStatus(ctx, func(context.Context) error { return nil }, component, true, at))
		}
		return checks
	}
	monitor, err := newStatusMonitor(nil, "", false, probe, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	assertState := func(want adminv1.ServerStatusState) {
		t.Helper()
		for _, component := range []string{"database", "admin_database"} {
			found := false
			for _, check := range monitor.snapshot().Checks {
				if check.Component == component {
					found = true
					if check.State != want {
						t.Fatalf("%s: state %v, want %v", component, check.State, want)
					}
				}
			}
			if !found {
				t.Fatalf("missing %s observation", component)
			}
		}
	}
	assertState(statusUnknown)
	monitor.collect(t.Context())
	assertState(statusAttention)
	now = now.Add(time.Minute)
	monitor.collect(t.Context())
	assertState(statusAttention)
	now = now.Add(3 * time.Minute)
	assertState(statusUnknown)
	monitor.collect(t.Context())
	assertState(statusAttention)
}

func TestDatabaseChannelBindingStartupWarningIsSecretSafe(t *testing.T) {
	for _, tc := range []struct {
		name          string
		database      string
		adminDatabase string
	}{
		{"strict", "require", "require"},
		{"database prefer", "prefer", "require"},
		{"admin database prefer", "require", "prefer"},
		{"both prefer", "prefer", "prefer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			databaseConfig := func(binding string) *pgxpool.Config {
				t.Helper()
				cfg, err := pgxpool.ParseConfig("postgresql://private-user:private-password@private-host/private-database?channel_binding=" + binding)
				if err != nil {
					t.Fatal("parse test database configuration")
				}
				return cfg
			}
			resources := &config.Resources{
				Database:      databaseConfig(tc.database),
				AdminDatabase: databaseConfig(tc.adminDatabase),
			}
			var buffer bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buffer, nil))
			warnDatabaseChannelBinding(logger, resources)
			wantDatabase := tc.database == "prefer"
			wantAdminDatabase := tc.adminDatabase == "prefer"
			if !wantDatabase && !wantAdminDatabase {
				if buffer.Len() != 0 {
					t.Fatal("strict binding emitted a startup warning")
				}
				return
			}
			logged := buffer.String()
			if strings.Count(logged, "\n") != 1 {
				t.Fatal("startup emitted more than one downgrade warning")
			}
			for _, forbidden := range []string{"private-", "postgresql://", "password", "sslkey"} {
				if strings.Contains(logged, forbidden) {
					t.Fatal("startup warning exposed database connection details")
				}
			}
			var record map[string]any
			if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if len(record) != 7 || record["level"] != "WARN" ||
				record["msg"] != "SCRAM-PLUS channel binding may downgrade" ||
				record["channel_binding"] != "prefer" ||
				record["database_downgrade_allowed"] != wantDatabase ||
				record["admin_database_downgrade_allowed"] != wantAdminDatabase ||
				record["next_action"] != "Enable SCRAM-PLUS and set channel_binding=require; pooler prefer is an explicit operator choice." {
				t.Fatal("startup warning omitted the safe binding policy or operator action")
			}
		})
	}
}

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
