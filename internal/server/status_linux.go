// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/config"
	"lindm/internal/server/serverdb"
	"lindm/internal/serverops"
)

const (
	statusUnknown   = adminv1.ServerStatusState_SERVER_STATUS_STATE_UNKNOWN
	statusOK        = adminv1.ServerStatusState_SERVER_STATUS_STATE_OK
	statusAttention = adminv1.ServerStatusState_SERVER_STATUS_STATE_ATTENTION
	statusFailed    = adminv1.ServerStatusState_SERVER_STATUS_STATE_FAILED
	statusInactive  = adminv1.ServerStatusState_SERVER_STATUS_STATE_INACTIVE
)

// Instance scope distinguishes disk and certificate state across replicas without
// leaking hostnames to metrics or public health responses.
func statusInstance(resources *config.Resources) (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("identify server status instance: %w", err)
	}
	digest := sha256.Sum256([]byte(host + "\x00" + config.Address(resources.Proto.GetAdminListener())))
	return fmt.Sprintf("%x", digest[:16]), nil
}

func operationalProbe(pool, adminPool *pgxpool.Pool, resources *config.Resources, native *nativeRepositories) statusProbe {
	instructions := enrollmentInstructions(resources, native)
	repositoryCheckedAt := time.Now()
	backupIdentity, backupIdentityErr := serverops.NewBackupIdentity(resources.Proto)
	// Keep only the public policy, not pool configuration copies or URL secrets.
	databasePrefer := resources.Database.ConnConfig.ChannelBinding == "prefer"
	adminDatabasePrefer := resources.AdminDatabase.ConnConfig.ChannelBinding == "prefer"
	databasePing, adminDatabasePing := pool.Ping, adminPool.Ping
	return func(ctx context.Context, now time.Time) []*adminv1.ServerStatusCheck {
		checks := []*adminv1.ServerStatusCheck{
			databaseStatus(ctx, databasePing, "database", databasePrefer, now),
			databaseStatus(ctx, adminDatabasePing, "admin_database", adminDatabasePrefer, now),
			certificateStatus("https_certificate", resources.AdminServerCertificate.Leaf, now),
			consoleCAStatus(resources, now),
			certificateStatus("device_https_certificate", resources.ServerCertificate.Leaf, now),
			certificateStatus("device_ca", resources.DeviceCACertificate, now),
			backupStatus(now, backupIdentity, func() (serverops.BackupHealth, error) {
				if backupIdentityErr != nil {
					return serverops.BackupHealth{}, backupIdentityErr
				}
				return serverops.ReadBackupHealth(serverops.BackupHealthPath)
			}),
			releaseFeedStatus(now, buildinfo.Current().Version, func() (serverops.ReleaseFeedHealth, error) {
				return serverops.ReadReleaseFeedHealth(serverops.ReleaseFeedHealthPath)
			}),
		}
		repository := statusCheck("agent_repository", statusUnknown, "Agent installation readiness is unavailable.", "Inspect installation readiness in Settings.", now)
		if instructions.GetReadiness() != nil {
			if instructions.GetReadiness().GetReady() {
				repository.State = statusOK
				repository.Summary = "Startup checks verified signed agent packages for the listed platforms."
				repository.NextAction = "Review platform coverage before enrolling devices."
			} else {
				repository.State = statusFailed
				repository.Summary = "This server cannot install agents on the listed platforms."
				repository.NextAction = "Inspect installation readiness in Settings."
			}
		}
		// Immutable repositories are verified at startup, not reverified by this
		// polling loop. Preserve that evidence time rather than claiming a new hash.
		repository.EvidenceAt = timestamppb.New(repositoryCheckedAt)
		checks = append(checks, repository, feedStatus(ctx, pool, now), diskStatus(now), queueStatus(ctx, pool, now))
		return checks
	}
}

func warnDatabaseChannelBinding(logger *slog.Logger, resources *config.Resources) {
	databasePrefer := resources.Database.ConnConfig.ChannelBinding == "prefer"
	adminDatabasePrefer := resources.AdminDatabase.ConnConfig.ChannelBinding == "prefer"
	if databasePrefer || adminDatabasePrefer {
		logger.Warn("SCRAM-PLUS channel binding may downgrade",
			"channel_binding", "prefer",
			"database_downgrade_allowed", databasePrefer,
			"admin_database_downgrade_allowed", adminDatabasePrefer,
			"next_action", "Enable SCRAM-PLUS and set channel_binding=require; pooler prefer is an explicit operator choice.")
	}
}

func databaseStatus(ctx context.Context, ping func(context.Context) error, component string, prefer bool, now time.Time) *adminv1.ServerStatusCheck {
	check := statusCheck(component, statusOK, "The verified database connection answered.", "This connection needs no action.", now)
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ping(probe); err != nil {
		check.State = statusFailed
		check.Summary = "The database connection did not answer."
		check.NextAction = "Check PostgreSQL availability and the server service journal."
	} else {
		check.EvidenceAt = timestamppb.New(now)
		if prefer {
			check.State = statusAttention
			check.Summary = "The database answered, but SCRAM-PLUS channel binding may downgrade."
			check.NextAction = "Enable SCRAM-PLUS and set channel_binding=require. Keep prefer only as an explicit choice for a pooler."
		}
	}
	return check
}

func certificateStatus(component string, cert *x509.Certificate, now time.Time) *adminv1.ServerStatusCheck {
	check := statusCheck(component, statusUnknown, "Certificate expiry is unavailable.", "Inspect the configured certificate before reopening traffic.", now)
	if cert == nil {
		return check
	}
	check.ExpiresAt = timestamppb.New(cert.NotAfter)
	check.EvidenceAt = timestamppb.New(now)
	check.State = statusOK
	check.Summary = "The loaded certificate is within its validity period."
	check.NextAction = "Plan certificate renewal before its expiry."
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		check.State = statusFailed
		check.Summary = "The loaded certificate is outside its validity period."
		check.NextAction = "Renew the certificate and restart the server under a reviewed maintenance plan."
	} else if cert.NotAfter.Sub(now) <= 30*24*time.Hour {
		check.State = statusAttention
		check.Summary = "The loaded certificate expires within 30 days."
		check.NextAction = "Renew the certificate before its expiry."
	}
	return check
}

func consoleCAStatus(resources *config.Resources, now time.Time) *adminv1.ServerStatusCheck {
	check := certificateStatus("console_ca", resources.AdminCACertificate, now)
	if resources.AdminCACertificate == nil && resources.Proto.GetAdminCaFile() == "" {
		check.State = statusInactive
		check.Summary = "No private console certificate authority is configured."
		check.NextAction = "A publicly trusted console certificate needs no custom CA import. Manual shared-TLS deployments use their configured issuer."
		return check
	}
	check.NextAction += " If the console uses a private CA, import the console CA printed by the installer, not the device CA. Turnkey installs use /etc/lindm/console-ca.crt."
	if cert := resources.AdminCACertificate; cert != nil {
		digest := sha256.Sum256(cert.Raw)
		check.Detail = fmt.Sprintf("Console CA public certificate SHA-256: %x. Turnkey browser trust uses ECDSA P-256/SHA-256; Go device transport stays Ed25519 with separate device trust.", digest)
	}
	return check
}

func backupStatus(now time.Time, expected serverops.BackupIdentity, read func() (serverops.BackupHealth, error)) *adminv1.ServerStatusCheck {
	check := statusCheck("backups", statusUnknown, "No readable backup completion record exists.", "Inspect the backup timer and run an encrypted backup.", now)
	health, err := read()
	if err != nil {
		return check
	}
	if !serverops.BackupHealthMatches(health, expected) {
		check.Summary = "No backup completion record matches this server configuration."
		check.NextAction = "Run an encrypted backup for this deployment, then refresh."
		return check
	}
	if !health.LastCompleted.IsZero() {
		check.EvidenceAt = timestamppb.New(health.LastCompleted)
	}
	if health.LastFailure != "" {
		check.State = statusFailed
		check.Summary = "The latest backup attempt failed."
		check.NextAction = "Inspect the backup service journal and repeat the backup."
		return check
	}
	if health.LastCompleted.IsZero() {
		return check
	}
	if !health.Encrypted || !health.Verified {
		check.State = statusFailed
		check.Summary = "The backup lacks confirmed encryption or archive completion."
		check.NextAction = "Complete an encrypted backup before relying on recovery."
		return check
	}
	check.State = statusOK
	check.Summary = "The latest encrypted backup archive completed; restore remains unproven."
	check.NextAction = "Keep an off-host copy and test a fenced restore."
	if health.LastCompleted.After(now.Add(time.Minute)) || now.Sub(health.LastCompleted) > time.Hour {
		check.State = statusAttention
		check.Summary = "The backup completion record is stale or ahead of the server clock."
		check.NextAction = "Check the backup timer and clock, then run a backup."
	}
	return check
}

func feedStatus(ctx context.Context, pool *pgxpool.Pool, now time.Time) *adminv1.ServerStatusCheck {
	check := statusCheck("advisory_feeds", statusUnknown, "The server could not read advisory feed freshness.", "Inspect advisory feeds and the server service journal.", now)
	row, err := serverdb.New(pool).ServerFeedHealth(ctx)
	if err != nil {
		return check
	}
	if row.EvidenceAt.Valid {
		check.EvidenceAt = timestamppb.New(row.EvidenceAt.Time)
	}
	if row.ExpiresAt.Valid {
		check.ExpiresAt = timestamppb.New(row.ExpiresAt.Time)
	}
	check.Detail = fmt.Sprintf("%d enabled; %d failed; %d unchecked; %d expired", row.Enabled, row.Failed, row.Unknown, row.Stale)
	switch {
	case row.Enabled == 0:
		check.State = statusInactive
		check.Summary = "This server has no enabled advisory feeds."
		check.NextAction = "Enable feeds for managed platforms or import an offline bundle."
	case row.Failed > 0:
		check.State = statusFailed
		check.Summary = "An advisory feed refresh failed."
	case row.Unknown > 0:
		check.Summary = "An enabled advisory feed has no freshness evidence."
	case row.Stale > 0:
		check.State = statusAttention
		check.Summary = "An advisory feed has expired."
	case row.EvidenceAt.Valid:
		check.State = statusOK
		check.Summary = "Enabled advisory feeds have current acquisition evidence."
		check.NextAction = "Review advisory coverage; fresh feeds do not prove full coverage."
	}
	return check
}

func diskStatus(now time.Time) *adminv1.ServerStatusCheck {
	check := statusCheck("disk", statusUnknown, "The server could not inspect its state storage.", "Check the server state volume and available space.", now)
	var stat unix.Statfs_t
	if err := unix.Statfs("/var/lib/lindmd", &stat); err != nil {
		return check
	}
	check.EvidenceAt = timestamppb.New(now)
	check.State = statusOK
	check.Summary = "Server state storage has available space and file slots."
	check.NextAction = "Monitor this volume separately from PostgreSQL and external backup storage."
	available := stat.Bavail * uint64(stat.Bsize)
	check.Detail = fmt.Sprintf("%d available bytes; %d available file slots", available, stat.Ffree)
	if stat.Blocks == 0 || stat.Files == 0 {
		check.State = statusUnknown
		check.Summary = "Server state storage did not report complete capacity evidence."
	} else if available < 1<<30 || float64(stat.Bavail)/float64(stat.Blocks) < 0.1 || float64(stat.Ffree)/float64(stat.Files) < 0.05 {
		check.State = statusAttention
		check.Summary = "Server state storage is running low on space or file slots."
		check.NextAction = "Expand the state volume or review retention without removing active data."
	}
	return check
}

func queueStatus(ctx context.Context, pool *pgxpool.Pool, now time.Time) *adminv1.ServerStatusCheck {
	check := statusCheck("job_queue", statusUnknown, "The server could not inspect delivery and report work.", "Inspect integrations and the server service journal.", now)
	row, err := serverdb.New(pool).ServerQueueHealth(ctx)
	if err != nil {
		return check
	}
	check.EvidenceAt = timestamppb.New(now)
	check.State = statusOK
	check.Summary = "Delivery and report work has no observed overdue backlog."
	check.NextAction = "Review integration deliveries for remote confirmation."
	check.Detail = fmt.Sprintf("%d pending deliveries; %d failed deliveries", row.Pending, row.Failed)
	if row.Failed > 0 {
		check.State = statusFailed
		check.Summary = "Integration deliveries need failure review."
		check.NextAction = "Review failed deliveries in Integrations before replaying them."
	} else if (row.OldestDueAt.Valid && now.Sub(row.OldestDueAt.Time) > 10*time.Minute) || (row.ReportDueAt.Valid && now.Sub(row.ReportDueAt.Time) > 10*time.Minute) {
		check.State = statusAttention
		check.Summary = "Delivery or report work is more than ten minutes overdue."
		check.NextAction = "Inspect worker logs and integration deliveries."
	}
	return check
}
