// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/custody"
)

type supportFacts struct {
	CreatedAt          time.Time
	Version            string
	OS                 string
	Architecture       string
	ConfigurationValid bool
	DatabaseAvailable  bool
	SchemaCompatible   bool
	RecoveryHold       bool
	Counts             map[string]int64
	Backup             supportBackup
	Release            supportRelease
}
type supportBackup struct {
	Known                                         bool
	LastCompleted                                 time.Time
	Encrypted, ArchiveComplete, LastAttemptFailed bool
}
type supportRelease struct {
	Known                              bool
	InstalledVersion, AvailableVersion string
	UpdateAvailable, SecurityUpdate    bool
	ExpiresAt                          time.Time
}

// Support writes a root-only tar containing structured allowlisted facts and an
// explicit omission manifest. It never reads journals, environment variables,
// SQL row text, user reasons, webhook URLs, setup secrets or private backup keys.
// Failed diagnostics remain unavailable, not successful empty reports.
func Support(ctx context.Context, configPath, outputPath string) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("operations: root_required")
	}
	if err = custody.PrivateDirectory(filepath.Dir(outputPath)); err != nil {
		return err
	}
	facts := supportFacts{CreatedAt: time.Now().UTC(), Version: supportVersion(buildinfo.Current().Version), OS: runtime.GOOS, Architecture: runtime.GOARCH, Counts: map[string]int64{}}
	stage, stageErr := offlineStage("lindmd-support-*")
	if stageErr == nil {
		defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
		if original, readErr := newResources(configPath, stage); readErr == nil {
			if expected, identityErr := NewBackupIdentity(original.config); identityErr == nil {
				if health, healthErr := ReadBackupHealth(BackupHealthPath); healthErr == nil && BackupHealthMatches(health, expected) {
					facts.Backup = safeSupportBackup(health)
				}
			}
		}
	}
	if health, readErr := ReadReleaseFeedHealth(ReleaseFeedHealthPath); readErr == nil {
		facts.Release = safeSupportRelease(health)
	}
	document, cleanup, configErr := StageRuntimeDatabaseConfig(configPath)
	if configErr == nil {
		defer func() { err = errors.Join(err, cleanup()) }()
		facts.ConfigurationValid = true
		configuration, databaseErr := document.Database()
		if databaseErr == nil {
			pool, poolErr := pgxpool.NewWithConfig(ctx, configuration)
			if poolErr == nil {
				defer pool.Close()
				if pingErr := pool.Ping(ctx); pingErr == nil {
					facts.DatabaseAvailable = true
					facts.SchemaCompatible = db.Check(ctx, pool) == nil
					if facts.SchemaCompatible {
						collectSupportCounts(ctx, pool, &facts)
					}
				}
			}
		}
	}
	return writeSupport(outputPath, facts)
}

func collectSupportCounts(ctx context.Context, pool *pgxpool.Pool, facts *supportFacts) {
	queries := map[string]string{
		"devices":                  "SELECT count(*) FROM devices",
		"revoked_devices":          "SELECT count(*) FROM devices WHERE state='revoked'",
		"held_devices":             "SELECT count(*) FROM devices WHERE state='recovery_hold'",
		"pending_device_actions":   "SELECT count(*) FROM device_actions WHERE closed_at IS NULL",
		"unknown_device_actions":   "SELECT count(*) FROM device_actions WHERE outcome_unknown",
		"pending_resource_actions": "SELECT count(*) FROM resource_actions WHERE closed_at IS NULL",
		"active_sessions":          "SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND absolute_expires_at>clock_timestamp()",
	}
	for name, query := range queries {
		var count int64
		if err := pool.QueryRow(ctx, query).Scan(&count); err == nil {
			facts.Counts[name] = count
		}
	}
	if err := pool.QueryRow(ctx, "SELECT hold FROM server_recovery_state WHERE singleton").Scan(&facts.RecoveryHold); err != nil {
		facts.RecoveryHold = true
	}
}

func safeSupportBackup(health BackupHealth) supportBackup {
	return supportBackup{Known: true, LastCompleted: health.LastCompleted, Encrypted: health.Encrypted, ArchiveComplete: health.Verified, LastAttemptFailed: health.LastFailure != ""}
}
func supportVersion(version string) string {
	if _, err := compareVersion(version, version); err != nil {
		return "unavailable"
	}
	return version
}
func safeSupportRelease(health ReleaseFeedHealth) supportRelease {
	return supportRelease{Known: health.Verified, InstalledVersion: supportVersion(health.InstalledVersion), AvailableVersion: supportVersion(health.AvailableVersion), UpdateAvailable: health.UpdateAvailable, SecurityUpdate: health.SecurityUpdate, ExpiresAt: health.ExpiresAt}
}

func writeSupport(path string, facts supportFacts) (err error) {
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	archive := tar.NewWriter(&boundedWriter{output, 1 << 20})
	manifest := struct {
		Format            int
		Included, Omitted []string
	}{Format: 1, Included: []string{"Build version and architecture", "Classified configuration/database compatibility", "Aggregate device/action/session counts", "Public backup completion and signed release discovery facts"}, Omitted: []string{"Logs and raw subprocess diagnostics", "Configuration files and database URLs", "All environment variables", "Private keys, passwords, cookies and token values", "Setup codes, enrollment secrets and authentication challenges", "Operator backup identities and all backup contents", "Hostnames, record identifiers and individual database rows", "Operator reasons, webhook URLs and other untrusted free text"}}
	for _, entry := range []struct {
		name  string
		value any
	}{{"manifest.json", manifest}, {"support.json", facts}} {
		name, value := entry.name, entry.value
		data, jsonErr := json.Marshal(value)
		if jsonErr != nil {
			return errors.Join(jsonErr, archive.Close(), output.Close())
		}
		if err = archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			return errors.Join(err, archive.Close(), output.Close())
		}
		if _, err = archive.Write(data); err != nil {
			return errors.Join(err, archive.Close(), output.Close())
		}
	}
	return errors.Join(archive.Close(), output.Sync(), output.Close())
}
