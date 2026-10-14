// SPDX-License-Identifier: Apache-2.0

// Package serverops owns privileged server backup, recovery and offline operations.
// It does not grant runtime database DDL or replace execution-authority verification.
package serverops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"

	"lindm/internal/custody"
)

const BackupHealthPath = "/var/lib/lindmd-operations/backup-health.json"

// BackupHealth contains public operational facts, never paths, credentials or
// subprocess diagnostics. Verified means a complete encrypted archive, not a drill.
type BackupHealth struct {
	Identity      BackupIdentity
	LastAttempt   time.Time
	LastCompleted time.Time
	LastFailure   string
	Encrypted     bool
	Verified      bool
	Artifact      string
}

// ReadBackupHealth reads the installer-owned redacted health record. Absence is
// returned to the caller rather than represented as a successful backup.
func ReadBackupHealth(path string) (BackupHealth, error) {
	var health BackupHealth
	data, err := custody.ReadRoot(path, 8192, false)
	if err != nil {
		return health, err
	}
	err = json.Unmarshal(data, &health)
	return health, err
}

// BackupIdentity binds completion evidence to the actual normalized configuration,
// not a mutable filename or a global host slot. Credential contents are excluded.
type BackupIdentity struct{ DeploymentID, PublicURL, DevicePublicURL, ConfigSHA256 string }

func NewBackupIdentity(cfg *configv1.ServerConfig) (BackupIdentity, error) {
	if cfg == nil {
		return BackupIdentity{}, errors.New("operations: backup_configuration_required")
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cfg)
	if err != nil {
		return BackupIdentity{}, err
	}
	digest := sha256.Sum256(data)
	return BackupIdentity{DeploymentID: cfg.GetDeploymentId(), PublicURL: cfg.GetPublicUrl(), DevicePublicURL: cfg.GetDevicePublicUrl(), ConfigSHA256: hex.EncodeToString(digest[:])}, nil
}

func BackupHealthMatches(health BackupHealth, identity BackupIdentity) bool {
	return identity.DeploymentID != "" && identity.ConfigSHA256 != "" && health.Identity == identity
}
