// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
	"lindm/internal/serverops"
)

// The status/confirmation domain reads a fresh caller-owned creation snapshot;
// it never writes privileged metadata or exposes an encrypted/private key file.
func newRecoveryCustodyReader(resources *config.Resources) func() (*adminv1.RecoveryKeyCustody, error) {
	expected, identityErr := serverops.NewBackupIdentity(resources.Proto)
	return func() (*adminv1.RecoveryKeyCustody, error) {
		if identityErr != nil {
			return nil, identityErr
		}
		health, err := serverops.ReadRecoveryCustodyHealth(serverops.RecoveryCustodyHealthPath)
		if err != nil {
			return nil, err
		}
		return recoveryCustodyProjection(health, expected)
	}
}

func recoveryCustodyProjection(health serverops.RecoveryCustodyHealth, expected serverops.BackupIdentity) (*adminv1.RecoveryKeyCustody, error) {
	if !serverops.RecoveryCustodyHealthMatches(health, expected) {
		return nil, errors.New("recovery custody record does not match this configuration")
	}
	custody := &adminv1.RecoveryKeyCustody{RecordedAt: timestamppb.New(health.CreatedAt)}
	if health.External && !health.RequiresExport && len(health.Exports) == 0 {
		custody.State = adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_EXTERNAL_RECIPIENTS
		return custody, nil
	}
	if !health.RequiresExport || health.External || len(health.Exports) == 0 {
		return nil, errors.New("recovery custody required-export evidence is incomplete")
	}
	custody.State = adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING
	custody.ConfirmationDigest = health.ConfirmationSHA256
	custody.Exports = make([]*adminv1.RecoveryKeyCustodyExport, len(health.Exports))
	for i, export := range health.Exports {
		var kind adminv1.RecoveryKeyCustodyExportKind
		switch export.Kind {
		case "canonical_authority":
			kind = adminv1.RecoveryKeyCustodyExportKind_RECOVERY_KEY_CUSTODY_EXPORT_KIND_CANONICAL_AUTHORITY
		case "fresh_database":
			kind = adminv1.RecoveryKeyCustodyExportKind_RECOVERY_KEY_CUSTODY_EXPORT_KIND_FRESH_DATABASE
		default:
			return nil, errors.New("recovery custody export kind is unavailable")
		}
		custody.Exports[i] = &adminv1.RecoveryKeyCustodyExport{Kind: kind, Path: export.Path, Sha256: export.SHA256, LocalPresent: export.Present}
	}
	return custody, nil
}
