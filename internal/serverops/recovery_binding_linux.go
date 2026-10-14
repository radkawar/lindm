// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"encoding/hex"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Only a separately authenticated complete checkpoint is authoritative. The
// earlier archive is a validated reference, never an invented security rollforward.
func validateRecoveryBinding(checkpoint *agentv1.ServerRecoveryCheckpoint, pinnedRoot []byte, original, current archiveManifest, originalHash, currentHash []byte, installedVersion string) error {
	if checkpoint == nil || !bytes.Equal(checkpoint.GetOriginalArchiveSha256(), originalHash) || !bytes.Equal(checkpoint.GetArchiveSha256(), currentHash) || !bytes.Equal(checkpoint.GetExecutionRootSha256(), pinnedRoot) {
		return errors.New("operations: recovery_checkpoint_digest_mismatch")
	}
	if current.FencedAt.IsZero() || !current.FencedAt.Equal(current.CapturedAt) || !checkpoint.GetCapturedAt().AsTime().Equal(current.FencedAt) || current.CapturedAt.Before(original.CapturedAt) {
		return errors.New("operations: recovery_checkpoint_fence_mismatch")
	}
	if current.Version != checkpoint.GetPackageVersion() || current.Version != installedVersion {
		return errors.New("operations: recovery_checkpoint_package_mismatch")
	}
	if checkpoint.GetDeploymentId() != current.DeploymentID || original.DeploymentID != current.DeploymentID || checkpoint.GetPublicUrl() != current.PublicURL || checkpoint.GetDevicePublicUrl() != current.DevicePublicURL || original.PublicURL != current.PublicURL || original.DevicePublicURL != current.DevicePublicURL {
		return errors.New("operations: recovery_checkpoint_deployment_or_origin_mismatch")
	}
	if current.ExecutionRootSHA256 != hex.EncodeToString(pinnedRoot) || checkpoint.GetRecoveryEpoch() <= current.MinimumRecoveryEpoch {
		return errors.New("operations: recovery_checkpoint_root_or_epoch_mismatch")
	}
	return nil
}
