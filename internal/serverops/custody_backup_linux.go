// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Private lab configurations never collect a different native deployment's
// global custody or state tree. Native encrypted objects have a finite inventory,
// authenticated by its root-owned deployment/origin creation record.
func (r *resourceSet) backupCustody() error {
	if r.base != "/etc/lindm" {
		return nil
	}
	record, err := readCustodyRecord(RecoveryCustodyHealthPath)
	if err != nil {
		return err
	}
	if record.GetDeploymentId() != r.config.GetDeploymentId() || record.GetPublicUrl() != r.config.GetPublicUrl() || record.GetDevicePublicUrl() != r.config.GetDevicePublicUrl() {
		return errors.New("operations: foreign_recovery_custody")
	}
	if err = r.copy(RecoveryCustodyHealthPath); err != nil {
		return err
	}
	for _, artifact := range record.GetArtifacts() {
		path := filepath.Join(recoveryCustodyDirectory, artifact.GetName())
		if err = r.copy(path); err != nil {
			return err
		}
		digest, err := digestFile(r.files[path])
		if err != nil {
			return err
		}
		expected := hex.EncodeToString(artifact.GetSha256())
		if digest != expected {
			return errors.New("operations: custody_artifact_digest_mismatch")
		}
		prefix, err := r.read(path, 1<<20)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(prefix, []byte("age-encryption.org/v1\n")) {
			return errors.New("operations: invalid_custody_ciphertext")
		}
	}
	if !record.GetExternal() {
		if _, err = os.Lstat(RecoveryCustodyBundlePath); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		if err = r.copy(RecoveryCustodyBundlePath); err != nil {
			return err
		}
		digest, err := digestFile(r.files[RecoveryCustodyBundlePath])
		if err != nil {
			return err
		}
		if digest != hex.EncodeToString(record.GetIdentityBundleSha256()) {
			return errors.New("operations: custody_bundle_digest_mismatch")
		}
	}
	return nil
}
