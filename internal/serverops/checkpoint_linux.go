// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/config"
	"lindm/internal/trust"
)

// CheckpointOptions is an explicitly offline custody operation. The checkpoint
// signer attests to a complete externally fenced snapshot, not simply possession
// of an encryption identity. Root keys must never be installed on the server.
type CheckpointOptions struct {
	Archive, SecurityArchive, IdentityFile, RootFile, Output string
	IdentityPassphrase                                       []byte
	Custody                                                  CustodySigningOptions
	RecoveryEpoch                                            uint64
	ConfirmFenced                                            bool
}

func SignCheckpoint(ctx context.Context, options CheckpointOptions) (err error) {
	if !options.ConfirmFenced || options.RecoveryEpoch == 0 {
		return errors.New("operations: offline_fenced_checkpoint_required")
	}
	if options.Custody.ExportFile == "" && options.Custody.IdentityFile == "" {
		return errors.New("operations: encrypted_checkpoint_custody_required")
	}
	if err = privateOutputDirectory(filepath.Dir(options.Output)); err != nil {
		return err
	}
	stage, err := offlineStage("lindmd-checkpoint-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	originalDir := filepath.Join(stage, "original")
	currentDir := filepath.Join(stage, "current")
	if err = os.Mkdir(originalDir, 0700); err != nil {
		return err
	}
	if err = os.Mkdir(currentDir, 0700); err != nil {
		return err
	}
	original, err := decryptArchive(ctx, options.Archive, options.IdentityFile, options.IdentityPassphrase, originalDir)
	if err != nil {
		return err
	}
	current, err := decryptArchive(ctx, options.SecurityArchive, options.IdentityFile, options.IdentityPassphrase, currentDir)
	if err != nil {
		return err
	}
	if current.FencedAt.IsZero() || current.CapturedAt.Before(original.CapturedAt) || original.DeploymentID != current.DeploymentID || original.PublicURL != current.PublicURL || original.DevicePublicURL != current.DevicePublicURL {
		return errors.New("operations: incomplete_security_checkpoint")
	}
	_, document, err := archivedConfiguration(current, currentDir)
	if err != nil {
		return err
	}
	resolved, err := document.Resolve()
	if err != nil {
		return err
	}
	defer resolved.HTTPClient.CloseIdleConnections()
	root, err := readCheckpointRoot(options.RootFile)
	if err != nil {
		return err
	}
	if root.GetDeploymentId() != current.DeploymentID {
		return errors.New("operations: checkpoint_deployment_mismatch")
	}
	rootDigest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		return err
	}
	if current.ExecutionRootSHA256 != hex.EncodeToString(rootDigest[:]) || options.RecoveryEpoch <= current.MinimumRecoveryEpoch {
		return errors.New("operations: checkpoint_root_pin_or_epoch_mismatch")
	}
	currentDigest, err := digestBytes(options.SecurityArchive)
	if err != nil {
		return err
	}
	originalDigest, err := digestBytes(options.Archive)
	if err != nil {
		return err
	}
	checkpoint := &agentv1.ServerRecoveryCheckpoint{DeploymentId: current.DeploymentID, CapturedAt: timestamppb.New(current.FencedAt), ArchiveSha256: currentDigest, OriginalArchiveSha256: originalDigest, RecoveryEpoch: options.RecoveryEpoch, PublicUrl: current.PublicURL, DevicePublicUrl: current.DevicePublicURL, PackageVersion: current.Version, ExecutionRootSha256: rootDigest[:]}
	authority, err := trust.New()
	if err != nil {
		return err
	}
	var keys []ed25519.PrivateKey
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	keys, err = LoadCustodySigningKeys(ctx, options.Custody, root)
	if err != nil {
		return err
	}
	envelope, err := authority.Sign(ctx, checkpoint, keys...)
	if err != nil {
		return err
	}
	if err = verifyCheckpoint(ctx, envelope, checkpoint, root); err != nil {
		return err
	}
	file, err := os.OpenFile(options.Output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(envelope)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func readCheckpointRoot(path string) (*agentv1.ExecutionRoot, error) {
	data, err := readOperationFile(path, 65536, false)
	if err != nil {
		return nil, err
	}
	root := new(agentv1.ExecutionRoot)
	if err = protojson.Unmarshal(data, root); err != nil {
		return nil, errors.New("operations: invalid_pinned_execution_root")
	}
	if err = protovalidate.Validate(root); err != nil {
		return nil, errors.New("operations: invalid_pinned_execution_root")
	}
	if !root.GetNotBefore().AsTime().Before(time.Now()) || !root.GetExpiresAt().AsTime().After(time.Now()) {
		return nil, errors.New("operations: pinned_root_expired")
	}
	return root, nil
}

func verifyCheckpoint(ctx context.Context, envelope []byte, checkpoint *agentv1.ServerRecoveryCheckpoint, root *agentv1.ExecutionRoot) error {
	var keys []ed25519.PublicKey
	for _, key := range root.GetKeys() {
		keys = append(keys, ed25519.PublicKey(key.GetPublicKey()))
	}
	authority, err := trust.New()
	if err != nil {
		return err
	}
	return authority.Verify(ctx, envelope, checkpoint, int(root.GetThreshold()), keys...)
}

func archivedConfiguration(manifest archiveManifest, directory string) (*resourceSet, *config.Document, error) {
	r := &resourceSet{files: map[string]string{}, owners: map[uint32]bool{0: true, uint32(os.Geteuid()): true}, base: filepath.Dir(manifest.ConfigPath), stage: directory, archived: true}
	for _, file := range manifest.Files {
		r.files[file.Path] = filepath.Join(directory, "files", strings.TrimPrefix(file.Path, "/"))
	}
	path, ok := r.files[manifest.ConfigPath]
	if !ok {
		return nil, nil, errors.New("operations: archived_configuration_missing")
	}
	original, err := config.Load(path)
	if err != nil {
		return nil, nil, errors.New("operations: invalid_archived_configuration")
	}
	r.config = original.Proto
	if r.config.GetDeploymentId() != manifest.DeploymentID || r.config.GetPublicUrl() != manifest.PublicURL || r.config.GetDevicePublicUrl() != manifest.DevicePublicURL {
		return nil, nil, errors.New("operations: archive_identity_mismatch")
	}
	if err = r.validateArchivedIntegrationKey(manifest); err != nil {
		return nil, nil, err
	}
	document, err := r.validate(manifest.ConfigPath)
	return r, document, err
}
