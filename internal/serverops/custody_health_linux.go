// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/custody"
)

const RecoveryCustodyHealthPath = "/var/lib/lindmd-operations/recovery-custody.json"
const RecoveryCustodyBundlePath = "/var/lib/lindmd-operations/recovery-custody.age"
const recoveryCustodyDirectory = "/etc/lindm/offline"

var recoveryArtifactNames = []string{"root-key-1.age", "root-key-2.age", "root-key-3.age", "sealed-pki-ca.age"}

type RecoveryCustodyExport struct {
	Kind, Path, SHA256 string
	Present            bool
}

type RecoveryCustodyHealth struct {
	DeploymentID, PublicURL, DevicePublicURL, ConfigSHA256, ConfirmationSHA256 string
	CreatedAt                                                                  time.Time
	External, RequiresExport                                                   bool
	Exports                                                                    []RecoveryCustodyExport
}

func RecoveryCustodyHealthMatches(health RecoveryCustodyHealth, expected BackupIdentity) bool {
	return expected.DeploymentID != "" && expected.ConfigSHA256 != "" && health.DeploymentID == expected.DeploymentID && health.PublicURL == expected.PublicURL && health.DevicePublicURL == expected.DevicePublicURL && health.ConfigSHA256 == expected.ConfigSHA256
}

func readCustodyRecord(path string) (*agentv1.ServerRecoveryCustody, error) {
	data, err := custody.ReadRoot(path, 16<<10, false)
	if err != nil {
		return nil, err
	}
	record := new(agentv1.ServerRecoveryCustody)
	if err = protojson.Unmarshal(data, record); err != nil {
		return nil, errors.New("operations: invalid_custody_metadata")
	}
	if err = protovalidate.Validate(record); err != nil {
		return nil, errors.New("operations: invalid_custody_metadata")
	}
	if err = validateArtifactInventory(record.GetArtifacts(), false); err != nil {
		return nil, err
	}
	return record, nil
}

// ReadRecoveryCustodyHealth validates a present cipher bundle's actual digest.
// Moving it off host does not erase the immutable creation record or falsely
// imply external custody: the owner acknowledgement still binds its exact digest.
func ReadRecoveryCustodyHealth(path string) (health RecoveryCustodyHealth, err error) {
	record, err := readCustodyRecord(path)
	if err != nil {
		return health, err
	}
	health = RecoveryCustodyHealth{DeploymentID: record.GetDeploymentId(), PublicURL: record.GetPublicUrl(), DevicePublicURL: record.GetDevicePublicUrl(), ConfigSHA256: hex.EncodeToString(record.GetConfigSha256()), CreatedAt: record.GetCreatedAt().AsTime()}
	requirements := custodyExportSet(record)
	serialized, err := (proto.MarshalOptions{Deterministic: true}).Marshal(requirements)
	if err != nil {
		return RecoveryCustodyHealth{}, err
	}
	digest := sha256.Sum256(serialized)
	health.ConfirmationSHA256 = hex.EncodeToString(digest[:])
	health.RequiresExport = len(requirements.GetExports()) > 0
	health.External = !health.RequiresExport
	for _, required := range requirements.GetExports() {
		kind := "canonical_authority"
		if required.GetKind() == agentv1.ServerRecoveryExportKind_SERVER_RECOVERY_EXPORT_KIND_FRESH_DATABASE {
			kind = "fresh_database"
		}
		entry := RecoveryCustodyExport{Kind: kind, Path: required.GetPath(), SHA256: hex.EncodeToString(required.GetSha256())}
		actualPath := entry.Path
		if filepath.Dir(path) != filepath.Dir(RecoveryCustodyHealthPath) {
			relative, relativeErr := filepath.Rel(filepath.Dir(RecoveryCustodyHealthPath), entry.Path)
			if relativeErr != nil {
				return RecoveryCustodyHealth{}, relativeErr
			}
			actualPath = filepath.Join(filepath.Dir(path), relative)
		}
		actual, readErr := custodyCipherDigest(actualPath, 8<<20)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return RecoveryCustodyHealth{}, readErr
		}
		if readErr == nil {
			if !bytes.Equal(actual, required.GetSha256()) {
				return RecoveryCustodyHealth{}, errors.New("operations: custody_export_digest_mismatch")
			}
			entry.Present = true
		}
		health.Exports = append(health.Exports, entry)
	}
	return health, nil
}

func custodyExportSet(record *agentv1.ServerRecoveryCustody) *agentv1.ServerRecoveryExportSet {
	set := &agentv1.ServerRecoveryExportSet{DeploymentId: record.GetDeploymentId(), PublicUrl: record.GetPublicUrl(), DevicePublicUrl: record.GetDevicePublicUrl(), ConfigSha256: record.GetConfigSha256()}
	if !record.GetExternal() {
		set.Exports = append(set.Exports, &agentv1.ServerRecoveryRequiredExport{Kind: agentv1.ServerRecoveryExportKind_SERVER_RECOVERY_EXPORT_KIND_CANONICAL_AUTHORITY, Path: RecoveryCustodyBundlePath, Sha256: record.GetIdentityBundleSha256()})
	}
	if database := record.GetDatabaseCustody(); database != nil && !database.GetExternal() {
		set.Exports = append(set.Exports, &agentv1.ServerRecoveryRequiredExport{Kind: agentv1.ServerRecoveryExportKind_SERVER_RECOVERY_EXPORT_KIND_FRESH_DATABASE, Path: database.GetIdentityBundlePath(), Sha256: database.GetIdentityBundleSha256()})
	}
	return set
}

// PublishRecoveryCustodyHealth is called by the privileged installer only. There
// is no runtime RPC or privileged broker that can publish this root-owned record.
func PublishRecoveryCustodyHealth(cfg *configv1.ServerConfig, external bool) error {
	if os.Geteuid() != 0 {
		return errors.New("operations: root_required")
	}
	identity, err := NewBackupIdentity(cfg)
	if err != nil {
		return err
	}
	configDigest, err := hex.DecodeString(identity.ConfigSHA256)
	if err != nil {
		return err
	}
	record := &agentv1.ServerRecoveryCustody{DeploymentId: identity.DeploymentID, PublicUrl: identity.PublicURL, DevicePublicUrl: identity.DevicePublicURL, ConfigSha256: configDigest, CreatedAt: timestamppb.New(time.Now().UTC()), External: external}
	for index, name := range recoveryArtifactNames {
		digest, err := custodyCipherDigest(filepath.Join(recoveryCustodyDirectory, name), 1<<20)
		if err != nil {
			return err
		}
		custodianIndex := uint32(index + 1)
		if index == 3 {
			custodianIndex = 1
		}
		record.Artifacts = append(record.Artifacts, &agentv1.ServerRecoveryCustodyArtifact{Name: name, CustodianIndex: custodianIndex, Sha256: digest})
	}
	if !external {
		record.IdentityBundleSha256, err = custodyCipherDigest(RecoveryCustodyBundlePath, 8<<20)
		if err != nil {
			return err
		}
	}
	if err = protovalidate.Validate(record); err != nil {
		return errors.New("operations: invalid_custody_publication")
	}
	data, err := protojson.Marshal(record)
	if err != nil {
		return err
	}
	return writeOperationBytes(RecoveryCustodyHealthPath, data, 0644)
}

func validateArtifactInventory(artifacts []*agentv1.ServerRecoveryCustodyArtifact, withData bool) error {
	if len(artifacts) != len(recoveryArtifactNames) {
		return errors.New("operations: incomplete_custody_inventory")
	}
	seen := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		index := -1
		for candidate, name := range recoveryArtifactNames {
			if name == artifact.GetName() {
				index = candidate
				break
			}
		}
		custodianIndex := uint32(index + 1)
		if index == 3 {
			custodianIndex = 1
		}
		if index < 0 || seen[artifact.GetName()] || artifact.GetCustodianIndex() != custodianIndex || len(artifact.GetSha256()) != sha256.Size {
			return errors.New("operations: invalid_custody_inventory")
		}
		seen[artifact.GetName()] = true
		if withData {
			data := artifact.GetEncryptedData()
			digest := sha256.Sum256(data)
			if !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) || !bytes.Equal(digest[:], artifact.GetSha256()) {
				return errors.New("operations: invalid_custody_ciphertext")
			}
		} else if len(artifact.GetEncryptedData()) != 0 {
			return errors.New("operations: custody_metadata_contains_artifact_data")
		}
	}
	return nil
}

func custodyCipherDigest(path string, limit int64) (_ []byte, err error) {
	file, before, err := custody.OpenRoot(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 64 || before.Size > limit {
		return nil, errors.New("operations: invalid_custody_ciphertext")
	}
	prefix := make([]byte, len("age-encryption.org/v1\n"))
	if _, err = io.ReadFull(file, prefix); err != nil || !bytes.Equal(prefix, []byte("age-encryption.org/v1\n")) {
		return nil, errors.New("operations: invalid_custody_ciphertext")
	}
	hash := sha256.New()
	_, _ = hash.Write(prefix)
	count, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || count+int64(len(prefix)) != before.Size {
		return nil, errors.New("operations: custody_ciphertext_changed")
	}
	var after unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &after); err != nil {
		return nil, err
	}
	if before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Size != after.Size {
		return nil, errors.New("operations: custody_ciphertext_changed")
	}
	return hash.Sum(nil), nil
}
