// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/custody"
)

// preserveFreshDatabaseCustody runs before source files replace the fresh target's
// generated authority. It preserves BOTH sealed CA keys and any independently
// passphrase-encrypted identity export, without decrypting or resealing either.
func preserveFreshDatabaseCustody(ctx context.Context, pool *pgxpool.Pool) (_ *agentv1.ServerRecoveryDatabaseCustody, err error) {
	creation, err := readCustodyRecord(RecoveryCustodyHealthPath)
	if err != nil {
		return nil, err
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return nil, errors.New("operations: fresh_database_trust_unavailable")
	}
	tlsConnection, ok := connection.Conn().PgConn().Conn().(*tls.Conn)
	if !ok {
		connection.Release()
		return nil, errors.New("operations: verified_database_tls_required")
	}
	state := tlsConnection.ConnectionState()
	connection.Release()
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, errors.New("operations: verified_database_ca_required")
	}
	chain := state.VerifiedChains[0]
	caDigest := sha256.Sum256(chain[len(chain)-1].Raw)
	directory := filepath.Join("/var/lib/lindmd-operations/database-custody", hex.EncodeToString(caDigest[:]))
	parent, _, err := custody.OpenRoot(filepath.Dir(filepath.Dir(directory)), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if err = parent.Close(); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(directory, 0755); err != nil {
		return nil, err
	}
	directoryFD, _, err := custody.OpenRoot(directory, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, directoryFD.Close()) }()
	record := &agentv1.ServerRecoveryDatabaseCustody{DatabaseCaSha256: caDigest[:], SealedPkiPath: filepath.Join(directory, "sealed-pki-ca.age"), External: creation.GetExternal()}
	source := filepath.Join(recoveryCustodyDirectory, "sealed-pki-ca.age")
	record.SealedPkiSha256, err = custodyCipherDigest(source, 1<<20)
	if err != nil {
		return nil, err
	}
	var expected []byte
	for _, artifact := range creation.GetArtifacts() {
		if artifact.GetName() == "sealed-pki-ca.age" {
			expected = artifact.GetSha256()
		}
	}
	if !bytes.Equal(expected, record.SealedPkiSha256) {
		return nil, errors.New("operations: fresh_database_custody_digest_mismatch")
	}
	input, _, err := custody.OpenRoot(source, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	copyErr := publishPrivate(record.SealedPkiPath, input, 0, 0, 0600)
	if err = errors.Join(copyErr, input.Close()); err != nil {
		return nil, err
	}
	if !creation.GetExternal() {
		digest, err := custodyCipherDigest(RecoveryCustodyBundlePath, 8<<20)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(digest, creation.GetIdentityBundleSha256()) {
			return nil, errors.New("operations: fresh_database_identity_digest_mismatch")
		}
		record.IdentityBundlePath = filepath.Join(directory, "identities.age")
		record.IdentityBundleSha256 = digest
		input, stat, err := custody.OpenRoot(RecoveryCustodyBundlePath, unix.O_RDONLY)
		if err != nil {
			return nil, err
		}
		copyErr := publishPrivate(record.IdentityBundlePath, input, 0, int(stat.Gid), 0640)
		if err = errors.Join(copyErr, input.Close()); err != nil {
			return nil, err
		}
	}
	if err = directoryFD.Sync(); err != nil {
		return nil, err
	}
	return record, nil
}

func rebindRecoveryCustody(cfg *configv1.ServerConfig, database *agentv1.ServerRecoveryDatabaseCustody) error {
	if os.Geteuid() != 0 {
		return errors.New("operations: root_required")
	}
	record, err := readCustodyRecord(RecoveryCustodyHealthPath)
	if err != nil {
		return err
	}
	identity, err := NewBackupIdentity(cfg)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(identity.ConfigSHA256)
	if err != nil {
		return err
	}
	record.DeploymentId = identity.DeploymentID
	record.PublicUrl = identity.PublicURL
	record.DevicePublicUrl = identity.DevicePublicURL
	record.ConfigSha256 = digest
	record.CreatedAt = timestamppb.New(time.Now().UTC())
	record.DatabaseCustody = database
	data, err := protojson.Marshal(record)
	if err != nil {
		return err
	}
	return writeOperationBytes(RecoveryCustodyHealthPath, data, 0644)
}
