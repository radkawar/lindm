// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// DeployIntegrationProof contains public digests and encrypted bytes only. It is
// a lab observer, never an API to reveal a destination's signing secret.
type DeployIntegrationProof struct {
	DestinationID       string `json:"destination_id"`
	EncryptionKeySHA256 string `json:"encryption_key_sha256"`
	SecretSHA256        string `json:"secret_sha256,omitempty"`
	Ciphertext          []byte `json:"ciphertext,omitempty"`
	SecretDecrypted     bool   `json:"secret_decrypted"`
	FreshKeyRejected    bool   `json:"fresh_key_rejected"`
}

// ObserveDeployIntegration runs inside the actual native guest. The browser
// creates the destination using the production API. Initial capture reads its
// real encrypted DB row; restored capture also requires that row to be unchanged.
// Fresh-key rejection deliberately uses the same ciphertext before DB restore.
func ObserveDeployIntegration(ctx context.Context, destination, digest string, captured []byte, rejectFresh bool) (_ *DeployIntegrationProof, err error) {
	id, parseErr := uuid.Parse(destination)
	wanted, digestErr := hex.DecodeString(digest)
	if os.Geteuid() != 0 || parseErr != nil || id.String() != destination || digestErr != nil || len(wanted) != sha256.Size || hex.EncodeToString(wanted) != digest || (rejectFresh && len(captured) == 0) {
		return nil, errors.New("deploy: invalid_native_integration_proof")
	}
	if err := custody.LockSecretMemory(); err != nil {
		return nil, errors.New("deploy: integration_proof_secret_memory_unavailable")
	}
	key, err := readDeployIntegrationRootSecret("/etc/lindm/integrations.key", 32, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	keyDigest := sha256.Sum256(key)
	proof := &DeployIntegrationProof{DestinationID: destination, EncryptionKeySHA256: hex.EncodeToString(keyDigest[:])}
	ciphertext := captured
	if !rejectFresh {
		dsn, readErr := readDeployIntegrationRootSecret("/etc/lindm/database-url", 1<<20, 0)
		if readErr != nil {
			return nil, readErr
		}
		defer clear(dsn)
		connection := strings.TrimSpace(string(dsn))
		address, addressErr := url.Parse(connection)
		cfg, configErr := pgxpool.ParseConfig(connection)
		if addressErr != nil || (address.Scheme != "postgresql" && address.Scheme != "postgres") || address.Query().Get("sslmode") != "verify-full" || configErr != nil || cfg.ConnConfig.User != "lindm_runtime" {
			return nil, errors.New("deploy: integration_proof_database_config_invalid")
		}
		pool, connectErr := pgxpool.NewWithConfig(ctx, cfg)
		if connectErr != nil {
			return nil, errors.New("deploy: integration_proof_database_unavailable")
		}
		defer pool.Close()
		var stored []byte
		if err := pool.QueryRow(ctx, "SELECT secret_ciphertext FROM integration_destinations WHERE id=$1 AND kind=1", id).Scan(&stored); err != nil {
			return nil, errors.New("deploy: integration_proof_destination_missing")
		}
		if len(captured) != 0 && !bytes.Equal(captured, stored) {
			return nil, errors.New("deploy: restored_integration_ciphertext_changed")
		}
		ciphertext = stored
	}
	secret, decryptErr := decryptDeployIntegration(key, ciphertext, id)
	defer clear(secret)
	if rejectFresh {
		if decryptErr == nil {
			return nil, errors.New("deploy: fresh_integration_key_decrypted_source_secret")
		}
		proof.FreshKeyRejected = true
		return proof, nil
	}
	if decryptErr != nil {
		return nil, errors.New("deploy: integration_secret_unreadable")
	}
	actual := sha256.Sum256(secret)
	if len(secret) < 32 || len(secret) > 64 || !bytes.Equal(wanted, actual[:]) {
		return nil, errors.New("deploy: integration_secret_digest_mismatch")
	}
	proof.SecretSHA256 = digest
	proof.SecretDecrypted = true
	proof.Ciphertext = ciphertext
	return proof, nil
}

func decryptDeployIntegration(key, ciphertext []byte, id uuid.UUID) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Matches the production integration service's maintained standard AEAD;
	// this observer authenticates the destination UUID, not merely file equality.
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, ciphertext, id[:])
}

func readDeployIntegrationRootSecret(path string, maximum, exact int64) (_ []byte, err error) {
	file, before, err := custody.OpenRoot(path, unix.O_RDONLY)
	if err != nil {
		return nil, errors.New("deploy: root_private_integration_resource_required")
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if before.Uid != 0 || before.Gid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Size < 0 || before.Size > maximum || (exact != 0 && before.Size != exact) {
		return nil, errors.New("deploy: root_private_integration_resource_required")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		clear(data)
		return nil, errors.New("deploy: integration_resource_read_failed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(data)) != before.Size {
		clear(data)
		return nil, errors.New("deploy: integration_resource_changed")
	}
	return data, nil
}

func observeGuestDeployIntegration(ctx context.Context, guest *guestVM, destination, digest string, captured []byte, rejectFresh bool) (*DeployIntegrationProof, error) {
	command := "chmod 0755 /root/lindm-deploy-input/lab-helper; /root/lindm-deploy-input/lab-helper deploy integrations-proof -destination-id " + nativeQuote(destination) + " -secret-sha256 " + nativeQuote(digest)
	var input io.Reader
	if len(captured) != 0 {
		command += " -ciphertext-stdin"
		body, err := json.Marshal(captured)
		if err != nil {
			return nil, err
		}
		defer clear(body)
		input = bytes.NewReader(body)
	}
	if rejectFresh {
		command += " -reject-fresh-key"
	}
	body, err := serverGuestCommand(ctx, guest, "observe native encrypted integration secret recovery", command, input)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	var proof DeployIntegrationProof
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil || proof.DestinationID != destination || len(proof.EncryptionKeySHA256) != 64 || (rejectFresh && !proof.FreshKeyRejected) || (!rejectFresh && (!proof.SecretDecrypted || proof.SecretSHA256 != digest)) {
		return nil, errors.New("deploy: incomplete_native_integration_proof")
	}
	return &proof, nil
}
