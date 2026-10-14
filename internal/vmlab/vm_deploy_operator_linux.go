// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"lindm/internal/serverops"
)

// InitializeDeployOperator creates only an encrypted backup identity, its public
// recipient, and a separate age-encrypted unlock escrow. The escrow's dedicated
// lab operator private identity is an explicitly authorized lab-only input; it
// never enters a VM, product, release, backup or support bundle.
func InitializeDeployOperator(ctx context.Context, directory, escrowRecipient string) error {
	if err := productionSigningDirectory(directory); err != nil {
		return err
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	passphrase := make([]byte, hex.EncodedLen(len(entropy)))
	hex.Encode(passphrase, entropy[:])
	clear(entropy[:])
	defer clear(passphrase)
	if err := serverops.GenerateBackupKey(ctx, filepath.Join(directory, "backup-identity.age"), filepath.Join(directory, "backup-recipient.txt"), passphrase); err != nil {
		return err
	}
	return encryptDeployEvidence(escrowRecipient, filepath.Join(directory, "backup-identity-unlock.age"), passphrase)
}

// ReadDeployEscrowPassphrase is confined to lab code. The caller must first make
// the custodian process non-dumpable and memory locked. Its result is cleared by
// the caller and can feed only protected anonymous pipes, never argv/env/logs.
func ReadDeployEscrowPassphrase(ctx context.Context, escrowPath, labIdentityPath string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	private, err := readDeployEscrowInput(labIdentityPath, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	identities, err := age.ParseIdentities(bytes.NewReader(private))
	if err != nil || len(identities) != 1 {
		return nil, errors.New("lab escrow requires exactly one protected dedicated X25519 operator identity")
	}
	if _, ok := identities[0].(*age.X25519Identity); !ok {
		return nil, errors.New("lab escrow does not accept plugin or interchangeable identity types")
	}
	ciphertext, err := readDeployEscrowInput(escrowPath, 8192)
	if err != nil {
		return nil, err
	}
	plain, err := age.Decrypt(bytes.NewReader(ciphertext), identities[0])
	if err != nil {
		return nil, errors.New("lab encrypted unlock escrow cannot be authenticated")
	}
	passphrase, err := io.ReadAll(io.LimitReader(plain, 1025))
	if err != nil || len(passphrase) < 20 || len(passphrase) > 1024 || bytes.ContainsAny(passphrase, "\r\n") {
		clear(passphrase)
		return nil, errors.New("lab encrypted unlock escrow has invalid passphrase contents or size")
	}
	return passphrase, nil
}

func readDeployEscrowInput(path string, limit int64) (body []byte, resultErr error) {
	file, stat, err := openDeployAuditProtected(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			clear(body)
			body = nil
		}
	}()
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Size < 1 || stat.Size > limit {
		return nil, errors.New("lab escrow input must be an operator-owned private regular single-link bounded file")
	}
	body, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		clear(body)
		return nil, errors.New("lab escrow input exceeds its protected byte bound")
	}
	return body, nil
}

// VerifyDeployOperatorEscrow proves a freshly reloaded durable escrow actually
// unlocks its encrypted backup identity and matches the separate public key.
// No private identity or passphrase leaves protected process memory.
func VerifyDeployOperatorEscrow(ctx context.Context, directory, labIdentity string) error {
	passphrase, err := ReadDeployEscrowPassphrase(ctx, filepath.Join(directory, "backup-identity-unlock.age"), labIdentity)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	ciphertext, err := readDeployEscrowInput(filepath.Join(directory, "backup-identity.age"), 16384)
	if err != nil {
		return err
	}
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return errors.New("lab backup identity unlock input invalid")
	}
	identity.SetMaxWorkFactor(18)
	plain, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return errors.New("lab encrypted backup identity could not be authenticated with durable escrow")
	}
	body, err := io.ReadAll(io.LimitReader(plain, 4097))
	if err != nil || len(body) > 4096 {
		clear(body)
		return errors.New("lab decrypted backup identity exceeded bounds")
	}
	defer clear(body)
	keys, err := age.ParseIdentities(bytes.NewReader(body))
	if err != nil || len(keys) != 1 {
		return errors.New("lab encrypted backup identity format invalid")
	}
	key, ok := keys[0].(*age.X25519Identity)
	if !ok {
		return errors.New("lab backup fixture identity type invalid")
	}
	public, err := readDeployEscrowInput(filepath.Join(directory, "backup-recipient.txt"), 4096)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(public)) != key.Recipient().String() {
		return errors.New("lab durable escrow unlocks an identity different from the backup public recipient")
	}
	return nil
}
