// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"lindm/internal/custody"
)

// ValidateRecipientFile checks the independently supplied public recipient. The
// installer never creates or receives the matching operator private identity.
func ValidateRecipientFile(path string) error { _, err := loadRecipient(path); return err }
func loadRecipient(path string) (age.Recipient, error) {
	data, err := custody.ReadRoot(path, 8192, false)
	if err != nil {
		return nil, err
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("operations: operator_age_public_recipient_required")
	}
	return recipient, nil
}

func decryptPassphraseFile(ctx context.Context, path string, passphrase []byte, limit int64) (_ []byte, err error) {
	if len(passphrase) < 20 || len(passphrase) > 1024 {
		return nil, errors.New("operations: protected_passphrase_required")
	}
	file, _, err := openOperationFile(path, limit+4096, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, errors.New("operations: invalid_passphrase_identity")
	}
	identity.SetMaxWorkFactor(18)
	plain, err := age.Decrypt(&contextReader{ctx, file}, identity)
	if err != nil {
		return nil, errors.New("operations: custody_decryption_failed")
	}
	data, err := io.ReadAll(io.LimitReader(plain, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("operations: custody_decryption_or_size_failed")
	}
	return data, nil
}

func loadIdentities(ctx context.Context, path string, passphrase []byte) ([]age.Identity, error) {
	data, err := decryptPassphraseFile(ctx, path, passphrase, 8192)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(identities) == 0 || len(identities) > 16 {
		return nil, errors.New("operations: invalid_encrypted_age_identity")
	}
	return identities, nil
}

// GenerateBackupKey is an offline operator command, not an installer step. Its
// identity is a standard passphrase-encrypted age identity, never plaintext disk.
func GenerateBackupKey(ctx context.Context, identityPath, recipientPath string, passphrase []byte) error {
	if identityPath == recipientPath {
		return errors.New("operations: distinct_key_outputs_required")
	}
	for _, path := range []string{identityPath, recipientPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "/etc/lindm/") || strings.HasPrefix(path, "/var/lib/lindmd/") || strings.HasPrefix(path, "/var/lib/lindmd-operations/") {
			return errors.New("operations: independent_offline_key_custody_required")
		}
		if err := privateOutputDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("operations: key_output_must_be_new")
		}
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil || len(passphrase) < 20 || len(passphrase) > 1024 {
		return errors.New("operations: protected_passphrase_required")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	private, err := os.OpenFile(identityPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encrypted, err := age.Encrypt(&contextWriter{ctx, private}, recipient)
	if err != nil {
		return errors.Join(err, private.Close())
	}
	_, writeErr := io.WriteString(encrypted, identity.String()+"\n")
	if err = errors.Join(writeErr, encrypted.Close(), private.Sync(), private.Close()); err != nil {
		return err
	}
	public, err := os.OpenFile(recipientPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr = public.WriteString(identity.Recipient().String() + "\n")
	return errors.Join(writeErr, public.Sync(), public.Close())
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer *contextWriter) Write(data []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	return writer.writer.Write(data)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}
