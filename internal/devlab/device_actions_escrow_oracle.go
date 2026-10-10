package devlab

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"lindm/internal/escrow"
)

// VerifyRecoveryCustody observes the real isolated server database and KEK. It
// returns no secret-bearing bytes and never modifies stored custody or audit rows.
func (f *AuthorityFixture) VerifyRecoveryCustody(ctx context.Context, actionID string, revealed []byte) (err error) {
	if f.closed || f.database == nil {
		return errors.New("custody oracle requires isolated authority")
	}
	cfg := f.database.admin.Copy()
	cfg.Database = f.database.name
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return errors.New("connect custody oracle failed")
	}
	defer func() { err = errors.Join(err, conn.Close(context.WithoutCancel(ctx))) }()
	record := new(escrow.Record)
	var binding []byte
	if err := conn.QueryRow(ctx, "SELECT binding_document,key_id,wrapped_key,ciphertext,secret_sha256 FROM device_action_escrow WHERE action_id=$1", actionID).Scan(&binding, &record.KeyID, &record.WrappedKey, &record.Ciphertext, &record.SecretSHA256); err != nil {
		return errors.New("read durable custody record failed")
	}
	if bytes.Contains(record.WrappedKey, revealed) || bytes.Contains(record.Ciphertext, revealed) {
		return errors.New("durable custody contains recovery plaintext")
	}
	encoded, err := os.ReadFile(filepath.Join(f.directory, "escrow-transport.pem"))
	if err != nil {
		return err
	}
	defer clear(encoded)
	block, _ := pem.Decode(encoded)
	if block == nil {
		return errors.New("invalid fixture transport key")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("parse fixture transport key failed")
	}
	transport, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return errors.New("unexpected fixture transport key type")
	}
	kek, err := os.ReadFile(filepath.Join(f.directory, "escrow-wrapping.key"))
	if err != nil {
		return err
	}
	defer clear(kek)
	custody, err := escrow.New(transport, kek)
	if err != nil {
		return err
	}
	plaintext, err := custody.Reveal(binding, record)
	if err != nil {
		return errors.New("actual custody KEK failed to open stored record")
	}
	defer clear(plaintext)
	if !bytes.Equal(plaintext, revealed) {
		return errors.New("stored custody differs from approved reveal")
	}
	kek[0] ^= 1
	wrong, err := escrow.New(transport, kek)
	if err != nil {
		return err
	}
	unexpected, rejected := wrong.Reveal(binding, record)
	clear(unexpected)
	if rejected == nil {
		return errors.New("incorrect custody KEK opened stored record")
	}
	var audited bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE action='recovery_key.reveal' AND resource_id=$1 AND actor_id IS NOT NULL AND reason=$2)", actionID, "verify literal recovery credential on disposable cold boot").Scan(&audited); err != nil {
		return errors.New("read reveal audit failed")
	}
	if !audited {
		return errors.New("approved reveal lacks committed actor and reason audit")
	}
	return nil
}
