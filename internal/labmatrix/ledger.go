// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

// FileSHA256 hashes a regular evidence file without following a final symlink.
func FileSHA256(path string) (_ string, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("lab matrix: evidence %s is not a regular file", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Append atomically adds entries to the ledger at path. Writers serialize on an
// exclusive lock of the ledger's directory; the new ledger replaces the old by
// rename only after it is validated and synced.
func Append(path string, entries ...*labv1.MatrixLedgerEntry) (err error) {
	dir := filepath.Dir(path)
	lock, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lab matrix: lock ledger: %w", err)
	}
	ledger, err := LoadLedger(path)
	if err != nil {
		return err
	}
	ledger.Entries = append(ledger.Entries, entries...)
	if err := protovalidate.Validate(ledger); err != nil {
		return fmt.Errorf("lab matrix: validate ledger: %w", err)
	}
	data, err := Marshal(ledger)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ledger-*.json")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	_, writeErr := tmp.Write(data)
	if writeErr == nil {
		writeErr = tmp.Chmod(0o644)
	}
	if writeErr == nil {
		writeErr = tmp.Sync()
	}
	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return lock.Sync()
}

// Marshal renders a ledger as stable two-space-indented protobuf JSON, the
// layout Prettier keeps.
func Marshal(ledger *labv1.MatrixLedger) ([]byte, error) {
	compact, err := protojson.Marshal(ledger)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
