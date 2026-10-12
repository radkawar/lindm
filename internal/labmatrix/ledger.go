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
	"slices"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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

// MergeLedger merges a change to the ledger structurally, so concurrent
// landings that each record entries compose: the entries theirs adds to base
// are appended to current (once: an entry current already holds is not
// repeated) and the entries theirs removes from base are removed from current.
// Entries are compared as records, never as text. A missing base or theirs is
// an empty ledger. The result is validated and rendered with Marshal.
func MergeLedger(current, base, theirs []byte) ([]byte, error) {
	parse := func(name string, data []byte) (*labv1.MatrixLedger, error) {
		ledger := new(labv1.MatrixLedger)
		if len(bytes.TrimSpace(data)) == 0 {
			return ledger, nil
		}
		if len(data) > maxFileBytes {
			return nil, fmt.Errorf("lab matrix: %s ledger exceeds %d bytes", name, maxFileBytes)
		}
		if err := decodeBytes(name+" ledger", data, ledger); err != nil {
			return nil, err
		}
		return ledger, nil
	}
	merged, err := parse("current", current)
	if err != nil {
		return nil, err
	}
	before, err := parse("base", base)
	if err != nil {
		return nil, err
	}
	after, err := parse("their", theirs)
	if err != nil {
		return nil, err
	}
	// take removes one entry equal to e from entries, reporting whether it
	// held one.
	take := func(entries *[]*labv1.MatrixLedgerEntry, e *labv1.MatrixLedgerEntry) bool {
		for i, candidate := range *entries {
			if proto.Equal(candidate, e) {
				*entries = slices.Delete(*entries, i, i+1)
				return true
			}
		}
		return false
	}
	removed := slices.Clone(before.GetEntries())
	var added []*labv1.MatrixLedgerEntry
	for _, e := range after.GetEntries() {
		if !take(&removed, e) {
			added = append(added, e)
		}
	}
	for _, e := range removed {
		take(&merged.Entries, e)
	}
	for _, e := range added {
		if !slices.ContainsFunc(merged.Entries, func(c *labv1.MatrixLedgerEntry) bool { return proto.Equal(c, e) }) {
			merged.Entries = append(merged.Entries, e)
		}
	}
	if err := protovalidate.Validate(merged); err != nil {
		return nil, fmt.Errorf("lab matrix: validate merged ledger: %w", err)
	}
	return Marshal(merged)
}
