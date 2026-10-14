// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/statefs"
)

const retiredPrefix = ".retired-"

// reclaimRetired retains the journal's current transaction, even when terminal.
// Any ambiguous old transaction blocks further staging instead of growing disk
// usage indefinitely. The executor's exclusive journal lock serializes cutovers.
func (e *Engine) reclaimRetired(ctx context.Context, state *agentv1.AgentUpdateJournal) error {
	if tx := state.GetTransaction(); tx != nil && (state.GetPhase() == "installed" || state.GetPhase() == "rejected") {
		active, err := helperActive(ctx, tx)
		if err != nil {
			return err
		}
		if active {
			return errors.New("terminal update helper is still active")
		}
		if err := removeRecoveryUnit(ctx, filepath.Join(e.store.Directory, tx.GetId())); err != nil {
			return err
		}
	}
	// A persistent helper for ANY transaction is a deletion fence. Never remove
	// another transaction's unit merely to make room for the next download.
	if err := recoveryUnitAbsent(unitDirectory); err != nil {
		return err
	}
	return reclaimTransactions(e.store.Directory, state.GetTransaction().GetId(), func(id string) (bool, error) {
		return helperActive(ctx, &agentv1.AgentUpdateTransaction{Id: id})
	})
}

func recoveryUnitAbsent(directory string) error {
	for _, path := range []string{filepath.Join(directory, recoveryUnit), filepath.Join(directory, "multi-user.target.wants", recoveryUnit)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(errors.New("update recovery unit still owns staging"), err)
		}
	}
	return nil
}

func reclaimTransactions(directory, current string, active func(string) (bool, error)) (resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(fd), "update-retention")
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	var candidates [256]string
	count := 0
	for {
		names, readErr := root.Readdirnames(32)
		for _, name := range names {
			id := strings.TrimPrefix(name, retiredPrefix)
			parsed, err := uuid.Parse(id)
			if err != nil || parsed.String() != id {
				continue
			}
			if id == current {
				if name != current {
					return errors.New("retired update is still current")
				}
				continue
			}
			if count == len(candidates) {
				return errors.New("retired update count exceeds bound")
			}
			candidates[count] = name
			count++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for _, name := range candidates[:count] {
		if err := reclaimTransaction(directory, name, strings.TrimPrefix(name, retiredPrefix), active); err != nil {
			return err
		}
	}
	return nil
}

func reclaimTransaction(root, name, id string, active func(string) (bool, error)) (resultErr error) {
	path := filepath.Join(root, name)
	fd, err := statefs.OpenDirectory(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	if running, err := active(id); err != nil || running {
		return errors.Join(errors.New("retired update helper is not inactive"), err)
	}
	if name == id {
		tx := &agentv1.AgentUpdateTransaction{}
		if err := journal.ReadUpdateRecord(path, "transaction.pb", tx); err == nil {
			if tx.GetId() != id {
				return errors.New("retired update identity mismatch")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		helper := &agentv1.AgentUpdateHelperState{}
		if err := journal.ReadUpdateRecord(path, "helper.pb", helper); err == nil {
			if helper.GetPhase() != "installed" && helper.GetPhase() != "rejected" {
				return errors.New("retired update has unresolved native effects")
			}
			if tx.GetId() != id {
				return errors.New("retired helper lacks transaction identity")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// No receipt and no journal reference means staging never consumed native
		// authority. A launch always follows its durable journal admission.
	}
	if err := checkedRetiredTree(path); err != nil {
		return err
	}
	retired := filepath.Join(root, retiredPrefix+id)
	if name == id {
		if _, err := os.Lstat(retired); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(errors.New("duplicate retired update"), err)
		}
		if err := os.Rename(path, retired); err != nil {
			return err
		}
	}
	// Sync even on replay: a crash may have occurred after rename but before
	// its fsync. Once this boundary commits, partially removed records are safe.
	if err := syncDirectory(root); err != nil {
		return err
	}
	if err := os.RemoveAll(retired); err != nil {
		return err
	}
	return syncDirectory(root)
}

func checkedRetiredTree(root string) error {
	count := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 4096 {
			return errors.New("retired update tree exceeds bound")
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		kind := stat.Mode & unix.S_IFMT
		// The checked 0700 transaction root excludes other users. APT may own
		// its otherwise empty cache/partial directory as _apt; never traverse
		// symlinks, writable shared nodes, devices or multiply-linked files.
		if stat.Mode&0022 != 0 || (kind != unix.S_IFDIR && kind != unix.S_IFREG) || (kind == unix.S_IFREG && (stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()))) {
			return errors.New("retired update tree custody mismatch")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("retired update contains symlink")
		}
		return nil
	})
}
