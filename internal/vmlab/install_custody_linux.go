// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// This exercises actual filesystem interleavings in a disposable fixture. It is
// not a production mutation API: ancestry, durable intents and recovery authority
// must be implemented by the executor before adopting the custody technique.
func checkProjectionCaptureRaces(units, anchor string, owned unix.Stat_t) (resultErr error) {
	visible := filepath.Join(units, projectionInstall)
	parentPath := filepath.Dir(visible)
	// Native disable may remove empty .wants directories. That is deliberately
	// observed by the caller, rather than assuming this parent survived.
	if err := os.MkdirAll(parentPath, 0700); err != nil {
		return err
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	custodyPath := filepath.Join(units, projectionCustody)
	custody, err := os.Open(custodyPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, custody.Close()) }()
	if err := os.Link(anchor, visible); err != nil {
		return err
	}
	if err := unix.Renameat2(int(parent.Fd()), projectionPrimary, int(custody.Fd()), "capture-owned", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	captured, err := projectionIdentity(filepath.Join(custodyPath, "capture-owned"))
	if err != nil {
		return err
	}
	if !sameProjectionIdentity(owned, captured) {
		return errors.New("captured fixture link was not the retained owned inode")
	}
	if err := unix.Unlinkat(int(custody.Fd()), "capture-owned", 0); err != nil {
		return err
	}
	// The administrator replacement arrives after observing the owned object
	// and before capture. A moved object is not necessarily the observed one.
	if err := os.Symlink("operator-first-target", visible); err != nil {
		return err
	}
	if err := unix.Renameat2(int(parent.Fd()), projectionPrimary, int(custody.Fd()), "capture-first", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	captured, err = projectionIdentity(filepath.Join(custodyPath, "capture-first"))
	if err != nil {
		return err
	}
	if sameProjectionIdentity(owned, captured) {
		return errors.New("replacement was mistaken for the retained owned inode")
	}
	if err := unix.Renameat2(int(custody.Fd()), "capture-first", int(parent.Fd()), projectionPrimary, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := requireProjectionTarget(visible, "operator-first-target"); err != nil {
		return err
	}
	// A newer public entry arrives before recovery. Neither entry may be lost.
	if err := unix.Renameat2(int(parent.Fd()), projectionPrimary, int(custody.Fd()), "capture-second", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := os.Symlink("operator-newer-target", visible); err != nil {
		return err
	}
	if err := unix.Renameat2(int(custody.Fd()), "capture-second", int(parent.Fd()), projectionPrimary, unix.RENAME_NOREPLACE); !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("restoration did not reject an occupied public name: %v", err)
	}
	if err := requireProjectionTarget(visible, "operator-newer-target"); err != nil {
		return err
	}
	if err := requireProjectionTarget(filepath.Join(custodyPath, "capture-second"), "operator-first-target"); err != nil {
		return err
	}
	// A replaced pathname can even contain unrelated regular-file data.
	if err := os.Remove(visible); err != nil {
		return err
	}
	const marker = "operator-owned regular-file data\n"
	if err := os.WriteFile(visible, []byte(marker), 0600); err != nil {
		return err
	}
	if err := unix.Renameat2(int(parent.Fd()), projectionPrimary, int(custody.Fd()), "capture-regular", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	captured, err = projectionIdentity(filepath.Join(custodyPath, "capture-regular"))
	if err != nil {
		return err
	}
	if captured.Mode&unix.S_IFMT != unix.S_IFREG || sameProjectionIdentity(owned, captured) {
		return errors.New("regular-file replacement was mistaken for owned symlink custody")
	}
	if err := os.Symlink("operator-newest-target", visible); err != nil {
		return err
	}
	if err := unix.Renameat2(int(custody.Fd()), "capture-regular", int(parent.Fd()), projectionPrimary, unix.RENAME_NOREPLACE); !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("regular-file restoration did not reject an occupied public name: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(custodyPath, "capture-regular"))
	if err != nil {
		return err
	}
	if string(data) != marker {
		return errors.New("unrelated captured regular-file data was not preserved")
	}
	if err := requireProjectionTarget(visible, "operator-newest-target"); err != nil {
		return err
	}
	after, err := projectionIdentity(anchor)
	if err != nil {
		return err
	}
	if !sameProjectionIdentity(owned, after) {
		return errors.New("owned anchor identity changed during replacement captures")
	}
	if err := requireProjectionTarget(anchor, "/usr/lib/systemd/system/"+projectionPrimary); err != nil {
		return err
	}
	return errors.Join(parent.Sync(), custody.Sync())
}

func requireProjectionTarget(path, expected string) error {
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if target != expected {
		return fmt.Errorf("fixture link %s changed: got %q, want %q", filepath.Base(path), target, expected)
	}
	return nil
}
