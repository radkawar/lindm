// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Only a completed reproducibility mismatch retains unsigned evidence. The
// evidence moves to the operator's output parent; ordinary errors and canceled
// work never leave native build trees in the system temporary directory.
func retainMismatch(ctx context.Context, work string, ownedWork os.FileInfo, parent string, first, second *buildOutput, cause error) (moved bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	prefix := "reproducibility-mismatch-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-"
	target, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return false, errors.Join(cause, err)
	}
	ownedTarget, err := os.Lstat(target)
	if err != nil {
		return false, errors.Join(cause, err)
	}
	retained := false
	defer func() {
		if !retained {
			cleanupErr := cleanupBuildWork(target, ownedTarget)
			if !errors.Is(cleanupErr, os.ErrNotExist) {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	if err := cleanupBuildWork(target, ownedTarget); err != nil {
		return false, errors.Join(cause, err)
	}
	ownedTarget = ownedWork
	renameErr := unix.Renameat2(unix.AT_FDCWD, work, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	if renameErr == nil {
		moved = true
	} else if errors.Is(renameErr, unix.EXDEV) {
		if err := os.Mkdir(target, 0700); err != nil {
			return false, errors.Join(cause, err)
		}
		created, statErr := os.Lstat(target)
		if statErr != nil {
			return false, errors.Join(cause, statErr)
		}
		ownedTarget = created
		if err := copyBuildTree(ctx, work, target, true); err != nil {
			return false, errors.Join(cause, err)
		}
	} else {
		return false, errors.Join(cause, renameErr)
	}
	if err := writeFailureEvidence(target, target, first, second, cause); err != nil {
		return moved, errors.Join(cause, err)
	}
	size, err := retainedTreeSize(ctx, target)
	if err != nil {
		return moved, err
	}
	if err := syncDirectory(target); err != nil {
		return moved, errors.Join(cause, err)
	}
	if err := syncDirectory(parent); err != nil {
		return moved, errors.Join(cause, err)
	}
	if err := ctx.Err(); err != nil {
		return moved, err
	}
	retained = true
	if !moved {
		if err := cleanupBuildWork(work, ownedWork); err != nil {
			return false, errors.Join(mismatchLocation(cause, target, size), err)
		}
		moved = true
	}
	return moved, mismatchLocation(cause, target, size)
}

func retainedTreeSize(ctx context.Context, directory string) (int64, error) {
	var size int64
	err := filepath.WalkDir(directory, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func mismatchLocation(cause error, directory string, size int64) error {
	quoted := "'" + strings.ReplaceAll(directory, "'", "'\\''") + "'"
	return fmt.Errorf("%w; both unsigned build trees and reproducibility-failure.json retained at %s (%d regular-file bytes). Remove with: chmod -R u+w -- %s && rm -rf -- %s", cause, directory, size, quoted, quoted)
}
