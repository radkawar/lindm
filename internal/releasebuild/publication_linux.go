// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

// Native signing paths must not inherit a normal clone's writable ancestry.
// The source checkout and final public export need not be private custody roots.
func createBuildWork() (string, os.FileInfo, error) {
	parent := os.TempDir()
	fd, err := statefs.OpenTemporaryParent(parent)
	if err != nil {
		return "", nil, fmt.Errorf("releasebuild: protected temporary parent required: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return "", nil, err
	}
	work, err := os.MkdirTemp(parent, ".lindm-release-")
	if err != nil {
		return "", nil, err
	}
	owned, err := os.Lstat(work)
	if err != nil {
		return "", nil, errors.Join(err, os.RemoveAll(work))
	}
	fd, err = statefs.OpenDirectory(work)
	if err != nil {
		return "", nil, errors.Join(err, cleanupBuildWork(work, owned))
	}
	if err := unix.Close(fd); err != nil {
		return "", nil, errors.Join(err, cleanupBuildWork(work, owned))
	}
	return work, owned, nil
}

// publishExport verifies before publication. Same-filesystem exports move once;
// cross-filesystem exports stream to a private destination sibling, verify that
// copy, and atomically publish it without replacing any existing user output.
func publishExport(ctx context.Context, source, output, trustedPublic, keyID string, installer bool) (err error) {
	verify := func(directory string) error {
		if _, err := Verify(ctx, directory, trustedPublic, keyID); err != nil {
			return err
		}
		if installer {
			return VerifyInstaller(ctx, directory, trustedPublic, keyID)
		}
		return nil
	}
	if err := verify(source); err != nil {
		return err
	}
	if err := syncDirectory(source); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	renameErr := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE)
	if renameErr == nil {
		return syncDirectory(filepath.Dir(output))
	}
	if !errors.Is(renameErr, unix.EXDEV) {
		return renameErr
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".lindm-export-")
	if err != nil {
		return err
	}
	owned, err := os.Lstat(stage)
	if err != nil {
		return errors.Join(err, os.RemoveAll(stage))
	}
	published := false
	defer func() {
		if !published {
			err = errors.Join(err, cleanupBuildWork(stage, owned))
		}
	}()
	if err := copyExport(ctx, source, stage); err != nil {
		return err
	}
	if err := verify(stage); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	published = true
	return syncDirectory(filepath.Dir(output))
}

func copyExport(ctx context.Context, source, destination string) error {
	return copyBuildTree(ctx, source, destination, false)
}

// Mismatch evidence preserves link text without following it. Public exports
// deliberately reject all links and special files.
func copyBuildTree(ctx context.Context, source, destination string, preserveLinks bool) error {
	return copyBuildDirectory(ctx, source, destination, preserveLinks, true)
}

func copyBuildDirectory(ctx context.Context, source, destination string, preserveLinks, root bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		input, output := filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			if err := os.Mkdir(output, 0700); err != nil {
				return err
			}
			if err := copyBuildDirectory(ctx, input, output, preserveLinks, false); err != nil {
				return err
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if preserveLinks && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(input)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, output); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return errors.New("releasebuild: export link or special file refused")
		}
		bound := int64(maxArtifact)
		if root {
			bound = exportCopyBound(entry.Name())
		}
		if err := copyExportFile(ctx, input, output, info.Mode().Perm()&0755, bound); err != nil {
			return err
		}
	}
	return syncDirectory(destination)
}

func copyExportFile(ctx context.Context, source, destination string, mode fs.FileMode, bound int64) (err error) {
	input, err := os.OpenFile(source, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	n, err := io.Copy(output, io.LimitReader(exportReader{ctx: ctx, reader: input}, bound+1))
	if err != nil {
		return err
	}
	if n > bound {
		return errors.New("releasebuild: copied export exceeds artifact bound")
	}
	return output.Sync()
}

func exportCopyBound(name string) int64 {
	if filepath.Ext(name) == ".snapshot" {
		for _, key := range [2]string{"ubuntu-24.04", "rhel-9"} {
			release, ok := platform.Lookup(key)
			if ok && release.Server != nil && name == release.Server.SnapshotName {
				return int64(serverdeps.HardMaxBytes)
			}
		}
	}
	return maxArtifact
}

type exportReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r exportReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
