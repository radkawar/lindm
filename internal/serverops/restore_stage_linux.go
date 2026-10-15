// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// Operational health state must remain traversable by lindmd; plaintext restore
// scratch needs a separate private tree outside the operational backup inventory.
const restoreStageParent = "/var/lib/lindmd-restore"

// Restore plaintext is destined for the data filesystem. Stage it privately
// there, rather than exhausting the distribution's small shared /run tmpfs.
func prepareRestoreStage(archives ...string) (string, func() error, error) {
	return prepareRestoreStageAt(restoreStageParent, archives...)
}

// The caller holds the operations lease: no live restore can own an old stage.
func prepareRestoreStageAt(path string, archives ...string) (string, func() error, error) {
	filesystem, err := prepareRestoreStageParent(path)
	if err != nil {
		return "", nil, err
	}
	var archiveBytes int64
	for _, archive := range archives {
		file, stat, openErr := openOperationFile(archive, maxArchive, true)
		if openErr != nil {
			return "", nil, openErr
		}
		if err = file.Close(); err != nil {
			return "", nil, err
		}
		archiveBytes += stat.Size
	}
	if err = checkRestoreStageSpace(filesystem, archiveBytes, len(archives)); err != nil {
		return "", nil, err
	}
	stage, err := os.MkdirTemp(path, "restore-*")
	if err != nil {
		return "", nil, err
	}
	return stage, func() error { return os.RemoveAll(stage) }, nil
}

func prepareRestoreStageParent(path string) (filesystem unix.Statfs_t, err error) {
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return filesystem, err
	}
	mkdirErr := unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700)
	if err = errors.Join(parent.Close(), ignoreExistingDirectory(mkdirErr)); err != nil {
		return filesystem, err
	}
	if err = custody.PrivateDirectory(path); err != nil {
		return filesystem, err
	}
	parent, _, err = custody.OpenRoot(path, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return filesystem, err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	root, err := os.OpenRoot(path)
	if err != nil {
		return filesystem, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err = sweepRestoreStages(parent, root); err != nil {
		return filesystem, err
	}
	err = unix.Fstatfs(int(parent.Fd()), &filesystem)
	return filesystem, err
}

func sweepRestoreStages(parent *os.File, root *os.Root) error {
	entries, err := parent.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "restore-") {
			continue
		}
		var stat unix.Stat_t
		if err = unix.Fstatat(int(parent.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0077 != 0 {
			return errors.New("operations: unsafe_restore_staging_entry")
		}
		if err = root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func ignoreExistingDirectory(err error) error {
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func checkRestoreStageSpace(filesystem unix.Statfs_t, archiveBytes int64, archives int) error {
	if filesystem.Bsize <= 0 || filesystem.Bsize > 1<<20 || archiveBytes < 0 || archives < 1 || archives > 2 || archiveBytes > int64(archives)*maxArchive {
		return errors.New("operations: invalid_restore_staging_capacity")
	}
	// age does not compress the tar stream, so ciphertext sizes bound the data
	// bytes. Reserve a filesystem block for every possible file and directory,
	// plus 64 MiB of headroom. The archive inventory is capped at 65,536 files.
	const entriesPerArchive = uint64(2*65536 + 4)
	blockSize := uint64(filesystem.Bsize)
	required := uint64(archiveBytes) + uint64(archives)*entriesPerArchive*blockSize + 64<<20
	if uint64(filesystem.Bavail) < (required+blockSize-1)/blockSize {
		available := uint64(filesystem.Bavail) * blockSize
		return fmt.Errorf("operations: insufficient_restore_staging_space: %s needs %d bytes free; available %d bytes; free space on the data filesystem before retrying", restoreStageParent, required, available)
	}
	return nil
}
