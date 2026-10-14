// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

// cleanupBuildWork only relaxes directory permissions within the private inode
// created by this invocation. Module files remain readonly; symlinks are never
// followed. It cannot be used to clean a shared module cache.
func cleanupBuildWork(path string, owned os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(owned, current) {
		return errors.New("releasebuild: cleanup work inode changed")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		directory, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := directory.Stat()
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Getuid()) {
				err = errors.New("releasebuild: cleanup directory not owned by builder")
			} else {
				err = directory.Chmod(info.Mode().Perm() | 0700)
			}
		}
		return errors.Join(err, directory.Close())
	})
	if err = errors.Join(err, root.Close()); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func consoleDigests(root string) (map[string]string, error) {
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if len(result) >= 8192 {
			return errors.New("releasebuild: console file count exceeds diagnostic bound")
		}
		sum, _, err := digestFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = sum
		return nil
	})
	return result, err
}

func writeFailureEvidence(work, retainedDirectory string, first, second *buildOutput, cause error) error {
	evidence := &releasev1.ReleaseBuildFailure{Reason: cause.Error(), RetainedWorkDirectory: retainedDirectory, Builds: []*releasev1.BuildObservation{first.observation, second.observation}}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}).Marshal(evidence)
	if err != nil {
		return err
	}
	if len(encoded) > maxDocument {
		return errors.New("releasebuild: failure evidence exceeds bound")
	}
	path := filepath.Join(work, "reproducibility-failure.json")
	if err := writeNew(path, encoded, 0600); err != nil {
		return err
	}
	return nil
}
