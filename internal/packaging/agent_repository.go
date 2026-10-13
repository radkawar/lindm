//go:build linux

package packaging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// AgentRepositoryPath is the immutable release payload installed with lindmd.
const AgentRepositoryPath = "/usr/share/lindmd/agent-repository"

// The caller authenticates the bundle before packaging it. Staging preserves
// every byte, rejects links/special files, and normalizes only installation modes
// and timestamps; it never creates keys or republishes repositories.
func stageAgentRepository(payload, bundle string, epoch int64) ([]stagedFile, error) {
	root, err := os.OpenRoot(bundle)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{"release.json", "release.json.dsse", "attestation.pub", "package-signing.asc", "repo/apt", "repo/rpm", "repo/arch"} {
		if _, err := root.Lstat(name); err != nil {
			return nil, fmt.Errorf("%w: incomplete agent repository: %s", ErrArtifact, name)
		}
	}
	var files []stagedFile
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel := filepath.Join(AgentRepositoryPath[1:], name)
		destination := filepath.Join(payload, rel)
		if info.IsDir() {
			return mkdir(destination, epoch)
		}
		total += info.Size()
		if !info.Mode().IsRegular() || info.Size() > 1<<30 || total > 4<<30 || len(files) >= 8192 {
			return fmt.Errorf("%w: unbounded or nonregular agent repository member", ErrArtifact)
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		err = errors.Join(copyFile(destination, file, 0o444, epoch), file.Close())
		if err != nil {
			return err
		}
		sum, _, err := hashFile(destination)
		if err != nil {
			return err
		}
		files = append(files, stagedFile{Rel: rel, Mode: 0o444, SHA256: sum})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, stampDirectories(payload, epoch)
}
