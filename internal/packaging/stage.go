//go:build linux

package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type stagedFile struct {
	Rel  string
	Mode os.FileMode
	Conf bool
}

func hashReader(r io.Reader) (string, int64, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	return hashReader(file)
}

func stagePayload(work string, binary *os.File, epoch int64, p product) (string, []stagedFile, string, error) {
	root := filepath.Join(work, "payload")
	if err := os.Mkdir(root, 0o755); err != nil {
		return "", nil, "", err
	}
	dirs := append([]string{"usr/bin", "usr/lib/systemd/system", "usr/lib/tmpfiles.d", "usr/lib/sysusers.d"}, p.dirs...)
	for _, dir := range dirs {
		if err := mkdir(filepath.Join(root, dir), epoch); err != nil {
			return "", nil, "", err
		}
	}
	files, err := p.payloadFiles()
	if err != nil {
		return "", nil, "", err
	}
	var staged []stagedFile
	for _, file := range files {
		body := file.body
		if file.name != "" {
			body, err = asset(file.name)
			if err != nil {
				return "", nil, "", err
			}
		}
		path := filepath.Join(root, file.rel)
		if err := writeFile(path, body, file.mode, epoch); err != nil {
			return "", nil, "", err
		}
		staged = append(staged, stagedFile{Rel: file.rel, Mode: file.mode, Conf: file.conf})
	}
	binaryRel := p.binary[1:]
	binaryPath := filepath.Join(root, binaryRel)
	if err := copyFile(binaryPath, binary, 0o755, epoch); err != nil {
		return "", nil, "", err
	}
	if _, err := binary.Seek(0, io.SeekStart); err != nil {
		return "", nil, "", err
	}
	want, _, err := hashReader(binary)
	if err != nil {
		return "", nil, "", err
	}
	got, _, err := hashFile(binaryPath)
	if err != nil {
		return "", nil, "", err
	}
	if got != want {
		return "", nil, "", fmt.Errorf("%w: staged binary digest changed", ErrArtifact)
	}
	staged = append(staged, stagedFile{Rel: binaryRel, Mode: 0o755})
	if err := stampDirectories(root, epoch); err != nil {
		return "", nil, "", err
	}
	return root, staged, want, nil
}

// Creating a child changes its parent's mtime after mkdir stamped it. Native
// SOURCE_DATE_EPOCH options only clamp timestamps from above, so normalize every
// directory after the complete tree is assembled, including implicit parents.
func stampDirectories(root string, epoch int64) error {
	stamp := time.Unix(epoch, 0)
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in native staging tree", ErrArtifact)
		}
		if info.IsDir() {
			return os.Chtimes(path, stamp, stamp)
		}
		return nil
	})
}

func installedSize(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: staged symlink", ErrArtifact)
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	kib := (total + 1023) / 1024
	if kib < 1 {
		kib = 1
	}
	return kib, nil
}
