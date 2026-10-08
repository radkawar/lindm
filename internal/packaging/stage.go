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

func stagePayload(work string, binary *os.File, epoch int64) (string, []stagedFile, string, error) {
	root := filepath.Join(work, "payload")
	if err := os.Mkdir(root, 0o755); err != nil {
		return "", nil, "", err
	}
	dirs := []string{
		"usr/libexec/lindm",
		"usr/lib/systemd/system",
		"usr/lib/tmpfiles.d",
		"usr/lib/sysusers.d",
		"usr/share/doc/lindm-agent",
		"etc/lindm",
	}
	for _, dir := range dirs {
		if err := mkdir(filepath.Join(root, dir), epoch); err != nil {
			return "", nil, "", err
		}
	}
	config, err := AgentConfigJSON()
	if err != nil {
		return "", nil, "", err
	}
	files := []struct {
		rel  string
		mode os.FileMode
		conf bool
		body []byte
		name string
	}{
		{rel: "usr/lib/systemd/system/" + executorUnit, mode: 0o644, name: "lindm-executor.service"},
		{rel: "usr/lib/systemd/system/" + agentUnit, mode: 0o644, name: "lindm-agent.service"},
		{rel: "usr/lib/tmpfiles.d/lindm.conf", mode: 0o644, name: "tmpfiles.conf"},
		{rel: "usr/lib/sysusers.d/lindm.conf", mode: 0o644, name: "sysusers.conf"},
		{rel: lifecyclePath[1:], mode: 0o755, name: "lifecycle.sh"},
		{rel: "usr/share/doc/lindm-agent/copyright", mode: 0o644, name: "copyright"},
		{rel: "etc/lindm/executor.json", mode: 0o640, conf: true, body: config},
		{rel: "etc/lindm/agent.json", mode: 0o644, conf: true, body: config},
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
	binaryRel := BinaryPath[1:]
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
	stamp := time.Unix(epoch, 0)
	if err := os.Chtimes(root, stamp, stamp); err != nil {
		return "", nil, "", err
	}
	return root, staged, want, nil
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
