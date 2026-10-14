// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

const maxDocument = 32 << 20
const maxArtifact = 5 << 30

// command never inherits Go, npm, shell startup or signing credentials.
func command(ctx context.Context, dir string, environment []string, name string, args ...string) ([]byte, error) {
	return commandWithFiles(ctx, dir, environment, nil, name, args...)
}

// commandWithFiles grants only the packaging helper explicitly selected secret
// descriptors. Compiler, npm and ordinary command calls inherit none.
func commandWithFiles(ctx context.Context, dir string, environment []string, files []*os.File, name string, args ...string) ([]byte, error) {
	stdout, stderr := nativeexec.NewBuffer(maxDocument), nativeexec.NewBuffer(maxDocument)
	env := append([]string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C", "TZ=UTC"}, environment...)
	bound := 15 * time.Minute
	if filepath.Base(name) == "go" && len(args) > 0 && args[0] == "build" {
		// Isolated cold compiler caches compete with the native lab on one host.
		bound = 45 * time.Minute
	}
	started := time.Now()
	err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: dir, Files: files, Stdout: stdout, Stderr: stderr, Timeout: bound})
	if err == nil && (stdout.Truncated() || stderr.Truncated()) {
		err = errors.New("releasebuild: tool output exceeds bound")
	}
	if err != nil {
		return nil, fmt.Errorf("releasebuild: %s after %s: %w\nstdout:\n%s\nstderr:\n%s", name, time.Since(started).Round(time.Millisecond), err, stdout.String(), stderr.String())
	}
	return stdout.Bytes(), nil
}

func digestFile(path string) (sum string, size int64, err error) {
	return digestBoundedFile(path, maxArtifact)
}

func digestBoundedFile(path string, bound int64) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > bound {
		return "", 0, errors.New("releasebuild: artifact is not a bounded regular file")
	}
	h := sha256.New()
	size, err = io.Copy(h, io.LimitReader(f, bound+1))
	if err != nil {
		return "", 0, err
	}
	if size > bound {
		return "", 0, errors.New("releasebuild: artifact grew beyond bound")
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func writeNew(path string, data []byte, mode fs.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func copyNew(src, dst string, mode fs.FileMode) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	n, err := io.Copy(out, io.LimitReader(in, maxArtifact+1))
	if err != nil {
		return err
	}
	if n > maxArtifact {
		return errors.New("releasebuild: copied artifact exceeds bound")
	}
	return out.Sync()
}

// snapshot selects tracked and nonignored source, excludes generated build trees,
// rejects links/special files and copies once before either builder can observe it.
func snapshot(ctx context.Context, repository, destination string) error {
	paths, err := sourcePaths(ctx, repository)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(repository)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var total int64
	for _, name := range paths {
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("releasebuild: source %s is not regular", name)
		}
		total += info.Size()
		if total > 512<<20 || info.Size() > 64<<20 {
			return errors.New("releasebuild: source exceeds bound")
		}
		target := filepath.Join(destination, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		input, err := root.Open(name)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0755)
		if err != nil {
			_ = input.Close()
			return err
		}
		if err := output.Chmod(info.Mode().Perm() & 0755); err != nil {
			return errors.Join(err, input.Close(), output.Close())
		}
		n, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
		err = errors.Join(copyErr, input.Close(), output.Close())
		if err != nil {
			return err
		}
		if n != info.Size() {
			return errors.New("releasebuild: source changed during capture")
		}
	}
	return nil
}

func treeDigest(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("releasebuild: source link or special file")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, size, err := digestFile(path)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(h, "%s\x00%o\x00%d\x00%s\n", filepath.ToSlash(rel), info.Mode().Perm(), size, sum)
		return err
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copySource(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyNew(path, target, info.Mode().Perm())
	})
}

// prepareWritableBuildSource mutates only a private builder tree after its
// original permissions and contents have been verified against the source digest.
func prepareWritableBuildSource(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("releasebuild: source link or special file")
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err == nil && !info.Mode().IsRegular() {
			err = errors.New("releasebuild: source link or special file")
		}
		if err == nil {
			err = file.Chmod(info.Mode().Perm() | 0200)
		}
		return errors.Join(err, file.Close())
	})
}

func readBounded(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("releasebuild: invalid bounded document")
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("releasebuild: document grew beyond bound")
	}
	return data, err
}

// captureBuildSource snapshots source and explicitly pinned release inputs once
// before either isolated builder starts.
func captureBuildSource(ctx context.Context, work, repository string, caBundle []byte) (string, string, error) {
	source := filepath.Join(work, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		return "", "", err
	}
	if err := snapshot(ctx, repository, source); err != nil {
		return "", "", err
	}
	if len(caBundle) != 0 {
		if err := os.Mkdir(filepath.Join(source, filepath.Dir(capturedCAPath)), 0700); err != nil {
			return "", "", err
		}
		if err := writeNew(filepath.Join(source, capturedCAPath), caBundle, 0644); err != nil {
			return "", "", err
		}
	}
	digest, err := treeDigest(source)
	return source, digest, err
}
