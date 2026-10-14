// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

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
	"strings"
)

// snapshotServerSource makes all upgrade/reproducibility builds consume the same
// bounded working-tree bytes, even while unrelated developers edit the checkout.
// This is not a clean-commit or release-provenance claim. Only Go build inputs
// (including SQL/native assets and the already-built console) are retained.
func snapshotServerSource(ctx context.Context, source, destination string) (string, error) {
	root, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return "", err
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	var total int64
	var entries int
	for _, input := range []string{"go.mod", "go.sum", "cmd", "internal", "db", "gen", "web"} {
		err := filepath.WalkDir(filepath.Join(root, input), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			entries++
			if entries > 32768 {
				return errors.New("server source snapshot exceeds entry limit")
			}
			if entry.IsDir() && (entry.Name() == "node_modules" || entry.Name() == ".cache") {
				return filepath.SkipDir
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return errors.New("source snapshot escaped checkout")
			}
			target := filepath.Join(destination, relative)
			if entry.IsDir() {
				return os.MkdirAll(target, 0700)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 64<<20 {
				return errors.New("source snapshot requires bounded regular files without symlinks")
			}
			total += info.Size()
			if total > 512<<20 {
				return errors.New("server source snapshot exceeds 512 MiB")
			}
			if _, err := fmt.Fprintf(hash, "%s\x00%d\x00", relative, info.Size()); err != nil {
				return err
			}
			return copyServerInput(ctx, path, target, info, hash, buffer)
		})
		if err != nil {
			return "", fmt.Errorf("snapshot server source: %w", err)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyServerInput(ctx context.Context, source, destination string, before fs.FileInfo, hash io.Writer, buffer []byte) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	opened, err := input.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) || before.Size() != opened.Size() || !before.ModTime().Equal(opened.ModTime()) {
		return errors.New("server source changed while opening")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	count, err := io.CopyBuffer(io.MultiWriter(output, hash), io.LimitReader(input, before.Size()+1), buffer)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := input.Stat()
	if err != nil {
		return err
	}
	if count != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("server source changed while copying")
	}
	return nil
}
