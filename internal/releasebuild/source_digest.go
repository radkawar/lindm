//go:build linux

package releasebuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceDigest hashes the exact bounded source selected by the release capture,
// without copying it or compiling anything. Cache consumers must compare the
// resulting build's source digest again before publishing a new cache entry.
func SourceDigest(ctx context.Context, repository string) (string, error) {
	paths, err := sourcePaths(ctx, repository)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(repository)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	hash := sha256.New()
	var total int64
	for _, name := range paths {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("releasebuild: source %s is not regular", name)
		}
		total += info.Size()
		if total > 512<<20 || info.Size() > 64<<20 {
			return "", errors.New("releasebuild: source exceeds bound")
		}
		sum, size, err := sourceFileDigest(root, name, info.Size())
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hash, "%s\x00%o\x00%d\x00%s\n", name, info.Mode().Perm()&0755, size, sum); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sourceFileDigest(root *os.Root, name string, size int64) (sum string, count int64, err error) {
	file, err := root.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	count, err = io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil {
		return "", 0, err
	}
	if count != size {
		return "", 0, errors.New("releasebuild: source changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func sourcePaths(ctx context.Context, repository string) ([]string, error) {
	listed, err := command(ctx, repository, nil, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	paths := strings.Split(strings.TrimSuffix(string(listed), "\x00"), "\x00")
	if len(paths) > 100000 {
		return nil, errors.New("releasebuild: source file count exceeds bound")
	}
	// Match filepath.WalkDir's component ordering, not flat path ordering.
	sort.Slice(paths, func(i, j int) bool { return sourcePathLess(paths[i], paths[j]) })
	kept := paths[:0]
	previous := ""
	for _, name := range paths {
		if name == previous {
			continue
		}
		previous = name
		if !filepath.IsLocal(name) {
			return nil, errors.New("releasebuild: invalid source path")
		}
		ignored := false
		for _, prefix := range []string{".git/", ".cache/", ".tools/", "artifacts/", "node_modules/", "web/dist/"} {
			if strings.HasPrefix(name, prefix) {
				ignored = true
				break
			}
		}
		if !ignored {
			kept = append(kept, name)
		}
	}
	return kept, nil
}

func sourcePathLess(a, b string) bool {
	for {
		partA, restA, moreA := strings.Cut(a, "/")
		partB, restB, moreB := strings.Cut(b, "/")
		if partA != partB {
			return partA < partB
		}
		if !moreA || !moreB {
			return !moreA && moreB
		}
		a, b = restA, restB
	}
}
