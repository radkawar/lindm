// Package reposnapshot captures bounded authenticated native repository closures.
package reposnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

const HardMaxBytes = uint64(16 << 30)
const HardMaxPackages = uint32(5000)
const maxManifestBytes = 8 << 20

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func safePath(s string) bool {
	if s == "" || s == "." || len(s) > 1024 || path.Clean(s) != s || strings.HasPrefix(s, "/") || s == ".." || strings.HasPrefix(s, "../") {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-+~:", c) {
			continue
		}
		return false
	}
	return true
}
func identity(m *labv1.RepositorySnapshotManifest) (string, error) {
	copy := proto.CloneOf(m)
	copy.ManifestSha256 = ""
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Load binds all trust decisions to the manifest's exact bytes. Small metadata
// is sealed in memfds before authentication/parsing; large RPMs are streamed
// once against both manifest SHA256 and the signed vendor checksum. Returned
// paths are never authority: consumers must hash bytes again before serving.
func Load(cache, digest string) (*labv1.RepositorySnapshotManifest, string, error) {
	if !validDigest(digest) {
		return nil, "", errors.New("invalid repository manifest SHA256")
	}
	cacheRoot, err := openSnapshotRoot(cache)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = cacheRoot.Close() }()
	relative := path.Join("repository-snapshots", "sha256", digest)
	entry, err := openRelative(cacheRoot, relative, true)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = entry.Close() }()
	entries, listErr := entry.ReadDir(3)
	if listErr != nil && !errors.Is(listErr, io.EOF) {
		return nil, "", listErr
	}
	if len(entries) != 2 {
		return nil, "", errors.New("snapshot entry contains unlisted content")
	}
	for _, entry := range entries {
		if entry.Name() != "manifest.json" && entry.Name() != "repository" {
			return nil, "", errors.New("snapshot entry contains unlisted content")
		}
	}
	file, err := openRelative(entry, "manifest.json", false)
	if err != nil {
		return nil, "", err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, "", errors.Join(errors.New("manifest must be a bounded regular file"), statErr, file.Close())
	}
	b, readErr := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(b) > maxManifestBytes {
		return nil, "", errors.Join(readErr, closeErr, errors.New("read bounded repository manifest"))
	}
	m := new(labv1.RepositorySnapshotManifest)
	if err := protojson.Unmarshal(b, m); err != nil {
		return nil, "", err
	}
	actual, err := identity(m)
	if err != nil || actual != digest || m.ManifestSha256 != digest {
		return nil, "", errors.New("repository manifest content address mismatch")
	}
	if err := validateManifestBounds(m); err != nil {
		return nil, "", err
	}
	root, err := openRelative(entry, "repository", true)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = root.Close() }()
	if err := validateRetainedTree(root, m); err != nil {
		return nil, "", err
	}
	if err := validateRepositoryFrom(context.Background(), root, m); err != nil {
		return nil, "", err
	}
	return m, filepath.Join(cache, filepath.FromSlash(relative), "repository"), nil
}

func validateManifestBounds(m *labv1.RepositorySnapshotManifest) error {
	if m.MaxBytes == 0 || m.MaxBytes > HardMaxBytes || m.MaxPackages == 0 || m.MaxPackages > HardMaxPackages || len(m.Files) > int(HardMaxPackages)+256 || len(m.RequestedPackages) == 0 || len(m.RequestedPackages) > int(HardMaxPackages) || len(m.BasePackages) == 0 || len(m.BasePackages) > int(HardMaxPackages) || m.SolverVersion == "" || len(m.SolverVersion) > 4096 || !validDigest(m.BaseImageSha256) {
		return errors.New("invalid closure bounds or missing native closure evidence")
	}
	var total uint64
	packages := uint32(0)
	previous := ""
	for _, item := range m.Files {
		if item == nil || !safePath(item.Path) || item.Path <= previous || !validDigest(item.Sha256) || item.SizeBytes == 0 || item.SizeBytes > m.MaxBytes-total {
			return errors.New("invalid snapshot file or aggregate bounds")
		}
		previous = item.Path
		total += item.SizeBytes
		if strings.HasSuffix(item.Path, ".rpm") {
			packages++
		}
	}
	if total != m.TotalBytes || packages == 0 || packages > m.MaxPackages {
		return errors.New("closure total/count mismatch")
	}
	return nil
}

// Reject extra cache content without recursively following sender-controlled
// links or reading an unbounded directory listing. Parent directories are the
// exact finite set implied by the manifest, not an independently trusted tree.
func validateRetainedTree(root *os.File, m *labv1.RepositorySnapshotManifest) error {
	expected := make(map[string]bool, len(m.Files)*2)
	for _, item := range m.Files {
		expected[item.Path] = false
		for parent := path.Dir(item.Path); parent != "."; parent = path.Dir(parent) {
			expected[parent] = true
			if len(expected) > 32768 {
				return errors.New("snapshot directory count bound")
			}
		}
	}
	var walk func(*os.File, string, int) error
	walk = func(directory *os.File, prefix string, depth int) error {
		if depth > 16 {
			return errors.New("snapshot directory depth bound")
		}
		for {
			entries, err := directory.ReadDir(128)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			for _, entry := range entries {
				name := path.Join(prefix, entry.Name())
				isDirectory, ok := expected[name]
				if !ok || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != isDirectory {
					return fmt.Errorf("unlisted or linked snapshot content: %s", name)
				}
				delete(expected, name)
				opened, err := openRelative(root, name, isDirectory)
				if err != nil {
					return err
				}
				if isDirectory {
					walkErr := walk(opened, name, depth+1)
					closeErr := opened.Close()
					if walkErr != nil || closeErr != nil {
						return errors.Join(walkErr, closeErr)
					}
				} else {
					info, statErr := opened.Stat()
					closeErr := opened.Close()
					if statErr != nil || closeErr != nil {
						return errors.Join(statErr, closeErr)
					}
					if !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
						return errors.New("snapshot file is not immutable regular content")
					}
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("snapshot manifest files are missing")
	}
	return nil
}

func publish(cache, staging string, m *labv1.RepositorySnapshotManifest) (_ *labv1.RepositorySnapshotManifest, _ string, err error) {
	slices.SortFunc(m.Files, func(a, b *labv1.RepositorySnapshotFile) int { return strings.Compare(a.GetPath(), b.GetPath()) })
	if err := validateManifestBounds(m); err != nil {
		return nil, "", err
	}
	digest, err := identity(m)
	if err != nil {
		return nil, "", err
	}
	m.ManifestSha256 = digest
	relative, err := filepath.Rel(cache, staging)
	if err != nil || !safePath(filepath.ToSlash(relative)) {
		return nil, "", errors.New("snapshot staging is outside the owned cache")
	}
	cacheRoot, err := openSnapshotRoot(cache)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = cacheRoot.Close() }()
	if filepath.ToSlash(relative) == path.Join("repository-snapshots", "sha256", digest) {
		return Load(cache, digest)
	}
	entry, err := openRelative(cacheRoot, filepath.ToSlash(relative), true)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = entry.Close() }()
	published := false
	defer func() {
		if !published {
			err = errors.Join(err, restoreSnapshotDirectories(entry, m))
			err = errors.Join(err, os.RemoveAll(staging))
		}
	}()
	if err := unix.Fchmod(int(entry.Fd()), 0700); err != nil {
		return nil, "", err
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	if err := writeSnapshotManifest(entry, b); err != nil {
		return nil, "", err
	}
	namespace, err := snapshotDirectory(cacheRoot, "repository-snapshots")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = namespace.Close() }()
	targetParent, err := snapshotDirectory(namespace, "sha256")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = targetParent.Close() }()
	sourceParent := cacheRoot
	if parent := path.Dir(filepath.ToSlash(relative)); parent != "." {
		sourceParent, err = openRelative(cacheRoot, parent, true)
		if err != nil {
			return nil, "", err
		}
		defer func() { _ = sourceParent.Close() }()
	}
	if err := setSnapshotModes(entry, m, 0500); err != nil {
		return nil, "", err
	}
	// RENAME_NOREPLACE makes concurrent import/capture winners explicit. A
	// loser authenticates the winner; it never overwrites or repairs an entry.
	err = unix.Renameat2(int(sourceParent.Fd()), path.Base(filepath.ToSlash(relative)), int(targetParent.Fd()), digest, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
		existing, root, loadErr := Load(cache, digest)
		if loadErr != nil {
			return nil, "", loadErr
		}
		return existing, root, nil
	}
	if err != nil {
		return nil, "", err
	}
	published = true
	// The source root must remain writable until its parent changes. Child
	// directories and payloads are already read-only through pinned descriptors.
	if err := unix.Fchmod(int(entry.Fd()), 0500); err != nil {
		return nil, "", err
	}
	return Load(cache, digest)
}
