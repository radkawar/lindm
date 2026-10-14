// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"lindm/internal/custody"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/statefs"
)

// atomicFile is used for private plan bytes and native pin replacement. Both the
// file and its directory are synchronized before the caller records ownership.
func atomicFile(path string, data []byte, mode fs.FileMode) (err error) {
	parent := filepath.Dir(path)
	fd, err := statefs.OpenTemporaryParent(parent)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	f, err := os.CreateTemp(parent, ".lindm-package-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer func() {
		if temporary != "" {
			err = errors.Join(err, os.Remove(temporary))
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err = f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	temporary = ""
	return unix.Fsync(fd)
}

func removeFile(path string) error {
	fd, err := statefs.OpenTemporaryParent(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return unix.Fsync(fd)
}

func hashFile(path string) (digest []byte, size uint64, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 8<<30 {
		return nil, 0, errors.New("packageprovider: unsafe artifact")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, stat.Size+1))
	if err != nil {
		return nil, 0, err
	}
	if n != stat.Size {
		return nil, 0, errors.New("packageprovider: artifact changed during hashing")
	}
	return hash.Sum(nil), uint64(n), nil
}

func artifactFor(path string) (*resourcev1.ArtifactRef, error) {
	digest, size, err := hashFile(path)
	if err != nil {
		return nil, err
	}
	return &resourcev1.ArtifactRef{Sha256: digest, SizeBytes: size, ArtifactId: uuid.NewSHA1(uuid.NameSpaceOID, digest).String()}, nil
}

func checkArtifact(path string, ref *resourcev1.ArtifactRef) error {
	digest, size, err := hashFile(path)
	if err != nil {
		return err
	}
	if ref == nil || size != ref.GetSizeBytes() || !bytes.Equal(digest, ref.GetSha256()) {
		return errors.New("packageprovider: staged artifact changed")
	}
	return nil
}

func digestMessage(message proto.Message) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

// snapshotDirectory commits the exact downloaded metadata and solver artifacts,
// including relative filenames; unrecognized symlinks/devices are never skipped.
func snapshotDirectory(directory string) ([]byte, error) {
	h := sha256.New()
	count := 0
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("packageprovider: symlink in native snapshot")
		}
		// Native lock files and transient partial-download directories carry no
		// source metadata. A nonempty partial file is nevertheless an error.
		rel, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if filepath.Base(path) == "lock" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() == 0 {
			return nil
		}
		if strings.HasPrefix(rel, "partial/") {
			return errors.New("packageprovider: incomplete native download")
		}
		count++
		if count > 10000 {
			return errors.New("packageprovider: native snapshot capacity")
		}
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(rel), rel, size)
		_, _ = h.Write(digest)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("packageprovider: empty source metadata")
	}
	return h.Sum(nil), nil
}

func syncTree(directory string) error {
	var directories []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		return errors.Join(f.Sync(), f.Close())
	})
	if err != nil {
		return err
	}
	slices.Reverse(directories)
	for _, path := range directories {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) storeManifest(directory string, manifest *resourcev1.PackageTransactionManifest) (*resourcev1.ArtifactRef, error) {
	if err := validateMessage(manifest); err != nil {
		return nil, err
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if len(data) > 256<<10 {
		return nil, errors.New("packageprovider: transaction manifest capacity")
	}
	digest := sha256.Sum256(data)
	path := filepath.Join(directory, "manifest.pb")
	if err := atomicFile(path, data, 0600); err != nil {
		return nil, err
	}
	if err := syncTree(directory); err != nil {
		return nil, err
	}
	transactionID := filepath.Base(directory)
	if parsed, err := uuid.Parse(transactionID); err != nil || parsed.String() != transactionID {
		return nil, ErrConflict
	}
	return &resourcev1.ArtifactRef{Sha256: digest[:], SizeBytes: uint64(len(data)), ArtifactId: transactionID}, nil
}

func (p *Provider) loadManifest(ref *resourcev1.ArtifactRef) (*resourcev1.PackageTransactionManifest, string, error) {
	if len(ref.GetSha256()) != sha256.Size {
		return nil, "", ErrConflict
	}
	if parsed, err := uuid.Parse(ref.GetArtifactId()); err != nil || parsed.String() != ref.GetArtifactId() {
		return nil, "", ErrConflict
	}
	directory := filepath.Join(p.state, ref.GetArtifactId())
	if err := checkArtifact(filepath.Join(directory, "manifest.pb"), ref); err != nil {
		return nil, "", err
	}
	data, err := custody.ReadRoot(filepath.Join(directory, "manifest.pb"), 256<<10, false)
	if err != nil {
		return nil, "", err
	}
	manifest := new(resourcev1.PackageTransactionManifest)
	if err := proto.Unmarshal(data, manifest); err != nil {
		return nil, "", err
	}
	if err := validateMessage(manifest); err != nil {
		return nil, "", err
	}
	return manifest, directory, nil
}
