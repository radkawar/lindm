// SPDX-License-Identifier: Apache-2.0

//go:build linux

package reposnapshot

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

const maxTrustBytes = uint64(4 << 20)
const maxPrimaryBytes = uint64(256 << 20)

// Openat2 forbids every symlink component, not only the final basename. Keeping
// this directory descriptor open also binds subsequent lookups across renames.
func openSnapshotRoot(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "snapshot-root"), nil
}

func openRelative(root *os.File, path string, directory bool) (*os.File, error) {
	if !safePath(path) {
		return nil, errors.New("invalid snapshot relative path")
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func retainedFile(m *labv1.RepositorySnapshotManifest, name string) (*labv1.RepositorySnapshotFile, error) {
	for _, f := range m.Files {
		if f.Path == name {
			return f, nil
		}
	}
	return nil, fmt.Errorf("snapshot manifest omits %s", name)
}

func openRetained(root *os.File, item *labv1.RepositorySnapshotFile) (*os.File, error) {
	if item == nil || item.SizeBytes == 0 || item.SizeBytes > HardMaxBytes || !validDigest(item.Sha256) {
		return nil, errors.New("invalid retained file bounds")
	}
	f, err := openRelative(root, item.Path, false)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != item.SizeBytes {
		_ = f.Close()
		return nil, fmt.Errorf("retained file size/type mismatch: %s", item.Path)
	}
	return f, nil
}

func newSealedFile(input io.Reader, bound uint64, expected string) (*os.File, error) {
	if bound == 0 || bound > maxPrimaryBytes {
		return nil, errors.New("immutable metadata snapshot exceeds bound")
	}
	fd, err := unix.MemfdCreate("lindm-repository-auth", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "sealed-repository-metadata")
	success := false
	defer func() {
		if !success {
			_ = file.Close()
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(input, int64(bound)+1))
	if err != nil {
		return nil, err
	}
	if uint64(n) != bound || hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, errors.New("immutable metadata snapshot differs from manifest")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	success = true
	return file, nil
}

func sealRetained(root *os.File, item *labv1.RepositorySnapshotFile, limit uint64) (*os.File, error) {
	if item.SizeBytes > limit {
		return nil, errors.New("retained metadata exceeds immutable snapshot bound")
	}
	input, err := openRetained(root, item)
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	return newSealedFile(input, item.SizeBytes, item.Sha256)
}

// checkRetained hashes the manifest identity and the vendor's signed checksum
// in one stream from one no-follow descriptor. A cache writer cannot satisfy
// these checks with two different versions of the pathname.
func checkRetained(root *os.File, item *labv1.RepositorySnapshotFile, signed *checksum, size uint64) error {
	if item.SizeBytes != size {
		return fmt.Errorf("signed size differs from manifest: %s", item.Path)
	}
	file, err := openRetained(root, item)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	manifestHash := sha256.New()
	var writers []io.Writer
	writers = append(writers, manifestHash)
	var vendorHash interface{ Sum([]byte) []byte }
	if signed != nil {
		if signed.Type == "sha256" {
			if signed.Value != item.Sha256 {
				return errors.New("signed SHA256 differs from manifest")
			}
		} else {
			h, err := checksumHash(signed.Type)
			if err != nil {
				return err
			}
			writers = append(writers, h)
			vendorHash = h
		}
	}
	n, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(file, int64(size)+1))
	if err != nil {
		return err
	}
	if uint64(n) != size || hex.EncodeToString(manifestHash.Sum(nil)) != item.Sha256 {
		return fmt.Errorf("manifest digest mismatch: %s", item.Path)
	}
	if vendorHash != nil && hex.EncodeToString(vendorHash.Sum(nil)) != signed.Value {
		return fmt.Errorf("signed digest mismatch: %s", item.Path)
	}
	return nil
}

func snapshotDirectory(parent *os.File, name string) (*os.File, error) {
	if !safePath(name) || path.Base(name) != name {
		return nil, errors.New("invalid snapshot directory component")
	}
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	return openRelative(parent, name, true)
}

func writeSnapshotManifest(entry *os.File, data []byte) (err error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".manifest-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat2(int(entry.Fd()), name, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC, Mode: 0400, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() {
		unlinkErr := unix.Unlinkat(int(entry.Fd()), name, 0)
		if !errors.Is(unlinkErr, unix.ENOENT) {
			err = errors.Join(err, unlinkErr)
		}
	}()
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	closeErr := errors.Join(file.Sync(), file.Close())
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	return unix.Renameat(int(entry.Fd()), name, int(entry.Fd()), "manifest.json")
}

func snapshotDirectories(m *labv1.RepositorySnapshotManifest) map[string]bool {
	directories := map[string]bool{"repository": true}
	for _, item := range m.Files {
		for parent := path.Dir(item.Path); parent != "."; parent = path.Dir(parent) {
			directories["repository/"+parent] = true
		}
	}
	return directories
}

func setSnapshotModes(entry *os.File, m *labv1.RepositorySnapshotManifest, directoryMode uint32) error {
	for _, item := range m.Files {
		file, err := openRelative(entry, "repository/"+item.Path, false)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &stat)
		if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
			return errors.Join(errors.New("snapshot publication refuses linked or nonregular files"), statErr, file.Close())
		}
		modeErr := unix.Fchmod(int(file.Fd()), 0400)
		closeErr := file.Close()
		if modeErr != nil || closeErr != nil {
			return errors.Join(modeErr, closeErr)
		}
	}
	for name := range snapshotDirectories(m) {
		directory, err := openRelative(entry, name, true)
		if err != nil {
			return err
		}
		modeErr := unix.Fchmod(int(directory.Fd()), directoryMode)
		closeErr := directory.Close()
		if modeErr != nil || closeErr != nil {
			return errors.Join(modeErr, closeErr)
		}
	}
	return nil
}

func restoreSnapshotDirectories(entry *os.File, m *labv1.RepositorySnapshotManifest) error {
	result := unix.Fchmod(int(entry.Fd()), 0700)
	for name := range snapshotDirectories(m) {
		directory, err := openRelative(entry, name, true)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		result = errors.Join(result, unix.Fchmod(int(directory.Fd()), 0700), directory.Close())
	}
	return result
}
