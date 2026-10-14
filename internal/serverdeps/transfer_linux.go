// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverdeps

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

// Export authenticates the closure and streams only its exact manifest allowlist.
// The wire format is a big-endian uint32 JSON length, that bounded manifest, then
// each sorted file's exact bytes. There are no sender-controlled archive headers.
func Export(ctx context.Context, cache, digest string, output io.Writer) (err error) {
	manifest, repository, err := Load(cache, digest)
	if err != nil {
		return err
	}
	data, err := protojson.Marshal(manifest)
	if err != nil || len(data) > maxManifestBytes {
		return errors.Join(err, errors.New("snapshot transfer manifest exceeds bound"))
	}
	root, err := openSnapshotRoot(repository)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := binary.Write(output, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if n, err := output.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	for _, entry := range manifest.GetFiles() {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := unix.Openat2(int(root.Fd()), entry.GetPath(), &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), entry.GetPath())
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != entry.GetSizeBytes() {
			return errors.Join(err, file.Close(), errors.New("snapshot export file changed"))
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(output, hash), file, int64(entry.GetSizeBytes()))
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != entry.GetSha256() {
			return fmt.Errorf("snapshot export digest changed: %s", entry.GetPath())
		}
	}
	return nil
}

func readTransferManifest(input io.Reader, digest string) (*serverdepsv1.Manifest, []byte, error) {
	if !validDigest(digest) {
		return nil, nil, errors.New("invalid snapshot transfer content address")
	}
	var size uint32
	if err := binary.Read(input, binary.BigEndian, &size); err != nil {
		return nil, nil, err
	}
	if size == 0 || size > maxManifestBytes {
		return nil, nil, errors.New("snapshot transfer manifest exceeds bound")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(input, data); err != nil {
		return nil, nil, err
	}
	manifest := new(serverdepsv1.Manifest)
	if err := protojson.Unmarshal(data, manifest); err != nil {
		return nil, nil, err
	}
	actual, err := identity(manifest)
	if err != nil || actual != digest || manifest.GetManifestSha256() != digest {
		return nil, nil, errors.New("snapshot transfer content address mismatch")
	}
	if err := validateManifestBounds(manifest); err != nil {
		return nil, nil, err
	}
	return manifest, data, nil
}

// Import enforces all bounds before transfer, verifies every received digest,
// and authenticates the completed private closure before atomic publication.
// Extra files, links and directories cannot be represented by this protocol.
func Import(ctx context.Context, cache, digest string, input io.Reader) (err error) {
	manifest, data, err := readTransferManifest(input, digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cache, 0700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(cache, ".repository-transfer-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	entry := filepath.Join(staging, "server-dependencies", "sha256", digest)
	if err := os.MkdirAll(filepath.Join(entry, "repository"), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(entry, "manifest.json"), data, 0400); err != nil {
		return err
	}
	for _, item := range manifest.GetFiles() {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.Join(entry, "repository", filepath.FromSlash(item.GetPath()))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(file, hash), input, int64(item.GetSizeBytes()))
		closeErr := errors.Join(file.Sync(), file.Close())
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.GetSha256() {
			return fmt.Errorf("snapshot transfer digest mismatch: %s", item.GetPath())
		}
	}
	var extra [1]byte
	if n, err := io.ReadFull(input, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("snapshot transfer contains extra or incomplete framing")
	}
	if _, _, err := Load(staging, digest); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(entry, "manifest.json"), 0600); err != nil {
		return err
	}
	_, _, err = Publish(ctx, cache, entry, manifest)
	return err
}
