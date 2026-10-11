//go:build linux

package reposnapshot

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
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
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
	fd, err := unix.Open(repository, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(fd), repository)
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

func readTransferManifest(input io.Reader, digest string) (*labv1.RepositorySnapshotManifest, []byte, error) {
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
	manifest := new(labv1.RepositorySnapshotManifest)
	if err := protojson.Unmarshal(data, manifest); err != nil {
		return nil, nil, err
	}
	actual, err := identity(manifest)
	if err != nil || actual != digest || manifest.GetManifestSha256() != digest {
		return nil, nil, errors.New("snapshot transfer content address mismatch")
	}
	if manifest.GetMaxBytes() == 0 || manifest.GetMaxBytes() > HardMaxBytes || manifest.GetMaxPackages() == 0 || manifest.GetMaxPackages() > HardMaxPackages || len(manifest.GetFiles()) > int(HardMaxPackages)+256 {
		return nil, nil, errors.New("invalid snapshot transfer limits")
	}
	var total uint64
	var packages uint32
	previous := ""
	for _, entry := range manifest.GetFiles() {
		if !safePath(entry.GetPath()) || entry.GetPath() <= previous || !validDigest(entry.GetSha256()) || entry.GetSizeBytes() == 0 || entry.GetSizeBytes() > manifest.GetMaxBytes()-total {
			return nil, nil, errors.New("invalid snapshot transfer file bounds")
		}
		total += entry.GetSizeBytes()
		previous = entry.GetPath()
		if strings.HasSuffix(entry.GetPath(), ".rpm") {
			packages++
		}
	}
	if total != manifest.GetTotalBytes() || packages == 0 || packages > manifest.GetMaxPackages() {
		return nil, nil, errors.New("snapshot transfer count or total mismatch")
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
	entry := filepath.Join(staging, "repository-snapshots", "sha256", digest)
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
	_, _, err = publish(cache, entry, manifest)
	return err
}
