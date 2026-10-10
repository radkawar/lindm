package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

const cacheMarker = "lindm verified image cache v1\n"

// Fetch acquires an image into a private, marked cache. Only a complete verified
// directory is published under the image digest. Existing entries are reverified
// without writes; corrupt entries fail closed and require explicit operator
// inspection/removal rather than automatic replacement.
func (f Fetcher) Fetch(ctx context.Context, m *labv1.ImageManifest, cacheDir string) (_ *VerifiedImage, err error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED {
		verified, err := VerifyCache(ctx, m, cacheDir)
		if err != nil {
			return nil, fmt.Errorf("authenticated vendor cache unavailable; acquire with lab images redhat fetch: %w", err)
		}
		return verified, nil
	}
	root, err := openCache(ctx, cacheDir, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	lock, err := lockImage(ctx, root, m.Sha256)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	entry := "sha256-" + m.Sha256
	partial := "." + entry + ".partial"
	// The marker reserves this namespace for the harness. Holding the persistent
	// per-digest flock excludes live writers, including other lab processes.
	if err := root.RemoveAll(partial); err != nil {
		return nil, fmt.Errorf("clean interrupted image staging: %w", err)
	}
	if _, err := root.Lstat(entry); err == nil {
		return verifyEntry(ctx, root, entry, m)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := root.Mkdir(partial, 0700); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.RemoveAll(partial)) }()
	client := f.client()
	defer client.CloseIdleConnections()
	for _, source := range []struct{ name, url string }{
		{"checksums", m.ChecksumUrl},
		{"key", m.KeyUrl},
	} {
		if err := download(ctx, client, root, partial+"/"+source.name, source.url, maxMetadataBytes, 2*time.Minute); err != nil {
			return nil, err
		}
	}
	var signature []byte
	if detachedChecksum(m.ChecksumMode) {
		if err := download(ctx, client, root, partial+"/signature", m.GetSignatureUrl(), maxMetadataBytes, 2*time.Minute); err != nil {
			return nil, err
		}
		signature, err = readCacheFile(root, partial+"/signature", maxMetadataBytes)
		if err != nil {
			return nil, err
		}
	}
	checksum, err := readCacheFile(root, partial+"/checksums", maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	key, err := readCacheFile(root, partial+"/key", maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	metadata, err := verifyMetadata(ctx, m, checksum, signature, key)
	if err != nil {
		return nil, err
	}
	if err := download(ctx, client, root, partial+"/image", m.ImageUrl, int64(m.ImageSizeBytes), 30*time.Minute); err != nil {
		return nil, err
	}
	result, err := verifyImage(ctx, m, filepath.Join(root.Name(), partial, "image"), metadata)
	if err != nil {
		return nil, err
	}
	files := []string{"image", "checksums", "key"}
	if detachedChecksum(m.ChecksumMode) {
		files = append(files, "signature")
	}
	if err := publishImageCache(root, partial, entry, files); err != nil {
		return nil, err
	}
	result.Path = filepath.Join(root.Name(), entry, "image")
	return result, nil
}

// VerifyCache is offline: it rechecks signatures for signed manifests, or the
// local vendor receipt for authenticated acquisitions, then exact size and bytes.
func VerifyCache(ctx context.Context, m *labv1.ImageManifest, cacheDir string) (_ *VerifiedImage, err error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	root, err := openCache(ctx, cacheDir, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	lock, err := lockImage(ctx, root, m.Sha256)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	return verifyEntry(ctx, root, "sha256-"+m.Sha256, m)
}

func verifyEntry(ctx context.Context, root *os.Root, entry string, m *labv1.ImageManifest) (*VerifiedImage, error) {
	info, err := root.Lstat(entry)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("cached image entry must be a directory, not a symlink")
	}
	base := filepath.Join(root.Name(), entry)
	result, err := VerifyArtifacts(ctx, m, Artifacts{
		Image:     filepath.Join(base, "image"),
		Checksum:  filepath.Join(base, "checksums"),
		Signature: filepath.Join(base, "signature"),
		Key:       filepath.Join(base, "key"),
	})
	if err != nil {
		return nil, fmt.Errorf("cached image failed verification; inspect %s before explicit removal: %w", base, err)
	}
	return result, nil
}

func openCache(ctx context.Context, directory string, create bool) (_ *os.Root, err error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("image cache directory is required")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(absolute, 0700); err != nil {
			return nil, err
		}
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("image cache must be a directory, not a symlink")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, root.Close())
		}
	}()
	info, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !os.SameFile(before, info) || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("image cache must be owned by the current user and not group/world writable")
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	if err := acquireLock(ctx, dir); err != nil {
		return nil, err
	}
	marker, err := readCacheFile(root, ".lindm-images", 128)
	if errors.Is(err, fs.ErrNotExist) && create {
		entries, readErr := dir.ReadDir(-1)
		if readErr != nil {
			return nil, readErr
		}
		if len(entries) != 0 {
			return nil, errors.New("refusing to initialize an unmarked nonempty image cache")
		}
		// Publish the marker only after the hierarchy created by MkdirAll is
		// durable. The initialization flock also covers concurrent creators.
		if err := syncCacheParents(ctx, absolute); err != nil {
			return nil, err
		}
		file, openErr := root.OpenFile(".lindm-images", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return nil, openErr
		}
		_, writeErr := file.WriteString(cacheMarker)
		if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
			return nil, err
		}
		if err := dir.Sync(); err != nil {
			return nil, err
		}
		marker = []byte(cacheMarker)
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("read image cache ownership marker: %w", err)
	}
	if string(marker) != cacheMarker {
		return nil, errors.New("image cache ownership marker is invalid")
	}
	return root, nil
}

// A directory fsync persists entries inside it, not its own entry in its parent.
// This runs once before the initialized marker, not on every image/cache read.
func syncCacheParents(ctx context.Context, directory string) error {
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("open image cache parent for durability: %w", err)
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return fmt.Errorf("sync image cache parent: %w", err)
		}
		if filepath.Dir(parent) == parent {
			return nil
		}
	}
}

func readCacheFile(root *os.Root, name string, limit int64) (_ []byte, err error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("cache artifact must be a regular file")
	}
	return readLimited(file, limit)
}

func lockImage(ctx context.Context, root *os.Root, digest string) (*os.File, error) {
	file, err := root.OpenFile("."+digest+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("image lock must be a private, singly linked regular file owned by the current user")
	}
	if err := acquireLock(ctx, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func acquireLock(ctx context.Context, file *os.File) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func syncDirectory(root *os.Root, name string) error {
	dir, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
