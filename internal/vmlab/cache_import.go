// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	labv1 "lindm/gen/lindm/lab/v1"
)

// InitializeImageCache applies the existing ownership marker and initialization
// lock before another cache namespace publishes entries alongside base images.
// Unmarked nonempty directories remain forbidden.
func InitializeImageCache(ctx context.Context, directory string) error {
	root, err := openCache(ctx, directory, true)
	if err != nil {
		return err
	}
	return root.Close()
}

// ImportCache publishes an rsync-staged authenticated entry into the host's
// persistent image cache. The destination uses the ordinary cache locks and
// verifier. Existing entries are reverified, never replaced or repaired.
func ImportCache(ctx context.Context, manifest *labv1.ImageManifest, source, destination string) (_ *VerifiedImage, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	root, err := openCache(ctx, destination, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	lock, err := lockImage(ctx, root, manifest.Sha256)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	entry := "sha256-" + manifest.Sha256
	if _, err := root.Lstat(entry); err == nil {
		return verifyEntry(ctx, root, entry, manifest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := VerifyCache(ctx, manifest, source); err != nil {
		return nil, fmt.Errorf("verify staged image: %w", err)
	}
	partial := "." + entry + ".partial"
	if err := root.RemoveAll(partial); err != nil {
		return nil, err
	}
	if err := root.Mkdir(partial, 0700); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.RemoveAll(partial)) }()
	files := []string{"image", "checksums", "key"}
	if detachedChecksum(manifest.ChecksumMode) {
		files = append(files, "signature")
	}
	if manifest.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED {
		files = []string{"image", "checksums"}
	}
	buffer := make([]byte, 1<<20)
	for _, name := range files {
		if err := copyStagedCacheFile(ctx, filepath.Join(source, entry, name), root, partial+"/"+name, buffer); err != nil {
			return nil, err
		}
	}
	verified, err := verifyEntry(ctx, root, partial, manifest)
	if err != nil {
		return nil, err
	}
	if err := publishImageCache(root, partial, entry, files); err != nil {
		return nil, err
	}
	verified.Path = filepath.Join(root.Name(), entry, "image")
	return verified, nil
}

func copyStagedCacheFile(ctx context.Context, source string, root *os.Root, destination string, buffer []byte) (err error) {
	input, err := openRegular(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := root.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			if _, err := output.Write(buffer[:n]); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
