// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

var vendorReceiptValidator, vendorReceiptValidatorErr = protovalidate.New(protovalidate.WithMessages(new(labv1.VendorImageReceipt)))

// ImportVendorImage imports bytes already acquired from the authenticated vendor
// API. It verifies the exact pinned image and sanitized receipt before publishing
// an immutable cache entry. The receipt is local provenance, not a vendor signature.
func ImportVendorImage(ctx context.Context, m *labv1.ImageManifest, cacheDir, imagePath string, receipt []byte) (_ *VerifiedImage, err error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	if m.ChecksumMode != labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED {
		return nil, errors.New("vendor import requires an authenticated vendor manifest")
	}
	if err := verifyVendorReceipt(m, receipt); err != nil {
		return nil, err
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
	if err := root.RemoveAll(partial); err != nil {
		return nil, fmt.Errorf("clean vendor image staging: %w", err)
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
	if err := copyVendorImage(ctx, root, partial+"/image", imagePath, int64(m.ImageSizeBytes)); err != nil {
		return nil, err
	}
	if err := root.WriteFile(partial+"/checksums", receipt, 0600); err != nil {
		return nil, err
	}
	result, err := verifyImage(ctx, m, filepath.Join(root.Name(), partial, "image"), verifiedMetadata{})
	if err != nil {
		return nil, err
	}
	if err := publishImageCache(root, partial, entry, []string{"image", "checksums"}); err != nil {
		return nil, err
	}
	result.Path = filepath.Join(root.Name(), entry, "image")
	return result, nil
}

func copyVendorImage(ctx context.Context, root *os.Root, destination, source string, size int64) (err error) {
	input, err := openRegular(source)
	if err != nil {
		return fmt.Errorf("open acquired vendor image: %w", err)
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := root.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	count, err := io.Copy(output, io.LimitReader(contextReader{ctx: ctx, reader: input}, size+1))
	if err != nil {
		return fmt.Errorf("copy acquired vendor image: %w", err)
	}
	if count != size {
		return errors.New("acquired vendor image size differs from pinned manifest")
	}
	return nil
}

func verifyVendorReceipt(m *labv1.ImageManifest, data []byte) error {
	if len(data) > maxMetadataBytes {
		return errors.New("vendor image receipt exceeds metadata limit")
	}
	receipt := new(labv1.VendorImageReceipt)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, receipt); err != nil {
		return errors.New("invalid vendor image receipt encoding")
	}
	if vendorReceiptValidatorErr != nil {
		return fmt.Errorf("compile vendor image receipt rules: %w", vendorReceiptValidatorErr)
	}
	if err := vendorReceiptValidator.Validate(receipt); err != nil {
		return errors.New("invalid vendor image receipt fields")
	}
	if receipt.ImageFilename != m.ImageFilename || receipt.Sha256 != m.Sha256 || receipt.ImageSizeBytes != m.ImageSizeBytes || receipt.Version != m.Version || receipt.Architecture != m.Architecture || receipt.MetadataUrl != m.ChecksumUrl {
		return errors.New("vendor image receipt differs from pinned manifest")
	}
	return nil
}

func publishImageCache(root *os.Root, partial, entry string, files []string) error {
	for _, name := range files {
		file, err := root.OpenFile(partial+"/"+name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		chmodErr := file.Chmod(0444)
		syncErr := file.Sync()
		if err := errors.Join(chmodErr, syncErr, file.Close()); err != nil {
			return err
		}
	}
	if err := syncDirectory(root, partial); err != nil {
		return err
	}
	// The private cache and per-digest flock protect the absence check through
	// rename. Never replace an existing entry, including a symlink or directory.
	if _, err := root.Lstat(entry); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("cache destination appeared during acquisition; refusing to replace it")
	}
	if err := root.Rename(partial, entry); err != nil {
		return err
	}
	return syncDirectory(root, ".")
}
