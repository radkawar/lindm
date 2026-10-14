// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

// maxMeasuredKernelBytes bounds a decompressed vendor kernel image.
const maxMeasuredKernelBytes = 512 << 20

// MeasuredKernelSHA256 returns the digest GRUB measures for a vendor kernel
// file: the file bytes, or for a gzip-compressed kernel (Ubuntu/Debian arm64
// Image.gz) the decompressed image GRUB's loader reads through gzio. The
// `.kernel` release target and every comparison with an event log use this
// form. The file must be a regular file without group/world write access.
func MeasuredKernelSHA256(name string) (_ []byte, err error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("recoveryboot: unsafe_ingredient")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	reader := bufio.NewReader(file)
	magic, err := reader.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var source io.Reader = reader
	if bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, compressed.Close()) }()
		// A concatenated or trailing member would not be one kernel image.
		compressed.Multistream(false)
		source = compressed
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(source, maxMeasuredKernelBytes+1))
	if err != nil {
		return nil, err
	}
	if written > maxMeasuredKernelBytes {
		return nil, errors.New("recoveryboot: vendor_kernel_too_large")
	}
	return hash.Sum(nil), nil
}

// matchesMeasuredKernel reports whether the vendor kernel file is the kernel
// whose GRUB measurement is want.
func matchesMeasuredKernel(name string, want []byte) error {
	got, err := MeasuredKernelSHA256(name)
	if err != nil {
		return err
	}
	if !equalDigest(got, want) {
		return errors.New("recoveryboot: ingredient_digest_mismatch")
	}
	return nil
}
