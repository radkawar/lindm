// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// GRUB measures a gzip kernel (Ubuntu/Debian arm64 Image.gz) after gzio
// decompression, and an uncompressed or PE kernel as its file bytes.
func TestMeasuredKernelDigestMatchesGRUBForm(t *testing.T) {
	dir := t.TempDir()
	image := bytes.Repeat([]byte("ARM64 kernel image "), 4096)
	imageDigest := sha256.Sum256(image)
	for name, data := range map[string][]byte{"plain": image, "gzip": gzipBytes(t, image)} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := MeasuredKernelSHA256(path)
		if err != nil || !bytes.Equal(got, imageDigest[:]) {
			t.Fatalf("%s: digest %x err %v", name, got, err)
		}
		if err := matchesMeasuredKernel(path, imageDigest[:]); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A compressed file is never accepted under its own file digest.
	compressed := filepath.Join(dir, "gzip")
	data, err := os.ReadFile(compressed)
	if err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(data)
	if err := matchesMeasuredKernel(compressed, fileDigest[:]); err == nil {
		t.Fatal("compressed file digest accepted as the measured kernel")
	}
	// A second gzip member is not part of the measured image.
	appended := filepath.Join(dir, "appended")
	if err := os.WriteFile(appended, append(gzipBytes(t, image), gzipBytes(t, []byte("extra"))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := MeasuredKernelSHA256(appended); err != nil || !bytes.Equal(got, imageDigest[:]) {
		t.Fatalf("appended member changed digest %x err %v", got, err)
	}
	writable := filepath.Join(dir, "writable")
	if err := os.WriteFile(writable, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := MeasuredKernelSHA256(writable); err == nil {
		t.Fatal("world-writable vendor kernel accepted")
	}
}
