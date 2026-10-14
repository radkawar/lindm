// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

type redHatAdmissionReader struct {
	remaining int64
	read      int64
}

func (r *redHatAdmissionReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	clear(p[:n])
	r.remaining -= n
	r.read += n
	return int(n), nil
}

type redHatAdmissionWriter struct {
	written int64
}

func (w *redHatAdmissionWriter) Write(p []byte) (int, error) {
	w.written += int64(len(p))
	return len(p), nil
}

func TestRedHatStream128MiBAdmissionBoundary(t *testing.T) {
	// Exercise the actual staging helper without allocating a synthetic record
	// or making a giant JSON-whitespace scan stand in for real CSAF coverage.
	const limit int64 = 128 << 20
	if redHatRecordBytes != limit {
		t.Fatalf("RHEL document admission changed: got %d want %d", redHatRecordBytes, limit)
	}
	for _, test := range []struct {
		name     string
		size     int64
		overflow bool
	}{
		{"below", limit - 1, false},
		{"exact", limit, false},
		{"one-over", limit + 1, true},
		{"far-over", 2 * limit, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &redHatAdmissionReader{remaining: test.size}
			output := &redHatAdmissionWriter{}
			err := copyArchive(t.Context(), output, input, redHatRecordBytes)
			if (err != nil) != test.overflow {
				t.Fatalf("admission at %d bytes: %v", test.size, err)
			}
			if output.written != min(test.size, limit) || input.read != min(test.size, limit+1) {
				t.Fatalf("unbounded admission: read=%d written=%d", input.read, output.written)
			}
		})
	}
}

func TestRedHatStreamLargestArchiveMember(t *testing.T) {
	// Repack the exact authenticated vendor member, streaming gzip -> tar.zst.
	// This is deliberately not a fabricated large JSON object or an allocated
	// tar byte slice: the archive parser must process the real 46,707,671 bytes.
	file, err := os.Create(filepath.Join(t.TempDir(), "rhsa-2024_9315.tar.zst"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	compressor, err := zstd.NewWriter(file, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(compressor)
	if err := archive.WriteHeader(&tar.Header{Name: "2024/rhsa-2024_9315.json", Typeflag: tar.TypeReg, Mode: 0600, Size: redHatLargeFixtureBytes}); err != nil {
		t.Fatal(err)
	}
	input := redHatLargeFixture(t)
	if n, err := io.Copy(archive, input); err != nil || n != redHatLargeFixtureBytes || input.N != 1 {
		t.Fatalf("copy exact original into archive: bytes=%d remaining=%d err=%v", n, input.N, err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	config := redHatSource("9.8", "standard")
	config.Format = advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES
	config.Url = "https://security.access.redhat.com/data/csaf/v2/"
	consume, assertClaims := redHatLargeConsumer(t, config.Url)
	if err := parseRedHatArchiveStream(t.Context(), config, file, redHatValidator(t), consume); err != nil {
		t.Fatal(err)
	}
	assertClaims()
}
