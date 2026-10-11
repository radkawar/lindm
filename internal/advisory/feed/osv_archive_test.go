package feed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func osvZip(t *testing.T, entries map[string][]byte, method uint16) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for name, raw := range entries {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestOSVArchiveStagingAndLimits(t *testing.T) {
	raw := fixture(t, "ubuntu-USN-6859-1.json")
	valid := osvZip(t, map[string][]byte{"notice.json": raw}, zip.Store)
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	config.Url = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
	for _, test := range []struct {
		name    string
		archive []byte
		reason  string
	}{
		{"valid", valid, ""},
		{"truncated", valid[:len(valid)-12], "open OSV ZIP"},
		{"entry-oversize", osvZip(t, map[string][]byte{"large.json": bytes.Repeat([]byte("x"), maxOSVRecordBytes+1)}, zip.Store), "unsupported or duplicate"},
		{"ratio", osvZip(t, map[string][]byte{"bomb.json": bytes.Repeat([]byte("x"), maxOSVRecordBytes)}, zip.Deflate), "compression ratio"},
		{"path", osvZip(t, map[string][]byte{"../notice.json": raw}, zip.Store), "unsupported or duplicate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			doc, err := Parse(config, bytes.NewReader(test.archive))
			if test.reason != "" {
				if err == nil || !strings.Contains(err.Error(), test.reason) {
					t.Fatalf("error = %v, want %s", err, test.reason)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(valid)
				if !doc.CompleteSnapshot || !bytes.Equal(doc.SourceSha256, digest[:]) || len(doc.Advisories) == 0 {
					t.Fatal("coverage/digest/findings lost")
				}
			}
			files, err := os.ReadDir(temp)
			if err != nil || len(files) != 0 {
				t.Fatalf("staging leaked: %v, %v", files, err)
			}
		})
	}
	config.ExpectedSha256 = make([]byte, 32)
	if _, err := Parse(config, bytes.NewReader(valid)); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("pin not enforced: %v", err)
	}
}

func TestOSVArchiveDownloadBounds(t *testing.T) {
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json")}, zip.Store)
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if chunked {
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
					}
				} else {
					w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.CreateTemp(t.TempDir(), "download")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			}()
			if _, err := client.downloadArchive(t.Context(), server.URL, file, int64(len(raw)-1), nil); err == nil {
				t.Fatal("oversize accepted")
			}
			info, err := file.Stat()
			if err != nil || info.Size() > int64(len(raw)-1) {
				t.Fatalf("wrote past cap: %v %v", info, err)
			}
		})
	}
}

func TestOSVArchiveCountAndEarlyScope(t *testing.T) {
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for i := 0; i <= maxEntries; i++ {
		if _, err := writer.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("%d.json", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	if _, err := Parse(config, bytes.NewReader(out.Bytes())); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("entry limit: %v", err)
	}
	foreign := []byte(`{"id":"FOREIGN","schema_version":"1.7.3","affected":[{"package":{"ecosystem":"Debian:12"},"ranges":"not decoded for foreign ecosystem"}]}`)
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json"), "foreign.json": foreign}, zip.Store)
	if _, err := Parse(config, bytes.NewReader(raw)); err != nil {
		t.Fatalf("foreign payload fully decoded: %v", err)
	}
	config.MaxArchiveBytes = proto.Uint64(1 << 20)
	if _, err := Parse(config, io.LimitReader(zeroReader{}, (1<<20)+1)); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("configured limit: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := copyArchive(ctx, io.Discard, bytes.NewReader(raw), int64(len(raw))); err == nil {
		t.Fatal("cancellation ignored")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestOSVArchiveTransferChecksum(t *testing.T) {
	raw := []byte("bounded archive")
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc32.Checksum(raw, crc32.MakeTable(crc32.Castagnoli)))
	correct := base64.StdEncoding.EncodeToString(checksum[:])
	for _, test := range []struct {
		name, header string
		wantError    bool
	}{
		{"correct", "crc32c=" + correct, false},
		{"mismatch", "crc32c=AAAAAA==", true},
		{"malformed", "crc32c=invalid", true},
		{"duplicate", "crc32c=" + correct + ", crc32c=" + correct, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Goog-Hash", test.header)
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.CreateTemp(t.TempDir(), "checksum")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			}()
			_, err = client.downloadArchive(t.Context(), server.URL, file, 1024, nil)
			if (err != nil) != test.wantError {
				t.Fatalf("checksum error = %v", err)
			}
		})
	}
}

func TestOSVArchiveDeduplicatesExactClaims(t *testing.T) {
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	raw := fixture(t, "ubuntu-USN-6859-1.json")
	single, err := Parse(config, bytes.NewReader(osvZip(t, map[string][]byte{"notice.json": raw}, zip.Store)))
	if err != nil {
		t.Fatal(err)
	}
	duplicated, err := Parse(config, bytes.NewReader(osvZip(t, map[string][]byte{"notice.json": raw, "copy.json": raw}, zip.Store)))
	if err != nil {
		t.Fatal(err)
	}
	if len(duplicated.Advisories) != len(single.Advisories) {
		t.Fatal("duplicate native claims consume capacity")
	}
	for i := range single.Advisories {
		if !proto.Equal(single.Advisories[i], duplicated.Advisories[i]) {
			t.Fatal("deduplication changed a claim")
		}
	}
}
