// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRepeatedProfileCapturesPreserveEvidence(t *testing.T) {
	const payload = "profile transport test payload"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/debug/pprof/profile" {
			t.Errorf("unexpected profile path: %s", r.URL.Path)
		}
		if _, err := io.WriteString(w, payload); err != nil {
			t.Errorf("write profile response: %v", err)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	first, err := captureProfile(context.Background(), server.URL, directory, 10000, "profile", 9*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := captureProfile(context.Background(), server.URL, directory, 10000, "profile", 39*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.Path == second.Path || first.ElapsedSeconds != 540 || second.ElapsedSeconds != 2340 {
		t.Fatal("later soak capture overwrote or lost the earlier capture time")
	}
	digest := sha256.Sum256([]byte(payload))
	for _, capture := range []ProfileArtifact{first, second} {
		contents, err := os.ReadFile(capture.Path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(capture.Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(contents) != payload || capture.Bytes != int64(len(payload)) || capture.SHA256 != hex.EncodeToString(digest[:]) || info.Mode().Perm() != 0600 {
			t.Fatal("profile evidence content, digest, size or private permissions changed")
		}
	}
	if _, err := captureProfile(context.Background(), server.URL, directory, 10000, "profile", 9*time.Minute); err == nil {
		t.Fatal("duplicate capture silently overwrote immutable evidence")
	}
}
