package vmlab

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dropAfter sends the declared length but closes the connection after cut
// bytes, as a vendor mirror does to a long DVD transfer.
func dropAfter(t *testing.T, w http.ResponseWriter, status int, headers map[string]string, body string, cut int) {
	t.Helper()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body[:cut]))
	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Error(err)
	}
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	_ = conn.Close()
}

func TestDownloadResumesExactRangeAfterMirrorDrop(t *testing.T) {
	payload := strings.Repeat("0123456789", 10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		if spec := r.Header.Get("Range"); spec != "" {
			if _, err := fmt.Sscanf(spec, "bytes=%d-", &offset); err != nil {
				t.Error(err)
				return
			}
		}
		remaining := payload[offset:]
		status, headers := http.StatusOK, map[string]string{}
		if offset > 0 {
			status = http.StatusPartialContent
			headers["Content-Range"] = fmt.Sprintf("bytes %d-%d/%d", offset, len(payload)-1, len(payload))
			if r.URL.Path == "/wrong-range" {
				headers["Content-Range"] = fmt.Sprintf("bytes 0-%d/%d", len(payload)-1, len(payload))
			}
		}
		switch r.URL.Path {
		case "/always-drops":
			dropAfter(t, w, status, headers, remaining, 1)
		default:
			// Each response delivers at most 30 bytes before the drop.
			if len(remaining) <= 30 {
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(remaining))
				return
			}
			dropAfter(t, w, status, headers, remaining, 30)
		}
	}))
	defer server.Close()
	client := (Fetcher{transport: server.Client().Transport}).client()
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		path string
		ok   bool
	}{{"resumable", true}, {"wrong-range", false}, {"always-drops", false}} {
		t.Run(tc.path, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = download(context.Background(), client, root, "staging", server.URL+"/"+tc.path, int64(len(payload)), 5*time.Second)
			if !tc.ok {
				if err == nil {
					t.Fatal("unsafe or unbounded resume accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			content, err := root.ReadFile("staging")
			if err != nil || string(content) != payload {
				t.Fatalf("resumed payload differs: %v %q", err, content)
			}
		})
	}
}
