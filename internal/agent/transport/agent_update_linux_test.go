// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestUpdateTransportStreamsExactRanges(t *testing.T) {
	data := bytes.Repeat([]byte("package"), 50000)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "agent.deb", time.Time{}, bytes.NewReader(data))
	}))
	defer server.Close()
	client := server.Client()
	var collected []byte
	for offset := 0; offset < len(data); {
		fetch := &agentv1.AgentUpdateFetch{RequestId: uuid.NewString(), Path: "targets/agent.deb", Offset: uint64(offset), Limit: 256 << 10}
		reply := fetchAgentUpdateChunk(t.Context(), client, server.URL, fetch)
		if reply.GetFailed() || reply.GetNotFound() || reply.GetRequestId() != fetch.GetRequestId() || len(reply.GetData()) > 256<<10 {
			t.Fatalf("range rejected: offset=%d reply=%v", offset, reply)
		}
		collected = append(collected, reply.GetData()...)
		offset += len(reply.GetData())
		if reply.GetEof() != (offset == len(data)) {
			t.Fatal("wrong transport EOF boundary")
		}
	}
	if !bytes.Equal(collected, data) {
		t.Fatal("range transport changed package bytes")
	}
}

func TestUpdateTransportRejectsWrongRangeAndOversizedBody(t *testing.T) {
	for _, mode := range []string{"wrong offset", "extra body", "ignored range", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "wrong offset":
					w.Header().Set("Content-Range", "bytes 0-3/10")
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write([]byte("four"))
				case "extra body":
					w.Header().Set("Content-Range", "bytes 4-7/10")
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write([]byte("extra"))
				case "ignored range":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("four"))
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
				}
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			reply := fetchAgentUpdateChunk(t.Context(), client, server.URL, &agentv1.AgentUpdateFetch{RequestId: uuid.NewString(), Path: "targets/agent.deb", Offset: 4, Limit: 4})
			if !reply.GetFailed() || len(reply.GetData()) != 0 {
				t.Fatal("ambiguous remote bytes admitted")
			}
		})
	}
}

func TestUpdateTransportRefusesTraversalBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = fmt.Fprint(w, "unsafe") }))
	defer server.Close()
	for _, path := range []string{"../keys/root", "targets/../private", "targets/%2e%2e/key", "targets/x?token=1", "https://evil.example/x", "/metadata/timestamp.json"} {
		reply := fetchAgentUpdateChunk(t.Context(), server.Client(), server.URL, &agentv1.AgentUpdateFetch{RequestId: uuid.NewString(), Path: path, Limit: 4})
		if !reply.GetFailed() {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe repository path reached network")
	}
}
