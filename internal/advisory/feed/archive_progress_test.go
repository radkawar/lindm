// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
)

// Large archive transfers report progress to the refresh watchdog and are not
// capped by the bounded client's whole-request timeout.
func TestArchiveTransferReportsProgressWithoutRequestTimeout(t *testing.T) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not *http.Transport")
	}
	client, err := New(&http.Client{Transport: transport.Clone()})
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Timeout == 0 || client.archive.Timeout != 0 {
		t.Fatalf("timeouts: bounded=%v archive=%v", client.http.Timeout, client.archive.Timeout)
	}
	calls := 0
	var out bytes.Buffer
	w := &progressWriter{dst: &out, progress: func() error { calls++; return nil }}
	chunk := make([]byte, progressBytes/2)
	for range 5 {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || out.Len() != 5*len(chunk) {
		t.Fatalf("progress calls=%d bytes=%d", calls, out.Len())
	}
	stalled := &progressWriter{dst: &out, progress: func() error { return errors.New("refresh canceled") }}
	if _, err := stalled.Write(make([]byte, progressBytes)); err == nil {
		t.Fatal("watchdog cancellation not propagated")
	}
}
