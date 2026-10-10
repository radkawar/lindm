package update

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/releaseupdate"
)

func TestBridgeRejectsUnsolicitedMismatchedAndOversizedReplies(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b := newBridge()
	if _, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: uuid.NewString(), Data: []byte("bad")}); err == nil {
		t.Fatal("unsolicited reply admitted")
	}
	done := make(chan error, 1)
	go func() {
		data, eof, err := b.chunk(ctx, "metadata/timestamp.json", 0, 4)
		if err == nil && (!eof || !bytes.Equal(data, []byte("good"))) {
			err = errors.New("wrong bridge result")
		}
		done <- err
	}()
	fetch, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{})
	if err != nil || fetch == nil {
		t.Fatalf("no executor fetch: %v", err)
	}
	if _, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: uuid.NewString(), Data: []byte("good"), Eof: true}); err == nil {
		t.Fatal("wrong identity admitted")
	}
	if _, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: fetch.GetRequestId(), Data: []byte("extra"), Eof: true}); err == nil {
		t.Fatal("oversized chunk admitted")
	}
	if _, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: fetch.GetRequestId(), Data: []byte("good"), Eof: true}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: fetch.GetRequestId(), Data: []byte("good"), Eof: true}); err == nil {
		t.Fatal("consumed fetch replay admitted")
	}
}

func TestBridgeCancellationUnblocksMissingNetworkPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	b := newBridge()
	done := make(chan error, 1)
	go func() { _, _, err := b.chunk(ctx, "metadata/timestamp.json", 0, 4); done <- err }()
	poll, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if fetch, err := b.exchange(poll, &agentv1.ExchangeAgentUpdateRequest{}); err != nil || fetch == nil {
		t.Fatalf("fetch: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-poll.Done():
		t.Fatal("missing peer held privileged worker after shutdown")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending != nil {
		t.Fatal("canceled work remains deliverable")
	}
}

func TestBridgeNotFoundAndEmptyChunkAreNotSuccess(t *testing.T) {
	for _, missing := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		b := newBridge()
		done := make(chan error, 1)
		go func() { _, err := b.fetch(ctx, "metadata/2.root.json", 8); done <- err }()
		fetch, err := b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{})
		if err != nil || fetch == nil {
			cancel()
			t.Fatalf("fetch: %v", err)
		}
		_, err = b.exchange(ctx, &agentv1.ExchangeAgentUpdateRequest{RequestId: fetch.GetRequestId(), NotFound: missing})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		err = <-done
		cancel()
		if err == nil || missing && !errors.Is(err, releaseupdate.ErrNotFound) {
			t.Fatalf("missing=%t error=%v", missing, err)
		}
	}
}

func TestRemoteReaderDoesNotTreatAnEmptyReadAsEOF(t *testing.T) {
	r := &remoteReader{ctx: t.Context(), bridge: newBridge(), path: "targets/package"}
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read=%d,%v", n, err)
	}
	r.eof = true
	if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF=%d,%v", n, err)
	}
}
