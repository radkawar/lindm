// Package update owns privileged agent-only update selection and native recovery.
// It never opens a network socket. Unprivileged transport answers bounded,
// executor-selected fetch requests; only the TUF client grants target authority.
package update

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/releaseupdate"
)

const chunkBytes = 256 << 10

// bridge has exactly one outstanding request and one reply. A disconnected or
// hostile network peer can delay an update only until the bounded worker deadline.
type bridge struct {
	mu      sync.Mutex
	pending *agentv1.AgentUpdateFetch
	reply   chan *agentv1.ExchangeAgentUpdateRequest
	changed chan struct{}
}

func newBridge() *bridge { return &bridge{changed: make(chan struct{}, 1)} }

func (b *bridge) exchange(ctx context.Context, answer *agentv1.ExchangeAgentUpdateRequest) (*agentv1.AgentUpdateFetch, error) {
	b.mu.Lock()
	if answer.GetRequestId() != "" {
		if b.pending == nil || answer.GetRequestId() != b.pending.GetRequestId() || len(answer.GetData()) > int(b.pending.GetLimit()) {
			b.mu.Unlock()
			return nil, errors.New("update transport response does not match outstanding request")
		}
		select {
		case b.reply <- proto.CloneOf(answer):
			b.pending = nil
		default:
			b.mu.Unlock()
			return nil, errors.New("update transport response already consumed")
		}
	}
	if b.pending != nil {
		result := proto.CloneOf(b.pending)
		b.mu.Unlock()
		return result, nil
	}
	b.mu.Unlock()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	case <-b.changed:
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		return nil, nil
	}
	return proto.CloneOf(b.pending), nil
}

func (b *bridge) chunk(ctx context.Context, path string, offset uint64, limit int) ([]byte, bool, error) {
	request := &agentv1.AgentUpdateFetch{RequestId: uuid.NewString(), Path: path, Offset: offset, Limit: uint32(min(limit, chunkBytes))}
	reply := make(chan *agentv1.ExchangeAgentUpdateRequest, 1)
	b.mu.Lock()
	if b.pending != nil {
		b.mu.Unlock()
		return nil, false, errors.New("concurrent update fetch")
	}
	b.pending, b.reply = request, reply
	b.mu.Unlock()
	select {
	case b.changed <- struct{}{}:
	default:
	}
	defer func() {
		b.mu.Lock()
		if b.pending == request {
			b.pending = nil
		}
		b.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case answer := <-reply:
		if answer.GetNotFound() {
			return nil, false, releaseupdate.ErrNotFound
		}
		if answer.GetFailed() {
			return nil, false, errors.New("update transport failed")
		}
		if len(answer.GetData()) == 0 && !answer.GetEof() {
			return nil, false, errors.New("empty update transport chunk")
		}
		return answer.GetData(), answer.GetEof(), nil
	}
}

func (b *bridge) fetch(ctx context.Context, path string, maximum int64) ([]byte, error) {
	// Metadata/catalog only. Packages use the streaming reader below.
	if maximum <= 0 || maximum > 16<<20 {
		return nil, errors.New("update metadata bound rejected")
	}
	reader := &remoteReader{ctx: ctx, bridge: b, path: path}
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("update metadata exceeds bound")
	}
	return data, nil
}

type remoteReader struct {
	ctx    context.Context
	bridge *bridge
	path   string
	offset uint64
	eof    bool
}

func (r *remoteReader) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if r.eof {
		return 0, io.EOF
	}
	data, eof, err := r.bridge.chunk(r.ctx, r.path, r.offset, len(out))
	if err != nil {
		return 0, err
	}
	n := copy(out, data)
	r.offset += uint64(n)
	r.eof = eof
	return n, nil
}
