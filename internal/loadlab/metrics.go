// SPDX-License-Identifier: Apache-2.0

// Package loadlab measures disposable real-process control-plane capacity. It is
// not an agent: synthetic devices keep signing keys in memory, never execute host
// operations, and can only connect to an owned devlab authority fixture.
package loadlab

import (
	"context"
	"errors"
	"maps"
	"math"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"lindm/internal/rpcreason"
)

type RPCResult struct {
	Calls              uint64
	Errors             uint64
	ErrorRate          float64
	NonRetryableErrors uint64
	Codes              map[string]uint64
	Reasons            map[string]uint64
	P50Milliseconds    int
	P95Milliseconds    int
	P99Milliseconds    int
	MaxMilliseconds    int64
}
type histogram struct {
	bins                        [30002]uint64
	calls, errors, nonRetryable uint64
	codes                       map[string]uint64
	reasons                     map[string]uint64
	max                         int64
}
type measurements struct {
	mu  sync.Mutex
	rpc map[string]*histogram
}

func (m *measurements) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		start := time.Now()
		response, err := next(ctx, req)
		elapsed := time.Since(start)
		m.observe(req.Spec().Procedure, elapsed, err)
		return response, err
	}
}
func (*measurements) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}
func (*measurements) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
func (m *measurements) observe(name string, elapsed time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rpc == nil {
		m.rpc = make(map[string]*histogram)
	}
	name = name[strings.LastIndexByte(name, '/')+1:]
	h := m.rpc[name]
	if h == nil {
		h = &histogram{codes: make(map[string]uint64), reasons: make(map[string]uint64)}
		m.rpc[name] = h
	}
	ms := elapsed.Milliseconds()
	bucket := min(ms, 30001)
	h.bins[bucket]++
	h.calls++
	h.max = max(h.max, ms)
	if err != nil {
		h.errors++
		code := connect.CodeOf(err)
		h.codes[code.String()]++
		var failure *connect.Error
		if errors.As(err, &failure) {
			reason := rpcreason.Get(failure)
			if len(reason) > 128 {
				reason = "oversized_reason"
			}
			if reason != "" && (len(h.reasons) < 32 || h.reasons[reason] > 0) {
				h.reasons[reason]++
			}
		}
		if code != connect.CodeUnavailable && code != connect.CodeResourceExhausted && code != connect.CodeDeadlineExceeded {
			h.nonRetryable++
		}
	}
}
func (m *measurements) snapshot(reset bool) map[string]RPCResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]RPCResult, len(m.rpc))
	for name, h := range m.rpc {
		result[name] = RPCResult{Calls: h.calls, Errors: h.errors, ErrorRate: float64(h.errors) / float64(h.calls), NonRetryableErrors: h.nonRetryable, Codes: maps.Clone(h.codes), Reasons: maps.Clone(h.reasons), P50Milliseconds: percentile(h, .50), P95Milliseconds: percentile(h, .95), P99Milliseconds: percentile(h, .99), MaxMilliseconds: h.max}
	}
	if reset {
		m.rpc = nil
	}
	return result
}
func percentile(h *histogram, q float64) int {
	target := uint64(math.Ceil(float64(h.calls) * q))
	var cumulative uint64
	for i, n := range h.bins {
		cumulative += n
		if cumulative >= target {
			return i
		}
	}
	return 30001
}
func breached(rpc map[string]RPCResult) bool {
	for name, r := range rpc {
		if r.NonRetryableErrors > 0 {
			return true
		}
		if (name == "GetSyncState" || name == "GetResourceWork") && r.P99Milliseconds >= 1000 {
			return true
		}
		if name == "GetFleetSummary" && (r.P95Milliseconds >= 500 || r.Errors > 0) {
			return true
		}
		if name == "AuthorizeResourceStart" && r.P95Milliseconds >= 1000 {
			return true
		}
	}
	return false
}

func snapshotsComplete(completed, attempted, devices uint64) bool {
	return completed*100 >= max(attempted, devices)*99
}

// HistogramData is a sparse, mergeable copy of one RPC histogram. A remote
// generator returns these so percentiles are computed over the exact combined
// distribution, never averaged from per-host percentiles.
type HistogramData struct {
	Bins                        map[int64]uint64
	Calls, Errors, NonRetryable uint64
	Codes, Reasons              map[string]uint64
	Max                         int64
}

func (m *measurements) export(reset bool) map[string]HistogramData {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]HistogramData, len(m.rpc))
	for name, h := range m.rpc {
		data := HistogramData{Bins: make(map[int64]uint64), Calls: h.calls, Errors: h.errors, NonRetryable: h.nonRetryable, Codes: maps.Clone(h.codes), Reasons: maps.Clone(h.reasons), Max: h.max}
		for i, n := range h.bins {
			if n != 0 {
				data.Bins[int64(i)] = n
			}
		}
		result[name] = data
	}
	if reset {
		m.rpc = nil
	}
	return result
}

func (m *measurements) merge(remote map[string]HistogramData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rpc == nil {
		m.rpc = make(map[string]*histogram)
	}
	for name, data := range remote {
		h := m.rpc[name]
		if h == nil {
			h = &histogram{codes: make(map[string]uint64), reasons: make(map[string]uint64)}
			m.rpc[name] = h
		}
		var binned uint64
		for i, n := range data.Bins {
			if i < 0 || i >= int64(len(h.bins)) {
				return errors.New("remote histogram bin out of range")
			}
			h.bins[i] += n
			binned += n
		}
		if binned != data.Calls {
			return errors.New("remote histogram calls do not match bins")
		}
		h.calls += data.Calls
		h.errors += data.Errors
		h.nonRetryable += data.NonRetryable
		h.max = max(h.max, data.Max)
		for code, n := range data.Codes {
			h.codes[code] += n
		}
		for reason, n := range data.Reasons {
			if len(h.reasons) < 32 || h.reasons[reason] > 0 {
				h.reasons[reason] += n
			}
		}
	}
	return nil
}
