// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/rpcreason"
)

const (
	recordingIdleInterval   = 2 * time.Second
	recordingActiveInterval = 100 * time.Millisecond
	recordingRetryInterval  = time.Second
)

var recordingReasonPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// recordingRelay carries sealed recording segments from the root executor to
// the server. It holds no key and no authority: the server decides what is
// stored, and its receipt tells the executor what may be released.
type recordingRelay struct {
	executor agentv1connect.ExecutorServiceClient
	cache    connectionCache
	gate     authorityGate
	receipts []*agentv1.AssistanceRecordingReceipt
	lastErr  string
}

func startAssistanceRecording(parent context.Context, executor agentv1connect.ExecutorServiceClient, gate authorityGate) func() {
	relay := &recordingRelay{executor: executor, gate: gate}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer relay.cache.Close()
		for ctx.Err() == nil {
			delay, err := relay.cycle(ctx)
			if ctx.Err() != nil {
				return
			}
			relay.log(err)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// cycle acknowledges the previous outcome, collects the next segments and
// stores them. A transport failure keeps the segments in the executor outbox;
// only an explicit server refusal becomes a final rejection.
func (r *recordingRelay) cycle(parent context.Context) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, assistanceCycleTimeout)
	defer cancel()
	exchange, err := rpc(ctx, r.executor.ExchangeAssistanceRecording, &agentv1.ExchangeAssistanceRecordingRequest{Receipts: r.receipts})
	if err != nil {
		return recordingRetryInterval, fmt.Errorf("exchange executor recording: %w", err)
	}
	r.receipts = nil
	if err := validateManagementMessage(exchange); err != nil {
		return recordingRetryInterval, fmt.Errorf("invalid executor recording segments: %w", err)
	}
	chunks := exchange.GetChunks()
	if len(chunks) == 0 {
		return recordingIdleInterval, nil
	}
	recordingID := chunks[0].GetRecordingId()
	authority, err := establish(ctx, r.executor, &r.cache, r.gate)
	if err != nil {
		return recordingRetryInterval, fmt.Errorf("establish recording session: %w", err)
	}
	stored, err := rpc(ctx, authority.servers.device.PutAssistanceRecording, &devicev1.PutAssistanceRecordingRequest{SessionEpoch: authority.epoch, SessionId: exchange.GetSessionId(), Chunks: chunks})
	if err != nil {
		if rejection := recordingRejection(err); rejection != "" {
			r.receipts = []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, Rejection: rejection}}
			return recordingActiveInterval, fmt.Errorf("server refused recording: %w", err)
		}
		return recordingRetryInterval, fmt.Errorf("store recording segments: %w", err)
	}
	r.receipts = []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, StoredThrough: stored.GetStoredThrough(), Stored: true}}
	return recordingActiveInterval, nil
}

// recordingRejection maps an explicit server refusal to a final rejection.
// Unavailable, deadline and fenced-session errors are retried.
func recordingRejection(err error) string {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return ""
	}
	switch connectErr.Code() {
	case connect.CodeFailedPrecondition, connect.CodeResourceExhausted, connect.CodeNotFound, connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeOutOfRange:
	default:
		return ""
	}
	reason := rpcreason.Get(connectErr)
	switch {
	case reason == "session_fenced":
		return ""
	case recordingReasonPattern.MatchString(reason):
		return reason
	default:
		return "recording_rejected"
	}
}

func (r *recordingRelay) log(err error) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	if text == r.lastErr {
		return
	}
	r.lastErr = text
	if err != nil {
		slog.Warn("remote assistance recording relay incomplete", "error", err)
	}
}
