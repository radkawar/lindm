// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
)

// adminRetryAttempts bounds lab admin calls on a loaded host: one slow
// response must not fail a long seed, and a persistently failing call still
// surfaces within about a minute.
const adminRetryAttempts = 4

// replaySafe reports whether repeating the call cannot apply it twice: reads,
// and mutations carrying a request_id, which the server replays exactly.
func replaySafe(req connect.AnyRequest) bool {
	procedure := req.Spec().Procedure
	method := procedure[strings.LastIndexByte(procedure, '/')+1:]
	if strings.HasPrefix(method, "Get") || strings.HasPrefix(method, "List") {
		return true
	}
	message, ok := req.Any().(proto.Message)
	return ok && message.ProtoReflect().Descriptor().Fields().ByName("request_id") != nil
}

// retryLoadedHost retries replay-safe unary calls that timed out or found the
// server unavailable, with backoff, while the caller's context is live.
// Definitive rejections are returned at once.
func retryLoadedHost(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		response, err := next(ctx, req)
		for attempt, backoff := 1, time.Second; attempt < adminRetryAttempts && err != nil && replaySafe(req); attempt, backoff = attempt+1, backoff*2 {
			if code := connect.CodeOf(err); code != connect.CodeDeadlineExceeded && code != connect.CodeUnavailable {
				break
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return response, err
			case <-timer.C:
			}
			response, err = next(ctx, req)
		}
		return response, err
	}
}
