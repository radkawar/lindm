// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestFileNativeWorkerJoinsOnEverySessionAuthorityLoss(t *testing.T) {
	cases := []struct {
		name  string
		cause agentv1.AssistanceEndCause
	}{
		{"stop", agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED},
		{"lock", agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED},
		{"logout", agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED},
		{"transport", agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED},
		{"lease", agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			entered, joined := make(chan struct{}), make(chan struct{})
			h.portal.choose = func(ctx context.Context, _ string) (*os.File, error) {
				close(entered)
				<-ctx.Done()
				close(joined)
				return nil, errors.Join(ErrPortalCancelled, ctx.Err())
			}
			inv := filesInvitation()
			activateTierOne(h, inv)
			directive := fileDirective(inv, h.clock.Now())
			h.sync(directive)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("chooser worker never entered")
			}
			switch tc.name {
			case "stop":
				h.notifier.next(t, "Remote assistance in progress").result <- actionStop
			case "transport":
				close(h.peers.peer.failed)
			case "lease":
				h.clock.Advance(31 * time.Second)
				h.sync(directive)
			default:
				h.helper.endAll(tc.cause, "test_native_lifetime")
			}
			h.waitEnded(tc.cause)
			select {
			case <-joined:
			default:
				t.Fatal("ended session retained native worker")
			}
			report := h.report()
			if !report.GetInputState().GetPaused() {
				t.Fatal("stop/revoke resumed remote input")
			}
			if report.GetFileTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED {
				t.Fatal("native cancellation did not finalize transfer")
			}
		})
	}
}
