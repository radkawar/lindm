// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func rebootFixture() *agentv1.OSUpdateRebootNotice {
	now := time.Now()
	return &agentv1.OSUpdateRebootNotice{ScheduleId: testSessionID, ScheduledFor: timestamppb.New(now.Add(5 * time.Minute)), Deadline: timestamppb.New(now.Add(time.Hour)), DeferUntil: timestamppb.New(now.Add(20 * time.Minute)), DeferralsRemaining: 2, Notice: "Save your work."}
}

func TestEmployeeDeferralUsesDisplayedScheduleAndExactRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "lost response", err: errors.New("transport lost after submit")},
		{name: "update lock busy", err: connect.NewError(connect.CodeUnavailable, errors.New("os_update_run_in_progress"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			notice := rebootFixture()
			response := &agentv1.SyncSessionResponse{LocalSession: localSession(), Reboot: notice}
			h.helper.applyReboot(h.ctx, response)
			posted := h.notifier.next(t, "System restart scheduled")
			if len(posted.notification.Actions) != 1 || !strings.Contains(posted.notification.Body, "Restart deadline:") {
				t.Fatalf("missing consequence or deferral: %+v", posted.notification)
			}
			posted.result <- "defer"
			var first *agentv1.OSUpdateRebootDeferralRequest
			h.client.set(func(req *agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
				if first == nil {
					first = proto.CloneOf(req.GetRebootDeferral())
				} else if !proto.Equal(first, req.GetRebootDeferral()) {
					t.Fatal("unacknowledged retry changed the mutation identity")
				}
				return nil, tc.err
			})
			h.helper.syncOnce(h.ctx, context.WithoutCancel(h.ctx))
			if first == nil || first.GetScheduleId() != notice.GetScheduleId() || !proto.Equal(first.GetScheduledFor(), notice.GetScheduledFor()) || first.GetRequestId() == "" {
				t.Fatalf("request not bound to displayed reboot: %v", first)
			}
			if !posted.isClosed() {
				t.Fatal("stale notification remained actionable after authority loss")
			}
			uncertain := h.notifier.next(t, "Restart deferral not confirmed")
			if !strings.Contains(uncertain.notification.Body, "original restart may still occur") {
				t.Fatal("unacknowledged action appeared confirmed")
			}
			h.clock.Advance(31 * time.Second)
			h.helper.syncOnce(h.ctx, context.WithoutCancel(h.ctx))
			if !proto.Equal(first, h.helper.rebootRequest) {
				t.Fatal("extended contention discarded the pending mutation")
			}
			h.client.set(func(req *agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
				if !proto.Equal(first, req.GetRebootDeferral()) {
					t.Fatal("ambiguous deferral became a new mutation")
				}
				next := proto.CloneOf(notice)
				next.ScheduledFor = next.DeferUntil
				next.DeferUntil = nil
				next.DeferralsRemaining--
				return &agentv1.SyncSessionResponse{LocalSession: localSession(), Reboot: next}, nil
			})
			h.helper.syncOnce(h.ctx, context.WithoutCancel(h.ctx))
			if h.helper.rebootRequest != nil {
				t.Fatal("confirmed mutation remained pending")
			}
			if updated := h.notifier.next(t, "System restart scheduled"); len(updated.notification.Actions) != 0 {
				t.Fatal("offered deferral without an authorized next instant")
			}
			h.helper.closeRebootNotice(h.ctx)
		})
	}
}

func TestEmployeeRebootPromptStopsForAssistanceOrAnotherUser(t *testing.T) {
	for _, wrongUser := range []bool{false, true} {
		h := newHarness(t)
		response := &agentv1.SyncSessionResponse{LocalSession: localSession(), Reboot: rebootFixture()}
		h.helper.applyReboot(h.ctx, response)
		posted := h.notifier.next(t, "System restart scheduled")
		if wrongUser {
			response.LocalSession.Uid++
		} else {
			response.Directives = []*agentv1.AssistanceDirective{{}}
		}
		h.helper.applyReboot(h.ctx, response)
		if !posted.isClosed() || h.helper.reboot != nil {
			t.Fatal("employee prompt survived assistance or identity change")
		}
	}
}

func TestEmployeeRejectedDeferralRetainsVisibleOriginalSchedule(t *testing.T) {
	h := newHarness(t)
	notice := rebootFixture()
	notice.Reason = "deferral_not_applied"
	h.helper.applyReboot(h.ctx, &agentv1.SyncSessionResponse{LocalSession: localSession(), Reboot: notice})
	posted := h.notifier.next(t, "System restart scheduled")
	if !strings.Contains(posted.notification.Body, "restart was not deferred") || !strings.Contains(posted.notification.Body, notice.GetScheduledFor().AsTime().Local().Format(time.RFC1123)) || len(posted.notification.Actions) != 1 {
		t.Fatalf("rejection hid original schedule or remaining authority: %+v", posted.notification)
	}
	h.helper.closeRebootNotice(h.ctx)
}
