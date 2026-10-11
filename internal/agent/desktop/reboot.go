package desktop

import (
	"context"
	"fmt"
	"html"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func (h *Helper) closeRebootNotice(parent context.Context) {
	if h.rebootNotice != nil {
		ctx, cancel := context.WithTimeout(parent, syncCallTimeout)
		if err := h.rebootNotice.Close(ctx); err != nil {
			h.logger.Warn("close restart notice", "err", err)
		}
		cancel()
		h.rebootNotice = nil
	}
	h.reboot = nil
}

func (h *Helper) rebootAction() {
	if h.rebootNotice == nil || h.reboot == nil || h.rebootRequest != nil {
		return
	}
	select {
	case action := <-h.rebootNotice.Result():
		if action == "defer" && h.reboot.GetDeferUntil() != nil {
			h.rebootRequest = &agentv1.OSUpdateRebootDeferralRequest{
				ScheduleId: h.reboot.GetScheduleId(), RequestId: uuid.NewString(),
				ScheduledFor: proto.CloneOf(h.reboot.GetScheduledFor()),
			}
		}
	default:
	}
}

func (h *Helper) applyReboot(parent context.Context, response *agentv1.SyncSessionResponse) {
	notice := response.GetReboot()
	if notice == nil || response.GetLocalSession().GetUid() != h.uid || len(response.GetDirectives()) != 0 {
		h.closeRebootNotice(parent)
		return
	}
	if proto.Equal(h.reboot, notice) {
		return
	}
	h.closeRebootNotice(parent)
	body := "Save your work. This device restarts at " + notice.GetScheduledFor().AsTime().Local().Format(time.RFC1123) + "."
	if notice.GetNotice() != "" {
		body += " " + notice.GetNotice()
	}
	body += " Restart deadline: " + notice.GetDeadline().AsTime().Local().Format(time.RFC1123) + "."
	switch notice.GetReason() {
	case "deferral_not_applied", "native_power_unavailable", "native_schedule_changed", "stale_reboot_notice", "native_power_inhibited":
		body += " The restart was not deferred. The time above still applies."
	}
	notification := Notification{Summary: "System restart scheduled", Body: html.EscapeString(body), Critical: true, Persistent: true}
	if notice.GetDeferUntil() != nil {
		notification.Actions = []NotificationAction{{Key: "defer", Label: "Defer until " + notice.GetDeferUntil().AsTime().Local().Format("Mon 15:04 MST")}}
		notification.Body += fmt.Sprintf(" %d deferrals remaining.", notice.GetDeferralsRemaining())
	} else {
		notification.Body += " No further deferral is available within your organisation's restart policy."
	}
	ctx, cancel := context.WithTimeout(parent, syncCallTimeout)
	defer cancel()
	posted, err := h.deps.notifier.Notify(ctx, notification)
	if err != nil {
		h.logger.Warn("post restart notice", "err", err)
		return
	}
	h.reboot, h.rebootNotice = proto.CloneOf(notice), posted
}

func (h *Helper) rebootUncertain() {
	ctx, cancel := context.WithTimeout(context.Background(), syncCallTimeout)
	defer cancel()
	if _, err := h.deps.notifier.Notify(ctx, Notification{
		Summary:  "Restart deferral not confirmed",
		Body:     "Save your work. The original restart may still occur. Waiting to confirm the same request.",
		Critical: true,
	}); err != nil {
		h.logger.Warn("post uncertain restart deferral", "err", err)
	}
}
