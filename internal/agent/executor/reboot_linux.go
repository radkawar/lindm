//go:build linux

package executor

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// sessionEnabled also opens the session socket whenever a signed capability
// policy may grant OS_UPDATES later: reboot deferral prompts must not depend on
// an executor restart after the grant.
func (cfg Config) sessionEnabled() bool {
	var local *agentv1.AgentConfig
	if cfg.Local != nil {
		local = cfg.Local.Proto
	}
	return cfg.RemoteAssistance.GetEnabled() || local.GetOsUpdateProvider().GetEnabled() || cfg.ActionProviderConfig.GetAllowPatchNow() ||
		(cfg.Local != nil && !local.GetCapabilityPolicy().GetRefuseRemote())
}

type rebootSessionProvider interface {
	SessionReboot(context.Context, *agentv1.OSUpdateRebootDeferralRequest) (*agentv1.OSUpdateRebootNotice, error)
}

type rebootPrompt struct {
	token    string
	schedule string
	local    string
	epoch    uint64
}

// syncReboot holds assistance admission's mutex through the bounded native
// deferral. A remote controller cannot race a displayed employee action, and
// any intervening assistance invalidates the prompt even after it has ended.
func (h *sessionService) syncReboot(ctx context.Context, uid uint32, request *agentv1.SyncSessionRequest, response *agentv1.SyncSessionResponse) error {
	h.broker.mu.Lock()
	defer h.broker.mu.Unlock()
	for _, session := range h.broker.sessions {
		if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || !session.helperEnded {
			delete(h.rebootPrompts, uid)
			return nil
		}
	}
	prompt, issued := h.rebootPrompts[uid]
	deferral := request.GetRebootDeferral()
	if deferral != nil {
		if !issued || prompt.token != deferral.GetScheduleId() || prompt.epoch != h.broker.rebootEpoch || prompt.local != response.GetLocalSession().GetLogindSessionId() {
			deferral = nil
		} else {
			deferral = proto.CloneOf(deferral)
			deferral.ScheduleId = prompt.schedule
		}
	}
	notice, err := h.reboots.SessionReboot(ctx, deferral)
	if err != nil {
		return err
	}
	if notice == nil {
		delete(h.rebootPrompts, uid)
		return nil
	}
	if !issued || prompt.schedule != notice.GetScheduleId() || prompt.epoch != h.broker.rebootEpoch || prompt.local != response.GetLocalSession().GetLogindSessionId() {
		if !issued && len(h.rebootPrompts) >= 1024 {
			return nil
		}
		prompt = rebootPrompt{token: uuid.NewString(), schedule: notice.GetScheduleId(), epoch: h.broker.rebootEpoch, local: response.GetLocalSession().GetLogindSessionId()}
		if h.rebootPrompts == nil {
			h.rebootPrompts = make(map[uint32]rebootPrompt)
		}
		h.rebootPrompts[uid] = prompt
	}
	notice.ScheduleId = prompt.token
	response.Reboot = notice
	return nil
}
