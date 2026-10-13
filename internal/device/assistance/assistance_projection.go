package assistance

import (
	"bytes"
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
)

// Store an explicit content-free projection, never the report itself: reports
// may contain clipboard text in command_result. This boundary is intentional.
func (s *Service) applyAssistanceProjection(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, report *agentv1.AssistanceReport, now time.Time, revoked *assistanceRevocations) error {
	bad := func(reason string) error {
		return endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, reason, false, revoked)
	}
	grant := assistancePolicy(report.GetGrantedCapabilities().GetPolicy())
	effective := decodeAssistancePolicy(row.EffectiveCapabilities)
	reportedEffective := assistancePolicy(report.GetEffectiveCapabilities())
	if !proto.Equal(assistancePolicy(report.GetRequestedCapabilities()), decodeAssistancePolicy(row.RequestedCapabilities)) || !proto.Equal(reportedEffective, intersectAssistancePolicy(reportedEffective, effective)) {
		return bad("capability_negotiation_invalid")
	}
	if len(row.CapabilityProjection) != 0 && !proto.Equal(reportedEffective, effective) {
		return bad("effective_capabilities_changed")
	}
	effective = reportedEffective
	if !proto.Equal(grant, intersectAssistancePolicy(grant, effective)) {
		return bad("capability_grant_exceeds_policy")
	}
	if grant.GetKeyboard() > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF && !row.ControlGranted {
		return bad("keyboard_without_control")
	}
	if grant.GetClipboard() > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF && row.Mode != int16(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL) {
		return bad("clipboard_without_control_request")
	}
	seen := make(map[string]bool, len(report.GetDisplays()))
	for _, display := range report.GetDisplays() {
		if seen[display.GetId()] {
			return bad("display_duplicate")
		}
		seen[display.GetId()] = true
	}
	if len(seen) == 0 {
		if report.GetSelectedDisplayId() != "" || report.GetDisplayGeneration() != 0 {
			return bad("display_selection_invalid")
		}
	} else if !seen[report.GetSelectedDisplayId()] || report.GetDisplayGeneration() == 0 {
		return bad("display_selection_invalid")
	}
	if len(seen) > 1 && grant.GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return bad("display_grant_exceeds_policy")
	}
	previous := assistanceProjection(*row)
	frame := report.GetDisplayFrame()
	if frame != nil && (frame.GetDisplayId() != report.GetSelectedDisplayId() || frame.GetGeneration() != report.GetDisplayGeneration()) {
		return bad("display_frame_invalid")
	}
	if len(row.CapabilityProjection) != 0 {
		if !proto.Equal(assistancePolicy(previous.GetGrantedCapabilities().GetPolicy()), grant) {
			return bad("capability_grant_changed")
		}
		if len(previous.GetDisplays()) != len(report.GetDisplays()) {
			return bad("display_grant_changed")
		}
		for i, display := range previous.GetDisplays() {
			if !proto.Equal(display, report.GetDisplays()[i]) {
				return bad("display_grant_changed")
			}
		}
		if previous.GetSelectedDisplayId() != report.GetSelectedDisplayId() || previous.GetDisplayGeneration() != report.GetDisplayGeneration() {
			command, err := s.commandForAssistance(ctx, q, *row, now)
			if err != nil {
				return err
			}
			result := report.GetCommandResult()
			if command.GetKind() != agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY || command.GetDisplayId() != report.GetSelectedDisplayId() || result.GetRequestId() != command.GetRequestId() || result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED || previous.GetDisplayGeneration() == ^uint32(0) || report.GetDisplayGeneration() != previous.GetDisplayGeneration()+1 {
				return bad("display_switch_unauthorized")
			}
		} else if previous.GetDisplayFrame() != nil {
			if frame != nil && !proto.Equal(frame, previous.GetDisplayFrame()) {
				return bad("display_frame_changed")
			}
			// A transient omission cannot replace a generation's first emitted frame.
			frame = previous.GetDisplayFrame()
		}
	}
	if len(row.CapabilityProjection) == 0 {
		data, err := proto.Marshal(effective)
		if err != nil {
			return err
		}
		if err := q.SetAssistanceEffectiveCapabilities(ctx, devicedb.SetAssistanceEffectiveCapabilitiesParams{ID: row.ID, EffectiveCapabilities: data}); err != nil {
			return err
		}
		row.EffectiveCapabilities = data
	}
	capabilities := proto.CloneOf(report.GetGrantedCapabilities())
	if capabilities == nil {
		capabilities = &agentv1.AssistanceCapabilities{}
	}
	capabilities.Policy = grant
	projection := &agentv1.AssistanceReport{GrantedCapabilities: capabilities, Displays: report.GetDisplays(), SelectedDisplayId: report.GetSelectedDisplayId(), DisplayGeneration: report.GetDisplayGeneration(), DisplayFrame: frame}
	data, err := proto.Marshal(projection)
	if err != nil {
		return err
	}
	if bytes.Equal(data, row.CapabilityProjection) {
		return nil
	}
	if err := q.SetAssistanceProjection(ctx, devicedb.SetAssistanceProjectionParams{ID: row.ID, CapabilityProjection: data}); err != nil {
		return err
	}
	row.CapabilityProjection = data
	return nil
}
