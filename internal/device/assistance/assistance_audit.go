// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func assistancePolicyModeName(mode agentv1.AssistancePolicyMode) string {
	switch assistanceMode(mode) {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		return "limited"
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		return "on"
	default:
		return "off"
	}
}

func assistancePolicyAudit(policy *agentv1.AssistancePolicy) []string {
	return []string{"clipboard", assistancePolicyModeName(policy.GetClipboard()), "keyboard", assistancePolicyModeName(policy.GetKeyboard()), "display_policy", assistancePolicyModeName(policy.GetDisplay()), "messages", assistancePolicyModeName(policy.GetMessages()), "files", assistancePolicyModeName(policy.GetFiles()), "reconnect", assistancePolicyModeName(policy.GetReconnect()), "recording", assistancePolicyModeName(policy.GetRecording()), "unattended", assistancePolicyModeName(policy.GetUnattended()), "elevation", assistancePolicyModeName(policy.GetElevation()), "annotation", assistancePolicyModeName(policy.GetAnnotation()), "audio", assistancePolicyModeName(policy.GetAudio()), "kde_plasma", assistancePolicyModeName(policy.GetKdePlasma()), "x11", assistancePolicyModeName(policy.GetX11())}
}

func assistanceOperationMetadata(row devicedb.AssistanceSession, actor uuid.UUID, command *agentv1.AssistanceCommand) devicedb.AssistanceCommand {
	requestID, _ := uuid.Parse(command.GetRequestId())
	return devicedb.AssistanceCommand{RequestID: requestID, SessionID: row.ID, DeviceID: row.DeviceID, OperatorID: actor, Kind: int16(command.GetKind()), Policy: row.EffectiveCapabilities, ByteCount: int32(len(command.GetText())), SpecialKey: int16(command.GetSpecialKey()), DisplayID: command.GetDisplayId(), AnnotationEnabled: command.GetAnnotationEnabled()}
}

// This whitelist of metadata fields is the entire audit boundary. In particular,
// request digests and command/result text are never accepted as audit arguments.
func assistanceOperationAudit(operation devicedb.AssistanceCommand, outcome, reason string) []string {
	direction, chord := "", ""
	switch agentv1.AssistanceCommandKind(operation.Kind) {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
		direction = "operator_to_user"
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		direction = "user_to_operator"
	}
	if operation.SpecialKey != 0 {
		chord = strings.ToLower(strings.TrimPrefix(agentv1.AssistanceSpecialKey(operation.SpecialKey).String(), "ASSISTANCE_SPECIAL_KEY_"))
	}
	pairs := []string{"request", operation.RequestID.String(), "kind", strings.ToLower(strings.TrimPrefix(agentv1.AssistanceCommandKind(operation.Kind).String(), "ASSISTANCE_COMMAND_KIND_")), "direction", direction, "bytes", strconv.FormatInt(int64(operation.ByteCount), 10), "chord", chord, "display", operation.DisplayID, "result", outcome, "reason", reason}
	if operation.Status != 0 {
		pairs = append(pairs, "status", strings.ToLower(strings.TrimPrefix(agentv1.AssistanceCommandStatus(operation.Status).String(), "ASSISTANCE_COMMAND_STATUS_")))
	}
	return append(pairs, assistancePolicyAudit(decodeAssistancePolicy(operation.Policy))...)
}

func denyAssistanceOperation(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, actor uuid.UUID, command *agentv1.AssistanceCommand, reason string, denied error) error {
	operation := assistanceOperationMetadata(row, actor, command)
	if err := recordAssistanceAudit(ctx, q, &actor, assistanceCommandAuditKind(operation), row, "", assistanceOperationAudit(operation, "denied", reason)...); err != nil {
		return err
	}
	return denied
}

// Admission failures have no operation row. Audit only normalized identities
// and server-owned projection; never use rejected request text or its digest.
func auditAssistanceAccessDenied(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, sessionID, requestID, reason string, denied error) error {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return denied
	}
	request, err := uuid.Parse(requestID)
	if err != nil {
		return denied
	}
	pairs := []string{"request", request.String(), "result", "denied", "reason", reason}
	var target *uuid.UUID
	row, err := q.GetAssistanceSession(ctx, id)
	if err == nil {
		target = &row.DeviceID
		pairs = append(pairs, assistancePolicyAudit(decodeAssistancePolicy(row.EffectiveCapabilities))...)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &actor, Action: auditkind.AssistanceCommandDenied.String(), ResourceID: id.String(), TargetDeviceID: target,
	}, core.AuditDetails(pairs...)); err != nil {
		return err
	}
	return denied
}

func (s *Service) assistanceAccessDenied(ctx context.Context, sessionID, requestID string, denied error) error {
	actor, ok := identity.PrincipalFromContext(ctx)
	// Anonymous requests have no actor. Zero-value handlers are also used by
	// the authorization matrix; production construction requires a pool.
	if !ok || s.Pool == nil {
		return denied
	}
	return core.MapErr(auditAssistanceAccessDenied(ctx, devicedb.New(s.Pool), actor.ID, sessionID, requestID, "authority_denied", denied))
}

func auditAssistancePolicyDenied(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, deviceID, requestID string, ceiling *agentv1.AssistancePolicy, denied error) error {
	id, err := uuid.Parse(deviceID)
	if err != nil {
		return denied
	}
	request, err := uuid.Parse(requestID)
	if err != nil {
		return denied
	}
	policy, err := loadAssistancePolicy(ctx, q, id)
	if err != nil {
		return err
	}
	details := append([]string{"request", request.String(), "result", "denied", "reason", "authority_denied"}, assistancePolicyAudit(intersectAssistancePolicy(policy, ceiling))...)
	if err := core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &actor, Action: auditkind.AssistancePolicy.String(), ResourceID: id.String(), TargetDeviceID: &id,
	}, core.AuditDetails(details...)); err != nil {
		return err
	}
	return denied
}

func (s *Service) assistancePolicyDenied(ctx context.Context, deviceID, requestID string, denied error) error {
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok || s.Pool == nil {
		return denied
	}
	return core.MapErr(auditAssistancePolicyDenied(ctx, devicedb.New(s.Pool), actor.ID, deviceID, requestID, s.AssistanceCeiling, denied))
}
