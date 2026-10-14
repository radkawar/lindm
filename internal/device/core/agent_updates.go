// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
)

// recordAgentUpdate runs only under the authenticated live-session authority lock.
// Nothing in this telemetry changes native success or execution authority.
func recordAgentUpdate(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal, epoch uint64, status *agentv1.AgentUpdateStatus, now time.Time) error {
	if status == nil {
		return nil // Absence is unknown, not a replacement for a historical report.
	}
	previous, err := q.GetAgentUpdateReport(ctx, principal.GenerationID)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil {
		old := new(agentv1.AgentUpdateStatus)
		if err := proto.Unmarshal(previous.Status, old); err != nil {
			return ErrInternalState
		}
		if old.GetObservedAt() != nil && (status.GetObservedAt() == nil || status.GetObservedAt().AsTime().Before(old.GetObservedAt().AsTime())) {
			return Invalid("agent_update_stale")
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		return err
	}
	digest, err := agentUpdateEventDigest(status)
	if err != nil {
		return err
	}
	if len(digest) != 0 && !bytes.Equal(digest, previous.EventDigest) {
		id := uuid.New()
		details := AuditDetails("phase", status.GetPhase())
		if diagnostic := status.GetNativeDiagnostic(); diagnostic != nil {
			details["manager"] = diagnostic.GetManager()
			details["native_phase"] = diagnostic.GetPhase()
			details["exit_code"] = strconv.FormatInt(int64(diagnostic.GetExitCode()), 10)
		}
		if err := InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: id, Action: auditkind.DeviceAgentUpdateReported.String(), ResourceID: principal.DeviceID.String(), TargetDeviceID: &principal.DeviceID}, details); err != nil {
			return err
		}
		if err := q.InsertAgentUpdateEvent(ctx, devicedb.InsertAgentUpdateEventParams{ID: id, GenerationID: principal.GenerationID, SessionEpoch: int64(epoch), Status: encoded, ReceivedAt: Timestamptz(now)}); err != nil {
			return err
		}
	}
	if len(digest) == 0 {
		digest = previous.EventDigest
	}
	if digest == nil {
		digest = []byte{}
	}
	return q.PutAgentUpdateReport(ctx, devicedb.PutAgentUpdateReportParams{GenerationID: principal.GenerationID, SessionEpoch: int64(epoch), Status: encoded, EventDigest: digest, ReceivedAt: Timestamptz(now)})
}

// Routine checking and refreshed timestamps do not grow the journal. A retained
// native failure identifies the same event through checking and process restarts;
// a different failure or terminal replacement receives a new audit entry.
func agentUpdateEventDigest(status *agentv1.AgentUpdateStatus) ([]byte, error) {
	meaningful := &agentv1.AgentUpdateStatus{Enabled: status.GetEnabled(), Version: status.GetVersion(), TransactionId: status.GetTransactionId(), NativeDiagnostic: status.GetNativeDiagnostic()}
	if status.GetNativeDiagnostic() == nil {
		switch status.GetPhase() {
		case "installed", "rejected", "recovery_required":
			meaningful.Phase, meaningful.Reason, meaningful.LastOutcome = status.GetPhase(), status.GetReason(), status.GetLastOutcome()
		default:
			return nil, nil
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(meaningful)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}
