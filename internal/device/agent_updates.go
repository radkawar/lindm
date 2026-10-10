package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
)

// recordAgentUpdate runs only under the authenticated live-session authority lock.
// Nothing in this telemetry changes native success or execution authority.
func recordAgentUpdate(ctx context.Context, q *devicedb.Queries, principal devicePrincipal, epoch uint64, status *agentv1.AgentUpdateStatus, now time.Time) error {
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
			return errInternalState
		}
		if old.GetObservedAt() != nil && (status.GetObservedAt() == nil || status.GetObservedAt().AsTime().Before(old.GetObservedAt().AsTime())) {
			return invalid("agent_update_stale")
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
		reason := "reported update phase=" + status.GetPhase()
		if diagnostic := status.GetNativeDiagnostic(); diagnostic != nil {
			reason = fmt.Sprintf("reported native failure manager=%s phase=%s exit_code=%d", diagnostic.GetManager(), diagnostic.GetPhase(), diagnostic.GetExitCode())
		}
		if err := q.InsertAuditEvent(ctx, devicedb.InsertAuditEventParams{ID: id, Action: "device.agent_update.reported", ResourceID: principal.DeviceID.String(), Reason: reason}); err != nil {
			return err
		}
		if err := q.InsertAgentUpdateEvent(ctx, devicedb.InsertAgentUpdateEventParams{ID: id, GenerationID: principal.GenerationID, SessionEpoch: int64(epoch), Status: encoded, ReceivedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	if len(digest) == 0 {
		digest = previous.EventDigest
	}
	if digest == nil {
		digest = []byte{}
	}
	return q.PutAgentUpdateReport(ctx, devicedb.PutAgentUpdateReportParams{GenerationID: principal.GenerationID, SessionEpoch: int64(epoch), Status: encoded, EventDigest: digest, ReceivedAt: timestamptz(now)})
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
