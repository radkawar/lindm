//go:build integration

package device

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func TestAgentUpdatePersistenceOrderingAndProjection(t *testing.T) {
	f := newEnrolled(t, 0)
	project := func() *adminv1.GetDeviceResponse {
		t.Helper()
		response, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg
	}
	if got := project(); got.GetAgentUpdate() != nil || got.GetAgentUpdateReceivedAt() != nil {
		t.Fatal("missing report became healthy")
	}
	status := &agentv1.AgentUpdateStatus{Enabled: true, Phase: "recovery_required", Version: "1.4.0", TransactionId: uuid.NewString(), Reason: "native_update_failed", ObservedAt: timestamppb.New(f.now), LastOutcome: "incomplete", NativeDiagnostic: &agentv1.NativeUpdateDiagnostic{Manager: "apt-get", Phase: "simulate", ExitCode: 100, ErrorLines: []string{"E: Unable to correct problems, you have held broken packages."}}}
	report := func(epoch uint64, value *agentv1.AgentUpdateStatus) error {
		_, err := f.svc.GetSyncState(f.deviceCtx(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: epoch, AgentUpdate: value}))
		return err
	}
	if err := report(1, status); err != nil {
		t.Fatal(err)
	}
	first := project()
	if !proto.Equal(first.GetAgentUpdate(), status) || !first.GetAgentUpdateReceivedAt().AsTime().Equal(f.now) {
		t.Fatalf("report projection lost facts: %v", first.GetAgentUpdate())
	}
	// Read the database, not a service cache, and exercise a new service instance.
	stored, err := devicedb.New(f.svc.pool).GetAgentUpdateReport(f.ctx, f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	persisted := new(agentv1.AgentUpdateStatus)
	if err := proto.Unmarshal(stored.Status, persisted); err != nil || !proto.Equal(persisted, status) {
		t.Fatalf("durable report changed: %v", err)
	}
	restarted, err := New(f.svc.pool, Config{DeploymentID: f.svc.deploymentID.String(), CACertificate: f.svc.ca, CAKey: f.svc.caKey, Identity: f.svc.identity})
	if err != nil {
		t.Fatal(err)
	}
	restarted.clock = func() time.Time { return f.now }
	f.svc = restarted
	for range 3 {
		f.now = f.now.Add(time.Second)
		if err := report(1, status); err != nil {
			t.Fatal(err)
		}
	}
	checking := proto.CloneOf(status)
	checking.Phase, checking.LastOutcome = "checking", "checking"
	checking.ObservedAt = timestamppb.New(f.now)
	if err := report(1, checking); err != nil {
		t.Fatal(err)
	}
	if err := report(1, nil); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(project().GetAgentUpdate(), checking) {
		t.Fatal("absent heartbeat erased historical failure")
	}
	if err := report(1, status); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("older observation replaced latest report: %v", err)
	}
	acquireTestSession(t, f.ctx, f.svc, f.principal, f.key, 1)
	if err := report(1, checking); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("retired session reported: %v", err)
	}
	if err := report(3, checking); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("future session reported: %v", err)
	}
	if err := report(2, checking); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM device_agent_update_events WHERE generation_id=$1", f.principal.GenerationID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("heartbeat/checking/restart duplicated failure: count=%d err=%v", count, err)
	}
	var eventBytes []byte
	if err := f.conn.QueryRow(f.ctx, "SELECT e.status FROM device_agent_update_events e JOIN audit_events a ON a.id=e.id WHERE e.generation_id=$1 AND a.action='device.agent_update.reported'", f.principal.GenerationID).Scan(&eventBytes); err != nil {
		t.Fatal(err)
	}
	event := new(agentv1.AgentUpdateStatus)
	if err := proto.Unmarshal(eventBytes, event); err != nil || !proto.Equal(event, status) {
		t.Fatalf("full audit-linked diagnostic lost: %v", err)
	}
	f.now = f.now.Add(time.Second)
	installed := proto.CloneOf(checking)
	installed.Phase, installed.LastOutcome, installed.Reason = "installed", "installed", ""
	installed.NativeDiagnostic, installed.ObservedAt = nil, timestamppb.New(f.now)
	if err := report(2, installed); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(project().GetAgentUpdate(), installed) {
		t.Fatal("terminal replacement was not projected")
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM device_agent_update_events WHERE generation_id=$1", f.principal.GenerationID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("terminal replacement not journaled: count=%d err=%v", count, err)
	}
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	hidden := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}}))
	if _, err := f.svc.GetDevice(hidden, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("diagnostic escaped device scope: %v", err)
	}
	q := devicedb.New(f.svc.pool)
	next := uuid.New()
	if err := q.InsertEnrollmentGeneration(f.ctx, devicedb.InsertEnrollmentGenerationParams{ID: next, DeviceID: f.principal.DeviceID, CreatedAt: timestamptz(f.now)}); err != nil {
		t.Fatal(err)
	}
	if err := q.SetDeviceGeneration(f.ctx, devicedb.SetDeviceGenerationParams{ID: f.principal.DeviceID, CurrentGenerationID: &next}); err != nil {
		t.Fatal(err)
	}
	if got := project(); got.GetAgentUpdate() != nil || got.GetAgentUpdateReceivedAt() != nil {
		t.Fatal("new generation borrowed old diagnostic")
	}
	if err := report(2, installed); err == nil {
		t.Fatal("retired generation reported")
	}
}

func TestAgentUpdateMalformedAndAtomicAudit(t *testing.T) {
	f := newEnrolled(t, 0)
	base := &agentv1.AgentUpdateStatus{Enabled: true, Phase: "recovery_required", ObservedAt: timestamppb.New(f.now), NativeDiagnostic: &agentv1.NativeUpdateDiagnostic{Manager: "apt-get", Phase: "apply", ExitCode: 100, ErrorLines: []string{"E: failed"}}}
	for name, mutate := range map[string]func(*agentv1.AgentUpdateStatus){
		"manager": func(s *agentv1.AgentUpdateStatus) { s.NativeDiagnostic.Manager = "/tmp/apt-get" },
		"phase":   func(s *agentv1.AgentUpdateStatus) { s.NativeDiagnostic.Phase = "arbitrary" },
		"exit":    func(s *agentv1.AgentUpdateStatus) { s.NativeDiagnostic.ExitCode = -2 },
		"lines":   func(s *agentv1.AgentUpdateStatus) { s.NativeDiagnostic.ErrorLines = make([]string, 9) },
		"line-bytes": func(s *agentv1.AgentUpdateStatus) {
			s.NativeDiagnostic.ErrorLines = []string{strings.Repeat("é", 257)}
		},
		"control": func(s *agentv1.AgentUpdateStatus) { s.NativeDiagnostic.ErrorLines = []string{"error\nforged"} },
		"status":  func(s *agentv1.AgentUpdateStatus) { s.Reason = strings.Repeat("x", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(base)
			mutate(bad)
			if _, err := f.svc.GetSyncState(f.deviceCtx(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1, AgentUpdate: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("malformed report accepted: %v", err)
			}
		})
	}
	if _, err := f.conn.Exec(f.ctx, `CREATE FUNCTION reject_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.agent_update.reported' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_update_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_update_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetSyncState(f.deviceCtx(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1, AgentUpdate: base})); err == nil {
		t.Fatal("report committed without required audit")
	}
	var reports, events int
	if err := f.conn.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM device_agent_update_reports), (SELECT count(*) FROM device_agent_update_events)").Scan(&reports, &events); err != nil || reports != 0 || events != 0 {
		t.Fatalf("rejected reports left durable state: %d %d %v", reports, events, err)
	}
}
