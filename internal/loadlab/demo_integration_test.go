//go:build integration && consolelab

package loadlab

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/devlab"
)

// SeedDemo must leave every review state as real server state, read back here
// only through the owner's Admin and integration APIs.
func TestSeedDemoProducesConsoleReviewStates(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the real console lab regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	started := time.Now()
	demo, presence, err := SeedDemo(ctx, fixture, DemoOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := presence.Stop(); err != nil {
			t.Error(err)
		}
	})
	t.Logf("seeded in %s", time.Since(started).Round(time.Second))
	if elapsed := time.Since(started); elapsed > 5*time.Minute {
		t.Fatalf("demo seeding took %s", elapsed)
	}
	encoded, err := json.Marshal(demo)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("demo: %s", encoded)
	states := map[string]int{}
	for _, device := range demo.Devices {
		states[device.State]++
	}
	if len(demo.Devices) != 9 || states["enrolled"] != 6 || states["pending"] != 1 || states["stale"] != 1 || states["revoked"] != 1 {
		t.Fatalf("unexpected demo fleet: %v", states)
	}
	routes := demo.Routes
	for _, id := range []string{routes.DeviceID, routes.ProfileID, routes.SecretID, routes.ActionID, routes.AssistanceSessionID, routes.RecoveryActionID} {
		if id == "" {
			t.Fatalf("missing route ID: %+v", routes)
		}
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := owner.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	admin := owner.Admin
	devices, err := admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 200}))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]*adminv1.Device{}
	for _, device := range devices.Msg.GetDevices() {
		listed[device.GetId()] = device
	}
	compliance := map[adminv1.DeviceCompliance]int{}
	for _, device := range demo.Devices {
		row := listed[device.ID]
		if row == nil {
			t.Fatalf("device %s not listed", device.ID)
		}
		want := map[string]adminv1.DeviceState{"enrolled": adminv1.DeviceState_DEVICE_STATE_ACTIVE, "stale": adminv1.DeviceState_DEVICE_STATE_ACTIVE, "pending": adminv1.DeviceState_DEVICE_STATE_PENDING, "revoked": adminv1.DeviceState_DEVICE_STATE_REVOKED}[device.State]
		if row.GetLifecycleState() != want || device.State != "pending" && row.GetHostname() != device.Hostname {
			t.Fatalf("device %+v listed as %v %q", device, row.GetLifecycleState(), row.GetHostname())
		}
		if device.State == "stale" && row.GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE {
			t.Fatalf("silent kiosk compliance is %v", row.GetCompliance())
		}
		compliance[row.GetCompliance()]++
	}
	// Converged read-only results comply; encryption drift, a native service
	// failure and unsupported kinds need attention.
	if listed[routes.DeviceID].GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_COMPLIANT || compliance[adminv1.DeviceCompliance_DEVICE_COMPLIANCE_COMPLIANT] != 2 || compliance[adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION] != 3 || compliance[adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED] == 0 {
		t.Fatalf("missing compliant/drifting/failed outcomes: %v", compliance)
	}
	encryption, err := admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: routes.DeviceID}))
	if err != nil || encryption.Msg.GetEscrow().GetActionId() != routes.RecoveryActionID || !encryption.Msg.GetEscrow().GetRetirementConfirmed() || !encryption.Msg.GetObservation().GetEncrypted() || !slices.Contains(encryption.Msg.GetObservation().GetLindmKeyslots(), encryption.Msg.GetEscrow().GetKeyslot()) || !slices.Contains(encryption.Msg.GetObservation().GetOccupiedKeyslots(), encryption.Msg.GetEscrow().GetKeyslot()) {
		t.Fatalf("route device lacks escrowed encrypted root: %v %v", encryption, err)
	}
	actions, err := admin.GetDeviceActions(ctx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: routes.DeviceID, PageSize: 50}))
	if err != nil || !actions.Msg.GetSessionsLocked() || len(actions.Msg.GetActions()) != 3 || !slices.ContainsFunc(actions.Msg.GetActions(), func(action *adminv1.DeviceAction) bool {
		return action.GetActionId() == routes.ActionID && action.GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	}) {
		t.Fatalf("route device action history: %v %v", actions, err)
	}
	approvals, err := admin.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 50}))
	if err != nil || !slices.ContainsFunc(approvals.Msg.GetApprovals(), func(approval *adminv1.Approval) bool {
		return approval.GetDeviceId() == routes.DeviceID && approval.GetState() == adminv1.ApprovalState_APPROVAL_STATE_PENDING
	}) {
		t.Fatalf("missing pending wipe approval: %v %v", approvals, err)
	}
	sessions, err := admin.ListAssistanceSessions(ctx, connect.NewRequest(&adminv1.ListAssistanceSessionsRequest{DeviceId: routes.DeviceID, PageSize: 10}))
	if err != nil || len(sessions.Msg.GetSessions()) != 2 {
		t.Fatalf("assistance sessions: %v %v", sessions, err)
	}
	causes := map[agentv1.AssistanceEndCause]bool{}
	for _, session := range sessions.Msg.GetSessions() {
		causes[session.GetEndCause()] = true
		if session.GetId() == routes.AssistanceSessionID && session.GetStartedAt() == nil {
			t.Fatal("completed assistance session never started")
		}
	}
	if !causes[agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED] || !causes[agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED] {
		t.Fatalf("assistance end causes: %v", causes)
	}
	findings, err := admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: routes.DeviceID, PageSize: 50}))
	if err != nil || !slices.ContainsFunc(findings.Msg.GetFindings(), func(finding *adminv1.AdvisoryFinding) bool { return finding.GetException() != nil }) {
		t.Fatalf("missing accepted advisory finding: %v %v", findings, err)
	}
	feeds, err := admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	published := 0
	for _, feed := range feeds.Msg.GetFeeds() {
		t.Logf("feed %s: advisories=%d fresh=%v error=%q", feed.GetId(), feed.GetAdvisoryCount(), feed.GetFresh(), feed.GetError())
		if feed.GetAdvisoryCount() > 0 && feed.GetError() == "" {
			published++
		}
	}
	if len(feeds.Msg.GetFeeds()) != 4 || published < 3 {
		t.Fatalf("served vendor fixtures were not published: %v", feeds)
	}
	for _, device := range demo.Devices {
		if device.State == "pending" || device.State == "revoked" {
			continue
		}
		findings, err := admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: device.ID, PageSize: 50}))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: compliance=%v findings=%d freshness=%v/%s", device.Hostname, listed[device.ID].GetCompliance(), len(findings.Msg.GetFindings()), findings.Msg.GetFreshness().GetState(), findings.Msg.GetFreshness().GetReason())
	}
	// Proposed risk: an AFFECTED finding pending independent review beside a
	// proposal whose finding evidence is unavailable.
	proposals := map[string]*adminv1.Approval{}
	for _, approval := range approvals.Msg.GetApprovals() {
		if approval.GetAcceptAdvisoryFinding() != nil && approval.GetState() == adminv1.ApprovalState_APPROVAL_STATE_PENDING {
			proposals[approval.GetAcceptAdvisoryFinding().GetReason()] = approval
		}
	}
	proposed, missing := proposals["Review the isolated management-network exposure before the scheduled patch window"], proposals["Review stopped because finding evidence is unavailable"]
	if len(proposals) != 2 || proposed.GetAdvisoryFinding() == nil || missing == nil || missing.GetAdvisoryFinding() != nil {
		t.Fatalf("advisory acceptance proposals: %v", proposals)
	}
	request := proposed.GetAcceptAdvisoryFinding()
	findings, err = admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: request.GetDeviceId(), PageSize: 50}))
	if err != nil || !slices.ContainsFunc(findings.Msg.GetFindings(), func(finding *adminv1.AdvisoryFinding) bool {
		return finding.GetId() == request.GetFindingId() && finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED
	}) {
		t.Fatalf("proposed finding is not AFFECTED: %v %v", findings, err)
	}
	pending, err := admin.GetPendingEnrollments(ctx, connect.NewRequest(&adminv1.GetPendingEnrollmentsRequest{PageSize: 10}))
	if err != nil || len(pending.Msg.GetEnrollments()) != 1 {
		t.Fatalf("pending enrollments: %v %v", pending, err)
	}
	if _, err := admin.GetProfileRevision(ctx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: routes.ProfileID})); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.GetSecret(ctx, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: routes.SecretID})); err != nil {
		t.Fatal(err)
	}
	destinations, err := owner.Integrations().ListDestinations(ctx, connect.NewRequest(&integrationsv1.ListDestinationsRequest{}))
	if err != nil || len(destinations.Msg.GetDestinations()) != 1 {
		t.Fatalf("webhook destination: %v %v", destinations, err)
	}
	schedules, err := owner.Reports().ListReportSchedules(ctx, connect.NewRequest(&integrationsv1.ListReportSchedulesRequest{}))
	if err != nil || len(schedules.Msg.GetSchedules()) != 1 {
		t.Fatalf("report schedule: %v %v", schedules, err)
	}
	// The present route device completes a console-requested refresh on a later
	// check-in, which makes wipe storage selectable again without reseeding.
	refresh, err := admin.CreateDeviceAction(ctx, connect.NewRequest(&adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: routes.DeviceID, EnrollmentGeneration: listed[routes.DeviceID].GetEnrollmentGeneration(),
		Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "Refresh storage before reviewing a wipe"}))
	if err != nil {
		t.Fatal(err)
	}
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	deadline := time.After(90 * time.Second)
	for {
		action, err := admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: refresh.Msg.GetAction().GetActionId()}))
		if err != nil {
			t.Fatal(err)
		}
		if action.Msg.GetAction().GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			break
		}
		select {
		case <-poll.C:
		case <-deadline:
			t.Fatalf("present device did not complete the console refresh: %v", action.Msg.GetAction())
		}
	}
	targets, err := admin.ListDeviceStorageTargets(ctx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: routes.DeviceID, ActionKind: "crypto_erase"}))
	if err != nil || !targets.Msg.GetFresh() || targets.Msg.GetUnavailableReason() != "" || len(targets.Msg.GetTargets()) == 0 {
		t.Fatalf("refreshed wipe storage: %v %v", targets, err)
	}
}
