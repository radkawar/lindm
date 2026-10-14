// SPDX-License-Identifier: Apache-2.0

//go:build integration && consolelab

package loadlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/orgapply"
)

// SeedDemo must leave every review state as real server state, read back here
// only through the owner's Admin and integration APIs.
func TestSeedDemoProducesConsoleReviewStates(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the real console lab regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Hour)
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
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	demo, presence, err := SeedDemo(ctx, fixture, DemoOptions{SourceDirectory: source, AdvisoryCache: filepath.Join(repository, ".cache", "lab", "advisories")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := presence.Stop(); err != nil {
			t.Error(err)
		}
	})
	t.Logf("seeded in %s", time.Since(started).Round(time.Second))
	encoded, err := json.Marshal(demo)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("demo: %s", encoded)
	states := map[string]int{}
	for _, device := range demo.Devices {
		states[device.State]++
	}
	if len(demo.Devices) != 13 || states["enrolled"] != 9 || states["pending"] != 1 || states["awaiting-inventory"] != 1 || states["stale"] != 1 || states["revoked"] != 1 {
		t.Fatalf("unexpected demo fleet: %v", states)
	}
	routes := demo.Routes
	for _, id := range []string{routes.DeviceID, routes.ProfileID, routes.FirewallProfileID, routes.SecretID, routes.ActionID, routes.AssistanceSessionID, routes.RecoveryActionID, routes.FactsPendingDeviceID, routes.RolloutID} {
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
		if !slices.Contains(row.GetMetadata().GetLabels(), "synthetic-demo") {
			t.Fatalf("device %s is not labelled synthetic", device.ID)
		}
		if device.State != "pending" && device.State != "awaiting-inventory" {
			detail, err := admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: device.ID}))
			if err != nil {
				t.Fatal(err)
			}
			// Captured baselines, plus the labelled synthetic scale packages.
			wantPackages := map[string]uint32{"Ubuntu 24.04 LTS": 664, "Fedora 44": 427, "RHEL 9": 490}[device.OS] + map[string]uint32{"ubuntu-ws-01": demoRoutePackages, demoScaleHostname: demoScalePackages}[device.Hostname]
			if wantPackages == 0 || detail.Msg.GetCurrentSnapshot().GetPackageCount() != wantPackages || !detail.Msg.GetCurrentSnapshot().GetPackagesAvailable() {
				t.Fatalf("%s did not replay its complete captured package batch: %v", device.Hostname, detail.Msg.GetCurrentSnapshot())
			}
		}
		want := map[string]adminv1.DeviceState{"enrolled": adminv1.DeviceState_DEVICE_STATE_ACTIVE, "stale": adminv1.DeviceState_DEVICE_STATE_ACTIVE, "pending": adminv1.DeviceState_DEVICE_STATE_PENDING, "awaiting-inventory": adminv1.DeviceState_DEVICE_STATE_PENDING, "revoked": adminv1.DeviceState_DEVICE_STATE_REVOKED}[device.State]
		if row.GetLifecycleState() != want || device.State != "pending" && device.State != "awaiting-inventory" && row.GetHostname() != device.Hostname {
			t.Fatalf("device %+v listed as %v %q", device, row.GetLifecycleState(), row.GetHostname())
		}
		if device.State == "stale" && row.GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE {
			t.Fatalf("silent kiosk compliance is %v", row.GetCompliance())
		}
		compliance[row.GetCompliance()]++
	}
	// Organization kinds without a native simulator provider remain attention,
	// never invented compliant outcomes.
	if listed[routes.DeviceID].GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION || compliance[adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION] < 3 {
		t.Fatalf("missing honest unsupported/failed outcomes: %v", compliance)
	}
	// Engineering tools' platform-limited package rows: the Fedora/RHEL git row
	// is outside the Ubuntu route device's platform, and the Ubuntu git row
	// waits on the Engineering laptop that has not reported inventory.
	for id, row := range map[string]struct {
		key  string
		want adminv1.ResourceDisposition
	}{routes.DeviceID: {"rpm/git", adminv1.ResourceDisposition_RESOURCE_DISPOSITION_NOT_APPLICABLE}, routes.FactsPendingDeviceID: {"deb/git", adminv1.ResourceDisposition_RESOURCE_DISPOSITION_WAITING_FOR_DEVICE_FACTS}} {
		state, err := admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: id}))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(state.Msg.GetResources(), func(item *adminv1.ResourceState) bool {
			return item.GetDesired().GetRef().GetCanonicalKey() == row.key && item.GetDisposition() == row.want && len(item.GetApplicability().GetProducts()) > 0
		}) {
			t.Fatalf("device %s lacks the %v %s row: %v", id, row.want, row.key, state.Msg.GetResources())
		}
	}
	// Capability-aware hosts report the status they derived from their signed
	// policy; rhel-srv-05 runs an agent that never reports. Blocked rows carry
	// the executor's capability, adoption and missing-unit refusals; the
	// approved password-policy adoption stays blocked on the local-only
	// password_provider every stock host lacks.
	statuses, reasons := map[agentv1.CapabilityStatus]bool{}, map[string]bool{}
	for _, device := range demo.Devices {
		if device.State != "enrolled" {
			continue
		}
		detail, err := admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: device.ID}))
		if err != nil {
			t.Fatal(err)
		}
		capabilities := detail.Msg.GetCapabilities()
		reported := capabilities.GetReported()
		switch device.Hostname {
		case "ubuntu-ws-01", "ubuntu-ws-02", "fedora-ws-03", "ubuntu-srv-04", demoScaleHostname:
			if reported.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE || reported.GetAppliedVersion() == 0 || reported.GetAppliedVersion() != capabilities.GetIssuedVersion() {
				t.Fatalf("%s capability report %v, issued %d", device.Hostname, reported, capabilities.GetIssuedVersion())
			}
		case "rhel-srv-05":
			if reported != nil {
				t.Fatalf("rhel-srv-05 reported capabilities: %v", reported)
			}
		}
		for _, observed := range reported.GetCapabilities() {
			statuses[observed.GetStatus()] = true
		}
		state, err := admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: device.ID}))
		if err != nil {
			t.Fatal(err)
		}
		// Pin review scenarios to their named host and item: a reason found on
		// some other host must not satisfy the Services review fixture contract.
		type reviewRow struct {
			key         string
			disposition adminv1.ResourceDisposition
			reason      string
		}
		var expectedRows []reviewRow
		switch device.Hostname {
		case "ubuntu-ws-02":
			if !slices.ContainsFunc(reported.GetCapabilities(), func(item *agentv1.CapabilityObservation) bool {
				return item.GetCapability() == agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES && item.GetStatus() == agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE && item.GetDetail() == "vendor_key_unrecognized"
			}) {
				t.Fatalf("ubuntu-ws-02 lacks the unavailable vendor-key package report: %v", reported)
			}
			expectedRows = []reviewRow{
				{"deb/git", adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED, "capability_packages_not_enabled"},
				{"rpm/git", adminv1.ResourceDisposition_RESOURCE_DISPOSITION_NOT_APPLICABLE, "resource_platform_not_applicable"},
			}
		case demoScaleHostname:
			expectedRows = []reviewRow{
				{"cups.service", adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED, "unit_not_installed"},
			}
		}
		for _, want := range expectedRows {
			if !slices.ContainsFunc(state.Msg.GetResources(), func(item *adminv1.ResourceState) bool {
				return item.GetDesired().GetRef().GetCanonicalKey() == want.key && item.GetDisposition() == want.disposition && item.GetReason() == want.reason
			}) {
				t.Fatalf("%s lacks %s with %v / %s: %v", device.Hostname, want.key, want.disposition, want.reason, state.Msg.GetResources())
			}
		}
		for _, item := range state.Msg.GetResources() {
			reasons[item.GetReason()] = true
		}
	}
	for _, status := range []agentv1.CapabilityStatus{agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL, agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED, agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE} {
		if !statuses[status] {
			t.Fatalf("no demo host reports %v: %v", status, statuses)
		}
	}
	for _, reason := range []string{"capability_firewall_not_enabled", "capability_packages_not_enabled", "capability_password_policy_not_enabled", "existing_account", "dependency_attention", "unit_not_installed"} {
		if !reasons[reason] {
			t.Fatalf("no demo resource is blocked with %s: %v", reason, reasons)
		}
	}
	encryption, err := admin.GetDeviceEncryption(ctx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: routes.DeviceID}))
	if err != nil || encryption.Msg.GetEscrow().GetActionId() != routes.RecoveryActionID || !encryption.Msg.GetEscrow().GetRetirementConfirmed() || !encryption.Msg.GetObservation().GetEncrypted() || !slices.Contains(encryption.Msg.GetObservation().GetLindmKeyslots(), encryption.Msg.GetEscrow().GetKeyslot()) || !slices.Contains(encryption.Msg.GetObservation().GetOccupiedKeyslots(), encryption.Msg.GetEscrow().GetKeyslot()) {
		t.Fatalf("route device lacks escrowed encrypted root: %v %v", encryption, err)
	}
	// Refresh, escrow rotation and lock succeeded; the later undo expired
	// unstarted, so the accounts stay locked.
	actions, err := admin.GetDeviceActions(ctx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: routes.DeviceID, PageSize: 50}))
	if err != nil || !actions.Msg.GetSessionsLocked() || len(actions.Msg.GetActions()) != 4 || !slices.ContainsFunc(actions.Msg.GetActions(), func(action *adminv1.DeviceAction) bool {
		return action.GetActionId() == routes.ActionID && action.GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	}) || !slices.ContainsFunc(actions.Msg.GetActions(), func(action *adminv1.DeviceAction) bool {
		return action.GetSpec().GetReleaseLock() != nil && action.GetClosedReason() == "expired_unstarted"
	}) {
		t.Fatalf("route device action history: %v %v", actions, err)
	}
	rollouts, err := admin.ListRollouts(ctx, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100}))
	if err != nil {
		t.Fatal(err)
	}
	var staged, adopting *adminv1.RolloutState
	for _, r := range rollouts.Msg.GetRollouts() {
		switch {
		case r.GetRollout().GetRolloutId() == routes.RolloutID:
			staged = r
		case r.GetStatus() == adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL:
			adopting = r
		}
	}
	// The reviewed rollout flow: a named staged rollout whose pilot the
	// promoter activated, and an adoption waiting for its single approval. The
	// review lists every adoption in the planned devices' resolution, which on
	// Engineering devices also holds the organization's own adoption rows.
	if staged.GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE || staged.GetRollout().GetName() == "" || staged.GetActivatedCount() == 0 {
		t.Fatalf("staged demo rollout: %v", staged)
	}
	if adopting.GetApprovalId() == "" || adopting.GetAdoptingCount() == 0 || !slices.ContainsFunc(adopting.GetAdopted(), func(ref *resourcev1.ResourceRef) bool {
		return ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL && ref.GetCanonicalKey() == "kernel.kptr_restrict"
	}) {
		t.Fatalf("adoption demo rollout: %v", adopting)
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
		if session.GetId() == routes.AssistanceSessionID && (session.GetInputState().GetEpoch() != 1 || !session.GetInputState().GetPaused()) {
			t.Fatal("completed synthetic assistance session lost its input epoch or terminal pause")
		}
	}
	if !causes[agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED] || !causes[agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED] {
		t.Fatalf("assistance end causes: %v", causes)
	}
	// The headless server reports assistance off: the console offers no request,
	// and a request is refused before any session exists.
	off, err := admin.GetAssistanceReadiness(ctx, connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: routes.AssistanceOffDeviceID}))
	if err != nil || off.Msg.GetReadiness().GetState() != adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_DISABLED || off.Msg.GetReadiness().GetDesktop() != adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_ABSENT {
		t.Fatalf("headless assistance-off readiness: %v %v", off, err)
	}
	if _, err := admin.CreateAssistanceSession(ctx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: routes.AssistanceOffDeviceID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "Refused before it exists"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("request to an assistance-off device: %v", err)
	}
	refused, err := admin.GetAssistanceSession(ctx, connect.NewRequest(&adminv1.GetAssistanceSessionRequest{SessionId: routes.RefusedAssistanceSessionID}))
	if err != nil || refused.Msg.GetSession().GetDeviceId() != routes.RefusedAssistanceDeviceID || refused.Msg.GetSession().GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED || refused.Msg.GetSession().GetStartedAt() != nil {
		t.Fatalf("refused assistance record: %v %v", refused, err)
	}
	findingRequest := &adminv1.ListDeviceFindingsRequest{DeviceId: routes.DeviceID, PageSize: 200}
	exposures := 0
	accepted := false
	for {
		findings, err := admin.ListDeviceFindings(ctx, connect.NewRequest(findingRequest))
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings.Msg.GetFindings() {
			if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED {
				exposures++
			}
			accepted = accepted || finding.GetException() != nil
		}
		findingRequest.PageToken = findings.Msg.GetNextPageToken()
		if findingRequest.PageToken == "" {
			break
		}
	}
	if exposures < 2 || !accepted {
		t.Fatalf("route device needs one accepted and another real exposed finding: exposures=%d accepted=%t", exposures, accepted)
	}
	feeds, err := admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	published := 0
	for _, feed := range feeds.Msg.GetFeeds() {
		t.Logf("feed %s: advisories=%d fresh=%v error=%q", feed.GetId(), feed.GetAdvisoryCount(), feed.GetFresh(), feed.GetError())
		// A successfully published export may still be incomplete: unscoped
		// vendor-record rejection must not be turned into fresh coverage.
		unscoped := false
		for _, rejected := range feed.GetRejectedRecords() {
			unscoped = unscoped || rejected.GetUnscoped()
		}
		if !feed.GetFresh() && !unscoped {
			t.Errorf("feed %s is not fresh and has no unscoped rejection explaining incomplete coverage", feed.GetId())
		}
		if unscoped && feed.GetFresh() {
			t.Errorf("feed %s reports fresh coverage despite an unscoped vendor-record rejection", feed.GetId())
		}
		if feed.GetAdvisoryCount() > 1 && feed.GetError() == "" && len(feed.GetArtifacts()) > 0 && feed.GetCheckedAt().AsTime().After(started) && feed.GetExpiresAt().AsTime().After(time.Now()) {
			published++
		}
	}
	if len(feeds.Msg.GetFeeds()) != 3 || published != 3 {
		t.Fatalf("real vendor publications=%d feeds=%d; want three current publications with retained provenance", published, len(feeds.Msg.GetFeeds()))
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
		if device.Hostname == "rhel-srv-05" && findings.Msg.GetFreshness().GetReason() != "rhel_platform_stream_unavailable" {
			t.Fatalf("captured unregistered RHEL platform invented coverage: %v", findings.Msg.GetFreshness())
		}
		// Its refused package scan leaves its real-feed findings standing on a
		// device that is no longer fully checked.
		if device.Hostname == "fedora-ws-03" && (findings.Msg.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || findings.Msg.GetFreshness().GetReason() != "package_collection_failed" || len(findings.Msg.GetFindings()) == 0) {
			t.Fatalf("refused package scan did not keep its findings unconfirmed: %v findings=%d", findings.Msg.GetFreshness(), len(findings.Msg.GetFindings()))
		}
	}
	// The console's first /advisories page (50 rows) names an advisory found on
	// a device that isn't fully checked.
	summary, err := admin.ListAdvisorySummary(ctx, connect.NewRequest(&adminv1.ListAdvisorySummaryRequest{PageSize: 50}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(summary.Msg.GetAdvisories(), func(advisory *adminv1.AdvisorySummary) bool { return advisory.GetUnknownDevices() > 0 }) {
		t.Fatalf("first advisory page names no advisory found on a device not fully checked: %v", summary.Msg)
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
	findings, err := admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: request.GetDeviceId(), PageSize: 50}))
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
	raw, err := os.ReadFile(filepath.Join(source, "lab", "demo", "org.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := orgapply.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := orgapply.Plan(ctx, admin, spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := orgapply.Apply(ctx, admin, plan, orgapply.Options{AccountClient: owner})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Secrets) != 0 {
		t.Fatal("second apply reissued credentials")
	}
	for _, outcome := range second.Outcomes {
		if outcome.Status == "unchanged" || outcome.Kind == "authorization" && outcome.Status == "unsupported" || outcome.Kind == "advisory_exception" && outcome.Status == "pending" {
			continue
		}
		t.Errorf("second organization apply changed state: %+v", outcome)
	}
	// Scale fixtures add many unrelated groups; only organization groups are
	// checked here.
	declared := make(map[string]bool, len(spec.GetGroups()))
	for _, group := range spec.GetGroups() {
		declared[group.GetId()] = true
	}
	var organizationGroups []*adminv1.DeviceGroup
	for token := ""; ; {
		groups, err := admin.ListDeviceGroups(ctx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 100, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range groups.Msg.GetGroups() {
			if declared[group.GetId()] {
				organizationGroups = append(organizationGroups, group)
			}
		}
		if token = groups.Msg.GetNextPageToken(); token == "" {
			break
		}
	}
	if len(organizationGroups) != len(spec.GetGroups()) {
		t.Fatalf("unexpected organization groups: %v", organizationGroups)
	}
	for _, group := range organizationGroups {
		if len(group.GetDeviceIds()) == 0 {
			t.Errorf("organization group %s has no provisioned members", group.GetName())
		}
		if group.GetName() == "Engineering" && !slices.Contains(group.GetDeviceIds(), routes.DeviceID) {
			t.Error("route device did not enroll through Engineering token membership")
		}
		if group.GetName() == "Contractors" {
			for _, device := range demo.Devices {
				if device.State != "stale" {
					continue
				}
				labels := listed[device.ID].GetMetadata().GetLabels()
				if !slices.Contains(group.GetDeviceIds(), device.ID) || !slices.Contains(labels, "synthetic-history-only") || slices.Contains(labels, "department/contractors") {
					t.Error("history-only kiosk lost RBAC membership or rejoined organization targeting")
				}
			}
		}
	}
	if !slices.Contains(listed[routes.DeviceID].GetMetadata().GetLabels(), "department/engineering") {
		t.Error("route device lost its provisioning token department label")
	}
	// Owner pass 2: a console assignment on the present route device must make
	// progress. Replacing the profile both adds items and releases removed ones;
	// each item gets a terminal result and each release completes. Returning to
	// the first organization profile re-adds items the device already ran once.
	// This runs after the idempotency apply above because it changes assignment.
	// Company baseline and Engineering tools adopt native state, so a direct
	// assignment of them needs an approval; these two profiles create only.
	byName := map[string]*adminv1.ProfileSummary{}
	for token := ""; ; {
		profiles, err := admin.ListProfiles(ctx, connect.NewRequest(&adminv1.ListProfilesRequest{PageSize: 100, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range profiles.Msg.GetProfiles() {
			byName[profile.GetName()] = profile
		}
		if token = profiles.Msg.GetNextPageToken(); token == "" {
			break
		}
	}
	if byName["Finance hardened"] == nil || byName["Contractors"] == nil {
		t.Fatalf("demo profiles: %d listed without the organization's Finance hardened and Contractors", len(byName))
	}
	assign := func(profile *adminv1.ProfileSummary) {
		t.Helper()
		current, err := admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: routes.DeviceID}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: routes.DeviceID, ExpectedAssignmentId: proto.String(current.Msg.GetAssignment().GetAssignmentId()), Target: &adminv1.ResourceAssignmentTarget{ProfileId: profile.GetProfileId(), RevisionId: profile.GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(86400), Reason: "Assign " + profile.GetName() + " from the console"})); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(3 * demoPresenceInterval)
		for {
			state, err := admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: routes.DeviceID}))
			if err != nil {
				t.Fatal(err)
			}
			done := state.Msg.GetAssignment().GetProfileId() == profile.GetProfileId() && len(state.Msg.GetResources()) == int(profile.GetResourceCount())
			for _, item := range state.Msg.GetResources() {
				disposition := item.GetDisposition()
				done = done && item.GetLatestAction().GetStatus() != nil && disposition != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING && disposition != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS
			}
			// Only "pending" releases are still in progress; a refused removal
			// (release_conflict) is final and must not leave the device stuck.
			for _, release := range state.Msg.GetReleases() {
				done = done && release.GetState() != "pending"
			}
			if done {
				return
			}
			select {
			case <-poll.C:
			case <-deadline:
				var stuck []string
				for _, item := range state.Msg.GetResources() {
					action := item.GetLatestAction()
					stuck = append(stuck, fmt.Sprintf("%s: %v reason=%q action=%q closed=%q state=%v", item.GetDesired().GetRef().GetCanonicalKey(), item.GetDisposition(), item.GetReason(), action.GetActionId(), action.GetClosedReason(), action.GetStatus().GetState()))
				}
				for _, release := range state.Msg.GetReleases() {
					stuck = append(stuck, fmt.Sprintf("release %s: %s reason=%q completed=%v", release.GetRef().GetCanonicalKey(), release.GetState(), release.GetReason(), release.GetCompletedAt() != nil))
				}
				t.Fatalf("present device did not process the %s assignment: %s", profile.GetName(), strings.Join(stuck, "; "))
			}
		}
	}
	assign(byName["Finance hardened"])
	assign(byName["Contractors"])
	assign(byName["Finance hardened"])
}

// Exercise organization targeting/dispatch independently of the expensive vendor
// import. The full SeedDemo regression above still requires all real feeds.
func TestDemoOrganizationResourceConvergence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	body, err := os.ReadFile("../../lab/demo/org.json")
	if err != nil {
		t.Fatal(err)
	}
	organization, err := orgapply.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.ConfigureAuthorization(ctx, organization.GetAuthorization()); err != nil {
		t.Fatal(err)
	}
	devices, err := demoDevices("../..")
	if err != nil {
		t.Fatal(err)
	}
	devices = devices[:1]
	r := &runner{fixture: fixture, metrics: &measurements{}, demo: devices, options: Options{Packages: 1, EnrollmentWorkers: 1}}
	if err := r.prepare(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.enrollmentTransport.CloseIdleConnections()
		if err := r.owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	})
	s := &demoSeed{runner: r, organization: organization}
	enrollment := proto.CloneOf(organization)
	enrollment.Rollouts, enrollment.Assignments = nil, nil
	applied, err := s.applyOrganization(ctx, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(applied.Secrets)
	for _, token := range organization.GetProvisioningTokens() {
		if token.GetName() == devices[0].department {
			devices[0].labels = append(devices[0].labels, token.GetRequest().GetMetadata().GetLabels()...)
		}
	}
	for _, secret := range applied.Secrets {
		if secret.Kind == "provisioning_token" && secret.Name == devices[0].department {
			devices[0].provisioningToken = secret.Value
		}
	}
	enrolled, err := r.enrollBatch(ctx, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	d := enrolled[0]
	defer d.close()
	if err := s.describe(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	// Adoption rows wait for one approval per rollout; a second admin decides
	// them, and the organization is applied again until no rollout awaits one.
	if err := fixture.UseAdminApprover(ctx); err != nil {
		t.Fatal(err)
	}
	approver, err := devlab.OpenApprovalSession(ctx, "", fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := approver.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	})
	s.approver = approver
	if err := s.rollOutOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.awaitRollouts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.converge(ctx, d); err != nil {
		state, readErr := s.owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: d.id}))
		if readErr == nil {
			for _, resource := range state.Msg.GetResources() {
				t.Logf("resource=%s disposition=%s reason=%s action=%s", resource.GetResourceId(), resource.GetDisposition(), resource.GetReason(), resource.GetLatestAction().GetStatus().GetState())
			}
		}
		t.Fatalf("converge: %v; state read: %v", err, readErr)
	}
}

// Interactive seeding accepts Fedora's only fixture finding before the
// asynchronous refused-scan setup starts. Acceptance must not stall that setup.
func TestInteractiveDemoRefusedScanAfterAcceptedFinding(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the console lab regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
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
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	demo, presence, err := SeedDemo(ctx, fixture, DemoOptions{
		SourceDirectory: source, FixtureFeeds: true, BackgroundPackageFailure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := presence.Stop(); err != nil {
			t.Error(err)
		}
	})
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
	var deviceID string
	for _, device := range demo.Devices {
		if device.Hostname == "fedora-ws-03" {
			deviceID = device.ID
		}
	}
	if deviceID == "" {
		t.Fatal("refused-scan fixture device is missing")
	}
	first, err := owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.GetTotals().GetAccepted() == 0 {
		t.Fatal("regression prerequisite: the only fixture finding must already have an accepted exception")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		result, err := owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		if result.Msg.GetFreshness().GetReason() == "package_collection_failed" {
			if len(result.Msg.GetFindings()) == 0 || result.Msg.GetFindings()[0].GetException() == nil {
				t.Fatal("refused scan lost the retained finding or its accepted exception")
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("accepted exception stalled the background refused scan", ctx.Err())
		case <-ticker.C:
		}
	}
}
