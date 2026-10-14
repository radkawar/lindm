// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	assistant "lindm/internal/mcp"
)

// Seed an actual opaque browser credential; RequireMCP, not WithPrincipal,
// constructs the authenticated proof used by the fresh domain fences.
func mcpBrowserCredential(t *testing.T, f *enrolledFixture, principal identity.Principal) (string, string) {
	t.Helper()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(material)
	digest := func(domain string) []byte {
		value := binary.BigEndian.AppendUint16(nil, uint16(len(domain)))
		value = append(value, domain...)
		value = append(value, 0)
		value = append(value, token...)
		hash := sha256.Sum256(value)
		return hash[:]
	}
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO sessions(token_hash,principal_id,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
VALUES($1,$2,now(),now(),now()+interval '30 minutes',now()+interval '12 hours')`, digest("lindm.session.v1"), principal.ID); err != nil {
		t.Fatal(err)
	}
	return token, base64.RawURLEncoding.EncodeToString(digest("lindm.csrf.v1"))
}

func mcpTestHandler(t *testing.T, f *enrolledFixture) http.Handler {
	t.Helper()
	_, admin := f.svc.AdminHandler()
	handler, err := assistant.New(admin, f.svc.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(f.ctx, "UPDATE mcp_settings SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	return f.svc.Identity.RequireMCP(handler)
}

func mcpHTTP(t *testing.T, ctx context.Context, handler http.Handler, token, csrf, tool string, input proto.Message) (*httptest.ResponseRecorder, *mcp.CallToolResult) {
	t.Helper()
	return mcpHTTPAt(t, ctx, handler, "https://admin.example", token, csrf, tool, input)
}

func mcpHTTPAt(t *testing.T, ctx context.Context, handler http.Handler, origin, token, csrf, tool string, input proto.Message) (*httptest.ResponseRecorder, *mcp.CallToolResult) {
	t.Helper()
	arguments := json.RawMessage(`{}`)
	if input != nil {
		var err error
		arguments, err = protojson.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": arguments}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, origin+"/mcp", bytes.NewReader(payload)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	request.Header.Set("Origin", origin)
	request.Header.Set("X-CSRF-Token", csrf)
	if token != "" {
		if csrf == "" {
			request.Header.Set("Authorization", "Bearer "+token)
		} else {
			request.AddCookie(&http.Cookie{Name: "__Host-lindm_session", Value: token})
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return recorder, nil
	}
	var response struct {
		Result *mcp.CallToolResult `json:"result"`
		Error  json.RawMessage     `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.Result == nil {
		t.Fatalf("MCP response: %s (decode=%v)", recorder.Body.String(), err)
	}
	return recorder, response.Result
}

func mcpReadData(t *testing.T, result *mcp.CallToolResult, target proto.Message) {
	t.Helper()
	if result == nil || result.IsError {
		t.Fatalf("MCP read failed: %v", result)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		TrustBoundary string          `json:"trustBoundary"`
		Data          json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.TrustBoundary == "" {
		t.Fatalf("trust boundary: %v", err)
	}
	if err := protojson.Unmarshal(envelope.Data, target); err != nil {
		t.Fatal(err)
	}
}

func TestMCPReadsFilterScopeAndAuditDeniedCalls(t *testing.T) {
	f := newEnrolled(t, 0)
	other := fleetSummaryEnroll(t, f)
	reader := insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor)
	if _, err := f.conn.Exec(f.ctx, `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, reader.ID, f.deviceID); err != nil {
		t.Fatal(err)
	}
	token, csrf := mcpBrowserCredential(t, f, reader)
	handler := mcpTestHandler(t, f)
	if response, _ := mcpHTTP(t, f.ctx, handler, "", "", "search_devices", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous HTTP=%d", response.Code)
	}
	get := httptest.NewRequest(http.MethodGet, "https://admin.example/mcp", nil).WithContext(f.ctx)
	get.AddCookie(&http.Cookie{Name: "__Host-lindm_session", Value: token})
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("stateless GET accepted: HTTP=%d", getResponse.Code)
	}
	_, result := mcpHTTP(t, f.ctx, handler, token, csrf, "search_devices", &adminv1.ListDevicesRequest{PageSize: 1})
	devices := new(adminv1.ListDevicesResponse)
	helpdesk := insertPrincipal(t, f.ctx, f.conn, identity.RoleHelpdesk)
	helpdeskToken, helpdeskCSRF := mcpBrowserCredential(t, f, helpdesk)
	_, permissionDenied := mcpHTTP(t, f.ctx, handler, helpdeskToken, helpdeskCSRF, "search_audit", nil)
	if permissionDenied == nil || !permissionDenied.IsError {
		t.Fatal("audit permission denial bypassed")
	}
	mcpReadData(t, result, devices)
	if len(devices.GetDevices()) != 1 || devices.GetDevices()[0].GetId() != f.deviceID || devices.GetNextPageToken() != "" {
		t.Fatalf("scope leaked: %v", devices)
	}
	_, denied := mcpHTTP(t, f.ctx, handler, token, csrf, "device_details", &adminv1.GetDeviceRequest{DeviceId: other.deviceID})
	if denied == nil || !denied.IsError {
		t.Fatalf("out-of-scope device admitted: %v", denied)
	}
	_, result = mcpHTTP(t, f.ctx, handler, token, csrf, "fleet_summary", nil)
	summary := new(adminv1.GetFleetSummaryResponse)
	mcpReadData(t, result, summary)
	if summary.GetLifecycle().GetTotalDevices() != 1 {
		t.Fatalf("summary scope leaked: %v", summary)
	}
	_, complianceResult := mcpHTTP(t, f.ctx, handler, token, csrf, "device_compliance", &adminv1.GetDeviceResourceStateRequest{DeviceId: f.deviceID})
	compliance := new(adminv1.GetDeviceResourceStateResponse)
	mcpReadData(t, complianceResult, compliance)
	if compliance.GetAssignment() != nil || len(compliance.GetResources()) != 0 {
		t.Fatal("unassigned device fabricated compliance evidence")
	}
	var attempts, denials int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE action='mcp.attempt' AND details->>'outcome'='attempt'),count(*) FILTER(WHERE action='mcp.attempt' AND details->>'outcome'='denied') FROM audit_events WHERE actor_id=$1`, reader.ID).Scan(&attempts, &denials); err != nil {
		t.Fatal(err)
	}
	if attempts < 3 || denials == 0 {
		t.Fatalf("missing MCP audit attempts=%d denials=%d", attempts, denials)
	}
}

func TestMCPRestartOnlyCreatesPendingApproval(t *testing.T) {
	f := newDeviceActionFixture(t)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	token, csrf := mcpBrowserCredential(t, f.enrolledFixture, owner)
	handler := mcpTestHandler(t, f.enrolledFixture)
	request := f.request(restartActionSpec())
	issueBody, err := protojson.Marshal(&authv1.IssueMCPTokenRequest{Label: "Read assistant", LifetimeSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	issue := httptest.NewRequest(http.MethodPost, "https://admin.example/auth/mcp/tokens", bytes.NewReader(issueBody)).WithContext(f.ctx)
	issue.Header.Set("Content-Type", "application/json")
	issue.Header.Set("Origin", "https://admin.example")
	issue.Header.Set("X-CSRF-Token", csrf)
	issue.AddCookie(&http.Cookie{Name: "__Host-lindm_session", Value: token})
	issued := httptest.NewRecorder()
	f.svc.Identity.Handler().ServeHTTP(issued, issue)
	readToken := new(authv1.IssueMCPTokenResponse)
	if issued.Code != http.StatusOK || protojson.Unmarshal(issued.Body.Bytes(), readToken) != nil {
		t.Fatalf("issue reader: HTTP=%d body=%s", issued.Code, issued.Body.String())
	}
	_, readDenied := mcpHTTP(t, f.ctx, handler, readToken.GetBearerToken(), "", "request_restart", request)
	if readDenied == nil || !readDenied.IsError {
		t.Fatal("read-only token created a proposal")
	}
	updateBody, err := protojson.Marshal(&authv1.UpdateMCPSettingsRequest{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	update := httptest.NewRequest(http.MethodPost, "https://admin.example/auth/mcp/settings", bytes.NewReader(updateBody)).WithContext(f.ctx)
	update.Header.Set("Content-Type", "application/json")
	update.Header.Set("Origin", "https://admin.example")
	update.Header.Set("X-CSRF-Token", csrf)
	update.AddCookie(&http.Cookie{Name: "__Host-lindm_session", Value: token})
	updated := httptest.NewRecorder()
	f.svc.Identity.Handler().ServeHTTP(updated, update)
	if updated.Code != http.StatusOK {
		t.Fatalf("settings update: HTTP=%d", updated.Code)
	}
	_, auditResult := mcpHTTP(t, f.ctx, handler, token, csrf, "search_audit", &adminv1.ListAuditEventsRequest{PageSize: 200})
	auditPage := new(adminv1.ListAuditEventsResponse)
	mcpReadData(t, auditResult, auditPage)
	sawSettings, sawIssue := false, false
	for _, event := range auditPage.GetEvents() {
		switch event.GetAction() {
		case "identity.mcp_settings_changed":
			sawSettings = event.GetDetails()["enabled"] == "true"
		case "identity.mcp_token_issued":
			sawIssue = event.GetDetails()["proposals_allowed"] == "false"
		}
	}
	if !sawSettings || !sawIssue {
		t.Fatalf("MCP management audit details unavailable settings=%v issue=%v", sawSettings, sawIssue)
	}
	_, result := mcpHTTP(t, f.ctx, handler, token, csrf, "request_restart", request)
	response := new(adminv1.CreateApprovalResponse)
	mcpReadData(t, result, response)
	approval := response.GetApproval()
	if approval.GetState() != adminv1.ApprovalState_APPROVAL_STATE_PENDING || approval.GetRequesterId() != owner.ID.String() || approval.GetCreateDeviceAction().GetRequestId() != request.GetRequestId() {
		t.Fatalf("proposal not pending/exact: %v", approval)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "pending" {
		t.Fatalf("persisted state=%s", state)
	}
	var actions, approvalAudits int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM device_actions WHERE device_id=$1", f.deviceID).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if actions != 0 {
		t.Fatalf("MCP dispatched %d actions", actions)
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='approval.created' AND resource_id=$1", approval.GetId()).Scan(&approvalAudits); err != nil {
		t.Fatal(err)
	}
	if approvalAudits != 1 {
		t.Fatalf("approval audit count=%d", approvalAudits)
	}
	request.Spec = shutdownActionSpec()
	request.RequestId = uuid.NewString()
	_, denied := mcpHTTP(t, f.ctx, handler, token, csrf, "request_restart", request)
	if denied == nil || !denied.IsError {
		t.Fatalf("nonrestart accepted: %v", denied)
	}
}

func TestMCPRolloutProposalCannotStartEvenWithoutPolicyApproval(t *testing.T) {
	f := newRolloutFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	review := f.review(t)
	if review.GetApprovalRequired() {
		t.Fatal("fixture already required approval; it cannot exercise the MCP fence")
	}
	conn, err := f.pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	enrolled := &enrolledFixture{ctx: t.Context(), svc: f.service, conn: conn.Conn()}
	token, csrf := mcpBrowserCredential(t, enrolled, f.actor)
	handler := mcpTestHandler(t, enrolled)
	request := reviewedRollout(review, "Review the assistant rollout proposal")
	_, result := mcpHTTPAt(t, t.Context(), handler, "https://localhost:18444", token, csrf, "prepare_rollout", request)
	response := new(adminv1.CreateApprovalResponse)
	mcpReadData(t, result, response)
	approval := response.GetApproval()
	if approval.GetState() != adminv1.ApprovalState_APPROVAL_STATE_PENDING || approval.GetStartRollout().GetRequestId() != request.GetRequestId() || approval.GetRollout().GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL || !approval.GetRollout().GetApprovalRequired() {
		t.Fatalf("rollout proposal not exact/pending: %v", approval)
	}
	if err := f.promoter.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	var assignments, heads int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM target_assignments").Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM resource_assignment_heads").Scan(&heads); err != nil {
		t.Fatal(err)
	}
	if assignments != 0 || heads != 0 {
		t.Fatalf("unapproved MCP proposal started assignments=%d heads=%d", assignments, heads)
	}
}
