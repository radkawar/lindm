// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
)

type failingAudit struct{}

func (failingAudit) AuditMCP(context.Context, string, string) error {
	return errors.New("audit store unavailable")
}
func (failingAudit) AuditMCPResult(context.Context, string, string, string) error {
	return errors.New("audit store unavailable")
}

func TestAuditFailureAndAnonymousPreventAPIAdmission(t *testing.T) {
	calls := 0
	handler, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }), failingAudit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, authenticated := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fleet_summary","arguments":{}}}`))
		if authenticated {
			request = request.WithContext(identity.WithPrincipal(request.Context(), identity.Principal{ID: uuid.New(), Role: identity.RoleOwner}))
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if authenticated {
			want = http.StatusServiceUnavailable
		}
		if response.Code != want {
			t.Fatalf("authenticated=%v HTTP=%d want=%d", authenticated, response.Code, want)
		}
	}
	if calls != 0 {
		t.Fatalf("audit/anonymous refusal admitted %d calls", calls)
	}
}

func TestPrincipalRateLimitIsBoundedAndExpires(t *testing.T) {
	now := time.Unix(1700000000, 0)
	limits := &principalLimits{clock: func() time.Time { return now }, entries: make(map[uuid.UUID]principalWindow)}
	principal := uuid.New()
	for range 60 {
		if !limits.allow(principal) {
			t.Fatal("permitted window refused")
		}
	}
	if limits.allow(principal) {
		t.Fatal("61st call admitted")
	}
	if !limits.allow(uuid.New()) {
		t.Fatal("one principal exhausted another's rate")
	}
	now = now.Add(time.Minute)
	if !limits.allow(principal) {
		t.Fatal("new window refused")
	}
	limits.entries = make(map[uuid.UUID]principalWindow)
	for len(limits.entries) < 4096 {
		limits.allow(uuid.New())
	}
	if limits.allow(uuid.New()) || len(limits.entries) != 4096 {
		t.Fatal("limiter grew beyond principal bound")
	}
	now = now.Add(time.Minute)
	if !limits.allow(uuid.New()) {
		t.Fatal("expired entries were not reclaimed")
	}
}

func TestReadOnlyOrMissingProofCannotCreateProposal(t *testing.T) {
	for _, definition := range toolDefinitions() {
		if !definition.proposal {
			continue
		}
		admitted := false
		result := callTool(identity.WithPrincipal(t.Context(), identity.Principal{ID: uuid.New(), Role: identity.RoleOwner}), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { admitted = true }), definition, []byte(`{}`))
		if !result.IsError || admitted {
			t.Fatalf("%s accepted unproven proposal", definition.name)
		}
	}
}

func TestProposalPayloadAllowlist(t *testing.T) {
	request := &adminv1.CreateDeviceActionRequest{Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}}
	proposal, err := proposalInput(request)
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := proposal.(*adminv1.CreateApprovalRequest)
	if !ok || approval.GetCreateDeviceAction() != request {
		t.Fatal("restart did not retain exact approval payload")
	}
	request.ApprovalId = uuid.NewString()
	if _, err := proposalInput(request); err == nil {
		t.Fatal("approval reuse admitted")
	}
	request.ApprovalId = ""
	request.Spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}
	if _, err := proposalInput(request); err == nil {
		t.Fatal("nonrestart action admitted")
	}
	for _, spec := range []*agentv1.DeviceActionSpec{
		{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{}}},
		{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{}}},
	} {
		request.Spec = spec
		if _, err := proposalInput(request); err == nil {
			t.Fatal("wipe proposal admitted")
		}
	}
	request.Spec = nil
	if _, err := proposalInput(request); err == nil {
		t.Fatal("missing action admitted")
	}
}

func TestComplianceOutputExcludesConfigurationAndExecutionOutput(t *testing.T) {
	original := &adminv1.GetDeviceResourceStateResponse{
		Assignment:    &adminv1.ResourceAssignment{},
		Resources:     []*adminv1.ResourceState{{ResourceId: "reported-resource", Desired: &resourcev1.ResourceDesiredState{}, LatestAction: &adminv1.ResourceActionSummary{}, Compliance: adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN}},
		RecentActions: []*adminv1.DeviceResourceAction{{ResourceId: "old-action"}},
	}
	body, err := protojson.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	body, err = complianceResult(body)
	if err != nil {
		t.Fatal(err)
	}
	response := new(adminv1.GetDeviceResourceStateResponse)
	if err := protojson.Unmarshal(body, response); err != nil {
		t.Fatal(err)
	}
	if response.Assignment != nil || len(response.RecentActions) != 0 || len(response.Resources) != 1 || response.Resources[0].Desired != nil || response.Resources[0].LatestAction != nil || response.Resources[0].GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN {
		t.Fatalf("configuration leaked or unknown changed: %v", response)
	}
}

func TestOversizedResponsesNeverExposePartialEvidence(t *testing.T) {
	response := &boundedResponse{header: make(http.Header)}
	body := bytes.Repeat([]byte("x"), maxResultBytes+1)
	if n, err := response.Write(body); err != nil || n != len(body) {
		t.Fatalf("API writer failed %d %v", n, err)
	}
	if !response.overflow || response.body.Len() != 0 {
		t.Fatal("oversized evidence retained")
	}
}

func TestAuditNamesRejectUntrustedControlAndUnicode(t *testing.T) {
	for _, value := range []string{"fleet_summary\nsecret", "not a tool", "设备", strings.Repeat("a", 65), "tool?secret"} {
		if boundedAuditName(value) != "unknown" {
			t.Fatal("untrusted audit value admitted")
		}
	}
	if boundedAuditName("tools/call") != "tools/call" || boundedAuditName("fleet_summary") != "fleet_summary" {
		t.Fatal("valid audit tags refused")
	}
}
