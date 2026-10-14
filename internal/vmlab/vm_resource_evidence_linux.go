// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Native records are embedded in the durable lab record, rather than pointing
// at files destroyed with the guest. SHA256 binds the exact independent bytes.
type VMResourceNativeRecord struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  []byte `json:"bytes"`
}

type VMResourceScenario struct {
	Name            string                           `json:"name"`
	StartedAt       time.Time                        `json:"started_at"`
	FinishedAt      time.Time                        `json:"finished_at"`
	Action          *adminv1.ResourceActionSummary   `json:"action,omitempty"`
	Release         *adminv1.ResourceRelease         `json:"release,omitempty"`
	ExecutorStatus  *agentv1.ResourceExecutionStatus `json:"executor_status,omitempty"`
	ExecutorHistory []vmServiceAttestationPhase      `json:"authenticated_executor_history,omitempty"`
	// DeviceActions are real server-dispatched device actions (for example a
	// quarantine during a firewall zone) whose root and server states agree.
	DeviceActions []*actionDispatchEvidence `json:"device_actions,omitempty"`
	Native        []VMResourceNativeRecord  `json:"native_records"`
	Passed        bool                      `json:"passed"`
	Failure       string                    `json:"failure,omitempty"`
}

type VMResourceKindEvidence struct {
	Kind            resourcev1.ResourceKind `json:"kind"`
	Scenarios       []VMResourceScenario    `json:"scenarios"`
	NativeQualified bool                    `json:"native_qualified"`
	Unproven        []string                `json:"unproven"`
}

type VMResourceEvidence struct {
	ExecutionPath string                   `json:"execution_path"`
	Fixture       []VMResourceNativeRecord `json:"fixture_records"`
	Kinds         []VMResourceKindEvidence `json:"kinds"`
	// This lane is deliberately not a claim that all resource kinds or physical
	// encryption/authentication/connectivity requirements have been qualified.
	LaunchGateOpen bool `json:"launch_gate_open"`
	// SecretPassword names the managed secret delivered to Kinds[9]; it
	// carries metadata only, never material.
	SecretPassword  *VMSecretPasswordEvidence `json:"secret_password,omitempty"`
	LocalAdmin      *VMLocalAdminEvidence     `json:"local_admin,omitempty"`
	ModuleBlocklist *VMResourceKindEvidence   `json:"module_blocklist,omitempty"`
	// Banner-only SSH qualification does not certify authentication policy.
	SSHBanner *VMResourceKindEvidence `json:"ssh_banner,omitempty"`
}

func newVMResourceEvidence() *VMResourceEvidence {
	return &VMResourceEvidence{Kinds: []VMResourceKindEvidence{
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, Unproven: []string{"native signed package lifecycle not completed"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, Unproven: []string{"native signed file lifecycle not completed"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, Unproven: []string{"installed signed account lane and independent local/NSS oracle not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, Unproven: []string{"installed signed account lane, UID reuse, password custody and home preservation not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, Unproven: []string{"persistent and live kernel state across reboot not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, Unproven: []string{"installed signed timer/drop-in lane not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, Unproven: []string{"independent allow/deny packet probes and connectivity guard not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, Unproven: []string{"approved disposable encrypted machine required; no owner demo access authorized"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY, Unproven: []string{"real weak-password rejection and lockout/login preservation not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, Unproven: []string{"SecretRef password hash delivery and SSH password login not exercised"}},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, Unproven: []string{"real pending update inside a timer-opened window, policy reboot and patch-now not exercised"}},
	}}
}

func resourceNativeRecord(name string, data []byte) VMResourceNativeRecord {
	digest := sha256.Sum256(data)
	return VMResourceNativeRecord{Name: name, SHA256: hex.EncodeToString(digest[:]), Bytes: data}
}

// Reject incomplete or server-only evidence before marking any kind qualified.
func qualifyResourceEvidence(kind *VMResourceKindEvidence, required []string) error {
	if kind == nil || len(kind.Scenarios) != len(required) {
		return errors.New("incomplete native resource scenarios")
	}
	for index, name := range required {
		scenario := &kind.Scenarios[index]
		if scenario.Name != name || !scenario.Passed || scenario.Failure != "" || scenario.StartedAt.IsZero() || scenario.FinishedAt.Before(scenario.StartedAt) || len(scenario.Native) == 0 || (scenario.Action == nil && scenario.Release == nil && scenario.ExecutorStatus == nil && len(scenario.DeviceActions) == 0) {
			return fmt.Errorf("native resource scenario %s lacks completed signed and independent evidence", name)
		}
		if scenario.ExecutorStatus != nil && (len(scenario.ExecutorHistory) == 0 || scenario.ExecutorStatus.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED) {
			return fmt.Errorf("native resource scenario %s lacks authenticated executor history", name)
		}
		if scenario.Action != nil && (scenario.Action.GetAttestedAt() == nil || scenario.Action.GetReceivedAt() == nil || scenario.Action.GetStatus() == nil || scenario.Action.GetClosedReason() != "result") {
			return fmt.Errorf("native resource scenario %s lacks accepted device-signed history", name)
		}
		if scenario.Release != nil && scenario.Release.GetState() != "released" && scenario.Release.GetState() != "release_conflict" {
			return fmt.Errorf("native resource scenario %s lacks a terminal release", name)
		}
		for _, action := range scenario.DeviceActions {
			if action == nil || action.ActionID == "" || action.RootState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED.String() || action.ServerState != action.RootState {
				return fmt.Errorf("native resource scenario %s lacks a server-accepted device action", name)
			}
		}
		for _, record := range scenario.Native {
			digest := sha256.Sum256(record.Bytes)
			if record.Name == "" || len(record.Bytes) == 0 || record.SHA256 != hex.EncodeToString(digest[:]) {
				return fmt.Errorf("native resource scenario %s has invalid record digest", name)
			}
		}
	}
	kind.NativeQualified = len(kind.Unproven) == 0
	return nil
}
