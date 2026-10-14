// SPDX-License-Identifier: Apache-2.0

// Package deploylab qualifies isolated deployments; it never treats laboratory
// credentials or simulated device rows as production trust or native evidence.
package deploylab

import (
	"errors"
	"time"
)

// FirstRunInstallScope never qualifies the full backup/upgrade/restore lifecycle.
const FirstRunInstallScope = "first-run-install-only"

// Operation records an observed operator boundary, not an inferred runbook step.
// Name is fixed harness text; commands, credentials and guest output are excluded.
type Operation struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Passed     bool      `json:"passed"`
	Failure    string    `json:"failure,omitempty"`
}

// Friction records an actually encountered failure or operator prerequisite.
type Friction struct {
	Operation   string `json:"operation"`
	Observation string `json:"observation"`
	Remedy      string `json:"remedy"`
}

// CustodyExport binds each visible recovery task to an observed off-host transfer.
type CustodyExport struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// BrowserRequest is a private handoff. It must never be included in evidence.
// SetupCode and authenticator state exist only in owned temporary mode0600 files.
type BrowserRequest struct {
	Phase             string          `json:"phase"`
	Origin            string          `json:"origin"`
	Username          string          `json:"username"`
	Password          string          `json:"password"`
	SetupCode         string          `json:"setupCode,omitempty"`
	SetupMethod       string          `json:"setupMethod,omitempty"`
	CAFile            string          `json:"caFile"`
	PrivateDirectory  string          `json:"privateDirectory"`
	EvidenceDirectory string          `json:"evidenceDirectory"`
	CredentialPath    string          `json:"credentialPath"`
	CommandPath       string          `json:"commandPath,omitempty"`
	Platform          string          `json:"platform,omitempty"`
	DeviceID          string          `json:"deviceId,omitempty"`
	ResultPath        string          `json:"resultPath"`
	CustodySHA256     string          `json:"custodySha256,omitempty"`
	CustodyExports    []CustodyExport `json:"custodyExports,omitempty"`
}

// BrowserEvidence is sanitized by the browser runner before publication. A
// managed action qualifies only after its own completed row appears for this
// exact device and a subsequently collected inventory is visible.
type BrowserEvidence struct {
	Phase                  string          `json:"phase"`
	Passed                 bool            `json:"passed"`
	Failure                string          `json:"failure,omitempty"`
	BrowserVersion         string          `json:"browser_version"`
	Authenticator          string          `json:"authenticator"`
	PasswordAndPasskey     bool            `json:"password_and_passkey"`
	CommandSHA256          string          `json:"command_sha256,omitempty"`
	CommandSource          string          `json:"command_source,omitempty"`
	DeviceID               string          `json:"device_id,omitempty"`
	ActionID               string          `json:"action_id,omitempty"`
	ActionCompleted        bool            `json:"action_completed"`
	ActionFinishedAt       time.Time       `json:"action_finished_at,omitempty"`
	FreshInventoryReceived bool            `json:"fresh_inventory_received"`
	Screenshots            []string        `json:"screenshots"`
	Operations             []Operation     `json:"operations"`
	OwnerStepUp            bool            `json:"owner_step_up"`
	OwnerCustodyAttested   bool            `json:"owner_custody_attested"`
	CustodySHA256          string          `json:"custody_sha256,omitempty"`
	CustodyExports         []CustodyExport `json:"custody_exports,omitempty"`
}

// ValidateBrowserEvidence prevents a green browser exit or a database-only
// check from being promoted into a completed deployment workflow.
func ValidateBrowserEvidence(request BrowserRequest, evidence *BrowserEvidence) error {
	if evidence == nil || !evidence.Passed || evidence.Phase != request.Phase || evidence.BrowserVersion == "" || len(evidence.Screenshots) == 0 {
		return errors.New("deploy: browser did not provide completed phase evidence")
	}
	switch request.Phase {
	case "setup":
		if !evidence.PasswordAndPasskey {
			return errors.New("deploy: setup did not prove password and passkey sign-in")
		}
	case "custody":
		if request.CustodySHA256 == "" || evidence.CustodySHA256 != request.CustodySHA256 || !evidence.OwnerStepUp || !evidence.OwnerCustodyAttested {
			return errors.New("deploy: encrypted off-server export did not receive a digest-bound owner passkey step-up attestation")
		}
		if len(request.CustodyExports) == 0 || len(evidence.CustodyExports) != len(request.CustodyExports) {
			return errors.New("deploy: custody export set was not displayed")
		}
		for index, expected := range request.CustodyExports {
			if evidence.CustodyExports[index] != expected {
				return errors.New("deploy: custody file transfer does not match the displayed export set")
			}
		}
	case "copy":
		if len(evidence.CommandSHA256) != 64 || evidence.CommandSource != "browser-clipboard" {
			return errors.New("deploy: enrollment command did not come from the browser clipboard")
		}
		for _, digit := range evidence.CommandSHA256 {
			if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
				return errors.New("deploy: clipboard evidence is not a SHA256 digest")
			}
		}
	case "manage":
		if request.DeviceID == "" || evidence.DeviceID != request.DeviceID || evidence.ActionID == "" || !evidence.ActionCompleted || evidence.ActionFinishedAt.IsZero() || !evidence.FreshInventoryReceived {
			return errors.New("deploy: same-device live inventory action did not complete")
		}
	default:
		return errors.New("deploy: unknown browser phase")
	}
	return nil
}

// Counts counts observed boundaries only. Each invocation of the installer or
// day-two CLI is one command; browser clicks and operator choices are decisions.
func Counts(operations []Operation) (commands, decisions, failures int) {
	for _, operation := range operations {
		switch operation.Kind {
		case "command":
			commands++
		case "decision":
			decisions++
		}
		if !operation.Passed {
			failures++
		}
	}
	return commands, decisions, failures
}
