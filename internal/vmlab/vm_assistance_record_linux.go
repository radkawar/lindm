// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// VMAssistanceResult is the nonsecret evidence record of `lab vm assistance`.
// Every screenshot and journal excerpt it references lives in the same new
// evidence directory and is bound by SHA-256; consumers re-verify the files.
type VMAssistanceResult struct {
	ImageID           string                     `json:"image_id"`
	ImageSHA256       string                     `json:"image_sha256"`
	Distribution      string                     `json:"distribution"`
	DesktopProfile    string                     `json:"desktop_profile"`
	Architecture      string                     `json:"architecture"`
	PackageSHA256     string                     `json:"package_sha256"`
	SignerFingerprint string                     `json:"package_signer"`
	LabSHA256         string                     `json:"lab_sha256"`
	LindmdSHA256      string                     `json:"lindmd_sha256"`
	Firmware          *EncryptedFirmwareEvidence `json:"firmware"`
	Runtime           *vmRuntimeEvidence         `json:"runtime"`
	RecipeVersion     string                     `json:"installer_recipe_version"`
	Database          string                     `json:"isolated_database"`
	Topology          string                     `json:"topology"`
	DeviceID          string                     `json:"device_id"`
	Relay             assistanceRelayEvidence    `json:"relay"`
	Guest             *assistanceGuestEvidence   `json:"guest"`
	Browser           *assistanceBrowserEvidence `json:"browser"`
	// Readiness is the server's assistance readiness the lane waited for
	// after publishing its desktop session inventory.
	Readiness         *assistanceReadinessEvidence  `json:"readiness,omitempty"`
	Scenarios         []*assistanceScenarioEvidence `json:"scenarios"`
	Audit             []assistanceAuditEvidence     `json:"audit"`
	Journals          []assistanceEvidenceFile      `json:"journals"`
	Screenshots       []assistanceEvidenceFile      `json:"screenshots"`
	Witnesses         []assistanceEvidenceFile      `json:"capability_witnesses"`
	BoundaryWitnesses []assistanceEvidenceFile      `json:"native_boundary_witnesses"`
	TierOnePassed     bool                          `json:"tier_one_passed"`
	FilesPassed       bool                          `json:"files_passed"`
	FileWitnesses     []assistanceEvidenceFile      `json:"file_transfer_witnesses"`
	WorkflowsPassed   bool                          `json:"tier_two_workflows_passed"`
	WorkflowWitnesses []assistanceEvidenceFile      `json:"workflow_witnesses"`
	// TierThreePassed covers password guidance, pointer and marks, sound and
	// unattended access; it never inherits from another run.
	TierThreePassed    bool                     `json:"tier_three_passed"`
	TierThreeWitnesses []assistanceEvidenceFile `json:"tier_three_witnesses"`
	// SelectedScenarios names a non-held subset run's selection; such a
	// record proves only those scenarios and never sets a tier flag.
	SelectedScenarios []string                   `json:"selected_scenarios,omitempty"`
	NotRun            []assistanceNotRunEvidence `json:"capabilities_not_run"`
	StartedAt         time.Time                  `json:"started_at"`
	FinishedAt        time.Time                  `json:"finished_at"`
	Passed            bool                       `json:"passed"`
	Failure           string                     `json:"failure,omitempty"`
	Boundaries        []string                   `json:"boundaries"`
}

// assistanceReadinessEvidence is GetAssistanceReadiness when the lane began.
type assistanceReadinessEvidence struct {
	State               string    `json:"state"`
	InventoryObservedAt time.Time `json:"inventory_observed_at"`
}

type assistanceNotRunEvidence struct {
	Scenario   string `json:"scenario"`
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

// assistanceEvidenceFile binds one evidence artifact by its path relative to
// the evidence directory.
type assistanceEvidenceFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type assistanceRelayEvidence struct {
	ListenerAddress string   `json:"listener_address"`
	ListenerPort    uint32   `json:"listener_port"`
	RelayAddress    string   `json:"relay_address"`
	PortMin         uint32   `json:"relay_port_min"`
	PortMax         uint32   `json:"relay_port_max"`
	URLs            []string `json:"urls"`
	GuestRoute      string   `json:"guest_route"`
}

type assistanceGuestEvidence struct {
	Desktop                *actionDesktopEvidence `json:"desktop"`
	LocalhostResolution    string                 `json:"localhost_resolution"`
	ControllerRoute        string                 `json:"controller_route,omitempty"`
	ExecutorSocket         string                 `json:"executor_session_socket"`
	SessionUnitState       string                 `json:"session_unit_state"`
	SessionUnitAutoStarted bool                   `json:"session_unit_auto_started"`
	// SessionUnitActivation is graphical-session.target when that target was
	// active, otherwise the packaged XDG autostart entry.
	SessionUnitActivation  string   `json:"session_unit_activation"`
	GraphicalSessionTarget string   `json:"graphical_session_target"`
	Packages               []string `json:"packages"`
	Terminal               string   `json:"terminal"`
	// Capabilities is the native capability probe of the lab session: what
	// the session helper's environment, portal frontend and notification
	// server expose, observed before any scenario.
	Capabilities *assistanceCapabilityEvidence `json:"capabilities"`
}

type assistanceCapabilityEvidence struct {
	// CurrentDesktop is XDG_CURRENT_DESKTOP in the user manager environment
	// the lindm-session.service helper inherits.
	CurrentDesktop string `json:"xdg_current_desktop"`
	// PortalInterfaces are the org.freedesktop.portal.* interfaces the portal
	// frontend exports with their version properties.
	PortalInterfaces []string `json:"portal_interfaces"`
	// NotificationServer is GetServerInformation; NotificationCapabilities
	// is GetCapabilities.
	NotificationServer       string `json:"notification_server"`
	NotificationCapabilities string `json:"notification_capabilities"`
}

type assistanceBrowserEvidence struct {
	Engine   string `json:"engine"`
	Version  string `json:"version"`
	Username string `json:"operator_username"`
}

type assistanceStateObservation struct {
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
}

type assistanceLocalEvidence struct {
	Username        string `json:"username"`
	UID             uint32 `json:"uid"`
	LogindSessionID string `json:"logind_session_id"`
}

// assistanceMediaEvidence is the console browser's own view of the received
// stream and its peer connection, read from standard WebRTC statistics.
type assistanceMediaEvidence struct {
	VideoWidth          int      `json:"video_width"`
	VideoHeight         int      `json:"video_height"`
	DecodedFrames       int      `json:"decoded_frames"`
	FramesDecoded       int      `json:"inbound_frames_decoded"`
	ConnectionState     string   `json:"connection_state"`
	TransportPolicy     string   `json:"ice_transport_policy"`
	RemoteApplication   bool     `json:"remote_offer_has_application_section"`
	DataChannels        []string `json:"data_channels"`
	LocalCandidateType  string   `json:"selected_local_candidate_type"`
	RemoteCandidateType string   `json:"selected_remote_candidate_type"`
	ControlButton       bool     `json:"control_button_present"`
	LocalRelayProtocol  string   `json:"selected_local_relay_protocol"`
	LocalCandidateURL   string   `json:"selected_local_candidate_url"`
}

type assistanceClickEvidence struct {
	Target string `json:"target"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
}

type assistanceScenarioEvidence struct {
	Name               string                           `json:"name"`
	Mode               string                           `json:"mode"`
	SessionID          string                           `json:"session_id"`
	DeviceID           string                           `json:"device_id"`
	OperatorID         string                           `json:"operator_id"`
	OperatorDisplay    string                           `json:"operator_display"`
	ExpectedCause      string                           `json:"expected_end_cause"`
	EndCause           string                           `json:"end_cause"`
	EndDetail          string                           `json:"end_detail,omitempty"`
	ExpectedDetail     string                           `json:"expected_end_detail,omitempty"`
	ConsoleEndCause    string                           `json:"console_end_cause_text,omitempty"`
	ControlGranted     bool                             `json:"control_granted"`
	LocalSession       *assistanceLocalEvidence         `json:"local_session,omitempty"`
	OfferFingerprint   string                           `json:"offer_fingerprint,omitempty"`
	AnswerFingerprint  string                           `json:"answer_fingerprint,omitempty"`
	States             []assistanceStateObservation     `json:"states"`
	Clicks             []assistanceClickEvidence        `json:"guest_local_clicks"`
	Media              *assistanceMediaEvidence         `json:"media,omitempty"`
	Nonce              string                           `json:"typed_nonce,omitempty"`
	NonceReceived      bool                             `json:"nonce_received_by_guest"`
	CaptureStopped     bool                             `json:"guest_capture_stopped"`
	Screenshots        []string                         `json:"screenshots"`
	CapabilityWitness  string                           `json:"capability_witness,omitempty"`
	BoundaryWitnesses  []string                         `json:"native_boundary_witnesses"`
	NegativeBoundaries []string                         `json:"negative_boundaries"`
	ModeAuthority      *assistanceModeAuthorityEvidence `json:"mode_authority,omitempty"`
	// LockPath is how the lock scenario locked the desktop.
	LockPath         string `json:"lock_path,omitempty"`
	FileWitness      string `json:"file_transfer_witness,omitempty"`
	WorkflowWitness  string `json:"workflow_witness,omitempty"`
	TierThreeWitness string `json:"tier_three_witness,omitempty"`
}

type assistanceAuditEvidence struct {
	ID             string            `json:"id"`
	OccurredAt     time.Time         `json:"occurred_at"`
	ActorID        string            `json:"actor_id,omitempty"`
	Action         string            `json:"action"`
	ResourceID     string            `json:"resource_id"`
	Reason         string            `json:"reason"`
	TargetDeviceID string            `json:"target_device_id"`
	Details        map[string]string `json:"details"`
}

// assistanceEvidence writes artifacts into one exclusively created directory
// and records their digests for the final record.
type assistanceEvidence struct {
	dir   string
	files map[string]assistanceEvidenceFile
}

func newAssistanceEvidence(dir string) (*assistanceEvidence, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("assistance evidence directory must be absolute")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("assistance evidence directory must be a private directory")
	}
	return &assistanceEvidence{dir: dir, files: map[string]assistanceEvidenceFile{}}, nil
}

// write stores data under a new relative name and returns its binding.
func (e *assistanceEvidence) write(name, relative string, data []byte) (assistanceEvidenceFile, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") || strings.ContainsAny(relative, "/\\") {
		return assistanceEvidenceFile{}, errors.New("assistance evidence names must be plain file names")
	}
	if _, exists := e.files[relative]; exists {
		return assistanceEvidenceFile{}, fmt.Errorf("assistance evidence %s already recorded", relative)
	}
	file, err := os.OpenFile(filepath.Join(e.dir, relative), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return assistanceEvidenceFile{}, err
	}
	written, err := file.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return assistanceEvidenceFile{}, fmt.Errorf("persist assistance evidence %s: %w", relative, err)
	}
	digest := sha256.Sum256(data)
	bound := assistanceEvidenceFile{Name: name, Path: relative, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(data))}
	e.files[relative] = bound
	return bound, nil
}

// bind records an artifact another owned process (the browser runner) wrote
// into the evidence directory.
func (e *assistanceEvidence) bind(name, relative string) (assistanceEvidenceFile, error) {
	if relative == "" || filepath.Base(relative) != relative || strings.HasPrefix(relative, ".") {
		return assistanceEvidenceFile{}, errors.New("assistance evidence names must be plain file names")
	}
	if _, exists := e.files[relative]; exists {
		return assistanceEvidenceFile{}, fmt.Errorf("assistance evidence %s already recorded", relative)
	}
	path := filepath.Join(e.dir, relative)
	info, err := os.Lstat(path)
	if err != nil {
		return assistanceEvidenceFile{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return assistanceEvidenceFile{}, fmt.Errorf("assistance evidence %s is not a bounded regular file", relative)
	}
	digest, size, err := assistanceEvidenceDigest(path)
	if err != nil {
		return assistanceEvidenceFile{}, err
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return assistanceEvidenceFile{}, err
	}
	bound := assistanceEvidenceFile{Name: name, Path: relative, SHA256: digest, Bytes: size}
	e.files[relative] = bound
	return bound, nil
}

// verifyAssistanceEvidence re-reads every bound artifact of a record and
// checks presence, size and digest, and that scenario screenshot references
// resolve to bound screenshots.
func verifyAssistanceEvidence(dir string, result *VMAssistanceResult) error {
	if result.TierOnePassed && !completeAssistanceTierOne(result) {
		return errors.New("Tier1 qualification lacks baseline, mode authority or native capability proofs")
	}
	if result.FilesPassed && (!result.TierOnePassed || !completeAssistanceFiles(result)) {
		return errors.New("file qualification lacks complete Tier1 and file safety proofs")
	}
	if result.WorkflowsPassed && (!result.TierOnePassed || !completeAssistanceWorkflows(result)) {
		return errors.New("workflow (Tier 2) qualification lacks complete Tier1 and workflow proofs")
	}
	if result.TierThreePassed && (!result.TierOnePassed || !completeAssistanceTierThree(result)) {
		return errors.New("tier 3 qualification lacks complete Tier1 and Tier 3 proofs")
	}
	screenshots := map[string]bool{}
	for _, group := range [][]assistanceEvidenceFile{result.Screenshots, result.Journals, result.Witnesses, result.BoundaryWitnesses, result.FileWitnesses, result.WorkflowWitnesses, result.TierThreeWitnesses} {
		for _, bound := range group {
			if bound.Path == "" || filepath.Base(bound.Path) != bound.Path {
				return fmt.Errorf("evidence %q is not a plain file name", bound.Path)
			}
			digest, size, err := assistanceEvidenceDigest(filepath.Join(dir, bound.Path))
			if err != nil {
				return fmt.Errorf("read evidence %s: %w", bound.Path, err)
			}
			if size != bound.Bytes || digest != bound.SHA256 {
				return fmt.Errorf("evidence %s does not match its recorded digest", bound.Path)
			}
		}
	}
	for _, bound := range result.Screenshots {
		screenshots[bound.Path] = true
	}
	for _, scenario := range result.Scenarios {
		if scenario.Name == "authority-view" || scenario.Name == "authority-control" {
			if err := verifyAssistanceModeAuthority(scenario); err != nil {
				return err
			}
		}
		if slices.Contains(assistanceFileScenarios, scenario.Name) {
			if err := verifyFilesWitnessRecord(dir, result, scenario); err != nil {
				return err
			}
		}
		if assistanceWorkflowScenario(scenario.Name) {
			if err := verifyWorkflowWitnessRecord(dir, result, scenario); err != nil {
				return err
			}
		}
		if assistanceTierThreeScenario(scenario.Name) {
			if err := verifyTierThreeWitnessRecord(dir, result, scenario); err != nil {
				return err
			}
		}
		if slices.Contains([]string{"clipboard", "clipboard-limited", "keyboard", "display", "message", "monitors"}, scenario.Name) {
			var binding *assistanceEvidenceFile
			for i := range result.Witnesses {
				if result.Witnesses[i].Path == scenario.CapabilityWitness {
					binding = &result.Witnesses[i]
				}
			}
			if binding == nil {
				return fmt.Errorf("capability scenario %s lacks a bound native witness", scenario.Name)
			}
			data, err := os.ReadFile(filepath.Join(dir, binding.Path))
			if err != nil {
				return err
			}
			var witness assistanceCapabilityWitness
			if err := json.Unmarshal(data, &witness); err != nil {
				return err
			}
			if err := verifyAssistanceCapabilityWitness(scenario, &witness); err != nil {
				return err
			}
		}
		for _, name := range requiredAssistanceBoundaries(scenario.Name) {
			var binding *assistanceEvidenceFile
			for i := range result.BoundaryWitnesses {
				candidate := &result.BoundaryWitnesses[i]
				if candidate.Name == name && slices.Contains(scenario.BoundaryWitnesses, candidate.Path) {
					binding = candidate
				}
			}
			if binding == nil {
				return fmt.Errorf("scenario %s lacks native boundary %s", scenario.Name, name)
			}
			data, err := os.ReadFile(filepath.Join(dir, binding.Path))
			if err != nil {
				return err
			}
			var boundary assistanceNativeBoundary
			if err := json.Unmarshal(data, &boundary); err != nil {
				return err
			}
			if err := verifyAssistanceNativeBoundary(scenario, &boundary); err != nil {
				return err
			}
		}
		for _, path := range scenario.Screenshots {
			if !screenshots[path] {
				return fmt.Errorf("scenario %s references unbound screenshot %s", scenario.Name, path)
			}
		}
	}
	return nil
}

// completeAssistanceTierOne checks the ledger after its bound witnesses have
// been verified. A capability-only selection never inherits baseline consent,
// mode authority or another run's native observations.
func completeAssistanceTierOne(result *VMAssistanceResult) bool {
	if len(result.SelectedScenarios) != 0 || len(result.NotRun) != 0 || len(result.Witnesses) != 6 || !completeAssistanceNativeBoundaries(result) {
		return false
	}
	for _, spec := range assistanceScenarios {
		if slices.Contains(assistanceFileScenarios, spec.name) || assistanceWorkflowScenario(spec.name) || assistanceTierThreeScenario(spec.name) {
			continue
		}
		index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == spec.name })
		if index < 0 {
			return false
		}
		scenario := result.Scenarios[index]
		if spec.capability == "" {
			control := spec.mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
			mode := "view"
			if control {
				mode = "control"
			}
			if scenario.Mode != mode || scenario.EndCause != assistanceCauseText(spec.cause) || scenario.ConsoleEndCause == "" || len(scenario.Screenshots) == 0 || !vmValidID(scenario.SessionID) {
				return false
			}
			if spec.cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED {
				if scenario.Media != nil || scenario.ControlGranted {
					return false
				}
			} else {
				if !scenario.CaptureStopped || scenario.LocalSession == nil || scenario.OfferFingerprint == "" || scenario.AnswerFingerprint == "" || scenario.Media == nil || verifyAssistanceMedia(scenario.Media, control, false, false, false) != nil {
					return false
				}
				if control && (!scenario.NonceReceived || len(scenario.Nonce) != 12) {
					return false
				}
			}
		}
		if spec.name == "authority-view" || spec.name == "authority-control" {
			if verifyAssistanceModeAuthority(scenario) != nil {
				return false
			}
		}
		if slices.Contains([]string{"clipboard", "clipboard-limited", "keyboard", "display", "message", "monitors"}, spec.name) {
			if scenario.CapabilityWitness == "" || !slices.ContainsFunc(result.Witnesses, func(file assistanceEvidenceFile) bool { return file.Path == scenario.CapabilityWitness }) {
				return false
			}
		}
	}
	return true
}

// assistanceEvidenceDigest streams bounded artifacts, including file-transfer
// payload witnesses, without retaining whole files in lab memory.
func assistanceEvidenceDigest(path string) (_ string, _ int64, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	before, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > 64<<20 {
		return "", 0, errors.New("evidence is not a bounded regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return "", 0, err
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if size != before.Size() || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return "", 0, errors.New("evidence changed during hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
