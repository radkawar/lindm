//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VMAssistanceResult is the nonsecret evidence record of `lab vm assistance`.
// Every screenshot and journal excerpt it references lives in the same new
// evidence directory and is bound by SHA-256; consumers re-verify the files.
type VMAssistanceResult struct {
	ImageID           string                        `json:"image_id"`
	ImageSHA256       string                        `json:"image_sha256"`
	Distribution      string                        `json:"distribution"`
	DesktopProfile    string                        `json:"desktop_profile"`
	Architecture      string                        `json:"architecture"`
	PackageSHA256     string                        `json:"package_sha256"`
	SignerFingerprint string                        `json:"package_signer"`
	LabSHA256         string                        `json:"lab_sha256"`
	LindmdSHA256      string                        `json:"lindmd_sha256"`
	Firmware          *EncryptedFirmwareEvidence    `json:"firmware"`
	Runtime           *vmRuntimeEvidence            `json:"runtime"`
	RecipeVersion     string                        `json:"installer_recipe_version"`
	Database          string                        `json:"isolated_database"`
	Topology          string                        `json:"topology"`
	DeviceID          string                        `json:"device_id"`
	Relay             assistanceRelayEvidence       `json:"relay"`
	Guest             *assistanceGuestEvidence      `json:"guest"`
	Browser           *assistanceBrowserEvidence    `json:"browser"`
	Scenarios         []*assistanceScenarioEvidence `json:"scenarios"`
	Audit             []assistanceAuditEvidence     `json:"audit"`
	Journals          []assistanceEvidenceFile      `json:"journals"`
	Screenshots       []assistanceEvidenceFile      `json:"screenshots"`
	StartedAt         time.Time                     `json:"started_at"`
	FinishedAt        time.Time                     `json:"finished_at"`
	Passed            bool                          `json:"passed"`
	Failure           string                        `json:"failure,omitempty"`
	Boundaries        []string                      `json:"boundaries"`
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
	GraphicalSessionTarget string                 `json:"graphical_session_target"`
	Packages               []string               `json:"packages"`
	Terminal               string                 `json:"terminal"`
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
	Name              string                       `json:"name"`
	Mode              string                       `json:"mode"`
	SessionID         string                       `json:"session_id"`
	ExpectedCause     string                       `json:"expected_end_cause"`
	EndCause          string                       `json:"end_cause"`
	EndDetail         string                       `json:"end_detail,omitempty"`
	ExpectedDetail    string                       `json:"expected_end_detail,omitempty"`
	ConsoleEndCause   string                       `json:"console_end_cause_text,omitempty"`
	ControlGranted    bool                         `json:"control_granted"`
	LocalSession      *assistanceLocalEvidence     `json:"local_session,omitempty"`
	OfferFingerprint  string                       `json:"offer_fingerprint,omitempty"`
	AnswerFingerprint string                       `json:"answer_fingerprint,omitempty"`
	States            []assistanceStateObservation `json:"states"`
	Clicks            []assistanceClickEvidence    `json:"guest_local_clicks"`
	Media             *assistanceMediaEvidence     `json:"media,omitempty"`
	Nonce             string                       `json:"typed_nonce,omitempty"`
	NonceReceived     bool                         `json:"nonce_received_by_guest"`
	CaptureStopped    bool                         `json:"guest_capture_stopped"`
	Screenshots       []string                     `json:"screenshots"`
}

type assistanceAuditEvidence struct {
	ID             string            `json:"id"`
	OccurredAt     time.Time         `json:"occurred_at"`
	ActorID        string            `json:"actor_id,omitempty"`
	Action         string            `json:"action"`
	SessionID      string            `json:"session_id"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return assistanceEvidenceFile{}, err
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return assistanceEvidenceFile{}, err
	}
	digest := sha256.Sum256(data)
	bound := assistanceEvidenceFile{Name: name, Path: relative, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(data))}
	e.files[relative] = bound
	return bound, nil
}

// verifyAssistanceEvidence re-reads every bound artifact of a record and
// checks presence, size and digest, and that scenario screenshot references
// resolve to bound screenshots.
func verifyAssistanceEvidence(dir string, result *VMAssistanceResult) error {
	screenshots := map[string]bool{}
	for _, group := range [][]assistanceEvidenceFile{result.Screenshots, result.Journals} {
		for _, bound := range group {
			if bound.Path == "" || filepath.Base(bound.Path) != bound.Path {
				return fmt.Errorf("evidence %q is not a plain file name", bound.Path)
			}
			data, err := os.ReadFile(filepath.Join(dir, bound.Path))
			if err != nil {
				return fmt.Errorf("read evidence %s: %w", bound.Path, err)
			}
			digest := sha256.Sum256(data)
			if int64(len(data)) != bound.Bytes || hex.EncodeToString(digest[:]) != bound.SHA256 {
				return fmt.Errorf("evidence %s does not match its recorded digest", bound.Path)
			}
		}
	}
	for _, bound := range result.Screenshots {
		screenshots[bound.Path] = true
	}
	for _, scenario := range result.Scenarios {
		for _, path := range scenario.Screenshots {
			if !screenshots[path] {
				return fmt.Errorf("scenario %s references unbound screenshot %s", scenario.Name, path)
			}
		}
	}
	return nil
}
