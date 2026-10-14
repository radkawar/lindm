// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/devlab"
)

// Tier 2 native scenarios. Each drives the real console, product prompt,
// desktop portal and session helper; recording playback decodes the GTK
// fixture's own nonces from the decrypted WebM, and reconnect performs a real
// logout or guest reboot before requiring fresh local and portal consent.
var (
	assistanceRecordingScenarios = []string{"recording", "recording-declined", "recording-refused", "recording-storage", "recording-permission", "recording-retention"}
	assistanceReconnectScenarios = []string{"reconnect-logout", "reconnect-reboot", "reconnect-declined", "reconnect-expired", "reconnect-revoked"}
)

const (
	assistanceArchiveRole      = "assistance-archive-only"
	assistanceNoRecordingsRole = "assistance-no-recordings"
	// The deployment bound for the storage-exhaustion scenario: a few seconds
	// of the encoder's 2.5 Mbit/s stream.
	assistanceRecordingTinyStorage = 1 << 20
	assistanceRecordingStorage     = 8 << 30
	assistanceRecordingDeviceProbe = "/run/lindm-lab-recording-start"
)

func assistanceWorkflowScenario(name string) bool {
	return slices.Contains(assistanceRecordingScenarios, name) || slices.Contains(assistanceReconnectScenarios, name)
}

func assistanceRecordingLimits() *agentv1.AssistanceRecordingPolicy {
	return &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 512 << 20}
}

func assistanceReconnectLimits() *agentv1.AssistanceReconnectPolicy {
	return &agentv1.AssistanceReconnectPolicy{WindowSeconds: 1800, MaxReconnects: 3}
}

// assistanceRecordingWitness is the native recording proof. It holds metadata
// and decoded fixture nonces only, never recording bytes.
type assistanceRecordingWitness struct {
	RecordingID          string                             `json:"recording_id"`
	Required             bool                               `json:"required"`
	State                string                             `json:"state"`
	Reason               string                             `json:"reason,omitempty"`
	Segments             uint32                             `json:"segments"`
	StoredBytes          uint64                             `json:"stored_bytes"`
	CiphertextSHA256     string                             `json:"ciphertext_sha256,omitempty"`
	PromptSummary        string                             `json:"prompt_ocr"`
	IndicatorSummary     string                             `json:"indicator_ocr,omitempty"`
	Nonces               []string                           `json:"fixture_nonces,omitempty"`
	Playback             *assistancePlaybackEvidence        `json:"playback,omitempty"`
	ServerAtRest         *devlab.AssistanceRecordingAtRest  `json:"server_at_rest,omitempty"`
	DeviceAtRestProbe    string                             `json:"device_at_rest_probe,omitempty"`
	DevicePlaintext      []string                           `json:"device_plaintext_files"`
	Denial               *assistanceRecordingDenial         `json:"retrieval_denial,omitempty"`
	ArchiveLiveDenial    *assistanceModeDenial              `json:"archive_live_denial,omitempty"`
	ArchivePlayback      *assistancePlaybackEvidence        `json:"archive_playback,omitempty"`
	AfterDeletion        *devlab.AssistanceRecordingAtRest  `json:"after_deletion,omitempty"`
	Audit                []assistanceAuditEvidence          `json:"audit"`
	StorageBound         uint64                             `json:"deployment_storage_bound,omitempty"`
	CaptureStoppedAt     time.Time                          `json:"capture_stopped_at,omitzero"`
	Policy               *agentv1.AssistancePolicy          `json:"device_policy"`
	Grant                *agentv1.AssistanceCapabilities    `json:"granted,omitempty"`
	Session              *assistanceWorkflowSessionEvidence `json:"session"`
	RetentionAccelerated bool                               `json:"retention_deadline_accelerated,omitempty"`
}

type assistancePlaybackEvidence struct {
	Seen []struct {
		Nonce string  `json:"nonce"`
		At    float64 `json:"at"`
	} `json:"seen"`
	VideoWidth  int  `json:"videoWidth"`
	VideoHeight int  `json:"videoHeight"`
	Frames      int  `json:"frames"`
	Complete    bool `json:"complete"`
}

type assistanceRecordingDenial struct {
	Actor       *assistanceActor `json:"actor"`
	HTTPStatus  int              `json:"http_status"`
	Code        string           `json:"code"`
	Reason      string           `json:"reason"`
	Listed      bool             `json:"listed"`
	PlayOffered bool             `json:"play_offered"`
}

type assistanceWorkflowSessionEvidence struct {
	ID              string                   `json:"id"`
	State           string                   `json:"state"`
	EndCause        string                   `json:"end_cause"`
	EndDetail       string                   `json:"end_detail,omitempty"`
	ReconnectOf     string                   `json:"reconnect_of,omitempty"`
	Local           *assistanceLocalEvidence `json:"local_session,omitempty"`
	ConsentedBefore []string                 `json:"states_before_consent"`
	PortalDialog    bool                     `json:"fresh_portal_dialog"`
	Offer           string                   `json:"offer_fingerprint,omitempty"`
}

// assistanceReconnectWitness links an approved session, its real logout or
// reboot, and the fresh linked session or the refusal.
type assistanceReconnectWitness struct {
	WorkflowID   string                               `json:"workflow_id"`
	Mode         string                               `json:"mode"`
	Interruption string                               `json:"interruption"`
	BootBefore   string                               `json:"boot_before,omitempty"`
	BootAfter    string                               `json:"boot_after,omitempty"`
	Previous     *assistanceWorkflowSessionEvidence   `json:"previous"`
	Waiting      *adminv1.AssistanceReconnectWorkflow `json:"waiting"`
	Next         *assistanceWorkflowSessionEvidence   `json:"next,omitempty"`
	Refusal      *assistanceReconnectRefusal          `json:"refusal,omitempty"`
	Final        *adminv1.AssistanceReconnectWorkflow `json:"final"`
	Audit        []assistanceAuditEvidence            `json:"audit"`
}

type assistanceReconnectRefusal struct {
	HTTPStatus int    `json:"http_status"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	Offered    bool   `json:"offered"`
}

type assistanceWorkflowWitness struct {
	Scenario  string                      `json:"scenario"`
	Recording *assistanceRecordingWitness `json:"recording,omitempty"`
	Reconnect *assistanceReconnectWitness `json:"reconnect,omitempty"`
}

// workflowScenario runs one Tier 2 scenario and binds its structured witness.
func (r *assistanceRun) workflowScenario(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string, spec assistanceScenarioSpec) (err error) {
	defer func() { err = errors.Join(err, r.stopFixture(context.WithoutCancel(ctx))) }()
	if err := r.release.Gate(spec.capability); err != nil {
		return err
	}
	witness := &assistanceWorkflowWitness{Scenario: spec.name}
	scenario := &assistanceScenarioEvidence{Name: spec.name, DeviceID: r.deviceID, Mode: "view", ExpectedCause: assistanceCauseText(spec.cause)}
	r.result.Scenarios = append(r.result.Scenarios, scenario)
	if slices.Contains(assistanceRecordingScenarios, spec.name) {
		witness.Recording, err = r.recordingScenario(ctx, fixture, options, private, spec, scenario)
	} else {
		witness.Reconnect, err = r.reconnectScenario(ctx, spec, scenario)
	}
	bindErr := r.bindWorkflowWitness(scenario, witness)
	if err != nil {
		return errors.Join(err, bindErr)
	}
	if bindErr != nil {
		return bindErr
	}
	return verifyAssistanceWorkflowWitness(spec.name, witness)
}

func (r *assistanceRun) bindWorkflowWitness(scenario *assistanceScenarioEvidence, witness *assistanceWorkflowWitness) error {
	data, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return err
	}
	bound, err := r.evidence.write("workflow-"+scenario.Name, "workflow-"+scenario.Name+".json", data)
	if err != nil {
		return err
	}
	r.result.WorkflowWitnesses = append(r.result.WorkflowWitnesses, bound)
	scenario.WorkflowWitness = bound.Path
	return nil
}

func (r *assistanceRun) setDevicePolicy(ctx context.Context, policy *agentv1.AssistancePolicy) error {
	_, err := r.owner.Admin.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: r.deviceID, Policy: policy}))
	return vmControlPlaneError("update assistance policy", err)
}

// ocrScreenshot reads a bound guest screenshot's text from its pixels.
func (r *assistanceRun) ocrScreenshot(ctx context.Context, path string) (string, error) {
	text, err := hostCommand(ctx, r.evidence.dir, "tesseract", nil, filepath.Join(r.evidence.dir, path), "stdout", "--psm", "11")
	return strings.Join(strings.Fields(strings.ToLower(string(text))), " "), err
}

// bannerOCR reads a bound guest screenshot and, separately, its located
// notification banner in grayscale upscaled three times. tesseract reads
// nothing of GNOME 50's light-on-dark banner in the full screenshot
// (layers-fedora44-files-04, as fedora44arm-tier1-18 for messages).
func (r *assistanceRun) bannerOCR(ctx context.Context, path string, img *image.RGBA, banner image.Rectangle) (string, error) {
	text, err := r.ocrScreenshot(ctx, path)
	if err != nil || banner.Empty() {
		return text, err
	}
	crop, err := r.screen.ocr(ctx, img, banner)
	return strings.TrimSpace(text + " " + crop), err
}

// workflowPrompt waits for the local prompt, binds its pixels and OCR, then
// makes the local seat's choice among the prompt's actions.
func (r *assistanceRun) workflowPrompt(ctx context.Context, scenario *assistanceScenarioEvidence, actions, choice int, name string) (string, error) {
	if _, err := r.waitSession(ctx, scenario, 3*time.Minute, "prompted", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED)); err != nil {
		return "", err
	}
	prompt, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
	if err != nil {
		return "", err
	}
	path, err := r.screen.save(scenario.Name+"-"+name, prompt)
	if err != nil {
		return "", err
	}
	scenario.Screenshots = append(scenario.Screenshots, path)
	text, err := r.bannerOCR(ctx, path, prompt, banner)
	if err != nil {
		return "", err
	}
	if err := r.browserScreenshot(ctx, scenario, name+"-awaiting-consent"); err != nil {
		return "", err
	}
	return text, r.screen.clickNotificationAction(ctx, banner, actions, choice, name, scenario)
}

// workflowShare requires a fresh portal dialog, shares the screen and waits
// for live relayed media in the console.
func (r *assistanceRun) workflowShare(ctx context.Context, scenario *assistanceScenarioEvidence) (*adminv1.AssistanceSession, error) {
	portal, dialog, err := r.screen.waitDialog(ctx, 45*time.Second)
	if err != nil {
		return nil, fmt.Errorf("no fresh portal dialog after local consent: %w", err)
	}
	if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
		return nil, err
	}
	prepared, evidenceName, err := r.screen.enablePortalShare(ctx, portal, dialog, false, scenario)
	if prepared != nil && evidenceName != "" {
		err = errors.Join(err, r.guestScreenshot(scenario, evidenceName, prepared))
	}
	if err != nil {
		return nil, err
	}
	if err := r.screen.click(ctx, portal.Bounds(), portalShareButton(dialog), "portal-share", scenario); err != nil {
		return nil, err
	}
	session, err := r.waitSession(ctx, scenario, 90*time.Second, "active", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE))
	if err != nil {
		return nil, err
	}
	if err := r.verifyBinding(scenario, session, false); err != nil {
		return nil, err
	}
	var media browserMedia
	if err := r.browser.call(ctx, "media", map[string]any{"minFrames": 15, "timeoutMs": 60000}, &media, 75*time.Second); err != nil {
		return nil, err
	}
	scenario.Media = &assistanceMediaEvidence{VideoWidth: media.VideoWidth, VideoHeight: media.VideoHeight, DecodedFrames: media.DecodedFrames, FramesDecoded: media.FramesDecoded, ConnectionState: media.ConnectionState, TransportPolicy: media.TransportPolicy, RemoteApplication: media.RemoteApplication, DataChannels: media.DataChannels, LocalCandidateType: media.LocalCandidateType, RemoteCandidateType: media.RemoteCandidateType, ControlButton: media.ControlButton, LocalRelayProtocol: media.LocalRelayProtocol, LocalCandidateURL: media.LocalCandidateURL}
	if err := verifyAssistanceMedia(scenario.Media, false, false, false, r.turnTCP); err != nil {
		return nil, err
	}
	return session, r.browserScreenshot(ctx, scenario, "live")
}

func (r *assistanceRun) workflowRequest(ctx context.Context, scenario *assistanceScenarioEvidence, capabilities map[string]string) error {
	if err := r.screen.waitNoBanner(ctx, 45*time.Second); err != nil {
		return err
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := r.browser.call(ctx, "request", map[string]any{"deviceId": r.deviceID, "mode": "view", "reason": "lab assistance " + scenario.Name + " scenario", "minutes": 10, "capabilities": capabilities}, &created, time.Minute); err != nil {
		return err
	}
	if !vmValidID(created.SessionID) {
		return errors.New("console did not open a session viewer")
	}
	scenario.SessionID = created.SessionID
	return nil
}

func sessionEvidence(session *adminv1.AssistanceSession, states []assistanceStateObservation) *assistanceWorkflowSessionEvidence {
	evidence := &assistanceWorkflowSessionEvidence{
		ID: session.GetId(), State: assistanceStateText(session.GetState()), EndCause: assistanceCauseText(session.GetEndCause()),
		EndDetail: session.GetEndDetail(), ReconnectOf: session.GetReconnectOf(), Offer: session.GetOfferFingerprint(),
	}
	if local := session.GetLocalSession(); local != nil {
		evidence.Local = &assistanceLocalEvidence{Username: local.GetUsername(), UID: local.GetUid(), LogindSessionID: local.GetLogindSessionId()}
	}
	for _, state := range states {
		if state.State == assistanceStateText(adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED) {
			break
		}
		evidence.ConsentedBefore = append(evidence.ConsentedBefore, state.State)
	}
	return evidence
}

func (r *assistanceRun) readSession(ctx context.Context, id string) (*adminv1.AssistanceSession, error) {
	response, err := r.owner.Admin.GetAssistanceSession(ctx, connect.NewRequest(&adminv1.GetAssistanceSessionRequest{SessionId: id}))
	if err != nil {
		return nil, vmControlPlaneError("read assistance session", err)
	}
	return response.Msg.GetSession(), nil
}

// waitRecording polls archive metadata until accept holds.
func (r *assistanceRun) waitRecording(ctx context.Context, sessionID string, timeout time.Duration, accept func(*adminv1.AssistanceRecording) bool) (*adminv1.AssistanceRecording, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		session, err := r.readSession(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if recording := session.GetRecording(); recording != nil && accept(recording) {
			return recording, nil
		}
		select {
		case <-ctx.Done():
			return session.GetRecording(), fmt.Errorf("recording did not reach the expected state (last %v): %w", session.GetRecording().GetState(), ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func recordingIn(states ...adminv1.AssistanceRecordingArchiveState) func(*adminv1.AssistanceRecording) bool {
	return func(recording *adminv1.AssistanceRecording) bool {
		return slices.Contains(states, recording.GetState())
	}
}

// auditFor reads the real audit log for the given resources.
func (r *assistanceRun) auditFor(ctx context.Context, resources ...string) ([]assistanceAuditEvidence, error) {
	var rows []assistanceAuditEvidence
	token := ""
	for range 50 {
		response, err := r.owner.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 200, PageToken: token}))
		if err != nil {
			return nil, vmControlPlaneError("list audit events", err)
		}
		for _, event := range response.Msg.GetEvents() {
			// An approval's domain audit (assistance.unattended.request and
			// its decision) is the device's, naming the approval in details.
			approval := event.GetDetails()["approval"]
			if (slices.Contains(resources, event.GetResourceId()) || approval != "" && slices.Contains(resources, approval)) && strings.HasPrefix(event.GetAction(), "assistance.") {
				rows = append(rows, assistanceAuditEvidence{ID: event.GetId(), OccurredAt: event.GetOccurredAt().AsTime(), ActorID: event.GetActorId(), Action: event.GetAction(), ResourceID: event.GetResourceId(), Reason: event.GetReason(), TargetDeviceID: event.GetTargetDeviceId(), Details: event.GetDetails()})
			}
		}
		if token = response.Msg.GetNextPageToken(); token == "" {
			break
		}
	}
	return rows, nil
}

// deviceRecordingPlaintext lists files written since the probe that contain
// the recorder's VP8 codec identifier: plaintext must never reach disk.
func (r *assistanceRun) deviceRecordingPlaintext(ctx context.Context) ([]string, error) {
	out, err := r.vm.guest.run(ctx, "sudo -n find /home /tmp /var/tmp /run/user -xdev -type f -newer "+assistanceRecordingDeviceProbe+" -size +4k -print0 2>/dev/null | sudo -n xargs -0r grep -l -a -F V_VP8 || true", nil, 64<<10, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// recordingScenario covers disclosure, consent, encrypted storage, playback,
// retrieval authority, deletion, retention and storage exhaustion.
func (r *assistanceRun) recordingScenario(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) (_ *assistanceRecordingWitness, err error) {
	policy := assistanceFullPolicy()
	witness := &assistanceRecordingWitness{Policy: policy, Required: spec.name == "recording" || spec.name == "recording-refused" || spec.name == "recording-storage"}
	if err := r.setDevicePolicy(ctx, policy); err != nil {
		return witness, err
	}
	if spec.name == "recording-storage" {
		restore, err := r.reconfigureRecordingStorage(ctx, fixture, assistanceRecordingTinyStorage)
		if err != nil {
			return witness, err
		}
		witness.StorageBound = assistanceRecordingTinyStorage
		defer func() { err = errors.Join(err, restore()) }()
	}
	if _, err := r.vm.guest.run(ctx, "sudo -n touch "+assistanceRecordingDeviceProbe, nil, 4096, 15*time.Second); err != nil {
		return witness, err
	}
	option := "User may choose recording"
	if witness.Required {
		option = "Recording required"
	}
	if err := r.workflowRequest(ctx, scenario, map[string]string{"Recording": option}); err != nil {
		return witness, err
	}
	actions, choice := 3, 0
	switch spec.name {
	case "recording", "recording-storage":
		actions = 2
	case "recording-refused":
		actions, choice = 2, 1
	case "recording-declined":
		choice = 1
	}
	if witness.PromptSummary, err = r.workflowPrompt(ctx, scenario, actions, choice, "consent"); err != nil {
		return witness, err
	}
	if spec.name == "recording-refused" {
		if err := r.finish(ctx, spec, scenario, false); err != nil {
			return witness, err
		}
		return witness, r.settleRecording(ctx, fixture, scenario, witness, adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_FAILED)
	}
	if spec.name == "recording-storage" {
		return witness, r.recordingStorageExhaustion(ctx, fixture, spec, scenario, witness)
	}
	session, err := r.workflowShare(ctx, scenario)
	if err != nil {
		return witness, err
	}
	witness.Grant = session.GetGrantedCapabilities()
	indicator, indicatorBanner, err := r.screen.waitBanner(ctx, 30*time.Second)
	if err != nil {
		return witness, err
	}
	path, err := r.screen.save(scenario.Name+"-indicator", indicator)
	if err != nil {
		return witness, err
	}
	scenario.Screenshots = append(scenario.Screenshots, path)
	if witness.IndicatorSummary, err = r.bannerOCR(ctx, path, indicator, indicatorBanner); err != nil {
		return witness, err
	}
	if spec.name != "recording-declined" {
		for range 2 {
			if err := r.startFixture(ctx, 1); err != nil {
				return witness, err
			}
			state, err := r.waitFixture(ctx, "fixture nonce", func(*assistanceFixtureState) bool { return true })
			if err != nil {
				return witness, err
			}
			witness.Nonces = append(witness.Nonces, state.ClipboardSource)
			if err := r.stopFixture(ctx); err != nil {
				return witness, err
			}
		}
	}
	if err := r.browser.call(ctx, "stop", nil, nil, time.Minute); err != nil {
		return witness, err
	}
	if err := r.finish(ctx, spec, scenario, true); err != nil {
		return witness, err
	}
	witness.CaptureStoppedAt = time.Now().UTC()
	if spec.name == "recording-declined" {
		return witness, r.settleRecording(ctx, fixture, scenario, witness, adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DECLINED)
	}
	if err := r.settleRecording(ctx, fixture, scenario, witness, adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_COMPLETE); err != nil {
		return witness, err
	}
	switch spec.name {
	case "recording":
		witness.Playback = new(assistancePlaybackEvidence)
		if err := r.browser.call(ctx, "playRecording", map[string]any{"deviceId": r.deviceID, "nonces": witness.Nonces, "reason": "lab recording playback review"}, witness.Playback, 3*time.Minute); err != nil {
			return witness, err
		}
		if err := r.browserScreenshot(ctx, scenario, "playback"); err != nil {
			return witness, err
		}
	case "recording-permission":
		if err := r.recordingAuthority(ctx, fixture, options, private, scenario, witness); err != nil {
			return witness, err
		}
	case "recording-retention":
		if err := fixture.ExpireAssistanceRecording(ctx, witness.RecordingID); err != nil {
			return witness, err
		}
		witness.RetentionAccelerated = true
		if _, err := r.waitRecording(ctx, scenario.SessionID, 3*time.Minute, recordingIn(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DELETED)); err != nil {
			return witness, err
		}
		after, err := fixture.InspectAssistanceRecording(ctx, witness.RecordingID)
		if err != nil {
			return witness, err
		}
		witness.AfterDeletion = &after
	}
	witness.Audit, err = r.auditFor(ctx, witness.RecordingID)
	return witness, err
}

// settleRecording records the archive's final metadata, server ciphertext
// observation and the device plaintext probe.
func (r *assistanceRun) settleRecording(ctx context.Context, fixture *devlab.AuthorityFixture, scenario *assistanceScenarioEvidence, witness *assistanceRecordingWitness, want ...adminv1.AssistanceRecordingArchiveState) error {
	recording, err := r.waitRecording(ctx, scenario.SessionID, 2*time.Minute, recordingIn(want...))
	if err != nil {
		return err
	}
	witness.RecordingID, witness.State, witness.Reason = recording.GetId(), strings.ToLower(strings.TrimPrefix(recording.GetState().String(), "ASSISTANCE_RECORDING_ARCHIVE_STATE_")), recording.GetReason()
	witness.Segments, witness.StoredBytes, witness.CiphertextSHA256 = recording.GetSegments(), recording.GetStoredBytes(), recording.GetCiphertextSha256()
	atRest, err := fixture.InspectAssistanceRecording(ctx, recording.GetId())
	if err != nil {
		return err
	}
	witness.ServerAtRest = &atRest
	witness.DeviceAtRestProbe = "find /home /tmp /var/tmp /run/user -newer " + assistanceRecordingDeviceProbe + " | grep -l V_VP8"
	if witness.DevicePlaintext, err = r.deviceRecordingPlaintext(ctx); err != nil {
		return err
	}
	session, err := r.readSession(ctx, scenario.SessionID)
	if err != nil {
		return err
	}
	witness.Session = sessionEvidence(session, scenario.States)
	witness.Audit, err = r.auditFor(ctx, recording.GetId())
	return err
}

// recordingStorageExhaustion requires required recording to end the session
// when the deployment's storage bound is exhausted.
func (r *assistanceRun) recordingStorageExhaustion(ctx context.Context, fixture *devlab.AuthorityFixture, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, witness *assistanceRecordingWitness) error {
	portal, dialog, err := r.screen.waitDialog(ctx, 45*time.Second)
	if err != nil {
		return err
	}
	if _, _, err := r.screen.enablePortalShare(ctx, portal, dialog, false, scenario); err != nil {
		return err
	}
	if err := r.screen.click(ctx, portal.Bounds(), portalShareButton(dialog), "portal-share", scenario); err != nil {
		return err
	}
	session, err := r.waitSession(ctx, scenario, 2*time.Minute, "ended", ended)
	if err != nil {
		return err
	}
	scenario.EndCause, scenario.EndDetail = assistanceCauseText(session.GetEndCause()), session.GetEndDetail()
	if session.GetEndCause() != spec.cause || session.GetEndDetail() != "recording_storage_failed" {
		return fmt.Errorf("storage exhaustion ended %s (%s), want %s (recording_storage_failed)", scenario.EndCause, scenario.EndDetail, scenario.ExpectedCause)
	}
	if err := waitAssistanceCaptureStopped(ctx, r.vm.guest); err != nil {
		return err
	}
	scenario.CaptureStopped = true
	if err := r.settleRecording(ctx, fixture, scenario, witness, adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_INCOMPLETE, adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_FAILED); err != nil {
		return err
	}
	return r.browser.call(ctx, "leave", map[string]any{"deviceId": r.deviceID}, nil, time.Minute)
}

// reconfigureRecordingStorage restarts the owned server with another storage
// bound and returns the restoration of the previous configuration.
func (r *assistanceRun) reconfigureRecordingStorage(ctx context.Context, fixture *devlab.AuthorityFixture, bound uint64) (func() error, error) {
	previous, err := fixture.AssistanceConfiguration()
	if err != nil {
		return nil, err
	}
	if previous.GetRecording() == nil {
		return nil, errors.New("assistance fixture lacks recording custody")
	}
	changed := proto.CloneOf(previous)
	changed.Recording.MaxStorageBytes = bound
	if err := fixture.ConfigureAssistance(ctx, changed, nil); err != nil {
		return nil, err
	}
	return func() error {
		restored := proto.CloneOf(previous)
		return fixture.ConfigureAssistance(context.WithoutCancel(ctx), restored, nil)
	}, nil
}

// recordingAuthority proves retrieval and deletion authority are separate
// from live assistance: a creator without retrieval is refused, an
// archive-only reader plays but cannot assist, and deletion destroys content.
func (r *assistanceRun) recordingAuthority(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string, scenario *assistanceScenarioEvidence, witness *assistanceRecordingWitness) error {
	denied, err := openAssistanceOperator(ctx, fixture, options, private, "recording-denied", assistanceNoRecordingsRole)
	if err != nil {
		return err
	}
	witness.Denial = new(assistanceRecordingDenial)
	err = denied.call(ctx, "recordingDenied", map[string]any{"deviceId": r.deviceID, "recordingId": witness.RecordingID}, witness.Denial, time.Minute)
	err = errors.Join(err, denied.Close())
	if options.PersistentDir != "" {
		err = errors.Join(err, retireAssistanceOperator(ctx, fixture, denied.accountID))
	}
	if err != nil {
		return err
	}
	archive, err := openAssistanceOperator(ctx, fixture, options, private, "recording-archive", assistanceArchiveRole)
	if err != nil {
		return err
	}
	witness.ArchivePlayback, witness.ArchiveLiveDenial = new(assistancePlaybackEvidence), new(assistanceModeDenial)
	err = archive.call(ctx, "playRecording", map[string]any{"deviceId": r.deviceID, "nonces": witness.Nonces, "reason": "lab archive-only review"}, witness.ArchivePlayback, 3*time.Minute)
	err = errors.Join(err, archive.call(ctx, "refuseMode", map[string]any{"deviceId": r.deviceID, "mode": "view"}, witness.ArchiveLiveDenial, time.Minute))
	err = errors.Join(err, archive.Close())
	if options.PersistentDir != "" {
		err = errors.Join(err, retireAssistanceOperator(ctx, fixture, archive.accountID))
	}
	if err != nil {
		return err
	}
	if err := r.browser.call(ctx, "deleteRecording", map[string]any{"deviceId": r.deviceID, "reason": "lab recording deletion"}, nil, time.Minute); err != nil {
		return err
	}
	if err := r.browserScreenshot(ctx, scenario, "deleted"); err != nil {
		return err
	}
	if _, err := r.waitRecording(ctx, scenario.SessionID, time.Minute, recordingIn(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DELETED)); err != nil {
		return err
	}
	after, err := fixture.InspectAssistanceRecording(ctx, witness.RecordingID)
	witness.AfterDeletion = &after
	return err
}

// reconnectScenario approves a reconnect-enabled session, interrupts it by a
// real logout or reboot, and requires the fresh linked request or refusal.
func (r *assistanceRun) reconnectScenario(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) (_ *assistanceReconnectWitness, err error) {
	policy := assistanceFullPolicy()
	mode := "Admin sends a new request"
	policy.Reconnect = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	witness := &assistanceReconnectWitness{Mode: "limited", Interruption: "logout"}
	switch spec.name {
	case "reconnect-reboot":
		policy.Reconnect, mode, witness.Mode, witness.Interruption = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "New request sent automatically", "on", "reboot"
	case "reconnect-expired":
		policy.ReconnectLimits.WindowSeconds = 60
	}
	if err := r.setDevicePolicy(ctx, policy); err != nil {
		return witness, err
	}
	defer func() { err = errors.Join(err, r.setDevicePolicy(context.WithoutCancel(ctx), assistanceFullPolicy())) }()
	if err := r.workflowRequest(ctx, scenario, map[string]string{"Reconnect": mode}); err != nil {
		return witness, err
	}
	if _, err := r.workflowPrompt(ctx, scenario, 2, 0, "consent"); err != nil {
		return witness, err
	}
	if _, err := r.workflowShare(ctx, scenario); err != nil {
		return witness, err
	}
	if spec.name == "reconnect-reboot" {
		witness.BootBefore, witness.BootAfter, err = r.rebootAssistanceGuest(ctx)
	} else {
		err = r.logoutAssistanceDesktop(ctx)
	}
	if err != nil {
		return witness, err
	}
	previous, err := r.waitSession(ctx, scenario, 3*time.Minute, "ended by the interruption", ended)
	if err != nil {
		return witness, err
	}
	scenario.EndCause, scenario.EndDetail = assistanceCauseText(previous.GetEndCause()), previous.GetEndDetail()
	scenario.ExpectedCause = scenario.EndCause
	witness.Previous = sessionEvidence(previous, scenario.States)
	witness.Waiting = previous.GetReconnect()
	witness.WorkflowID = previous.GetReconnect().GetId()
	if spec.name != "reconnect-reboot" {
		if err := r.reloginAssistanceDesktop(ctx); err != nil {
			return witness, err
		}
	}
	switch spec.name {
	case "reconnect-expired":
		// Only the workflow's own 60 s window may elapse; nothing else changes.
		expiry := time.NewTimer(65 * time.Second)
		select {
		case <-ctx.Done():
			expiry.Stop()
			return witness, ctx.Err()
		case <-expiry.C:
		}
		err = r.reconnectRefused(ctx, scenario, witness)
	case "reconnect-revoked":
		revoked := proto.CloneOf(policy)
		revoked.Reconnect, revoked.ReconnectLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
		if err := r.setDevicePolicy(ctx, revoked); err != nil {
			return witness, err
		}
		err = r.reconnectRefused(ctx, scenario, witness)
	default:
		err = r.reconnectFresh(ctx, spec, scenario, witness)
	}
	if err != nil {
		return witness, err
	}
	final, err := r.readSession(ctx, previous.GetId())
	if err != nil {
		return witness, err
	}
	witness.Final = final.GetReconnect()
	witness.Audit, err = r.auditFor(ctx, witness.WorkflowID)
	return witness, err
}

// reconnectFresh requires a new linked session that passes through a fresh
// local prompt and a fresh portal dialog before any media.
func (r *assistanceRun) reconnectFresh(ctx context.Context, spec assistanceScenarioSpec, previous *assistanceScenarioEvidence, witness *assistanceReconnectWitness) error {
	var created struct {
		SessionID string `json:"sessionId"`
	}
	method := "reconnect"
	if spec.name == "reconnect-reboot" {
		method = "followReconnect"
	}
	if err := r.browser.call(ctx, method, map[string]any{"deviceId": r.deviceID, "sessionId": previous.SessionID, "timeoutMs": 300000}, &created, 6*time.Minute); err != nil {
		return err
	}
	if !vmValidID(created.SessionID) || created.SessionID == previous.SessionID {
		return errors.New("console did not open the linked reconnect session")
	}
	next := &assistanceScenarioEvidence{Name: spec.name + "-resumed", DeviceID: r.deviceID, Mode: "view", SessionID: created.SessionID, ExpectedCause: assistanceCauseText(spec.cause)}
	r.result.Scenarios = append(r.result.Scenarios, next)
	choice := 0
	if spec.name == "reconnect-declined" {
		choice = 1
	}
	if _, err := r.workflowPrompt(ctx, next, 2, choice, "reconnect-consent"); err != nil {
		return err
	}
	if spec.name == "reconnect-declined" {
		if err := r.finish(ctx, spec, next, false); err != nil {
			return err
		}
		session, err := r.readSession(ctx, created.SessionID)
		if err != nil {
			return err
		}
		witness.Next = sessionEvidence(session, next.States)
		return nil
	}
	session, err := r.workflowShare(ctx, next)
	if err != nil {
		return err
	}
	witness.Next = sessionEvidence(session, next.States)
	witness.Next.PortalDialog = true
	if err := r.browser.call(ctx, "stop", nil, nil, time.Minute); err != nil {
		return err
	}
	return r.finish(ctx, spec, next, true)
}

func (r *assistanceRun) reconnectRefused(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceReconnectWitness) error {
	witness.Refusal = new(assistanceReconnectRefusal)
	if err := r.browser.call(ctx, "reconnectRefused", map[string]any{"deviceId": r.deviceID, "sessionId": scenario.SessionID}, witness.Refusal, time.Minute); err != nil {
		return err
	}
	return r.browserScreenshot(ctx, scenario, "reconnect-refused")
}

// logoutAssistanceDesktop ends the lab user's graphical login through logind.
func (r *assistanceRun) logoutAssistanceDesktop(ctx context.Context) error {
	session := r.result.Guest.Desktop.SessionID
	if !logindSessionID.MatchString(session) {
		return errors.New("invalid logind session identifier")
	}
	_, err := r.vm.guest.run(ctx, "sudo -n loginctl terminate-session "+session, nil, 4096, 30*time.Second)
	return err
}

// reloginAssistanceDesktop restarts the display manager, whose configured
// automatic login signs the lab user in again as at boot, then waits for the
// packaged session helper and a clean desktop reference.
func (r *assistanceRun) reloginAssistanceDesktop(ctx context.Context) error {
	if err := pollGuest(ctx, r.vm.guest, time.Minute, "logind session end", "! loginctl show-session "+r.result.Guest.Desktop.SessionID+" >/dev/null 2>&1"); err != nil {
		return err
	}
	if _, err := r.vm.guest.run(ctx, "sudo -n systemctl restart display-manager.service", nil, 4096, time.Minute); err != nil {
		return err
	}
	return r.resumeAssistanceDesktop(ctx, true)
}

// resumeAssistanceDesktop binds the new login. After a reboot an automatic
// reconnect request is already on screen, so a clean reference never settles
// (layers-ubuntu24-reconnect-01); the same display's pre-reboot reference is
// kept instead.
func (r *assistanceRun) resumeAssistanceDesktop(ctx context.Context, recapture bool) error {
	desktop, err := prepareAssistanceDesktop(ctx, r.vm, r.desktop, r.release, true)
	if err != nil {
		return err
	}
	if desktop.SessionID == r.result.Guest.Desktop.SessionID {
		return errors.New("the lab user's login did not change after the interruption")
	}
	r.result.Guest.Desktop = desktop
	if err := waitAssistanceSessionUnit(ctx, r.vm.guest, r.desktop, &assistanceGuestEvidence{}); err != nil {
		return err
	}
	if !recapture {
		return nil
	}
	// logind session IDs restart after a reboot, so the name also carries the
	// scenario count (layers-ubuntu24-reconnect-10 reused session 10).
	_, err = r.screen.captureReference(ctx, fmt.Sprintf("desktop-reference-after-%s-%d", desktop.SessionID, len(r.result.Scenarios)))
	return err
}

// rebootAssistanceGuest performs a real in-guest reboot, answers the
// encrypted boot prompt on the serial console when the golden asks for it,
// and returns the boot IDs before and after.
func (r *assistanceRun) rebootAssistanceGuest(ctx context.Context) (string, string, error) {
	out, err := r.vm.guest.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return "", "", err
	}
	before := strings.TrimSpace(string(out))
	previous, err := uuid.Parse(before)
	if err != nil {
		return "", "", errors.New("invalid guest boot ID")
	}
	console, err := r.vm.serial(ctx)
	if err != nil {
		return before, "", err
	}
	defer func() { _ = console.Close() }()
	if _, err := r.vm.guest.run(ctx, "sudo -n systemd-run --quiet --on-active=2s --unit=lindm-lab-assistance-reboot /usr/bin/systemctl reboot", nil, 4096, 30*time.Second); err != nil {
		return before, "", err
	}
	unlockCtx, stop := context.WithCancel(ctx)
	defer stop()
	unlocked := make(chan error, 1)
	go func() {
		_, err := unlockEncryptedSerial(unlockCtx, console, r.vm.InitialUnlockSecret(), r.vm.bootConsole)
		unlocked <- err
	}()
	// The installer-built golden has no cloud-init: waiting for it failed
	// "sudo: cloud-init: command not found" (layers-fedora44-reconnect-01).
	bootCtx, cancelBoot := context.WithTimeout(ctx, 8*time.Minute)
	bootErr := awaitGuestBootChange(bootCtx, r.vm.guest, previous)
	cancelBoot()
	stop()
	_ = console.SetReadDeadline(time.Now())
	if unlockErr := <-unlocked; unlockErr != nil && bootErr == nil && !errors.Is(unlockErr, context.Canceled) {
		bootErr = unlockErr
	}
	if bootErr != nil {
		return before, "", bootErr
	}
	out, err = r.vm.guest.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return before, "", err
	}
	after := strings.TrimSpace(string(out))
	if after == before {
		return before, after, errors.New("guest boot ID did not change")
	}
	return before, after, r.resumeAssistanceDesktop(ctx, false)
}

func auditActions(rows []assistanceAuditEvidence) []string {
	actions := make([]string, 0, len(rows))
	for _, row := range rows {
		actions = append(actions, row.Action)
	}
	return actions
}

// verifyAssistanceWorkflowWitness is the qualification rule for each Tier 2
// scenario. It is applied when the witness is produced and again when the
// bound record is verified.
func verifyAssistanceWorkflowWitness(name string, witness *assistanceWorkflowWitness) error {
	if witness == nil || witness.Scenario != name {
		return errors.New("workflow witness does not name its scenario")
	}
	if slices.Contains(assistanceRecordingScenarios, name) {
		return verifyRecordingWitness(name, witness.Recording)
	}
	if slices.Contains(assistanceReconnectScenarios, name) {
		return verifyReconnectWitness(name, witness.Reconnect)
	}
	return fmt.Errorf("unknown workflow scenario %s", name)
}

func verifyRecordingWitness(name string, w *assistanceRecordingWitness) error {
	if w == nil || !vmValidID(w.RecordingID) || w.ServerAtRest == nil || w.Session == nil {
		return errors.New("recording witness lacks archive identity, storage observation or session")
	}
	if len(w.DevicePlaintext) != 0 {
		return fmt.Errorf("recording plaintext reached device storage: %v", w.DevicePlaintext)
	}
	if w.ServerAtRest.PlaintextMarkers != 0 {
		return errors.New("recording plaintext reached server storage")
	}
	if int(w.Segments) != w.ServerAtRest.Segments && w.State != "deleted" {
		return errors.New("stored segments differ from archive metadata")
	}
	required := name == "recording" || name == "recording-refused" || name == "recording-storage"
	if !strings.Contains(w.PromptSummary, map[bool]string{true: "recorded", false: "recording requested"}[required]) {
		return errors.New("consent prompt did not disclose recording before capture")
	}
	actions := auditActions(w.Audit)
	switch name {
	case "recording-refused":
		if w.State != "failed" || w.Segments != 0 || !slices.Contains(actions, "assistance.recording.stop") {
			return errors.New("refused required recording captured or was not audited")
		}
		return nil
	case "recording-declined":
		if w.State != "declined" || w.Segments != 0 || strings.Contains(w.IndicatorSummary, "recording") {
			return errors.New("declined optional recording captured or claimed recording")
		}
		return nil
	case "recording-storage":
		if (w.State != "incomplete" && w.State != "failed") || w.Reason != "recording_storage_full" || w.StorageBound == 0 || w.StoredBytes > w.StorageBound {
			return errors.New("storage exhaustion was not a bounded, recorded failure")
		}
		return nil
	}
	if !strings.Contains(w.IndicatorSummary, "recording") || !slices.Contains(actions, "assistance.recording.start") || !slices.Contains(actions, "assistance.recording.stop") {
		return errors.New("recording lacks its continuous indicator or start/stop audit")
	}
	if len(w.Nonces) != 2 || w.Nonces[0] == w.Nonces[1] {
		return errors.New("recording lacks two distinct known screen states")
	}
	switch name {
	case "recording":
		if w.State != "complete" || len(w.CiphertextSHA256) != 64 || !orderedPlayback(w.Playback, w.Nonces) || !slices.Contains(actions, "assistance.recording.read") {
			return errors.New("recording did not play the known screen changes in order after audited retrieval")
		}
	case "recording-permission":
		if w.Denial == nil || w.Denial.HTTPStatus != 403 || w.Denial.Reason != "permission_denied" || w.Denial.PlayOffered || !w.Denial.Listed {
			return errors.New("principal without retrieval permission could retrieve or was offered playback")
		}
		if w.ArchiveLiveDenial == nil || w.ArchiveLiveDenial.HTTPStatus != 403 || !orderedPlayback(w.ArchivePlayback, w.Nonces) {
			return errors.New("archive-only reader could assist live or could not play")
		}
		if w.AfterDeletion == nil || w.AfterDeletion.Segments != 0 || w.AfterDeletion.KeyRetained || !slices.Contains(actions, "assistance.recording.delete") {
			return errors.New("deletion retained recording content, key or audit gap")
		}
	case "recording-retention":
		if !w.RetentionAccelerated || w.AfterDeletion == nil || w.AfterDeletion.Segments != 0 || w.AfterDeletion.KeyRetained || !slices.Contains(actions, "assistance.recording.retention") {
			return errors.New("retention did not delete and audit the archive")
		}
	}
	return nil
}

func orderedPlayback(playback *assistancePlaybackEvidence, nonces []string) bool {
	if playback == nil || playback.VideoWidth <= 0 || playback.VideoHeight <= 0 || !playback.Complete || len(playback.Seen) != len(nonces) {
		return false
	}
	for i, seen := range playback.Seen {
		if seen.Nonce != nonces[i] || (i > 0 && seen.At < playback.Seen[i-1].At) {
			return false
		}
	}
	return true
}

func verifyReconnectWitness(name string, w *assistanceReconnectWitness) error {
	if w == nil || !vmValidID(w.WorkflowID) || w.Previous == nil || w.Waiting == nil || w.Final == nil {
		return errors.New("reconnect witness lacks workflow, interrupted session or final state")
	}
	// An ON workflow issues its linked invitation as soon as the rebooted
	// device returns, before the lab reads it, so it is already active again
	// on a newer session (layers-fedora44-reconnect-03); anything else must
	// be seen waiting.
	reissued := name == "reconnect-reboot" && w.Waiting.GetState() == adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE &&
		w.Waiting.GetReconnects() > 0 && w.Next != nil && w.Waiting.GetLatestSessionId() == w.Next.ID && w.Waiting.GetOriginSessionId() == w.Previous.ID
	if w.Waiting.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING && !reissued {
		return errors.New("interruption did not leave the approved workflow waiting")
	}
	eligible := []string{"session_ended", "session_locked", "connection_failed", "authorization_lost"}
	if !slices.Contains(eligible, w.Previous.EndCause) || (w.Previous.EndCause == "authorization_lost" && w.Previous.EndDetail != "device_unreachable") {
		return fmt.Errorf("interrupted session ended %s (%s), not by logout or reboot", w.Previous.EndCause, w.Previous.EndDetail)
	}
	actions := auditActions(w.Audit)
	switch name {
	case "reconnect-expired", "reconnect-revoked":
		reason := map[string]string{"reconnect-expired": "assistance_reconnect_expired", "reconnect-revoked": "assistance_reconnect_not_waiting"}[name]
		if w.Refusal == nil || w.Refusal.Code != "failed_precondition" || w.Refusal.Reason != reason || w.Refusal.Offered || w.Next != nil {
			return errors.New("expired or revoked workflow issued a reconnect")
		}
		want := map[string]string{"reconnect-expired": "assistance.reconnect.expire", "reconnect-revoked": "assistance.reconnect.end"}[name]
		if !slices.Contains(actions, want) {
			return fmt.Errorf("workflow lacks audit %s", want)
		}
		return nil
	}
	next := w.Next
	if next == nil || next.ReconnectOf != w.Previous.ID || next.ID == w.Previous.ID || !slices.Contains(actions, "assistance.reconnect.request") {
		return errors.New("reconnect did not issue a linked fresh invitation")
	}
	for _, state := range next.ConsentedBefore {
		// A declined invitation ends without consent: "ended" follows
		// "prompted" with no media state between (layers-ubuntu24-reconnect-05).
		if state != "requested" && state != "prompted" && (name != "reconnect-declined" || state != "ended") {
			return errors.New("linked session reached media before fresh consent")
		}
	}
	if name == "reconnect-declined" {
		if next.EndCause != "declined" || w.Final.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED {
			return errors.New("declined reconnect did not end the workflow")
		}
		return nil
	}
	if !next.PortalDialog || next.Local == nil || w.Previous.Local == nil || next.Local.LogindSessionID == w.Previous.Local.LogindSessionID || !slices.Contains(actions, "assistance.reconnect.consent") {
		return errors.New("reconnect reused the old login or skipped fresh portal consent")
	}
	if name == "reconnect-reboot" && (w.BootBefore == "" || w.BootBefore == w.BootAfter) {
		return errors.New("reboot scenario lacks a real boot change")
	}
	return nil
}

// completeAssistanceWorkflows requires every Tier 2 scenario's bound witness.
func completeAssistanceWorkflows(result *VMAssistanceResult) bool {
	for _, name := range append(slices.Clone(assistanceRecordingScenarios), assistanceReconnectScenarios...) {
		index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == name })
		if index < 0 || result.Scenarios[index].WorkflowWitness == "" || !slices.ContainsFunc(result.WorkflowWitnesses, func(file assistanceEvidenceFile) bool {
			return file.Name == "workflow-"+name && file.Path == result.Scenarios[index].WorkflowWitness
		}) {
			return false
		}
	}
	return true
}

func assistanceRecordingCustody(fixture *devlab.AuthorityFixture, assistance *configv1.AssistanceConfig) error {
	custody, err := fixture.AssistanceRecordingCustody(assistanceRecordingStorage)
	if err != nil {
		return err
	}
	assistance.Recording = custody
	return nil
}

// verifyWorkflowWitnessRecord re-reads the bound witness of a recorded
// workflow scenario and applies its qualification rule again.
func verifyWorkflowWitnessRecord(dir string, result *VMAssistanceResult, scenario *assistanceScenarioEvidence) error {
	index := slices.IndexFunc(result.WorkflowWitnesses, func(file assistanceEvidenceFile) bool {
		return file.Name == "workflow-"+scenario.Name && file.Path == scenario.WorkflowWitness
	})
	if index < 0 || result.WorkflowWitnesses[index].Bytes <= 0 || result.WorkflowWitnesses[index].Bytes > 4<<20 {
		return errors.New("workflow scenario lacks a bounded SHA-bound structured witness")
	}
	data, err := os.ReadFile(filepath.Join(dir, scenario.WorkflowWitness))
	if err != nil {
		return err
	}
	var witness assistanceWorkflowWitness
	if err := json.Unmarshal(data, &witness); err != nil {
		return err
	}
	return verifyAssistanceWorkflowWitness(scenario.Name, &witness)
}
