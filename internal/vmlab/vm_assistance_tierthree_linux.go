// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// Tier 3 native scenarios. Each drives the real console, product prompts,
// desktop portal, polkit agent, GNOME Shell overlay, PipeWire graph and
// session helper. Password guidance replays every input kind while paused and
// requires a locally typed password to succeed; pointer marks are located in
// QMP scanout pixels per head; sound is measured as known tones in the
// console's own audio element; unattended access goes through two people, a
// locked and a signed-out seat, a reboot and revocation.
var assistanceTierThreeScenarios = []string{"elevation", "annotation", "annotation-monitors", "audio", "audio-declined", "unattended", "unattended-lock", "unattended-revoked"}

const (
	assistanceElevationResultPath = "/home/" + actionDesktopUser + "/lindm-assistance-elevation"
	assistanceUnattendedStatePath = "/home/" + actionDesktopUser + "/.local/state/lindm/assistance-unattended.json"
	assistanceAudioOutput         = "Lindm lab output"
	assistanceAudioMicrophone     = "Lindm lab microphone"
	assistanceOutputTone          = 440
	assistanceMicrophoneTone      = 880
	// A shared tone stands at least this far above the median spectrum; a
	// muted or stopped one stays below the silence bound.
	assistanceToneAudible = 20
	assistanceToneSilent  = 6
	// The overlay's pointer ring is 16 px in radius and 5 px wide.
	assistanceOverlayPointerPixels = 150
	assistanceOverlayStrokePixels  = 100
	assistanceOverlayStray         = 20
	assistanceOverlayTolerance     = 0.03
)

func assistanceTierThreeScenario(name string) bool {
	return slices.Contains(assistanceTierThreeScenarios, name)
}

func assistanceTierThreePolicy() *agentv1.AssistancePolicy {
	const on = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	policy := assistanceFullPolicy()
	policy.Elevation, policy.Annotation, policy.Audio = on, on, on
	policy.Unattended = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	policy.UnattendedLimits = &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 86400, MaxEnrollmentDays: 7, MaxSessionSeconds: 1800}
	return policy
}

type assistanceTierThreeWitness struct {
	Scenario   string                             `json:"scenario"`
	Policy     *agentv1.AssistancePolicy          `json:"device_policy"`
	Granted    *agentv1.AssistanceCapabilities    `json:"granted,omitempty"`
	Session    *assistanceWorkflowSessionEvidence `json:"session,omitempty"`
	Elevation  *assistanceElevationWitness        `json:"elevation,omitempty"`
	Annotation *assistanceAnnotationWitness       `json:"annotation,omitempty"`
	Audio      *assistanceAudioWitness            `json:"audio,omitempty"`
	Unattended *assistanceUnattendedWitness       `json:"unattended,omitempty"`
	Audit      []assistanceAuditEvidence          `json:"audit"`
}

type assistanceRPCRefusal struct {
	Kind       string           `json:"kind,omitempty"`
	HTTPStatus int              `json:"http_status"`
	Code       string           `json:"code"`
	Reason     string           `json:"reason"`
	Offered    bool             `json:"offered,omitempty"`
	Actor      *assistanceActor `json:"actor,omitempty"`
}

type assistanceElevationWitness struct {
	Note            string                        `json:"operator_note"`
	GuidanceOCR     string                        `json:"guidance_ocr"`
	Paused          *agentv1.AssistanceInputState `json:"paused_state"`
	ControlDisabled bool                          `json:"console_control_disabled"`
	ProbeEvents     int                           `json:"replayed_input_events"`
	Refusals        []assistanceRPCRefusal        `json:"paused_command_refusals"`
	PolkitOCR       string                        `json:"polkit_dialog_ocr"`
	PkexecExit      string                        `json:"pkexec_exit_status"`
	Resumed         *agentv1.AssistanceInputState `json:"resumed_state"`
	InputAfter      bool                          `json:"remote_input_after_local_resume"`
}

// assistanceOverlayObservation is one QMP scanout's overlay pixels: those
// that changed from the head's reference and match the overlay colour.
type assistanceOverlayObservation struct {
	Head        int        `json:"head"`
	Expected    [2]float64 `json:"expected"`
	Pixels      int        `json:"matching_pixels"`
	Centroid    [2]float64 `json:"centroid"`
	OtherPixels int        `json:"other_head_pixels"`
	Screenshot  string     `json:"screenshot"`
}

type assistanceAnnotationWitness struct {
	Mode          string                              `json:"mode"`
	NoticeOCR     string                              `json:"notice_ocr"`
	Pointer       []assistanceOverlayObservation      `json:"pointer"`
	Stroke        *assistanceOverlayObservation       `json:"stroke,omitempty"`
	LocalClick    *assistancePointerWitness           `json:"local_click_through,omitempty"`
	ClearedPixels int                                 `json:"stroke_pixels_after_local_clear"`
	HiddenPixels  int                                 `json:"pointer_pixels_after_local_hide"`
	ConsoleHidden bool                                `json:"console_reports_hidden"`
	ShowOffered   bool                                `json:"console_offers_show_after_hide"`
	Report        *agentv1.AssistanceAnnotationReport `json:"final_report"`
}

type assistanceToneLevels struct {
	Present bool               `json:"present"`
	Levels  map[string]float64 `json:"levels"`
	Floor   float64            `json:"floor"`
	Frames  int                `json:"frames"`
}

type assistanceAudioWitness struct {
	Mode          string                         `json:"mode"`
	PromptOCR     []string                       `json:"choice_ocr"`
	Shared        *agentv1.AssistanceAudioReport `json:"shared_report"`
	Heard         *assistanceToneLevels          `json:"heard"`
	Muted         *assistanceToneLevels          `json:"muted,omitempty"`
	Unmuted       *assistanceToneLevels          `json:"unmuted,omitempty"`
	Stopped       *assistanceToneLevels          `json:"stopped,omitempty"`
	Final         *agentv1.AssistanceAudioReport `json:"final_report"`
	ConsoleStatus string                         `json:"console_status"`
}

type assistanceUnattendedWitness struct {
	OptInOCR      string                                        `json:"opt_in_prompt_ocr"`
	Enrollment    *adminv1.AssistanceUnattendedEnrollment       `json:"enrollment"`
	StateFile     string                                        `json:"device_state_file"`
	ApprovalID    string                                        `json:"approval_id"`
	SelfApproval  *assistanceRPCRefusal                         `json:"self_approval"`
	Grant         *adminv1.AssistanceUnattendedGrant            `json:"grant"`
	BannerOCR     string                                        `json:"banner_ocr,omitempty"`
	Connections   map[string]*assistanceWorkflowSessionEvidence `json:"connections"`
	PortalDialogs map[string]bool                               `json:"portal_dialog_during_connection"`
	Refusals      map[string]*assistanceRPCRefusal              `json:"refusals,omitempty"`
	BootBefore    string                                        `json:"boot_before,omitempty"`
	BootAfter     string                                        `json:"boot_after,omitempty"`
	Final         *adminv1.ListUnattendedAssistanceResponse     `json:"final"`
	StateAfter    string                                        `json:"device_state_file_after"`
}

// tierThreeScenario runs one Tier 3 scenario and binds its structured witness.
func (r *assistanceRun) tierThreeScenario(ctx context.Context, spec assistanceScenarioSpec) (err error) {
	defer func() { err = errors.Join(err, r.stopFixture(context.WithoutCancel(ctx))) }()
	if err := r.release.Gate(spec.capability); err != nil {
		return err
	}
	policy := assistanceTierThreePolicy()
	witness := &assistanceTierThreeWitness{Scenario: spec.name, Policy: policy}
	mode := map[bool]string{true: "control", false: "view"}[spec.mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL]
	scenario := &assistanceScenarioEvidence{Name: spec.name, DeviceID: r.deviceID, Mode: mode, ExpectedCause: assistanceCauseText(spec.cause)}
	r.result.Scenarios = append(r.result.Scenarios, scenario)
	if err := r.setDevicePolicy(ctx, policy); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.setDevicePolicy(context.WithoutCancel(ctx), assistanceFullPolicy())) }()
	resources := []string{}
	switch {
	case spec.name == "elevation":
		witness.Elevation, err = r.elevationScenario(ctx, spec, scenario)
	case strings.HasPrefix(spec.name, "annotation"):
		witness.Annotation, err = r.annotationScenario(ctx, spec, scenario)
	case strings.HasPrefix(spec.name, "audio"):
		witness.Audio, err = r.audioScenario(ctx, spec, scenario, policy)
	default:
		witness.Unattended, resources, err = r.unattendedScenario(ctx, spec, scenario)
	}
	if vmValidID(scenario.SessionID) {
		if session, readErr := r.readSession(ctx, scenario.SessionID); readErr == nil {
			witness.Session, witness.Granted = sessionEvidence(session, scenario.States), session.GetGrantedCapabilities()
		}
		resources = append(resources, scenario.SessionID)
	}
	if err == nil {
		witness.Audit, err = r.auditFor(ctx, resources...)
	}
	bindErr := r.bindTierThreeWitness(scenario, witness)
	if err != nil {
		return errors.Join(err, bindErr)
	}
	if bindErr != nil {
		return bindErr
	}
	return verifyAssistanceTierThreeWitness(spec.name, witness)
}

func (r *assistanceRun) bindTierThreeWitness(scenario *assistanceScenarioEvidence, witness *assistanceTierThreeWitness) error {
	data, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return err
	}
	bound, err := r.evidence.write("tierthree-"+scenario.Name, "tierthree-"+scenario.Name+".json", data)
	if err != nil {
		return err
	}
	r.result.TierThreeWitnesses = append(r.result.TierThreeWitnesses, bound)
	scenario.TierThreeWitness = bound.Path
	return nil
}

// tierThreeRequest sends an attended request with the given capability
// choices, accepts the local prompt, makes any further local choices the
// helper asks before the portal dialog, and shares the screen.
func (r *assistanceRun) tierThreeRequest(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, capabilities map[string]string, actions, choice int, beforePortal func() error) (string, *adminv1.AssistanceSession, error) {
	if err := r.screen.waitNoBanner(ctx, 45*time.Second); err != nil {
		return "", nil, err
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := r.browser.call(ctx, "request", map[string]any{"deviceId": r.deviceID, "mode": scenario.Mode, "reason": "lab assistance " + spec.name + " scenario", "minutes": 10, "capabilities": capabilities}, &created, time.Minute); err != nil {
		return "", nil, err
	}
	if !vmValidID(created.SessionID) {
		return "", nil, errors.New("console did not open a session viewer")
	}
	scenario.SessionID = created.SessionID
	prompt, err := r.workflowPrompt(ctx, scenario, actions, choice, "consent")
	if err != nil {
		return prompt, nil, err
	}
	if beforePortal != nil {
		if err := beforePortal(); err != nil {
			return prompt, nil, err
		}
	}
	portal, dialog, err := r.screen.waitDialog(ctx, 45*time.Second)
	if err != nil {
		return prompt, nil, fmt.Errorf("no portal dialog after local consent: %w", err)
	}
	if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
		return prompt, nil, err
	}
	control := scenario.Mode == "control"
	prepared, evidenceName, err := r.screen.enablePortalShare(ctx, portal, dialog, control, scenario)
	if prepared != nil && evidenceName != "" {
		err = errors.Join(err, r.guestScreenshot(scenario, evidenceName, prepared))
	}
	if err != nil {
		return prompt, nil, err
	}
	if spec.name == "annotation-monitors" {
		if err := r.screen.selectMonitors(ctx, dialog, scenario); err != nil {
			return prompt, nil, err
		}
	} else if err := r.screen.selectOfferedMonitor(ctx, dialog, scenario); err != nil {
		return prompt, nil, err
	}
	if err := r.screen.click(ctx, portal.Bounds(), portalShareButton(dialog), "portal-share", scenario); err != nil {
		return prompt, nil, err
	}
	session, err := r.liveSession(ctx, scenario, control)
	return prompt, session, err
}

// liveSession waits for ACTIVE and the console's relayed media.
func (r *assistanceRun) liveSession(ctx context.Context, scenario *assistanceScenarioEvidence, control bool) (*adminv1.AssistanceSession, error) {
	session, err := r.waitSession(ctx, scenario, 90*time.Second, "active", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE))
	if err != nil {
		return nil, err
	}
	if session.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE {
		return session, fmt.Errorf("session ended %s (%s) before media", assistanceCauseText(session.GetEndCause()), session.GetEndDetail())
	}
	if err := r.verifyBinding(scenario, session, control); err != nil {
		return nil, err
	}
	var media browserMedia
	if err := r.browser.call(ctx, "media", map[string]any{"minFrames": 15, "timeoutMs": 60000}, &media, 75*time.Second); err != nil {
		return nil, err
	}
	scenario.Media = &assistanceMediaEvidence{VideoWidth: media.VideoWidth, VideoHeight: media.VideoHeight, DecodedFrames: media.DecodedFrames, FramesDecoded: media.FramesDecoded, ConnectionState: media.ConnectionState, TransportPolicy: media.TransportPolicy, RemoteApplication: media.RemoteApplication, DataChannels: media.DataChannels, LocalCandidateType: media.LocalCandidateType, RemoteCandidateType: media.RemoteCandidateType, ControlButton: media.ControlButton, LocalRelayProtocol: media.LocalRelayProtocol, LocalCandidateURL: media.LocalCandidateURL}
	annotate := session.GetGrantedCapabilities().GetPolicy().GetAnnotation() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if err := verifyAssistanceMedia(scenario.Media, control, false, annotate, r.turnTCP); err != nil {
		return nil, err
	}
	return session, r.browserScreenshot(ctx, scenario, "live")
}

// tierThreeBanner waits for a local notification whose OCR contains every
// word, binds it, and optionally chooses one of its actions.
func (r *assistanceRun) tierThreeBanner(ctx context.Context, scenario *assistanceScenarioEvidence, name string, words []string, actions, choice int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for attempt := 0; ; attempt++ {
		img, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
		if err != nil {
			return "", fmt.Errorf("%s notification: %w", name, err)
		}
		path, err := r.screen.save(fmt.Sprintf("%s-%s-%d", scenario.Name, name, attempt), img)
		if err != nil {
			return "", err
		}
		scenario.Screenshots = append(scenario.Screenshots, path)
		text, err := r.bannerOCR(ctx, path, img, banner)
		if err != nil {
			return "", err
		}
		if ocrContainsAll(text, words) {
			if actions == 0 {
				return text, nil
			}
			return text, r.screen.clickNotificationAction(ctx, banner, actions, choice, name, scenario)
		}
		// Another notice (the "in progress" notice GNOME shows at activation,
		// layers-fedora44-files-02) can stay ahead of this one on an idle
		// seat. After a few reads, local activity lets GNOME hide it.
		if attempt >= 3 {
			if err := r.screen.nudge(ctx, img.Bounds(), attempt); err != nil {
				return text, err
			}
		}
		select {
		case <-ctx.Done():
			return text, fmt.Errorf("%s notification never showed %q (last %q): %w", name, words, text, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func (r *assistanceRun) operatorStop(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) error {
	if err := r.browser.call(ctx, "stop", nil, nil, time.Minute); err != nil {
		return err
	}
	return r.finish(ctx, spec, scenario, true)
}

// elevationScenario pauses remote input through the operator's guidance,
// replays input while the real polkit agent asks for a password, types the
// password on the local seat, and resumes only through the local action.
func (r *assistanceRun) elevationScenario(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) (*assistanceElevationWitness, error) {
	witness := &assistanceElevationWitness{}
	password, err := assistanceLocalPassword()
	if err != nil {
		return witness, err
	}
	line := []byte(actionDesktopUser + ":" + password + "\n")
	_, err = r.vm.guest.run(ctx, "sudo -n chpasswd", bytes.NewReader(line), 4096, 30*time.Second)
	clear(line)
	if err != nil {
		return witness, fmt.Errorf("set lab desktop password: %w", err)
	}
	// polkit authenticates an administrator identity, which on the golden is
	// the provisioning account (wheel/sudo), not the desktop user whose
	// password the local seat types (layers-fedora44-tier3-07 asked for
	// lindm-lab). This lab-only admin rule names the desktop user as that
	// identity; it still requires the typed password and bypasses nothing.
	rule := "polkit.addAdminRule(function(action, subject) { return [\"unix-user:" + actionDesktopUser + "\"]; });\n"
	if _, err := r.vm.guest.run(ctx, "sudo -n sh -eu -c 'umask 022; cat > /etc/polkit-1/rules.d/49-lindm-lab-admin.rules'", strings.NewReader(rule), 4096, 30*time.Second); err != nil {
		return witness, fmt.Errorf("name the lab desktop user as polkit administrator: %w", err)
	}
	_, session, err := r.tierThreeRequest(ctx, spec, scenario, map[string]string{"Keyboard": "Text and physical keys", "Clipboard": "Send and read text", "Password prompts": "Guide and pause input"}, 2, 0, nil)
	if err != nil {
		return witness, err
	}
	// One real remote click establishes the console's input epoch.
	if err := r.browser.call(ctx, "click", map[string]any{"x": 0.5, "y": 0.5}, nil, 30*time.Second); err != nil {
		return witness, err
	}
	nonce, err := assistanceNonce()
	if err != nil {
		return witness, err
	}
	witness.Note = "lab password step " + nonce[:8]
	var guide struct {
		ControlDisabled bool `json:"controlDisabled"`
	}
	if err := r.browser.call(ctx, "elevationGuide", map[string]any{"note": witness.Note}, &guide, time.Minute); err != nil {
		return witness, err
	}
	witness.ControlDisabled = guide.ControlDisabled
	if witness.GuidanceOCR, err = r.tierThreeBanner(ctx, scenario, "elevation-guidance", []string{"paused", nonce[:8]}, 0, 0); err != nil {
		return witness, err
	}
	paused, err := r.readSession(ctx, session.GetId())
	if err != nil {
		return witness, err
	}
	witness.Paused = paused.GetInputState()
	if err := r.browserScreenshot(ctx, scenario, "input-paused"); err != nil {
		return witness, err
	}
	if err := r.openElevationTerminal(ctx); err != nil {
		return witness, err
	}
	if err := pollGuest(ctx, r.vm.guest, 45*time.Second, "polkit authentication dialog", "pgrep -f polkit-agent-helper-1 >/dev/null"); err != nil {
		return witness, err
	}
	time.Sleep(2 * time.Second)
	dialog, err := r.vm.guest.screendump(ctx)
	if err != nil {
		return witness, err
	}
	path, err := r.screen.save(scenario.Name+"-polkit-dialog", dialog)
	if err != nil {
		return witness, err
	}
	scenario.Screenshots = append(scenario.Screenshots, path)
	if witness.PolkitOCR, err = r.ocrScreenshot(ctx, path); err != nil {
		return witness, err
	}
	var probe struct {
		Sent     int                    `json:"sent"`
		Refusals []assistanceRPCRefusal `json:"refusals"`
	}
	if err := r.browser.call(ctx, "pausedInputProbe", map[string]any{"sessionId": session.GetId()}, &probe, time.Minute); err != nil {
		return witness, err
	}
	witness.ProbeEvents, witness.Refusals = probe.Sent, probe.Refusals
	// Any replayed key that reached the dialog would corrupt the password.
	for _, char := range password {
		if err := r.vm.guest.sendKey(ctx, string(char)); err != nil {
			return witness, err
		}
	}
	if err := r.vm.guest.sendKey(ctx, "ret"); err != nil {
		return witness, err
	}
	exit, err := waitAssistanceNonce(ctx, r.vm.guest, assistanceElevationResultPath, 45*time.Second)
	witness.PkexecExit = exit
	if err != nil {
		return witness, err
	}
	// In-session notices carry the indicator's Stop as their last action.
	if _, err := r.tierThreeBanner(ctx, scenario, "elevation-resume", []string{"paused"}, 2, 0); err != nil {
		return witness, err
	}
	if err := r.browser.call(ctx, "elevationResumed", nil, nil, 90*time.Second); err != nil {
		return witness, err
	}
	resumed, err := r.readSession(ctx, session.GetId())
	if err != nil {
		return witness, err
	}
	witness.Resumed = resumed.GetInputState()
	if err := r.typeNonce(ctx, scenario); err != nil {
		return witness, err
	}
	witness.InputAfter = scenario.NonceReceived
	return witness, r.operatorStop(ctx, spec, scenario)
}

// assistanceLocalPassword draws a password typed by QEMU key codes alone.
func assistanceLocalPassword() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var raw [14]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// openElevationTerminal runs pkexec in a terminal of the lab user's own
// session, so the desktop's polkit agent asks on the local seat.
func (r *assistanceRun) openElevationTerminal(ctx context.Context) error {
	argv := r.release.Lab.Session.Terminal
	if len(argv) == 0 {
		return fmt.Errorf("assistance terminal is not maintained for %s", r.release.Name)
	}
	waiter := `pkexec /usr/bin/true; printf %s "$?" > ` + nativeQuote(assistanceElevationResultPath)
	script := `rm -f ` + nativeQuote(assistanceElevationResultPath) + `
setsid sudo -n -H -u "$u" sh -eu -c ` + nativeQuote(assistanceTerminalAtHome) + ` sh env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus ` + r.desktop.userEnv + ` ` + strings.Join(argv, " ") + ` bash -c ` + nativeQuote(waiter) + ` </dev/null >/dev/null 2>&1 &`
	if _, err := r.vm.guest.run(ctx, r.desktop.rootScript(script), nil, 4096, 30*time.Second); err != nil {
		return fmt.Errorf("open pkexec terminal in the lab session: %w", err)
	}
	return nil
}

// annotationScenario shows the operator pointer and a mark over the native
// GTK witness, proves local clicks pass through, then applies the local
// Clear and Hide.
func (r *assistanceRun) annotationScenario(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) (_ *assistanceAnnotationWitness, err error) {
	witness := &assistanceAnnotationWitness{Mode: "on"}
	heads := 1
	capabilities := map[string]string{"Pointer and marks": "Pointer and marks"}
	if spec.name == "annotation-monitors" {
		heads, witness.Mode = 2, "limited"
		capabilities = map[string]string{"Pointer and marks": "Pointer only", "Displays": "Select shared displays"}
		if err := r.screen.waitNoBanner(ctx, 45*time.Second); err != nil {
			return witness, err
		}
		head, err := activateAssistanceHead(ctx, r.vm.guest)
		if err != nil {
			return witness, err
		}
		r.headConnection = head
		defer func() { err = errors.Join(err, r.releaseAssistanceHead(context.WithoutCancel(ctx), head)) }()
		if err := r.observeMonitorLayout(ctx); err != nil {
			return witness, err
		}
		if _, err := r.screen.captureReference(ctx, "annotation-two-head-reference"); err != nil {
			return witness, err
		}
	}
	if err := r.ensureOverlayExtension(ctx); err != nil {
		return witness, err
	}
	_, session, err := r.tierThreeRequest(ctx, spec, scenario, capabilities, 2, 0, nil)
	if err != nil {
		return witness, err
	}
	if heads == 2 && len(session.GetDisplays()) != 2 {
		return witness, fmt.Errorf("portal granted %d displays, require two real monitors", len(session.GetDisplays()))
	}
	if err := r.startFixture(ctx, heads); err != nil {
		return witness, err
	}
	var marker assistanceMonitorWitness
	if err := r.browser.call(ctx, "marker", nil, &marker, 45*time.Second); err != nil {
		return witness, err
	}
	references := make([]*image.RGBA, heads)
	for head := range heads {
		if references[head], err = r.vm.guest.screendumpHead(ctx, head); err != nil {
			return witness, err
		}
	}
	restoreReference, err := r.useFixtureReference(ctx)
	if err != nil {
		return witness, err
	}
	defer restoreReference()
	if err := r.browser.call(ctx, "annotation", map[string]any{"enabled": true}, nil, time.Minute); err != nil {
		return witness, err
	}
	if witness.NoticeOCR, err = r.tierThreeBanner(ctx, scenario, "annotation-notice", []string{"pointer"}, 0, 0); err != nil {
		return witness, err
	}
	pointAt := [2]float64{0.3, 0.3}
	observe := func(name string, head int, expected [2]float64, match func(r, g, b uint8) bool) (assistanceOverlayObservation, *image.RGBA, error) {
		observation := assistanceOverlayObservation{Head: head, Expected: expected}
		img, err := r.vm.guest.screendumpHead(ctx, head)
		if err != nil {
			return observation, nil, err
		}
		if observation.Screenshot, err = r.screen.save(fmt.Sprintf("%s-%s-head-%d", scenario.Name, name, head), img); err != nil {
			return observation, nil, err
		}
		scenario.Screenshots = append(scenario.Screenshots, observation.Screenshot)
		observation.Pixels, observation.Centroid = overlayPixels(references[head], img, r.overlayExclusion(img), match)
		for other := range heads {
			if other == head {
				continue
			}
			otherImg, err := r.vm.guest.screendumpHead(ctx, other)
			if err != nil {
				return observation, nil, err
			}
			pixels, _ := overlayPixels(references[other], otherImg, r.overlayExclusion(otherImg), match)
			observation.OtherPixels += pixels
		}
		return observation, img, nil
	}
	pointer := func(head int) error {
		if err := r.browser.call(ctx, "point", map[string]any{"x": pointAt[0], "y": pointAt[1], "holdMs": 2500}, nil, time.Minute); err != nil {
			return err
		}
		observation, _, err := observe("pointer", head, pointAt, overlayPointerColour)
		witness.Pointer = append(witness.Pointer, observation)
		return err
	}
	if err := pointer(marker.Head); err != nil {
		return witness, err
	}
	if heads == 2 {
		var choices struct {
			Labels []string `json:"labels"`
		}
		if err := r.browser.call(ctx, "displays", nil, &choices, 30*time.Second); err != nil {
			return witness, err
		}
		for _, label := range choices.Labels {
			var next assistanceMonitorWitness
			if err := r.browser.call(ctx, "display", map[string]any{"label": label}, &next, time.Minute); err != nil {
				return witness, err
			}
			if next.Head != marker.Head {
				if err := pointer(next.Head); err != nil {
					return witness, err
				}
				break
			}
		}
	} else {
		// A local click under the shown ring reaches the native window: the
		// overlay never takes input from the seat.
		if witness.LocalClick, err = r.localFixtureClick(ctx, scenario, pointAt); err != nil {
			return witness, err
		}
		from, to := [2]float64{0.55, 0.2}, [2]float64{0.8, 0.4}
		if err := r.browser.call(ctx, "draw", map[string]any{"from": map[string]float64{"x": from[0], "y": from[1]}, "to": map[string]float64{"x": to[0], "y": to[1]}}, nil, time.Minute); err != nil {
			return witness, err
		}
		stroke, _, err := observe("stroke", 0, [2]float64{(from[0] + to[0]) / 2, (from[1] + to[1]) / 2}, overlayStrokeColour)
		witness.Stroke = &stroke
		if err != nil {
			return witness, err
		}
		if err := r.browser.call(ctx, "stopPointing", nil, nil, 30*time.Second); err != nil {
			return witness, err
		}
		if _, err := r.tierThreeBanner(ctx, scenario, "annotation-clear", []string{"pointer"}, 3, 0); err != nil {
			return witness, err
		}
		time.Sleep(time.Second)
		cleared, _, err := observe("cleared", 0, stroke.Expected, overlayStrokeColour)
		if err != nil {
			return witness, err
		}
		witness.ClearedPixels = cleared.Pixels
		if err := r.browser.call(ctx, "point", map[string]any{"x": pointAt[0], "y": pointAt[1], "holdMs": 1000}, nil, time.Minute); err != nil {
			return witness, err
		}
		if _, err := r.tierThreeBanner(ctx, scenario, "annotation-hide", []string{"pointer"}, 3, 1); err != nil {
			return witness, err
		}
		if err := r.browser.call(ctx, "point", map[string]any{"x": pointAt[0], "y": pointAt[1], "holdMs": 2500}, nil, time.Minute); err != nil {
			return witness, err
		}
		hidden, _, err := observe("hidden", 0, pointAt, overlayPointerColour)
		if err != nil {
			return witness, err
		}
		witness.HiddenPixels = hidden.Pixels
		var state struct {
			ShowOffered bool `json:"showOffered"`
			Hidden      bool `json:"hidden"`
		}
		if err := r.browser.call(ctx, "annotationState", nil, &state, 30*time.Second); err != nil {
			return witness, err
		}
		witness.ShowOffered, witness.ConsoleHidden = state.ShowOffered, state.Hidden
		if err := r.browserScreenshot(ctx, scenario, "pointer-hidden"); err != nil {
			return witness, err
		}
	}
	if heads == 2 {
		if err := r.browser.call(ctx, "annotation", map[string]any{"enabled": false}, nil, time.Minute); err != nil {
			return witness, err
		}
	}
	final, err := r.readSession(ctx, session.GetId())
	if err != nil {
		return witness, err
	}
	witness.Report = final.GetAnnotation()
	return witness, r.operatorStop(ctx, spec, scenario)
}

// ensureOverlayExtension requires GNOME Shell to know the packaged overlay;
// the session helper itself enables it for a session and disables it after.
// GNOME Shell discovers a newly installed system extension only at login, so
// the lab signs the user in again when the running shell does not list it.
func (r *assistanceRun) ensureOverlayExtension(ctx context.Context) error {
	known := r.desktop.rootScript(`as gnome-extensions info lindm-overlay@lindm.dev >/dev/null`)
	if _, err := r.vm.guest.run(ctx, known, nil, 4096, 30*time.Second); err == nil {
		return nil
	}
	if err := r.logoutAssistanceDesktop(ctx); err != nil {
		return err
	}
	if err := r.reloginAssistanceDesktop(ctx); err != nil {
		return err
	}
	if _, err := r.vm.guest.run(ctx, known, nil, 4096, 30*time.Second); err != nil {
		return fmt.Errorf("GNOME Shell does not list the packaged overlay after login: %w", err)
	}
	return nil
}

func (r *assistanceRun) localFixtureClick(ctx context.Context, scenario *assistanceScenarioEvidence, at [2]float64) (*assistancePointerWitness, error) {
	before, err := r.waitFixture(ctx, "local click baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return nil, err
	}
	img, err := r.vm.guest.screendumpHead(ctx, 0)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	point := image.Pt(bounds.Min.X+int(at[0]*float64(bounds.Dx())), bounds.Min.Y+int(at[1]*float64(bounds.Dy())))
	display, local := r.screen.localPoint(bounds, point)
	if err := r.vm.guest.pointerClick(ctx, display, local, "left"); err != nil {
		return nil, err
	}
	scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: "fixture-under-overlay", X: point.X, Y: point.Y})
	after, err := r.waitFixture(ctx, "local click through the overlay", func(state *assistanceFixtureState) bool { return len(state.Clicks) > len(before.Clicks) })
	if err != nil {
		return nil, err
	}
	click := after.Clicks[len(after.Clicks)-1]
	return &click, verifyAssistancePointer(click, 0, at[0], at[1])
}

// overlayPixels counts pixels outside exclude that changed from the reference
// and match the overlay colour, and returns their normalized centroid.
func overlayPixels(reference, current *image.RGBA, exclude image.Rectangle, match func(r, g, b uint8) bool) (int, [2]float64) {
	if reference == nil || current == nil || reference.Bounds() != current.Bounds() {
		return 0, [2]float64{-1, -1}
	}
	bounds := current.Bounds()
	count, sumX, sumY := 0, 0.0, 0.0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			pixel, before := current.RGBAAt(x, y), reference.RGBAAt(x, y)
			if pixel == before || !match(pixel.R, pixel.G, pixel.B) || image.Pt(x, y).In(exclude) {
				continue
			}
			count++
			sumX += float64(x - bounds.Min.X)
			sumY += float64(y - bounds.Min.Y)
		}
	}
	if count == 0 {
		return 0, [2]float64{-1, -1}
	}
	return count, [2]float64{sumX / float64(count) / float64(bounds.Dx()), sumY / float64(count) / float64(bounds.Dy())}
}

// overlayExclusion is the notice banner over the witness with its drop
// shadow. The witness's red field matches the stroke colour, so wherever the
// banner or its shadow moved it counted as marks: 3117 "stroke" pixels
// remained after a visible local Clear (layers-fedora44-tier3-15).
func (r *assistanceRun) overlayExclusion(img *image.RGBA) image.Rectangle {
	banner, found := r.screen.area.locate(r.screen.reference, img)
	if !found {
		return image.Rectangle{}
	}
	return banner.Inset(-bannerShadowMargin)
}

// bannerShadowMargin covers GNOME's notification drop shadow.
const bannerShadowMargin = 24

// overlayPointerColour matches the overlay's orange ring (1.0, 0.6, 0.0).
func overlayPointerColour(r, g, b uint8) bool {
	return r >= 200 && g >= 110 && g <= 190 && b <= 80
}

// overlayStrokeColour matches the overlay's red marks (0.93, 0.26, 0.21).
func overlayStrokeColour(r, g, b uint8) bool {
	return r >= 180 && g <= 110 && b <= 100 && int(r)-int(g) >= 100
}

// audioScenario plays known tones into a virtual output and microphone and
// measures them in the console after the local choices, then mutes and stops
// locally. The declined variant shares nothing.
func (r *assistanceRun) audioScenario(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, policy *agentv1.AssistancePolicy) (_ *assistanceAudioWitness, err error) {
	witness := &assistanceAudioWitness{Mode: "on"}
	request := "Output and microphone"
	if spec.name == "audio-declined" {
		witness.Mode, request = "limited", "Selected output only"
		policy.Audio = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
		if err := r.setDevicePolicy(ctx, policy); err != nil {
			return witness, err
		}
	}
	outputs, err := r.prepareAssistanceAudio(ctx)
	if err != nil {
		return witness, err
	}
	defer func() {
		if err != nil {
			// Fedora 44's screen capture got no frames while the lab sound
			// graph existed (layers-fedora44-tier3-30/-31): keep the graph.
			graph := r.desktop.rootScript("as pw-dump --no-colors; as pw-top -b -n 3 || true")
			err = errors.Join(err, runAssistanceSetup(context.WithoutCancel(ctx), r.vm.guest, r.evidence, r.result, "audio-failure-graph", graph, 30*time.Second))
		}
		err = errors.Join(err, r.stopAssistanceAudio(context.WithoutCancel(ctx)))
	}()
	index := slices.Index(outputs, assistanceAudioOutput)
	if index < 0 || index > 1 {
		return witness, fmt.Errorf("lab output is not one of the two offered outputs: %q", outputs)
	}
	actions := min(len(outputs), 2) + 1
	choice := index
	if spec.name == "audio-declined" {
		choice = actions - 1
	}
	// The helper asks for sound, then the microphone, before the portal.
	choose := func() error {
		text, err := r.tierThreeBanner(ctx, scenario, "sound-choice", []string{"sound"}, actions, choice)
		witness.PromptOCR = append(witness.PromptOCR, text)
		if err != nil || spec.name != "audio" {
			return err
		}
		text, err = r.tierThreeBanner(ctx, scenario, "microphone-choice", []string{"microphone"}, 2, 0)
		witness.PromptOCR = append(witness.PromptOCR, text)
		return err
	}
	_, session, err := r.tierThreeRequest(ctx, spec, scenario, map[string]string{"Sound": request}, 2, 0, choose)
	if err != nil {
		return witness, err
	}
	want := agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING
	if spec.name == "audio-declined" {
		want = agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED
	}
	shared, err := r.waitAudio(ctx, session.GetId(), want)
	witness.Shared = shared
	if err != nil {
		return witness, err
	}
	tones := []int{assistanceOutputTone, assistanceMicrophoneTone}
	measure := func(name string) (*assistanceToneLevels, error) {
		levels := new(assistanceToneLevels)
		err := r.browser.call(ctx, "audioSpectrum", map[string]any{"frequencies": tones, "durationMs": 4000}, levels, time.Minute)
		if err == nil {
			err = r.browserScreenshot(ctx, scenario, "sound-"+name)
		}
		return levels, err
	}
	if witness.Heard, err = measure("shared"); err != nil {
		return witness, err
	}
	if spec.name == "audio" {
		if _, err := r.tierThreeBanner(ctx, scenario, "sound-mute", []string{"sound"}, 3, 0); err != nil {
			return witness, err
		}
		if _, err := r.waitAudio(ctx, session.GetId(), agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED); err != nil {
			return witness, err
		}
		// The helper stops writing at once, but the browser's receive jitter
		// buffer still plays what had arrived: 4 of a muted window's 40
		// frames carried a fading tone (layers-fedora44-tier3-33).
		select {
		case <-ctx.Done():
			return witness, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if witness.Muted, err = measure("muted"); err != nil {
			return witness, err
		}
		if _, err := r.tierThreeBanner(ctx, scenario, "sound-unmute", []string{"sound"}, 3, 0); err != nil {
			return witness, err
		}
		if _, err := r.waitAudio(ctx, session.GetId(), agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING); err != nil {
			return witness, err
		}
		if witness.Unmuted, err = measure("unmuted"); err != nil {
			return witness, err
		}
		if _, err := r.tierThreeBanner(ctx, scenario, "sound-stop", []string{"sound"}, 3, 1); err != nil {
			return witness, err
		}
		if _, err := r.waitAudio(ctx, session.GetId(), agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED); err != nil {
			return witness, err
		}
		if witness.Stopped, err = measure("stopped"); err != nil {
			return witness, err
		}
	}
	var status struct {
		Text string `json:"text"`
	}
	if err := r.browser.call(ctx, "audioStatus", nil, &status, 30*time.Second); err != nil {
		return witness, err
	}
	witness.ConsoleStatus = status.Text
	final, err := r.readSession(ctx, session.GetId())
	if err != nil {
		return witness, err
	}
	witness.Final = final.GetAudio()
	return witness, r.operatorStop(ctx, spec, scenario)
}

func (r *assistanceRun) waitAudio(ctx context.Context, sessionID string, state agentv1.AssistanceAudioState) (*agentv1.AssistanceAudioReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		session, err := r.readSession(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if session.GetAudio().GetState() == state {
			return session.GetAudio(), nil
		}
		select {
		case <-ctx.Done():
			return session.GetAudio(), fmt.Errorf("sound did not reach %s (last %v): %w", state, session.GetAudio().GetState(), ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// prepareAssistanceAudio creates the lab output (a null sink fed a 440 Hz
// tone) and the lab microphone (an 880 Hz source node) in the lab user's
// PipeWire graph and returns the output descriptions in graph order, as the
// helper offers them. PipeWire's own pw-play plays the tones: GStreamer's
// pipewiresink streams never started on Fedora 44, so the whole graph stayed
// suspended and the screen capture got no frames
// (layers-fedora44-audio-diag-03). WirePlumber 0.5 does not link a playback
// stream to a source node, so the microphone tone is linked by hand.
func (r *assistanceRun) prepareAssistanceAudio(ctx context.Context) ([]string, error) {
	script := `for freq in ` + fmt.Sprint(assistanceOutputTone) + ` ` + fmt.Sprint(assistanceMicrophoneTone) + `; do
  as python3 -c 'import math, struct, sys, wave
f = int(sys.argv[1]); rate = 16000
with wave.open(sys.argv[2], "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
    period = b"".join(struct.pack("<h", int(0.4 * 32767 * math.sin(2 * math.pi * f * i / rate))) for i in range(rate))
    w.writeframes(period * 300)' "$freq" "/tmp/lindm-lab-tone-$freq.wav"
done
as pw-cli create-node adapter '{ factory.name=support.null-audio-sink node.name=lindm-lab-output node.description="` + assistanceAudioOutput + `" media.class=Audio/Sink object.linger=true audio.position=[ FL FR ] }' >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do as pw-dump --no-colors | grep -q '"node.name": "lindm-lab-output"' && break; sleep 0.5; done
as systemd-run --user --collect --unit=lindm-lab-tone-output pw-play --target lindm-lab-output /tmp/lindm-lab-tone-` + fmt.Sprint(assistanceOutputTone) + `.wav
as pw-cli create-node adapter '{ factory.name=support.null-audio-sink node.name=lindm-lab-microphone node.description="` + assistanceAudioMicrophone + `" media.class=Audio/Source/Virtual object.linger=true audio.position=[ FL FR ] }' >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do as pw-dump --no-colors | grep -q '"node.name": "lindm-lab-microphone"' && break; sleep 0.5; done
as systemd-run --user --collect --unit=lindm-lab-tone-microphone pw-play -P '{ node.name=lindm-lab-microphone-tone node.autoconnect=false }' /tmp/lindm-lab-tone-` + fmt.Sprint(assistanceMicrophoneTone) + `.wav
for i in 1 2 3 4 5 6 7 8 9 10; do as pw-link -o | grep -q '^lindm-lab-microphone-tone:' && break; sleep 0.5; done
tone=$(as pw-link -o | grep -m1 '^lindm-lab-microphone-tone:')
for port in $(as pw-link -i | grep '^lindm-lab-microphone:'); do
  as pw-link "$tone" "$port"
done
# The tone units are collected on exit, so a missing node keeps their journal
# (layers-fedora44-tier3-18 offered no microphone).
for node in lindm-lab-output lindm-lab-microphone; do
  as pw-dump --no-colors | grep -q "\"node.name\": \"$node\"" && continue
  echo "missing PipeWire node $node" >&2
  as journalctl --user --no-pager -n 40 -u lindm-lab-tone-output.service -u lindm-lab-tone-microphone.service >&2 || true
  as pw-dump --no-colors | grep -E '"(node.name|media.class)"' >&2 || true
  exit 1
done
# Both lab nodes must run before a session starts.
for i in 1 2 3 4 5 6 7 8 9 10; do
  top=$(as pw-top -b -n 2 || true)
  printf '%s\n' "$top" | grep -Eq '^R .* lindm-lab-output *$' && printf '%s\n' "$top" | grep -Eq '^R .* lindm-lab-microphone *$' && exit 0
  sleep 0.5
done
echo "lab sound graph is not running" >&2
printf '%s\n' "$top" >&2
as pw-link -l >&2 || true
as journalctl --user --no-pager -n 20 -u lindm-lab-tone-output.service -u lindm-lab-tone-microphone.service >&2 || true
exit 1`
	if err := runAssistanceSetup(ctx, r.vm.guest, r.evidence, r.result, "audio-start", r.desktop.rootScript(script), time.Minute); err != nil {
		return nil, err
	}
	out, err := r.vm.guest.run(ctx, r.desktop.rootScript("as pw-dump --no-colors"), nil, 8<<20, 30*time.Second)
	if err != nil {
		return nil, err
	}
	outputs, microphones, err := labAudioNodes(out)
	if err != nil {
		return nil, err
	}
	if len(microphones) == 0 || microphones[0] != assistanceAudioMicrophone {
		return nil, fmt.Errorf("lab microphone is not the first microphone the helper offers: %q", microphones)
	}
	return outputs, nil
}

func (r *assistanceRun) stopAssistanceAudio(ctx context.Context) error {
	_, err := r.vm.guest.run(ctx, r.desktop.rootScript(`as systemctl --user stop lindm-lab-tone-output.service lindm-lab-tone-microphone.service || true
for id in $(as pw-cli ls Node | sed -n 's/^[[:space:]]*id \([0-9]*\),.*/\1/p'); do
  as pw-cli info "$id" 2>/dev/null | grep -Eq 'node.name = "lindm-lab-(output|microphone)"' && as pw-cli destroy "$id" >/dev/null || true
done
rm -f /tmp/lindm-lab-tone-*.wav`), nil, 64<<10, 30*time.Second)
	return err
}

// labAudioNodes lists sink and source descriptions in pw-dump order, as the
// helper's own enumeration orders its local choices.
func labAudioNodes(data []byte) (outputs, microphones []string, err error) {
	var objects []struct {
		Type string `json:"type"`
		Info struct {
			Props map[string]any `json:"props"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &objects); err != nil {
		return nil, nil, fmt.Errorf("decode guest PipeWire graph: %w", err)
	}
	for _, object := range objects {
		if object.Type != "PipeWire:Interface:Node" {
			continue
		}
		class, _ := object.Info.Props["media.class"].(string)
		description, _ := object.Info.Props["node.description"].(string)
		if description == "" {
			description, _ = object.Info.Props["node.name"].(string)
		}
		switch class {
		case "Audio/Sink":
			outputs = append(outputs, description)
		case "Audio/Source", "Audio/Source/Virtual":
			microphones = append(microphones, description)
		}
	}
	return outputs, microphones, nil
}

// unattendedScenario opts the lab user in during an attended session, then
// requests, self-approval-refuses, approves and activates an access period
// and exercises the scenario's unattended path.
func (r *assistanceRun) unattendedScenario(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence) (*assistanceUnattendedWitness, []string, error) {
	witness := &assistanceUnattendedWitness{Connections: map[string]*assistanceWorkflowSessionEvidence{}, PortalDialogs: map[string]bool{}, Refusals: map[string]*assistanceRPCRefusal{}}
	var resources []string
	optIn := &assistanceScenarioEvidence{Name: spec.name + "-opt-in", DeviceID: r.deviceID, Mode: "view", ExpectedCause: assistanceCauseText(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)}
	r.result.Scenarios = append(r.result.Scenarios, optIn)
	optInSpec := assistanceScenarioSpec{name: optIn.Name, mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED}
	prompt, session, err := r.tierThreeRequest(ctx, optInSpec, optIn, map[string]string{"Unattended access": "Approved time window"}, 3, 1, nil)
	witness.OptInOCR = prompt
	if err != nil {
		return witness, resources, err
	}
	resources = append(resources, session.GetId())
	enrollment, err := r.waitEnrollment(ctx, adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_ENROLLED)
	witness.Enrollment = enrollment
	if err != nil {
		return witness, resources, err
	}
	resources = append(resources, enrollment.GetId())
	if witness.StateFile, err = r.unattendedStateFile(ctx); err != nil {
		return witness, resources, err
	}
	if err := r.operatorStop(ctx, optInSpec, optIn); err != nil {
		return witness, resources, err
	}
	grant, err := r.approveUnattended(ctx, witness)
	if grant != nil {
		resources = append(resources, grant.GetId())
	}
	resources = append(resources, witness.ApprovalID)
	if err != nil {
		return witness, resources, err
	}
	switch spec.name {
	case "unattended":
		err = r.unattendedConnection(ctx, spec, scenario, witness, "connect")
		if err == nil {
			err = r.unattendedStopLocally(ctx, spec, scenario, witness)
		}
		if err == nil {
			witness.Refusals["after-turn-off"], err = r.unattendedRefusal(ctx, grant.GetId())
		}
	case "unattended-lock":
		err = r.unattendedLock(ctx, spec, scenario, witness, grant.GetId())
	case "unattended-revoked":
		err = r.unattendedRevoked(ctx, spec, scenario, witness, grant.GetId())
	}
	if err != nil {
		return witness, resources, err
	}
	final, err := r.owner.Admin.ListUnattendedAssistance(ctx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: r.deviceID}))
	if err != nil {
		return witness, resources, vmControlPlaneError("list unattended assistance", err)
	}
	witness.Final = final.Msg
	for _, extra := range final.Msg.GetGrants() {
		resources = append(resources, extra.GetId())
	}
	for _, connection := range witness.Connections {
		resources = append(resources, connection.ID)
	}
	witness.StateAfter, err = r.unattendedStateFile(ctx)
	return witness, resources, err
}

func (r *assistanceRun) waitEnrollment(ctx context.Context, state adminv1.AssistanceUnattendedEnrollmentStatus) (*adminv1.AssistanceUnattendedEnrollment, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		response, err := r.owner.Admin.ListUnattendedAssistance(ctx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: r.deviceID}))
		if err != nil {
			return nil, vmControlPlaneError("list unattended assistance", err)
		}
		for _, enrollment := range response.Msg.GetEnrollments() {
			if enrollment.GetUsername() == actionDesktopUser && enrollment.GetState() == state {
				return enrollment, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("unattended opt-in did not reach %s: %w", state, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// unattendedStateFile reports the device-local opt-in's mode and owner.
func (r *assistanceRun) unattendedStateFile(ctx context.Context) (string, error) {
	out, err := r.vm.guest.run(ctx, "sudo -n stat -c '%a %U %F' "+nativeQuote(assistanceUnattendedStatePath)+" 2>/dev/null || echo absent", nil, 256, 10*time.Second)
	return strings.TrimSpace(string(out)), err
}

// approveUnattended requests an access period as the operator, proves the
// operator cannot approve it, approves it as a second person and activates
// it in the console.
func (r *assistanceRun) approveUnattended(ctx context.Context, witness *assistanceUnattendedWitness) (*adminv1.AssistanceUnattendedGrant, error) {
	if err := r.browser.call(ctx, "unattendedRequest", map[string]any{"deviceId": r.deviceID, "username": actionDesktopUser, "hours": 1, "reason": "lab unattended assistance access period"}, nil, time.Minute); err != nil {
		return nil, err
	}
	approval, err := r.pendingUnattendedApproval(ctx)
	if err != nil {
		return nil, err
	}
	witness.ApprovalID = approval.GetId()
	witness.SelfApproval = new(assistanceRPCRefusal)
	if err := r.browser.call(ctx, "unattendedSelfApproval", map[string]any{"approvalId": approval.GetId()}, witness.SelfApproval, time.Minute); err != nil {
		return nil, err
	}
	if _, err := r.owner.Admin.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "independent lab unattended access approval"})); err != nil {
		return nil, vmControlPlaneError("approve unattended access", err)
	}
	if err := r.browser.call(ctx, "unattendedActivate", map[string]any{"deviceId": r.deviceID}, nil, time.Minute); err != nil {
		return nil, err
	}
	response, err := r.owner.Admin.ListUnattendedAssistance(ctx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: r.deviceID}))
	if err != nil {
		return nil, vmControlPlaneError("list unattended assistance", err)
	}
	for _, grant := range response.Msg.GetGrants() {
		if grant.GetApprovalId() == approval.GetId() {
			witness.Grant = grant
			return grant, nil
		}
	}
	return nil, errors.New("activated access period is not listed")
}

func (r *assistanceRun) pendingUnattendedApproval(ctx context.Context) (*adminv1.Approval, error) {
	response, err := r.owner.Admin.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 200}))
	if err != nil {
		return nil, vmControlPlaneError("list approvals", err)
	}
	for _, approval := range response.Msg.GetApprovals() {
		if approval.GetState() == adminv1.ApprovalState_APPROVAL_STATE_PENDING && approval.GetAuthorizeUnattendedAssistance().GetDeviceId() == r.deviceID {
			return approval, nil
		}
	}
	return nil, errors.New("no pending unattended access approval for the lab device")
}

// unattendedConnection connects through the console's Connect now and
// requires the local banner, no portal dialog and relayed media.
func (r *assistanceRun) unattendedConnection(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, witness *assistanceUnattendedWitness, key string) error {
	if err := r.screen.waitNoBanner(ctx, 45*time.Second); err != nil {
		return err
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := r.browser.call(ctx, "unattendedConnect", map[string]any{"deviceId": r.deviceID}, &created, time.Minute); err != nil {
		return err
	}
	if !vmValidID(created.SessionID) {
		return errors.New("console did not open the unattended connection")
	}
	connection := scenario
	if scenario.SessionID != "" {
		connection = &assistanceScenarioEvidence{Name: spec.name + "-" + key, DeviceID: r.deviceID, Mode: "view", ExpectedCause: scenario.ExpectedCause}
		r.result.Scenarios = append(r.result.Scenarios, connection)
	}
	connection.SessionID = created.SessionID
	session, dialog, err := r.watchUnattended(ctx, connection, true)
	witness.PortalDialogs[key] = dialog
	if session != nil {
		witness.Connections[key] = sessionEvidence(session, connection.States)
	}
	if err != nil {
		return err
	}
	if witness.BannerOCR, err = r.tierThreeBanner(ctx, connection, "unattended-banner", []string{"unattended"}, 0, 0); err != nil {
		return err
	}
	if _, err := r.liveSession(ctx, connection, false); err != nil {
		return err
	}
	return nil
}

// watchUnattended follows a connection to ACTIVE (live) or to its end and
// records whether any portal dialog appeared on the seat meanwhile.
func (r *assistanceRun) watchUnattended(ctx context.Context, scenario *assistanceScenarioEvidence, live bool) (*adminv1.AssistanceSession, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	dialog := false
	for {
		session, err := r.readSession(ctx, scenario.SessionID)
		if err != nil {
			return nil, dialog, err
		}
		state := assistanceStateText(session.GetState())
		if len(scenario.States) == 0 || scenario.States[len(scenario.States)-1].State != state {
			scenario.States = append(scenario.States, assistanceStateObservation{State: state, ObservedAt: time.Now().UTC()})
		}
		img, err := r.vm.guest.screendump(ctx)
		if err != nil {
			return session, dialog, err
		}
		if _, found := locatePortalDialog(img); found && !dialog {
			dialog = true
			if err := r.guestScreenshot(scenario, "unexpected-portal-dialog", img); err != nil {
				return session, dialog, err
			}
		}
		if ended(session) || (live && session.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE) {
			if err := r.guestScreenshot(scenario, "unattended-"+state, img); err != nil {
				return session, dialog, err
			}
			if live && ended(session) {
				return session, dialog, fmt.Errorf("unattended connection ended %s (%s)", assistanceCauseText(session.GetEndCause()), session.GetEndDetail())
			}
			return session, dialog, nil
		}
		select {
		case <-ctx.Done():
			return session, dialog, fmt.Errorf("unattended connection stayed %s: %w", state, ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// unattendedStopLocally chooses "Stop and turn off unattended" on the banner.
func (r *assistanceRun) unattendedStopLocally(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, witness *assistanceUnattendedWitness) error {
	if _, err := r.tierThreeBanner(ctx, scenario, "unattended-turn-off", []string{"unattended"}, 2, 1); err != nil {
		return err
	}
	if err := r.finish(ctx, spec, scenario, true); err != nil {
		return err
	}
	session, err := r.readSession(ctx, scenario.SessionID)
	if err != nil {
		return err
	}
	witness.Connections["connect"] = sessionEvidence(session, scenario.States)
	_, err = r.waitEnrollment(ctx, adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_REVOKED)
	return err
}

// unattendedRefusal asks the server for an unattended connection directly.
func (r *assistanceRun) unattendedRefusal(ctx context.Context, grantID string) (*assistanceRPCRefusal, error) {
	refusal := new(assistanceRPCRefusal)
	err := r.browser.call(ctx, "tierThreeCall", map[string]any{"method": "CreateAssistanceSession", "body": map[string]any{
		"requestId": uuid.NewString(), "deviceId": r.deviceID, "mode": "ASSISTANCE_MODE_VIEW", "reason": "lab unattended refusal probe", "maxDurationSeconds": 600, "unattendedGrantId": grantID,
	}}, refusal, time.Minute)
	return refusal, err
}

// unattendedLock requires refusal on a locked and on a signed-out seat, then
// a dialog-free connection after a real reboot.
func (r *assistanceRun) unattendedLock(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, witness *assistanceUnattendedWitness, grantID string) error {
	scenario.LockPath = "loginctl lock-session"
	if err := lockAssistanceSession(ctx, r.vm.guest, r.result.Guest.Desktop.SessionID, true); err != nil {
		return err
	}
	locked := &assistanceScenarioEvidence{Name: spec.name + "-locked", DeviceID: r.deviceID, Mode: "view"}
	r.result.Scenarios = append(r.result.Scenarios, locked)
	if err := r.unattendedRefusedConnection(ctx, locked, witness, "locked"); err != nil {
		return err
	}
	if err := lockAssistanceSession(ctx, r.vm.guest, r.result.Guest.Desktop.SessionID, false); err != nil {
		return err
	}
	if err := r.logoutAssistanceDesktop(ctx); err != nil {
		return err
	}
	if err := pollGuest(ctx, r.vm.guest, time.Minute, "logind session end", "! loginctl show-session "+r.result.Guest.Desktop.SessionID+" >/dev/null 2>&1"); err != nil {
		return err
	}
	signedOut := &assistanceScenarioEvidence{Name: spec.name + "-signed-out", DeviceID: r.deviceID, Mode: "view"}
	r.result.Scenarios = append(r.result.Scenarios, signedOut)
	if err := r.unattendedRefusedConnection(ctx, signedOut, witness, "signed-out"); err != nil {
		return err
	}
	if err := r.reloginAssistanceDesktop(ctx); err != nil {
		return err
	}
	var err error
	if witness.BootBefore, witness.BootAfter, err = r.rebootAssistanceGuest(ctx); err != nil {
		return err
	}
	if err := r.unattendedConnection(ctx, spec, scenario, witness, "after-reboot"); err != nil {
		return err
	}
	if err := r.operatorStop(ctx, spec, scenario); err != nil {
		return err
	}
	session, err := r.readSession(ctx, scenario.SessionID)
	if err != nil {
		return err
	}
	witness.Connections["after-reboot"] = sessionEvidence(session, scenario.States)
	_, err = r.owner.Admin.RevokeUnattendedAssistance(ctx, connect.NewRequest(&adminv1.RevokeUnattendedAssistanceRequest{DeviceId: r.deviceID, GrantId: grantID, Reason: "lab unattended lock scenario cleanup"}))
	return vmControlPlaneError("revoke unattended access", err)
}

// unattendedRefusedConnection requires a connection that ends before any
// banner or media.
func (r *assistanceRun) unattendedRefusedConnection(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceUnattendedWitness, key string) error {
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := r.browser.call(ctx, "unattendedConnect", map[string]any{"deviceId": r.deviceID}, &created, time.Minute); err != nil {
		return err
	}
	if !vmValidID(created.SessionID) {
		return errors.New("console did not open the unattended connection")
	}
	scenario.SessionID = created.SessionID
	session, dialog, err := r.watchUnattended(ctx, scenario, false)
	witness.PortalDialogs[key] = dialog
	if session != nil {
		witness.Connections[key] = sessionEvidence(session, scenario.States)
		scenario.EndCause, scenario.EndDetail = assistanceCauseText(session.GetEndCause()), session.GetEndDetail()
		scenario.ExpectedCause = scenario.EndCause
	}
	if err != nil {
		return err
	}
	return r.browser.call(ctx, "leave", map[string]any{"deviceId": r.deviceID}, nil, time.Minute)
}

// unattendedRevoked revokes a live connection's access period from the
// console's server, then proves an expired and an out-of-schedule period
// are refused.
func (r *assistanceRun) unattendedRevoked(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, witness *assistanceUnattendedWitness, grantID string) error {
	if err := r.unattendedConnection(ctx, spec, scenario, witness, "connect"); err != nil {
		return err
	}
	if _, err := r.owner.Admin.RevokeUnattendedAssistance(ctx, connect.NewRequest(&adminv1.RevokeUnattendedAssistanceRequest{DeviceId: r.deviceID, GrantId: grantID, Reason: "lab unattended revocation during a connection"})); err != nil {
		return vmControlPlaneError("revoke unattended access", err)
	}
	if err := r.finish(ctx, spec, scenario, true); err != nil {
		return err
	}
	session, err := r.readSession(ctx, scenario.SessionID)
	if err != nil {
		return err
	}
	witness.Connections["connect"] = sessionEvidence(session, scenario.States)
	short, err := r.shortUnattendedGrant(ctx, nil)
	if err != nil {
		return err
	}
	// Only the period's own 300 s bound elapses.
	wait := time.Until(short.GetNotAfter().AsTime()) + 5*time.Second
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
	}
	if witness.Refusals["expired"], err = r.unattendedRefusal(ctx, short.GetId()); err != nil {
		return err
	}
	policy := assistanceTierThreePolicy()
	policy.Unattended = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	if err := r.setDevicePolicy(ctx, policy); err != nil {
		return err
	}
	later := time.Now().UTC().Add(72 * time.Hour)
	scheduled, err := r.shortUnattendedGrant(ctx, &agentv1.AssistanceUnattendedSchedule{TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{{Weekday: uint32(later.Weekday()), StartMinute: uint32(later.Hour() * 60), DurationMinutes: 60}}})
	if err != nil {
		return err
	}
	witness.Refusals["outside-schedule"], err = r.unattendedRefusal(ctx, scheduled.GetId())
	return err
}

// shortUnattendedGrant requests, approves and activates a 300 s access
// period through the authenticated RPCs the console form uses.
func (r *assistanceRun) shortUnattendedGrant(ctx context.Context, schedule *agentv1.AssistanceUnattendedSchedule) (*adminv1.AssistanceUnattendedGrant, error) {
	authorize := map[string]any{
		"requestId": uuid.NewString(), "deviceId": r.deviceID, "mode": "ASSISTANCE_MODE_VIEW", "reason": "lab short unattended access period",
		"notBefore": timestamppb.Now().AsTime().Format(time.RFC3339Nano), "durationSeconds": 300, "targetUsername": actionDesktopUser,
	}
	if schedule != nil {
		windows := make([]map[string]any, 0, len(schedule.GetWindows()))
		for _, window := range schedule.GetWindows() {
			windows = append(windows, map[string]any{"weekday": window.GetWeekday(), "startMinute": window.GetStartMinute(), "durationMinutes": window.GetDurationMinutes()})
		}
		authorize["schedule"] = map[string]any{"timeZone": schedule.GetTimeZone(), "windows": windows}
	}
	var created struct {
		HTTPStatus int `json:"http_status"`
		Body       struct {
			Approval struct {
				ID string `json:"id"`
			} `json:"approval"`
		} `json:"body"`
	}
	if err := r.browser.call(ctx, "tierThreeCall", map[string]any{"method": "CreateApproval", "body": map[string]any{"lifetimeSeconds": 600, "authorizeUnattendedAssistance": authorize}}, &created, time.Minute); err != nil {
		return nil, err
	}
	if created.HTTPStatus != 200 || !vmValidID(created.Body.Approval.ID) {
		return nil, fmt.Errorf("short access period approval not created (HTTP %d)", created.HTTPStatus)
	}
	if _, err := r.owner.Admin.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Body.Approval.ID, Reason: "independent lab short unattended approval"})); err != nil {
		return nil, vmControlPlaneError("approve short unattended access", err)
	}
	authorize["approvalId"] = created.Body.Approval.ID
	var activated struct {
		HTTPStatus int    `json:"http_status"`
		Reason     string `json:"reason"`
		Body       struct {
			Grant struct {
				ID string `json:"id"`
			} `json:"grant"`
		} `json:"body"`
	}
	if err := r.browser.call(ctx, "tierThreeCall", map[string]any{"method": "AuthorizeUnattendedAssistance", "body": authorize}, &activated, time.Minute); err != nil {
		return nil, err
	}
	if activated.HTTPStatus != 200 || !vmValidID(activated.Body.Grant.ID) {
		return nil, fmt.Errorf("short access period not activated (HTTP %d, %s)", activated.HTTPStatus, activated.Reason)
	}
	response, err := r.owner.Admin.ListUnattendedAssistance(ctx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: r.deviceID}))
	if err != nil {
		return nil, vmControlPlaneError("list unattended assistance", err)
	}
	for _, grant := range response.Msg.GetGrants() {
		if grant.GetId() == activated.Body.Grant.ID {
			return grant, nil
		}
	}
	return nil, errors.New("short access period is not listed")
}

// verifyAssistanceTierThreeWitness is the qualification rule for each Tier 3
// scenario, applied when the witness is produced and again on the record.
func verifyAssistanceTierThreeWitness(name string, w *assistanceTierThreeWitness) error {
	if w == nil || w.Scenario != name || w.Policy == nil {
		return errors.New("tier three witness does not name its scenario and policy")
	}
	actions := auditActions(w.Audit)
	require := func(want ...string) error {
		for _, action := range want {
			if !slices.Contains(actions, action) {
				return fmt.Errorf("tier three scenario %s lacks audit %s", name, action)
			}
		}
		return nil
	}
	switch name {
	case "elevation":
		return verifyElevationWitness(w.Elevation, require)
	case "annotation", "annotation-monitors":
		return verifyAnnotationWitness(name, w.Annotation, require)
	case "audio", "audio-declined":
		return verifyAudioWitness(name, w.Audio, require)
	case "unattended", "unattended-lock", "unattended-revoked":
		return verifyUnattendedWitness(name, w.Unattended, require)
	}
	return fmt.Errorf("unknown tier three scenario %s", name)
}

func verifyElevationWitness(w *assistanceElevationWitness, require func(...string) error) error {
	if w == nil || w.Paused == nil || w.Resumed == nil {
		return errors.New("elevation witness lacks paused and resumed input state")
	}
	if !w.Paused.GetPaused() || w.Paused.GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION || !w.ControlDisabled {
		return errors.New("guidance did not pause remote input for the password")
	}
	if !strings.Contains(w.GuidanceOCR, "paused") {
		return errors.New("local guidance was not visible")
	}
	if w.ProbeEvents != 16 || len(w.Refusals) != 2 {
		return errors.New("paused input probe did not replay every input kind and command")
	}
	for _, refusal := range w.Refusals {
		if refusal.Code != "failed_precondition" || refusal.Reason != "assistance_input_paused" {
			return fmt.Errorf("paused command %s was not refused: %s %s", refusal.Kind, refusal.Code, refusal.Reason)
		}
	}
	if w.PkexecExit != "0" {
		return fmt.Errorf("locally typed password did not authenticate (pkexec exit %q): remote input reached the dialog or the dialog failed", w.PkexecExit)
	}
	if w.Resumed.GetPaused() || w.Resumed.GetEpoch() <= w.Paused.GetEpoch() || !w.InputAfter {
		return errors.New("local resume did not restore remote input under a new epoch")
	}
	return require("assistance.elevation.request", "assistance.elevation.pause", "assistance.elevation.resume")
}

func overlayNear(o assistanceOverlayObservation, minimum int) bool {
	return o.Pixels >= minimum && o.OtherPixels <= assistanceOverlayStray && math.Abs(o.Centroid[0]-o.Expected[0]) <= assistanceOverlayTolerance && math.Abs(o.Centroid[1]-o.Expected[1]) <= assistanceOverlayTolerance
}

func verifyAnnotationWitness(name string, w *assistanceAnnotationWitness, require func(...string) error) error {
	if w == nil || !strings.Contains(w.NoticeOCR, "pointer") {
		return errors.New("annotation witness lacks the local pointer notice")
	}
	if name == "annotation-monitors" {
		if len(w.Pointer) != 2 || w.Pointer[0].Head == w.Pointer[1].Head || !overlayNear(w.Pointer[0], assistanceOverlayPointerPixels) || !overlayNear(w.Pointer[1], assistanceOverlayPointerPixels) {
			return errors.New("pointer did not follow the shared monitor or leaked to the other head")
		}
		return require("assistance.annotation.enable", "assistance.annotation.disable")
	}
	if len(w.Pointer) != 1 || !overlayNear(w.Pointer[0], assistanceOverlayPointerPixels) {
		return errors.New("operator pointer was not drawn at the pointed location")
	}
	if w.Stroke == nil || w.Stroke.Pixels < assistanceOverlayStrokePixels || w.Stroke.OtherPixels != 0 {
		return errors.New("operator mark was not drawn")
	}
	if w.LocalClick == nil {
		return errors.New("local click under the overlay did not reach the native window")
	}
	if w.ClearedPixels > assistanceOverlayStray || w.HiddenPixels > assistanceOverlayStray {
		return errors.New("local Clear or Hide left overlay pixels")
	}
	if !w.ConsoleHidden || w.ShowOffered || w.Report == nil || !w.Report.GetHidden() || w.Report.GetEnabled() || w.Report.GetClears() == 0 {
		return errors.New("local Hide was not final or not reported")
	}
	return require("assistance.annotation.enable", "assistance.annotation.clear", "assistance.annotation.disable")
}

func toneLevel(levels *assistanceToneLevels, tone int) float64 {
	if levels == nil || !levels.Present || levels.Frames == 0 {
		return 0
	}
	return levels.Levels[fmt.Sprint(tone)]
}

func verifyAudioWitness(name string, w *assistanceAudioWitness, require func(...string) error) error {
	if w == nil || w.Shared == nil || w.Final == nil || len(w.PromptOCR) == 0 {
		return errors.New("audio witness lacks the local choice and reports")
	}
	if name == "audio-declined" {
		if len(w.PromptOCR) != 1 || w.Shared.GetState() != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED || (w.Heard != nil && w.Heard.Present) {
			return errors.New("declined or limited sound reached the operator or prompted for the microphone")
		}
		return require("assistance.audio.consent")
	}
	if w.Shared.GetOutputSource() != assistanceAudioOutput || w.Shared.GetMicrophoneSource() != assistanceAudioMicrophone {
		return errors.New("shared sound did not name the locally chosen output and microphone")
	}
	if toneLevel(w.Heard, assistanceOutputTone) < assistanceToneAudible || toneLevel(w.Heard, assistanceMicrophoneTone) < assistanceToneAudible {
		return errors.New("operator did not hear the known output and microphone tones")
	}
	if toneLevel(w.Muted, assistanceOutputTone) > assistanceToneSilent || toneLevel(w.Muted, assistanceMicrophoneTone) > assistanceToneSilent {
		return errors.New("local mute did not silence sound")
	}
	if toneLevel(w.Unmuted, assistanceOutputTone) < assistanceToneAudible {
		return errors.New("local unmute did not restore sound")
	}
	if toneLevel(w.Stopped, assistanceOutputTone) > assistanceToneSilent || w.Final.GetState() != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED {
		return errors.New("local stop did not end sound sharing")
	}
	return require("assistance.audio.consent", "assistance.audio.mute", "assistance.audio.stop")
}

func verifyUnattendedWitness(name string, w *assistanceUnattendedWitness, require func(...string) error) error {
	if w == nil || w.Enrollment == nil || w.Grant == nil || w.SelfApproval == nil {
		return errors.New("unattended witness lacks opt-in, grant or self-approval refusal")
	}
	if !strings.Contains(w.OptInOCR, "unattended") || w.Enrollment.GetUsername() != actionDesktopUser || !strings.HasPrefix(w.StateFile, "600 "+actionDesktopUser+" ") {
		return errors.New("opt-in was not a local choice stored privately for the user")
	}
	if w.SelfApproval.HTTPStatus < 400 || w.SelfApproval.Offered {
		return errors.New("the requester could approve their own unattended access")
	}
	if w.Grant.GetApproverId() == "" || w.Grant.GetApproverId() == w.Grant.GetOperatorId() {
		return errors.New("unattended access was not approved by a second person")
	}
	for key, dialog := range w.PortalDialogs {
		if dialog {
			return fmt.Errorf("unattended connection %s showed a portal dialog", key)
		}
	}
	notStarted := func(key string) error {
		connection := w.Connections[key]
		if connection == nil || (connection.EndCause != "no_eligible_session" && connection.EndCause != "session_locked") || slices.Contains(connection.ConsentedBefore, "active") {
			return fmt.Errorf("unattended connection reached a %s seat", key)
		}
		return nil
	}
	common := []string{"assistance.unattended.request", "assistance.unattended.approve", "assistance.unattended.authorize", "assistance.unattended.enroll", "assistance.unattended.start", "assistance.unattended.stop"}
	switch name {
	case "unattended":
		connection := w.Connections["connect"]
		if connection == nil || connection.EndCause != "user_stopped" || connection.EndDetail != "unattended_turned_off" || !strings.Contains(w.BannerOCR, "unattended") {
			return errors.New("unattended connection lacked the banner or the local turn-off")
		}
		if w.StateAfter != "absent" || refusalReason(w.Refusals["after-turn-off"]) != "assistance_unattended_not_enrolled" {
			return errors.New("turning unattended access off locally did not remove the opt-in")
		}
		return require(append(common, "assistance.unattended.revoke")...)
	case "unattended-lock":
		if err := errors.Join(notStarted("locked"), notStarted("signed-out")); err != nil {
			return err
		}
		if after := w.Connections["after-reboot"]; after == nil || after.EndCause != "operator_stopped" || w.BootBefore == "" || w.BootBefore == w.BootAfter {
			return errors.New("persistent grant did not serve a connection after a real reboot")
		}
		return require(append(common, "assistance.unattended.revoke")...)
	case "unattended-revoked":
		if connection := w.Connections["connect"]; connection == nil || connection.EndCause != "authorization_lost" {
			return errors.New("revocation did not end the live unattended connection")
		}
		if refusalReason(w.Refusals["expired"]) != "assistance_unattended_outside_approval" || refusalReason(w.Refusals["outside-schedule"]) != "assistance_unattended_outside_schedule" {
			return errors.New("expired or out-of-schedule access period was not refused")
		}
		return require(append(common, "assistance.unattended.revoke")...)
	}
	return fmt.Errorf("unknown unattended scenario %s", name)
}

func refusalReason(refusal *assistanceRPCRefusal) string {
	if refusal == nil || refusal.HTTPStatus < 400 {
		return ""
	}
	return refusal.Reason
}

// completeAssistanceTierThree requires every Tier 3 scenario's bound witness.
func completeAssistanceTierThree(result *VMAssistanceResult) bool {
	for _, name := range assistanceTierThreeScenarios {
		index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == name })
		if index < 0 || result.Scenarios[index].TierThreeWitness == "" || !slices.ContainsFunc(result.TierThreeWitnesses, func(file assistanceEvidenceFile) bool {
			return file.Name == "tierthree-"+name && file.Path == result.Scenarios[index].TierThreeWitness
		}) {
			return false
		}
	}
	return true
}

// verifyTierThreeWitnessRecord re-reads a bound Tier 3 witness and applies
// its qualification rule again.
func verifyTierThreeWitnessRecord(dir string, result *VMAssistanceResult, scenario *assistanceScenarioEvidence) error {
	index := slices.IndexFunc(result.TierThreeWitnesses, func(file assistanceEvidenceFile) bool {
		return file.Name == "tierthree-"+scenario.Name && file.Path == scenario.TierThreeWitness
	})
	if index < 0 || result.TierThreeWitnesses[index].Bytes <= 0 || result.TierThreeWitnesses[index].Bytes > 4<<20 {
		return errors.New("tier three scenario lacks a bounded SHA-bound structured witness")
	}
	data, err := os.ReadFile(filepath.Join(dir, scenario.TierThreeWitness))
	if err != nil {
		return err
	}
	var witness assistanceTierThreeWitness
	if err := json.Unmarshal(data, &witness); err != nil {
		return err
	}
	return verifyAssistanceTierThreeWitness(scenario.Name, &witness)
}

// ocrGlyphs folds tesseract's 1/l/i and 0/o confusions.
var ocrGlyphs = strings.NewReplacer("i", "1", "l", "1", "o", "0")

// ocrAlnum keeps only value's lowercase letters and digits, glyph-folded:
// tesseract inserts stray punctuation ("a9295a/7f", layers-fedora44-tier3-20)
// and GNOME wraps text at hyphens.
func ocrAlnum(value string) string {
	return ocrGlyphs.Replace(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(value)))
}

// ocrContainsAll reports whether OCR text holds every word, compared on
// letters and digits with glyph confusions folded on both sides: the guidance
// nonce "51ea2e99" read as "5lea2e99" (layers-fedora44-tier3-09).
func ocrContainsAll(text string, words []string) bool {
	folded := ocrAlnum(text)
	return !slices.ContainsFunc(words, func(word string) bool { return !strings.Contains(folded, ocrAlnum(word)) })
}

// ocrContainsApprox reports whether some substring of text is within
// maxEdits insertions, deletions or substitutions of needle (Sellers'
// approximate substring match).
func ocrContainsApprox(text, needle string, maxEdits int) bool {
	if len(needle) == 0 {
		return true
	}
	// column[i] is the least edit cost of needle[:i] ending at the current
	// text position; a match may start anywhere, so column[0] stays 0.
	column := make([]int, len(needle)+1)
	for i := range column {
		column[i] = i
	}
	if column[len(needle)] <= maxEdits {
		return true
	}
	for j := range len(text) {
		diagonal := column[0]
		for i := 1; i <= len(needle); i++ {
			cost := 1
			if needle[i-1] == text[j] {
				cost = 0
			}
			next := min(column[i]+1, column[i-1]+1, diagonal+cost)
			diagonal, column[i] = column[i], next
		}
		if column[len(needle)] <= maxEdits {
			return true
		}
	}
	return false
}
