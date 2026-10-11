//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
)

// assistanceRun carries one lane's live resources across scenarios.
type assistanceRun struct {
	vm       *EncryptedVM
	screen   *assistanceScreen
	browser  *assistanceBrowser
	owner    *devlab.OwnerSession
	evidence *assistanceEvidence
	result   *VMAssistanceResult
	release  *platform.Release
	deviceID string
	// turnTCP requires the console's selected relay candidate to use TURN
	// over TCP, as a remote browser behind an SSH forward must.
	turnTCP bool
}

// browserMedia mirrors the runner's camelCase observation.
type browserMedia struct {
	VideoWidth          int      `json:"videoWidth"`
	VideoHeight         int      `json:"videoHeight"`
	DecodedFrames       int      `json:"decodedFrames"`
	FramesDecoded       int      `json:"framesDecoded"`
	ConnectionState     string   `json:"connectionState"`
	TransportPolicy     string   `json:"transportPolicy"`
	RemoteApplication   bool     `json:"remoteApplication"`
	DataChannels        []string `json:"dataChannels"`
	LocalCandidateType  string   `json:"localCandidateType"`
	RemoteCandidateType string   `json:"remoteCandidateType"`
	ControlButton       bool     `json:"controlButton"`
	LocalRelayProtocol  string   `json:"localRelayProtocol"`
}

// assistanceNoncePath is written only by the guest terminal's own shell.
const assistanceNoncePath = "/home/" + actionDesktopUser + "/lindm-assistance-nonce"

func (r *assistanceRun) browserScreenshot(ctx context.Context, scenario *assistanceScenarioEvidence, name string) error {
	var shot struct {
		Path string `json:"path"`
	}
	file := "console-" + scenario.Name + "-" + name + ".png"
	if err := r.browser.call(ctx, "screenshot", map[string]any{"name": file}, &shot, 30*time.Second); err != nil {
		return err
	}
	if shot.Path != file {
		return errors.New("browser runner saved an unexpected screenshot")
	}
	bound, err := r.evidence.bind("console "+scenario.Name+" "+name, file)
	if err != nil {
		return err
	}
	r.result.Screenshots = append(r.result.Screenshots, bound)
	scenario.Screenshots = append(scenario.Screenshots, bound.Path)
	return nil
}

func (r *assistanceRun) guestScreenshot(scenario *assistanceScenarioEvidence, name string, img *image.RGBA) error {
	path, err := r.screen.save(scenario.Name+"-"+name, img)
	if err != nil {
		return err
	}
	scenario.Screenshots = append(scenario.Screenshots, path)
	return nil
}

// waitSession polls the admin API, recording each observed state, until done
// accepts the session. An unexpected end fails immediately with its cause.
func (r *assistanceRun) waitSession(ctx context.Context, scenario *assistanceScenarioEvidence, timeout time.Duration, what string, done func(*adminv1.AssistanceSession) bool) (*adminv1.AssistanceSession, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		response, err := r.owner.Admin.GetAssistanceSession(ctx, connect.NewRequest(&adminv1.GetAssistanceSessionRequest{SessionId: scenario.SessionID}))
		if err != nil {
			return nil, vmControlPlaneError("read assistance session", err)
		}
		session := response.Msg.GetSession()
		state := assistanceStateText(session.GetState())
		if len(scenario.States) == 0 || scenario.States[len(scenario.States)-1].State != state {
			scenario.States = append(scenario.States, assistanceStateObservation{State: state, ObservedAt: time.Now().UTC()})
		}
		if done(session) {
			return session, nil
		}
		if session.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ENDED {
			return session, fmt.Errorf("session ended %s (%s) while waiting for %s", assistanceCauseText(session.GetEndCause()), session.GetEndDetail(), what)
		}
		select {
		case <-ctx.Done():
			return session, fmt.Errorf("assistance session did not reach %s (last %s): %w", what, state, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func atLeast(state adminv1.AssistanceState) func(*adminv1.AssistanceSession) bool {
	return func(session *adminv1.AssistanceSession) bool {
		return session.GetState() >= state && session.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED
	}
}

func ended(session *adminv1.AssistanceSession) bool {
	return session.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ENDED
}

// scenario runs one complete session: console request, local consent through
// the product prompt and the desktop portal, live media in the console, the
// scenario's end path, and device-side capture shutdown.
func (r *assistanceRun) scenario(ctx context.Context, spec assistanceScenarioSpec) error {
	control := spec.mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	scenario := &assistanceScenarioEvidence{Name: spec.name, Mode: map[bool]string{true: "control", false: "view"}[control], ExpectedCause: assistanceCauseText(spec.cause)}
	r.result.Scenarios = append(r.result.Scenarios, scenario)
	if err := r.screen.waitNoBanner(ctx, 45*time.Second); err != nil {
		return err
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := r.browser.call(ctx, "request", map[string]any{"deviceId": r.deviceID, "mode": scenario.Mode, "reason": "lab assistance " + spec.name + " scenario", "minutes": 10}, &created, time.Minute); err != nil {
		return err
	}
	if !vmValidID(created.SessionID) {
		return errors.New("console did not open a session viewer")
	}
	scenario.SessionID = created.SessionID
	if _, err := r.waitSession(ctx, scenario, 90*time.Second, "prompted", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED)); err != nil {
		return err
	}
	prompt, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "consent-prompt", prompt); err != nil {
		return err
	}
	if err := r.browserScreenshot(ctx, scenario, "awaiting-consent"); err != nil {
		return err
	}
	// The prompt's actions are declared allow, decline.
	if spec.cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED && !spec.portalCancel {
		if err := r.screen.click(ctx, prompt.Bounds(), notificationActionPoint(banner, 2, 1), "consent-decline", scenario); err != nil {
			return err
		}
		return r.finish(ctx, spec, scenario, false)
	}
	if err := r.screen.click(ctx, prompt.Bounds(), notificationActionPoint(banner, 2, 0), "consent-allow", scenario); err != nil {
		return err
	}
	portal, dialog, err := r.screen.waitDialog(ctx, 45*time.Second)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
		return err
	}
	if spec.portalCancel {
		if err := r.screen.click(ctx, portal.Bounds(), portalCancelButton(dialog), "portal-cancel", scenario); err != nil {
			return err
		}
		return r.finish(ctx, spec, scenario, false)
	}
	if control {
		if err := r.screen.click(ctx, portal.Bounds(), portalControlSwitch(dialog), "portal-allow-remote-interaction", scenario); err != nil {
			return err
		}
		enabled, err := r.screen.waitSwitchOn(ctx, dialog, 10*time.Second)
		if err != nil {
			return err
		}
		if err := r.guestScreenshot(scenario, "portal-interaction-enabled", enabled); err != nil {
			return err
		}
	}
	if err := r.screen.click(ctx, portal.Bounds(), portalShareButton(dialog), "portal-share", scenario); err != nil {
		return err
	}
	session, err := r.waitSession(ctx, scenario, 90*time.Second, "active", atLeast(adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE))
	if err != nil {
		return err
	}
	if err := r.verifyBinding(scenario, session, control); err != nil {
		return err
	}
	var media browserMedia
	if err := r.browser.call(ctx, "media", map[string]any{"minFrames": 15, "timeoutMs": 60000}, &media, 75*time.Second); err != nil {
		return err
	}
	scenario.Media = &assistanceMediaEvidence{VideoWidth: media.VideoWidth, VideoHeight: media.VideoHeight, DecodedFrames: media.DecodedFrames, FramesDecoded: media.FramesDecoded, ConnectionState: media.ConnectionState, TransportPolicy: media.TransportPolicy, RemoteApplication: media.RemoteApplication, DataChannels: media.DataChannels, LocalCandidateType: media.LocalCandidateType, RemoteCandidateType: media.RemoteCandidateType, ControlButton: media.ControlButton, LocalRelayProtocol: media.LocalRelayProtocol}
	if err := verifyAssistanceMedia(scenario.Media, control, r.turnTCP); err != nil {
		return err
	}
	if err := r.browserScreenshot(ctx, scenario, "live"); err != nil {
		return err
	}
	sharing, err := r.vm.guest.screendump(ctx)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "sharing", sharing); err != nil {
		return err
	}
	switch spec.cause {
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED:
		if err := r.typeNonce(ctx, scenario); err != nil {
			return err
		}
		if err := r.browser.call(ctx, "stop", nil, nil, time.Minute); err != nil {
			return err
		}
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED:
		// The in-progress indicator is critical with the single action "stop".
		indicator, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
		if err != nil {
			return err
		}
		if err := r.guestScreenshot(scenario, "indicator", indicator); err != nil {
			return err
		}
		if err := r.screen.click(ctx, indicator.Bounds(), notificationActionPoint(banner, 1, 0), "indicator-stop", scenario); err != nil {
			return err
		}
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED:
		if err := lockAssistanceSession(ctx, r.vm.guest, r.result.Guest.Desktop.SessionID, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported scenario end cause %s", spec.cause)
	}
	return r.finish(ctx, spec, scenario, true)
}

// verifyBinding checks the server bound the consenting local session the lab
// logged in through GDM, and that control was granted exactly when requested.
func (r *assistanceRun) verifyBinding(scenario *assistanceScenarioEvidence, session *adminv1.AssistanceSession, control bool) error {
	local := session.GetLocalSession()
	scenario.LocalSession = &assistanceLocalEvidence{Username: local.GetUsername(), UID: local.GetUid(), LogindSessionID: local.GetLogindSessionId()}
	scenario.ControlGranted = session.GetControlGranted()
	scenario.OfferFingerprint, scenario.AnswerFingerprint = session.GetOfferFingerprint(), session.GetAnswerFingerprint()
	if local.GetUsername() != actionDesktopUser || local.GetLogindSessionId() != r.result.Guest.Desktop.SessionID {
		return fmt.Errorf("session bound %s/%s, not the GDM autologin session %s", local.GetUsername(), local.GetLogindSessionId(), r.result.Guest.Desktop.SessionID)
	}
	if scenario.ControlGranted != control {
		return fmt.Errorf("control_granted=%t for a %s session", scenario.ControlGranted, scenario.Mode)
	}
	if scenario.OfferFingerprint == "" || scenario.AnswerFingerprint == "" {
		return errors.New("active session lacks DTLS fingerprints")
	}
	return nil
}

// verifyAssistanceMedia requires decoded video over a relay-only connection,
// and an input channel exactly for control sessions.
func verifyAssistanceMedia(media *assistanceMediaEvidence, control, turnTCP bool) error {
	if media.VideoWidth <= 0 || media.VideoHeight <= 0 || media.DecodedFrames < 15 || media.FramesDecoded <= 0 {
		return fmt.Errorf("console decoded no live video (%dx%d, %d frames)", media.VideoWidth, media.VideoHeight, media.DecodedFrames)
	}
	if media.ConnectionState != "connected" || media.TransportPolicy != "relay" || media.LocalCandidateType != "relay" || media.RemoteCandidateType != "relay" {
		return fmt.Errorf("console media path is not a connected relay-only pair (%s, policy %s, %s/%s)", media.ConnectionState, media.TransportPolicy, media.LocalCandidateType, media.RemoteCandidateType)
	}
	if turnTCP && media.LocalRelayProtocol != "tcp" {
		return fmt.Errorf("console relay candidate used %q, want TURN over TCP", media.LocalRelayProtocol)
	}
	input := slices.Contains(media.DataChannels, "lindm-input")
	if control && (!media.RemoteApplication || !input || !media.ControlButton) {
		return errors.New("control session lacks the lindm-input data channel or control toggle")
	}
	if !control && (media.RemoteApplication || len(media.DataChannels) != 0 || media.ControlButton) {
		return errors.New("view session negotiated a data channel or offered control")
	}
	return nil
}

// typeNonce proves remote input: the console clicks into a guest terminal and
// types a fresh nonce that only the terminal's own shell writes to a file.
func (r *assistanceRun) typeNonce(ctx context.Context, scenario *assistanceScenarioEvidence) error {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	scenario.Nonce = hex.EncodeToString(nonce[:])
	terminal, err := openAssistanceTerminal(ctx, r.vm.guest, r.release, assistanceNoncePath)
	if err != nil {
		return err
	}
	r.result.Guest.Terminal = terminal
	window, err := r.screen.waitCentreWindow(ctx, 30*time.Second)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "terminal", window); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "control", nil, nil, time.Minute); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "click", map[string]any{"x": 0.5, "y": 0.5}, nil, 30*time.Second); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "type", map[string]any{"text": scenario.Nonce, "enter": true}, nil, 30*time.Second); err != nil {
		return err
	}
	received, err := waitAssistanceNonce(ctx, r.vm.guest, assistanceNoncePath, 30*time.Second)
	if err != nil {
		return err
	}
	if received != scenario.Nonce {
		return fmt.Errorf("guest terminal received %q, not the typed nonce", received)
	}
	scenario.NonceReceived = true
	return r.browserScreenshot(ctx, scenario, "input")
}

// finish waits for the required end cause on the server and in the console,
// proves device capture stopped, restores the desktop, and leaves the viewer.
func (r *assistanceRun) finish(ctx context.Context, spec assistanceScenarioSpec, scenario *assistanceScenarioEvidence, started bool) error {
	session, err := r.waitSession(ctx, scenario, 90*time.Second, "ended", ended)
	if err != nil {
		return err
	}
	scenario.EndCause, scenario.EndDetail = assistanceCauseText(session.GetEndCause()), session.GetEndDetail()
	if session.GetEndCause() != spec.cause {
		return fmt.Errorf("session ended %s (%s), want %s", scenario.EndCause, scenario.EndDetail, scenario.ExpectedCause)
	}
	if spec.cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED {
		if session.GetConsentedAt() != nil || session.GetStartedAt() != nil {
			return errors.New("declined session records consent or start")
		}
	}
	var console struct {
		Cause string `json:"cause"`
	}
	if err := r.browser.call(ctx, "ended", map[string]any{"timeoutMs": 30000}, &console, 45*time.Second); err != nil {
		return err
	}
	scenario.ConsoleEndCause = console.Cause
	if err := r.browserScreenshot(ctx, scenario, "ended"); err != nil {
		return err
	}
	if started {
		if err := waitAssistanceCaptureStopped(ctx, r.vm.guest); err != nil {
			return err
		}
		scenario.CaptureStopped = true
	}
	final, err := r.vm.guest.screendump(ctx)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "ended", final); err != nil {
		return err
	}
	if spec.cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED {
		if err := lockAssistanceSession(ctx, r.vm.guest, r.result.Guest.Desktop.SessionID, false); err != nil {
			return err
		}
		if _, err := waitActionDesktop(ctx, r.vm, false); err != nil {
			return fmt.Errorf("unlock lab desktop after lock scenario: %w", err)
		}
	}
	return r.browser.call(ctx, "leave", map[string]any{"deviceId": r.deviceID}, nil, time.Minute)
}

// collectAssistanceAudit reads the real audit log through the admin API and
// requires each scenario's request, consent, start and end causes.
func collectAssistanceAudit(ctx context.Context, owner *devlab.OwnerSession, scenarios []*assistanceScenarioEvidence) ([]assistanceAuditEvidence, error) {
	sessions := map[string]*assistanceScenarioEvidence{}
	for _, scenario := range scenarios {
		sessions[scenario.SessionID] = scenario
	}
	var rows []assistanceAuditEvidence
	token := ""
	for range 50 {
		response, err := owner.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 200, PageToken: token}))
		if err != nil {
			return nil, vmControlPlaneError("list audit events", err)
		}
		for _, event := range response.Msg.GetEvents() {
			if !strings.HasPrefix(event.GetAction(), "assistance.") || sessions[event.GetResourceId()] == nil {
				continue
			}
			rows = append(rows, assistanceAuditEvidence{ID: event.GetId(), OccurredAt: event.GetOccurredAt().AsTime(), ActorID: event.GetActorId(), Action: event.GetAction(), SessionID: event.GetResourceId(), Reason: event.GetReason()})
		}
		token = response.Msg.GetNextPageToken()
		if token == "" {
			break
		}
	}
	for _, scenario := range scenarios {
		actions := map[string]string{}
		for _, row := range rows {
			if row.SessionID == scenario.SessionID {
				actions[row.Action] = row.Reason
			}
		}
		for _, action := range assistanceAuditExpectations[scenario.Name] {
			if _, ok := actions[action]; !ok {
				return rows, fmt.Errorf("scenario %s lacks audit %s", scenario.Name, action)
			}
		}
		if end, ok := actions["assistance.end"]; !ok || !slices.Contains(strings.Fields(end), "cause="+scenario.ExpectedCause) {
			return rows, fmt.Errorf("scenario %s lacks assistance.end with cause=%s", scenario.Name, scenario.ExpectedCause)
		}
		if scenario.ExpectedCause == assistanceCauseText(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED) {
			if _, consented := actions["assistance.consent"]; consented {
				return rows, fmt.Errorf("declined scenario %s was audited as consented", scenario.Name)
			}
		}
	}
	return rows, nil
}
