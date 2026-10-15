// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"strings"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	modeOff     = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	modeLimited = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	modeOn      = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
)

func TestDesktopProfileSelectionUsesExecutorSessionType(t *testing.T) {
	for _, tc := range []struct {
		sessionType, desktop string
		want                 *desktopProfile
	}{
		{"wayland", "ubuntu:GNOME", gnomeWayland},
		{"wayland", "COSMIC", cosmicWayland},
		{"wayland", "COSMIC:GNOME", cosmicWayland},
		{"wayland", "KDE", kdePlasmaWayland},
		// The helper's environment never turns an X11 session into Wayland.
		{"x11", "X-Cinnamon", unlistedX11},
		{"x11", "KDE", x11Profile("KDE")},
		{"x11", "ubuntu:GNOME", x11Profile("GNOME")},
		{"wayland", "Hyprland", unlisted},
		{"", "GNOME", unlisted},
	} {
		if got := desktopProfileFor(tc.sessionType, tc.desktop); got != tc.want {
			t.Fatalf("%s/%s = %s, want %s", tc.sessionType, tc.desktop, got.name, tc.want.name)
		}
	}
}

// x11Profile is the qualified X11 row for desktop, or the refusal row.
func x11Profile(desktop string) *desktopProfile {
	if profile, ok := x11Profiles[desktop]; ok {
		return profile
	}
	return unlistedX11
}

func fullPolicy() *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{
		Clipboard: modeOn, Keyboard: modeOn, Display: modeOn, Messages: modeOn, Files: modeOn, Reconnect: modeOn, Recording: modeOn,
		FileLimits:      &agentv1.AssistanceFilePolicy{MaxFileBytes: 1, MaxSessionBytes: 1, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}},
		ReconnectLimits: &agentv1.AssistanceReconnectPolicy{WindowSeconds: 600},
		RecordingLimits: &agentv1.AssistanceRecordingPolicy{RetentionDays: 7},
	}
}

func TestDesktopGateAdmission(t *testing.T) {
	everything := &desktopProfile{name: "test_desktop", gate: x11Gate, gateName: "test", view: true, control: true, qualified: allCapabilities}
	viewOnly := &desktopProfile{name: "test_view", gate: x11Gate, gateName: "test", view: true, qualified: capDisplay | capMessages}
	for _, tc := range []struct {
		name    string
		profile *desktopProfile
		gate    agentv1.AssistancePolicyMode
		mode    agentv1.AssistanceMode
		refusal string
		reasons map[capability]string
	}{
		{name: "off", profile: everything, gate: modeOff, mode: modeView, refusal: "test_policy_off"},
		{name: "unspecified_is_off", profile: everything, gate: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED, mode: modeView, refusal: "test_policy_off"},
		{name: "no_qualified_view", profile: unlistedX11, gate: modeOn, mode: modeView, refusal: "x11_desktop_unqualified"},
		{name: "limited_never_downgrades_control", profile: everything, gate: modeLimited, mode: modeControl, refusal: "test_control_not_permitted"},
		{name: "on_unqualified_control", profile: viewOnly, gate: modeOn, mode: modeControl, refusal: "test_control_unqualified"},
		{name: "limited_view_withholds_input", profile: everything, gate: modeLimited, mode: modeView, reasons: map[capability]string{
			capClipboard: reasonDesktopViewOnly, capKeyboard: reasonDesktopViewOnly, capFiles: reasonDesktopViewOnly,
		}},
		{name: "on_withholds_unqualified", profile: viewOnly, gate: modeOn, mode: modeView, reasons: map[capability]string{
			capClipboard: reasonDesktopUnqualified, capKeyboard: reasonDesktopUnqualified, capFiles: reasonDesktopUnqualified,
			capReconnect: reasonDesktopUnqualified, capRecording: reasonDesktopUnqualified,
		}},
		{name: "on_qualified_everything", profile: everything, gate: modeOn, mode: modeControl, reasons: map[capability]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consented := fullPolicy()
			consented.X11 = tc.gate
			admission := admitDesktop(tc.profile, tc.mode, consented)
			if admission.refusal != tc.refusal {
				t.Fatalf("refusal = %q, want %q", admission.refusal, tc.refusal)
			}
			if consented.GetClipboard() != modeOn || consented.GetX11() != tc.gate {
				t.Fatal("admission mutated the consented policy")
			}
			if tc.refusal != "" {
				return
			}
			policy := admission.policy
			if policy.GetX11() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED || policy.GetKdePlasma() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED {
				t.Fatal("narrowed policy carries an admission gate into the grant")
			}
			if len(admission.reasons) != len(tc.reasons) {
				t.Fatalf("reasons = %v, want %v", admission.reasons, tc.reasons)
			}
			for capability, reason := range tc.reasons {
				if admission.reasons[capability] != reason {
					t.Fatalf("reason %d = %q, want %q", capability, admission.reasons[capability], reason)
				}
			}
			modes := map[capability]agentv1.AssistancePolicyMode{capClipboard: policy.GetClipboard(), capKeyboard: policy.GetKeyboard(), capDisplay: policy.GetDisplay(),
				capMessages: policy.GetMessages(), capFiles: policy.GetFiles(), capReconnect: policy.GetReconnect(), capRecording: policy.GetRecording()}
			for capability, mode := range modes {
				_, withheld := tc.reasons[capability]
				if withheld != (mode == modeOff) {
					t.Fatalf("capability %d mode %v, withheld %t", capability, mode, withheld)
				}
			}
			if (policy.GetFiles() == modeOff) != (policy.GetFileLimits() == nil) || (policy.GetReconnect() == modeOff) != (policy.GetReconnectLimits() == nil) || (policy.GetRecording() == modeOff) != (policy.GetRecordingLimits() == nil) {
				t.Fatal("withheld capability kept its limits")
			}
		})
	}
}

// Tier 3 capabilities have no KDE or X11 lane: a gated desktop withholds them
// with the exact reason, and unattended limits go with the mode.
func TestDesktopGateWithholdsTierThree(t *testing.T) {
	for _, profile := range []*desktopProfile{kdePlasmaWayland, x11Profiles["GNOME"]} {
		consented := fullPolicy()
		consented.KdePlasma, consented.X11 = modeOn, modeOn
		consented.Unattended, consented.Elevation, consented.Annotation, consented.Audio = modeOn, modeOn, modeOn, modeOn
		consented.UnattendedLimits = &agentv1.AssistanceUnattendedPolicy{}
		admission := admitDesktop(profile, modeControl, consented)
		if admission.refusal != "" {
			t.Fatalf("%s: refusal %q", profile.name, admission.refusal)
		}
		policy := admission.policy
		if policy.GetUnattended() != modeOff || policy.GetElevation() != modeOff || policy.GetAnnotation() != modeOff || policy.GetAudio() != modeOff || policy.GetUnattendedLimits() != nil {
			t.Fatalf("%s: Tier 3 admitted: %v", profile.name, policy)
		}
		granted := &agentv1.AssistanceCapabilities{}
		admission.annotate(granted, "")
		for _, reason := range []string{granted.GetUnattendedReason(), granted.GetElevationReason(), granted.GetAnnotationReason(), granted.GetAudioReason()} {
			if reason != reasonDesktopUnqualified {
				t.Fatalf("%s: reason %q", profile.name, reason)
			}
		}
	}
}

// An absent desktop policy gate is not qualification for optional tools.
// GNOME retains its native tiers; COSMIC admits only its baseline lane.
func TestUngatedProfilesStillEnforceQualification(t *testing.T) {
	admission := admitDesktop(gnomeWayland, modeControl, fullPolicy())
	if admission.refusal != "" || len(admission.reasons) != 0 || admission.policy.GetClipboard() != modeOn || admission.policy.GetFiles() != modeOn {
		t.Fatalf("GNOME: %+v", admission)
	}
	admission = admitDesktop(cosmicWayland, modeControl, fullPolicy())
	if admission.refusal != "" || admission.policy.GetKeyboard() != modeOn ||
		admission.policy.GetClipboard() != modeOff || admission.policy.GetFiles() != modeOff ||
		admission.reasons[capClipboard] != reasonDesktopUnqualified || admission.reasons[capFiles] != reasonDesktopUnqualified {
		t.Fatalf("COSMIC: %+v", admission)
	}
	for _, reason := range admission.reasons {
		if reason != reasonDesktopUnqualified {
			t.Fatalf("COSMIC narrowing reason: %q", reason)
		}
	}
	if admitDesktop(unlisted, modeView, fullPolicy()).refusal != "desktop_unqualified" {
		t.Fatal("an unlisted desktop was admitted")
	}
}

func desktopInvitation(mode agentv1.AssistanceMode, gates func(*agentv1.AssistancePolicy)) *agentv1.AssistanceInvitation {
	inv := invitation(mode, time.Minute, 10*time.Minute)
	inv.RequestedCapabilities = &agentv1.AssistancePolicy{Keyboard: modeOn, Clipboard: modeOn, Messages: modeOn, Display: modeOn}
	effective := &agentv1.AssistancePolicy{Keyboard: modeOn, Clipboard: modeOn, Messages: modeOn, Display: modeOn}
	gates(effective)
	inv.EffectiveCapabilities = effective
	return inv
}

// A gate the device policy leaves OFF refuses before any prompt or dialog,
// after the native portal and lock checks named their own gaps.
func TestDesktopGateOffRefusesBeforeConsent(t *testing.T) {
	for _, tc := range []struct {
		name, sessionType, desktop, detail string
		gates                              func(*agentv1.AssistancePolicy)
	}{
		{"kde_off", "wayland", "KDE", "kde_plasma_policy_off", func(p *agentv1.AssistancePolicy) { p.X11 = modeOn }},
		{"x11_off", "x11", "ubuntu:GNOME", "x11_policy_off", func(p *agentv1.AssistancePolicy) { p.KdePlasma = modeOn }},
		{"kde_limited_control", "wayland", "KDE", "kde_plasma_control_not_permitted", func(p *agentv1.AssistancePolicy) { p.KdePlasma = modeLimited }},
		// Plasma on X11 has no qualified row even with the X11 gate on.
		{"x11_unlisted_desktop", "x11", "KDE", "x11_desktop_unqualified", func(p *agentv1.AssistancePolicy) { p.X11 = modeOn; p.KdePlasma = modeOn }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDesktopHarness(t, tc.desktop)
			h.local.SessionType = tc.sessionType
			mode := modeView
			if strings.HasSuffix(tc.detail, "control_not_permitted") {
				mode = modeControl
			}
			h.sync(directiveFor(desktopInvitation(mode, tc.gates)))
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
			if report.GetEndDetail() != tc.detail {
				t.Fatalf("detail = %q, want %q", report.GetEndDetail(), tc.detail)
			}
			select {
			case notice := <-h.notifier.posted:
				t.Fatalf("posted %q for a refused desktop", notice.notification.Summary)
			default:
			}
			if h.portal.openCount() != 0 {
				t.Fatal("portal dialog opened for a refused desktop")
			}
		})
	}
}

// An admitted KDE Plasma session discloses and requests only the
// capabilities its qualification row lists, and reports its profile.
func TestKDEPlasmaAdmissionNarrowsToQualifiedRow(t *testing.T) {
	h := newDesktopHarness(t, "KDE")
	h.local.Desktop = "KDE"
	directive := directiveFor(desktopInvitation(modeControl, func(p *agentv1.AssistancePolicy) { p.KdePlasma = modeOn }))
	if !kdePlasmaWayland.control {
		h.sync(directive)
		if report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE); report.GetEndDetail() != "kde_plasma_control_unqualified" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
		return
	}
	h.sync(directive)
	prompt := h.notifier.next(t, "Remote assistance request")
	// Plasma's RemoteDesktop dialog has no view-only choice and no monitor
	// picker; the prompt must say so instead of promising one.
	if body := prompt.notification.Body; strings.Contains(body, "allow viewing only") || !strings.Contains(body, "every monitor, together with control") {
		t.Fatalf("KDE control prompt misstates the system dialog: %q", body)
	}
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	h.portal.mu.Lock()
	checked := h.portal.checked[len(h.portal.checked)-1].Policy
	h.portal.mu.Unlock()
	for _, field := range []struct {
		capability capability
		mode       agentv1.AssistancePolicyMode
		disclosure string
	}{
		{capClipboard, checked.GetClipboard(), "\nClipboard:"},
		{capKeyboard, checked.GetKeyboard(), "\nKeyboard:"},
		{capDisplay, checked.GetDisplay(), "\nDisplays:"},
		{capMessages, checked.GetMessages(), "\nMessages:"},
	} {
		qualified := kdePlasmaWayland.qualified&field.capability != 0
		if policyEnabled(field.mode) != qualified || strings.Contains(prompt.notification.Body, field.disclosure) != qualified {
			t.Fatalf("capability %d: requested %v, disclosed %t, qualified %t", field.capability, field.mode, strings.Contains(prompt.notification.Body, field.disclosure), qualified)
		}
	}
	prompt.result <- actionAllow
	report := h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	granted := report.GetGrantedCapabilities()
	if granted.GetDesktopProfile() != "kde_plasma_wayland" || granted.GetPortalVersions() != "screencast_5" {
		t.Fatalf("granted profile %q versions %q", granted.GetDesktopProfile(), granted.GetPortalVersions())
	}
	if granted.GetPolicy().GetKdePlasma() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED {
		t.Fatal("grant carries the admission gate")
	}
	if kdePlasmaWayland.qualified&capClipboard == 0 && granted.GetClipboardReason() != reasonDesktopUnqualified {
		t.Fatalf("clipboard reason = %q", granted.GetClipboardReason())
	}
	if kdePlasmaWayland.qualified&capKeyboard == 0 && granted.GetKeyboardReason() != reasonDesktopUnqualified {
		t.Fatalf("keyboard reason = %q", granted.GetKeyboardReason())
	}
}

func TestCOSMICControlConsentDisclosesSelectedScreenAndInputTogether(t *testing.T) {
	h := newDesktopHarness(t, "COSMIC")
	h.notifier.server, h.notifier.version = "cosmic-notifications", "1.10.0-lindm-actions.1"
	h.sync(directiveFor(invitation(modeControl, time.Minute, 10*time.Minute)))
	prompt := h.notifier.next(t, "Remote assistance request")
	body := prompt.notification.Body
	if strings.Contains(body, "allow viewing only") || strings.Contains(body, "every monitor") ||
		!strings.Contains(body, "selected screen together with control") || !strings.Contains(body, "no view-only choice") {
		t.Fatalf("COSMIC control prompt misstates native consent: %q", body)
	}
}
