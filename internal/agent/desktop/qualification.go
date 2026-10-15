// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// capability is one optional AssistancePolicy capability.
type capability uint16

const (
	capClipboard capability = 1 << iota
	capKeyboard
	capDisplay
	capMessages
	capFiles
	capReconnect
	capRecording
	capUnattended
	capElevation
	capAnnotation
	capAudio

	allCapabilities = capClipboard | capKeyboard | capDisplay | capMessages | capFiles | capReconnect | capRecording | capUnattended | capElevation | capAnnotation | capAudio
	// inputCapabilities inject into, or take content from, the session; a
	// LIMITED desktop gate never admits them.
	inputCapabilities = capClipboard | capKeyboard | capFiles | capUnattended | capElevation | capAnnotation | capAudio
)

// Narrowing reasons reported in AssistanceCapabilities.
const (
	reasonDesktopUnqualified = "desktop_capability_unqualified"
	reasonDesktopViewOnly    = "desktop_policy_view_only"
)

// desktopProfile is one row of the desktop qualification table: the
// capabilities natively qualified for one desktop and session type. A
// capability source support without a recorded native lane is absent.
type desktopProfile struct {
	// name is the audited profile, reported as desktop_profile.
	name string
	// gate selects a Tier 3 policy gate. Nil defaults to ON, but still
	// narrows capabilities to the profile and refuses unlisted desktops.
	gate func(*agentv1.AssistancePolicy) agentv1.AssistancePolicyMode
	// gateName prefixes the exact refusal details of a gated profile.
	gateName string
	// view and control are the qualified ScreenCast and RemoteDesktop paths.
	view, control bool
	// qualified are the individually qualified optional capabilities.
	qualified capability
	// sharedControlDialog: the desktop's RemoteDesktop dialog grants screen
	// sharing of every output and input together, with no view-only choice
	// and no monitor picker (xdg-desktop-portal-kde), so the product prompt
	// must not promise a later view-only choice.
	sharedControlDialog bool
	// selectedControlDialog grants the picked screen together with input,
	// with no view-only choice (COSMIC's device icons are not toggles).
	selectedControlDialog bool
	// fixedTuple is selected only after live runtime verification, including
	// the patched locker. It never changes the static stock lock table.
	fixedTuple bool
}

func kdePlasmaGate(policy *agentv1.AssistancePolicy) agentv1.AssistancePolicyMode {
	return policy.GetKdePlasma()
}

func x11Gate(policy *agentv1.AssistancePolicy) agentv1.AssistancePolicyMode {
	return policy.GetX11()
}

// The qualification table. Each gated row lists only what its maintained
// `lab vm assistance` lane passed natively (docs/verification.md); GNOME
// parity is never assumed for another desktop or for X11.
var (
	gnomeWayland  = &desktopProfile{name: "gnome_wayland", view: true, control: true, qualified: allCapabilities}
	cosmicWayland = &desktopProfile{name: "cosmic_wayland", view: true, control: true, qualified: capKeyboard, selectedControlDialog: true}
	// KDE Plasma 6.6 on Wayland (Fedora 44, xdg-desktop-portal-kde 6.6):
	// kscreenlocker sets logind LockedHint and locks on Session.Lock.
	kdePlasmaWayland = &desktopProfile{name: "kde_plasma_wayland", gate: kdePlasmaGate, gateName: "kde_plasma", view: true, control: true, qualified: capKeyboard, sharedControlDialog: true}
	// These profiles are never selected by desktopProfileFor. Their reviewed
	// deployed tuples must pass the session's FixedDesktopQualifier first.
	hyprlandWayland  = &desktopProfile{name: "hyprland_wayland", view: true, control: true, qualified: capKeyboard, selectedControlDialog: true, fixedTuple: true}
	cinnamonX11Fixed = &desktopProfile{name: "cinnamon_x11_fixed", gate: x11Gate, gateName: "x11", view: true, control: true, qualified: capKeyboard, selectedControlDialog: true, fixedTuple: true}
	// x11Profiles are the qualified X11 desktops, keyed on an
	// XDG_CURRENT_DESKTOP component. Every other X11 session is refused.
	x11Profiles = map[string]*desktopProfile{
		// GNOME 46 on Xorg (Ubuntu 24.04 "ubuntu-xorg"): Mutter serves the
		// same ScreenCast/RemoteDesktop portal and GNOME Shell banners; its
		// screen shield sets LockedHint. VIEW, CONTROL and the keyboard its
		// control lane types through are qualified; nothing else.
		"GNOME": {name: "gnome_x11", gate: x11Gate, gateName: "x11", view: true, control: true, qualified: capKeyboard},
	}
	// unlistedX11 refuses X11 desktops without a qualified row.
	unlistedX11 = &desktopProfile{name: "x11_unqualified", gate: x11Gate, gateName: "x11"}
	// unlisted refuses Wayland desktops outside the table; the portal and
	// lock checks already refuse every such desktop observed in the lab.
	unlisted = &desktopProfile{name: "desktop_unqualified"}
)

// desktopProfileFor selects the profile of a logind session type (from the
// executor, never the helper) and the helper's XDG_CURRENT_DESKTOP.
func desktopProfileFor(sessionType, currentDesktop string) *desktopProfile {
	names := strings.Split(currentDesktop, ":")
	// A mixed desktop name must not let a fixed-tuple desktop inherit a
	// GNOME/KDE profile before its runtime has been verified.
	for _, name := range names {
		if strings.EqualFold(name, "Hyprland") || strings.EqualFold(name, "X-Cinnamon") || strings.EqualFold(name, "Cinnamon") {
			if sessionType == "x11" {
				return unlistedX11
			}
			return unlisted
		}
	}
	if sessionType == "x11" {
		for _, name := range names {
			if profile, ok := x11Profiles[name]; ok {
				return profile
			}
		}
		return unlistedX11
	}
	if sessionType != "wayland" {
		return unlisted
	}
	switch {
	case slices.Contains(names, "COSMIC"):
		return cosmicWayland
	case slices.Contains(names, "GNOME"):
		return gnomeWayland
	case slices.Contains(names, "KDE"):
		return kdePlasmaWayland
	}
	return unlisted
}

func fixedDesktopProfileFor(sessionType, currentDesktop string) *desktopProfile {
	switch {
	case sessionType == "wayland" && currentDesktop == "Hyprland":
		return hyprlandWayland
	case sessionType == "x11" && currentDesktop == "X-Cinnamon":
		return cinnamonX11Fixed
	default:
		return nil
	}
}

func (d *sessionDeps) qualifiedDesktopProfile(ctx context.Context, sessionType string) (*desktopProfile, error) {
	stock := desktopProfileFor(sessionType, d.currentDesktop)
	fixed := fixedDesktopProfileFor(sessionType, d.currentDesktop)
	if fixed == nil || d.fixedDesktopQualifier == nil {
		return stock, nil
	}
	if err := d.fixedDesktopQualifier.Verify(ctx, sessionType, d.currentDesktop); err != nil {
		return stock, err
	}
	return fixed, nil
}

// desktopAdmission is the profile's decision for one invitation.
type desktopAdmission struct {
	profile *desktopProfile
	// policy is the consented policy narrowed to the profile; it never
	// carries the admission gates themselves.
	policy *agentv1.AssistancePolicy
	// reasons names each capability the profile withheld.
	reasons map[capability]string
	// refusal, when set, ends the session UNAVAILABLE before consent.
	refusal string
	// runtimeErr preserves a rejected fixed tuple's evidence failure without
	// hiding earlier native portal or notification gaps.
	runtimeErr error
}

// admitDesktop narrows the consented policy to the profile. OFF refuses the
// desktop; LIMITED admits VIEW with qualified non-input capabilities and
// refuses CONTROL (never downgraded); ON admits qualified control and input
// capabilities too. Unqualified capabilities are withheld with an exact
// reason rather than refused, like a portal that does not grant them.
func admitDesktop(profile *desktopProfile, mode agentv1.AssistanceMode, consented *agentv1.AssistancePolicy) desktopAdmission {
	policy := proto.CloneOf(consented)
	policy.KdePlasma, policy.X11 = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_UNSPECIFIED
	admission := desktopAdmission{profile: profile, policy: policy, reasons: map[capability]string{}}
	gate := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	if profile.gate != nil {
		gate = profile.gate(consented)
	}
	control := mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	switch {
	case profile == unlisted:
		admission.refusal = unlisted.name
	case !policyEnabled(gate):
		admission.refusal = profile.gateName + "_policy_off"
	case !profile.view:
		admission.refusal = profile.gateName + "_desktop_unqualified"
	case control && gate != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		admission.refusal = profile.gateName + "_control_not_permitted"
	case control && !profile.control:
		admission.refusal = profile.gateName + "_control_unqualified"
	}
	if admission.refusal != "" {
		return admission
	}
	off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	for _, field := range [...]struct {
		capability capability
		mode       *agentv1.AssistancePolicyMode
	}{
		{capClipboard, &policy.Clipboard},
		{capKeyboard, &policy.Keyboard},
		{capDisplay, &policy.Display},
		{capMessages, &policy.Messages},
		{capFiles, &policy.Files},
		{capReconnect, &policy.Reconnect},
		{capRecording, &policy.Recording},
		{capUnattended, &policy.Unattended},
		{capElevation, &policy.Elevation},
		{capAnnotation, &policy.Annotation},
		{capAudio, &policy.Audio},
	} {
		if !policyEnabled(*field.mode) {
			continue
		}
		switch {
		case profile.qualified&field.capability == 0:
			admission.reasons[field.capability] = reasonDesktopUnqualified
		case gate != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && inputCapabilities&field.capability != 0:
			admission.reasons[field.capability] = reasonDesktopViewOnly
		default:
			continue
		}
		*field.mode = off
	}
	if !policyEnabled(policy.Files) {
		policy.FileLimits = nil
	}
	if !policyEnabled(policy.Reconnect) {
		policy.ReconnectLimits = nil
	}
	if !policyEnabled(policy.Recording) {
		policy.RecordingLimits = nil
	}
	if !policyEnabled(policy.Unattended) {
		policy.UnattendedLimits = nil
	}
	return admission
}

// annotate records the profile, the grant's portal interface versions and
// every withheld capability's reason on the reported grant.
func (a desktopAdmission) annotate(granted *agentv1.AssistanceCapabilities, portalVersions string) {
	granted.DesktopProfile, granted.PortalVersions = a.profile.name, portalVersions
	for capability, reason := range a.reasons {
		switch capability {
		case capClipboard:
			granted.ClipboardReason = reason
		case capKeyboard:
			granted.KeyboardReason = reason
		case capDisplay:
			granted.DisplayReason = reason
		case capMessages:
			granted.MessagesReason = reason
		case capFiles:
			granted.FilesReason = reason
		case capReconnect:
			granted.ReconnectReason = reason
		case capRecording:
			granted.RecordingReason = reason
		case capUnattended:
			granted.UnattendedReason = reason
		case capElevation:
			granted.ElevationReason = reason
		case capAnnotation:
			granted.AnnotationReason = reason
		case capAudio:
			granted.AudioReason = reason
		}
	}
}
