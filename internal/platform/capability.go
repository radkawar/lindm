// SPDX-License-Identifier: Apache-2.0

package platform

// Capability is one gated product capability. Capability names are also the
// documentation column keys.
type Capability string

const (
	Inventory           Capability = "inventory"
	Lifecycle           Capability = "lifecycle"
	Dispatch            Capability = "dispatch"
	Packages            Capability = "packages"
	Accounts            Capability = "accounts"
	Sysctl              Capability = "sysctl"
	Definitions         Capability = "definitions"
	Password            Capability = "password"
	Firewall            Capability = "firewall"
	Encryption          Capability = "encryption"
	Wipe                Capability = "wipe"
	ReportLoss          Capability = "report-loss"
	Lock                Capability = "lock"
	RecoverySanitize    Capability = "recovery-sanitize"
	SelfUpdate          Capability = "self-update"
	Assistance          Capability = "assistance"
	AssistanceClipboard Capability = "assistance-clipboard"
	AssistanceKeyboard  Capability = "assistance-keyboard"
	AssistanceDisplays  Capability = "assistance-displays"
	AssistanceMessages  Capability = "assistance-messages"
	AssistanceFiles     Capability = "assistance-files"
	AssistanceReconnect Capability = "assistance-reconnect"
	AssistanceRecording Capability = "assistance-recording"
	// Tier 3: unattended access, elevation guidance, pointer/annotation
	// overlay and audio each gate independently of the interactive session.
	AssistanceUnattended Capability = "assistance-unattended"
	AssistanceElevation  Capability = "assistance-elevation"
	AssistanceAnnotation Capability = "assistance-annotation"
	AssistanceAudio      Capability = "assistance-audio"
	// AssistanceKDE and AssistanceX11 are the Tier 3 desktop rows: a release
	// supports them only with a native lane of the KDE Plasma Wayland or X11
	// session; the helper's qualification table names the capabilities.
	AssistanceKDE  Capability = "assistance-kde"
	AssistanceX11  Capability = "assistance-x11"
	Advisories     Capability = "advisories"
	OSUpdate       Capability = "os-update"
	ReleaseUpgrade Capability = "release-upgrade"
)

// Capabilities lists every capability in documentation order.
var Capabilities = []Capability{
	Inventory, Lifecycle, Dispatch, Packages, Accounts, Sysctl, Definitions, Password, Firewall,
	Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, SelfUpdate, Assistance,
	AssistanceClipboard, AssistanceKeyboard, AssistanceDisplays, AssistanceMessages, AssistanceFiles,
	AssistanceReconnect, AssistanceRecording, AssistanceUnattended, AssistanceElevation, AssistanceAnnotation, AssistanceAudio,
	AssistanceKDE, AssistanceX11, Advisories, OSUpdate, ReleaseUpgrade,
}

// ResourceCapabilities are the configuration-resource provider capabilities.
var ResourceCapabilities = []Capability{Packages, Accounts, Sysctl, Definitions, Password, Firewall}
