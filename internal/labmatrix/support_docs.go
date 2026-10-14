// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"fmt"
	"slices"
	"strings"

	"lindm/internal/gendoc"
	"lindm/internal/platform"
)

// supportRequirement names the outcomes needed for one public claim. Empty
// cells selects outcomes by capability, rather than treating a base desktop
// outcome as proof of independently implemented remote-desktop components.
type supportRequirement struct {
	capabilities []platform.Capability
	cells        []string
	allowScope   string
	tpm          bool
}

var supportRequirements = []supportRequirement{
	{capabilities: []platform.Capability{platform.Lifecycle}, cells: []string{"enroll-from-console"}},
	{capabilities: append(slices.Clone(platform.ResourceCapabilities), platform.Dispatch), cells: []string{"resources", "dispatch", "services"}},
	{capabilities: []platform.Capability{platform.Encryption}, cells: []string{"encrypted"}},
	{capabilities: []platform.Capability{platform.Encryption}, cells: []string{"encrypted", "tpm-unattended-boots"}, tpm: true},
	{capabilities: []platform.Capability{platform.Lock}, cells: []string{"device-actions"}},
	{capabilities: []platform.Capability{platform.Encryption, platform.Wipe}, cells: []string{"encrypted", "device-actions"}},
	{capabilities: []platform.Capability{platform.OSUpdate}, cells: []string{"os-update"}},
	{capabilities: []platform.Capability{platform.Advisories}, cells: []string{"advisories"}},
	{capabilities: []platform.Capability{platform.Assistance}, cells: []string{"assistance"}, allowScope: "GNOME"},
	{capabilities: []platform.Capability{platform.Assistance, platform.AssistanceClipboard, platform.AssistanceKeyboard, platform.AssistanceDisplays, platform.AssistanceMessages}, allowScope: "GNOME"},
}

// RenderSupport summarizes planned outcomes without exposing execution details.
// A failure, missing image or execution-only restriction never means that an
// implemented product capability is unsupported. Partial outcomes cannot prove
// a complete composite, and every architecture remains a separate row.
func RenderSupport(cells []*Cell) (string, error) {
	type rowKey struct{ release, architecture string }
	var order []rowKey
	rowsByKey := map[rowKey][]*Cell{}
	for _, c := range cells {
		key := rowKey{c.Release.Key, c.Architecture}
		if _, ok := rowsByKey[key]; !ok {
			order = append(order, key)
		}
		rowsByKey[key] = append(rowsByKey[key], c)
	}
	var notes []string
	note := func(reason string) string {
		i := slices.Index(notes, reason)
		if i < 0 {
			i, notes = len(notes), append(notes, reason)
		}
		return fmt.Sprintf("✗ [^support-%d]", i+1)
	}
	pair := func(a, b string) string {
		if a == b {
			return a
		}
		return a + " / " + b
	}
	var rows [][]string
	for _, key := range order {
		planned := rowsByKey[key]
		r := planned[0].Release
		arch := key.architecture
		if arch == "aarch64" {
			arch = "arm64"
		}
		distribution := fmt.Sprintf("[%s](docs/platforms/%s)", gendoc.Escape(r.Name), r.Page)
		if r.Version.Rule == platform.VersionAbsent || r.Version.Rule == platform.VersionSnapshot {
			distribution += " (rolling)"
		}
		statuses := make([]string, len(supportRequirements))
		for i, requirement := range supportRequirements {
			statuses[i] = supportText(r, key.architecture, planned, requirement, note)
		}
		findings := statuses[7]
		if r.BaseCoverage() != nil && findings == "✓" {
			findings += " (base packages)"
		}
		rows = append(rows, []string{
			distribution, gendoc.Escape(arch),
			statuses[0], statuses[1], pair(statuses[2], statuses[3]), pair(statuses[4], statuses[5]),
			statuses[6], findings, pair(statuses[8], statuses[9]),
		})
	}
	table, err := gendoc.Table([]string{"Distribution / release", "Architecture", "Enrolment", "Profiles", "Disk / TPM", "Lock / wipe", "OS updates", "Findings", "Assistance"}, rows)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("✓ supported · ✗ not supported (reason below) · not yet tested.\n\n")
	b.WriteString("Paired values show disk encryption / TPM2 unlock, lock / cryptographic wipe, and GNOME viewing / controls. A single value applies to both. Profiles include all configuration providers; assistance controls include keyboard, clipboard, display selection and messages.\n\n")
	b.WriteString(table)
	b.WriteString("\nEncryption and wipe require an encrypted installation; TPM2 unlock requires a compatible TPM and boot configuration. Wipe erases encryption keys, not physical drives. Assistance requires a compatible desktop and user consent. Distribution pages describe other desktops and assistance tools. Findings cover distribution packages; derived distributions marked “base packages” cover their upstream packages.\n")
	for i, reason := range notes {
		fmt.Fprintf(&b, "\n[^support-%d]: %s\n", i+1, reason)
	}
	return b.String(), nil
}

func supportText(r *platform.Release, arch string, cells []*Cell, requirement supportRequirement, note func(string) string) string {
	var reasons []string
	for _, capability := range requirement.capabilities {
		if reason := r.GateReasonOn(capability, arch); reason != "" {
			reasons = appendUnique(reasons, publicSupportReason(capability, reason))
		}
	}
	if requirement.tpm && r.Lab.TPM.Unsupported != "" {
		reasons = appendUnique(reasons, "The installed boot configuration cannot unlock systemd TPM2 tokens.")
	}
	if len(reasons) > 0 {
		return note(strings.Join(reasons, " "))
	}
	complete := func(c *Cell) bool {
		return c.State == Pass && c.Entry != nil && (c.Entry.GetScope() == "" || (requirement.allowScope != "" && c.Entry.GetScope() == requirement.allowScope))
	}
	for _, name := range requirement.cells {
		if !slices.ContainsFunc(cells, func(c *Cell) bool { return c.Spec.GetName() == name && complete(c) }) {
			return "not yet tested"
		}
	}
	for _, capability := range requirement.capabilities {
		if !slices.ContainsFunc(cells, func(c *Cell) bool {
			if len(requirement.cells) > 0 && !slices.Contains(requirement.cells, c.Spec.GetName()) {
				return false
			}
			return complete(c) && slices.Contains(c.Kinds, capability)
		}) {
			return "not yet tested"
		}
	}
	return "✓"
}

// Registry restrictions choose the status; these capability-level explanations
// deliberately do not copy internal recipe names, error codes or test jargon.
func publicSupportReason(capability platform.Capability, reason string) string {
	switch {
	case strings.Contains(reason, "no ScreenCast or RemoteDesktop"):
		return "The desktop portal provides neither screen capture nor remote control."
	case strings.Contains(reason, "notification_actions_hidden"):
		return "The desktop cannot display the required Allow/Decline consent buttons."
	case strings.Contains(reason, "session_lock_state_unreported"):
		return "The desktop does not report its locked state, so screen sharing cannot stop safely at lock."
	case strings.Contains(reason, "no vendor advisory feed"):
		return "No vendor advisory feed covers this distribution's packages."
	case strings.Contains(reason, "Origins-Pattern"):
		return "The update runner does not implement this distribution's security-origin selection."
	case strings.Contains(reason, "ALPM guard"):
		return "The distribution requires its own updater and refuses direct package-manager system upgrades."
	case strings.Contains(reason, "definition provider floor"):
		return "The shipped systemd is older than the configuration definition provider requires."
	case strings.Contains(reason, "store a transaction without privileges"):
		return "The shipped package manager cannot prepare the required unprivileged transaction."
	case strings.Contains(reason, "Omarchy") && capability == platform.Firewall:
		return "The firewall provider requires firewalld, but the installed firewall uses ufw."
	case capability == platform.Password:
		return "Password-policy integration is not supported with this release's PAM stack."
	case capability == platform.OSUpdate:
		return "No automatic OS-update integration is supported for this release."
	case capability == platform.AssistanceClipboard || capability == platform.AssistanceKeyboard || capability == platform.AssistanceDisplays || capability == platform.AssistanceMessages:
		return "The desktop does not support all requested remote-assistance controls."
	case capability == platform.Encryption || capability == platform.Lock || capability == platform.Wipe || capability == platform.Assistance:
		return "The required encrypted-installation or desktop integration is not supported for this release."
	default:
		return fmt.Sprintf("The %s provider is not implemented for this release or architecture.", gendoc.Escape(string(capability)))
	}
}
