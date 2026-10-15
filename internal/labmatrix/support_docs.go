// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"fmt"
	"slices"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/gendoc"
	"lindm/internal/platform"
)

type supportFeature struct {
	capabilities []platform.Capability
	cell         string
}

var supportFeatures = []supportFeature{
	{[]platform.Capability{platform.Lifecycle}, "enroll-from-console"},
	{platform.ResourceCapabilities, "resources"},
	{[]platform.Capability{platform.Encryption}, "encrypted"},
	{[]platform.Capability{platform.Lock, platform.Wipe}, "device-actions"},
	{[]platform.Capability{platform.OSUpdate}, "os-update"},
	{[]platform.Capability{platform.Advisories}, "advisories"},
	{[]platform.Capability{platform.Assistance}, "assistance"},
}

// supportHistory retains successful subsets of the same feature. A later scoped
// pass supplements an earlier run rather than erasing it. Image identity and
// revision floors are exactly those used by the detailed verification table;
// a latest failure does not get replaced with an older successful result.
func (in *Inputs) supportHistory(cells []*Cell) []*Cell {
	type key struct{ release, architecture, cell string }
	entries := make(map[key][]*labv1.MatrixLedgerEntry)
	for _, e := range in.Ledger.GetEntries() {
		if e.GetVerdict() == labv1.MatrixVerdict_MATRIX_VERDICT_PASS && !in.superseded[e] {
			k := key{e.GetPlatform(), e.GetArchitecture(), e.GetCell()}
			entries[k] = append(entries[k], e)
		}
	}
	out := slices.Clone(cells)
	for _, c := range cells {
		if c.Entry == nil || c.Entry.GetVerdict() != labv1.MatrixVerdict_MATRIX_VERDICT_PASS {
			continue
		}
		for _, e := range entries[key{c.Release.Key, c.Architecture, c.Spec.GetName()}] {
			if e == c.Entry || !in.entryMatches(c, e) {
				continue
			}
			recorded := *c
			recorded.Entry = e
			out = append(out, &recorded)
		}
	}
	return out
}

// RenderSupport describes feature support, not the completeness of a test run.
// Scoped successes count for the feature they exercised; unsupported subfeatures
// become short footnotes on a supported feature, not a whole-column refusal.
func RenderSupport(cells []*Cell) (string, error) {
	var releases []*platform.Release
	byRelease := make(map[string][]*Cell)
	var armReleases []*platform.Release
	for _, c := range cells {
		if platform.SameArchitecture(c.Architecture, "aarch64") {
			if supportPassed(c) && !slices.Contains(armReleases, c.Release) {
				armReleases = append(armReleases, c.Release)
			}
			continue
		}
		if !platform.SameArchitecture(c.Architecture, "x86_64") {
			continue
		}
		if _, ok := byRelease[c.Release.Key]; !ok {
			releases = append(releases, c.Release)
		}
		byRelease[c.Release.Key] = append(byRelease[c.Release.Key], c)
	}
	var notes []string
	note := func(mark string, reasons []string) string {
		if len(reasons) == 0 {
			return mark
		}
		var b strings.Builder
		b.WriteString(mark)
		for _, reason := range reasons {
			i := slices.Index(notes, reason)
			if i < 0 {
				i, notes = len(notes), append(notes, reason)
			}
			fmt.Fprintf(&b, " [^support-%d]", i+1)
		}
		return b.String()
	}
	var rows [][]string
	for _, r := range releases {
		row := []string{supportReleaseLink(r)}
		for i, feature := range supportFeatures {
			mark, reason := supportFeatureText(r, byRelease[r.Key], i, feature)
			row = append(row, note(mark, reason))
		}
		rows = append(rows, row)
	}
	table, err := gendoc.Table([]string{"Distribution / release", "Enrolment", "Profiles", "Encryption / TPM", "Lock & wipe", "OS updates", "Findings", "Assistance"}, rows)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("x86_64: ✓ supported · ✗ not supported · not yet tested. Footnotes name feature limits.\n\n")
	b.WriteString(table)
	if len(armReleases) > 0 {
		var links []string
		for _, r := range releases {
			if slices.Contains(armReleases, r) {
				links = append(links, supportReleaseLink(r))
			}
		}
		fmt.Fprintf(&b, "\narm64 builds are available for %s; their distribution pages list the tested features.\n", strings.Join(links, ", "))
	}
	b.WriteString("\nEncryption and wipe require an encrypted installation. TPM2 unlock needs a compatible TPM and boot setup. Wipe erases encryption keys, not physical drives. Assistance requires a compatible desktop and user consent. Findings cover packages in the vendor's advisory feed. Extra assistance tools depend on the desktop.\n")
	for i, reason := range notes {
		fmt.Fprintf(&b, "\n[^support-%d]: %s\n", i+1, reason)
	}
	return b.String(), nil
}

func supportReleaseLink(r *platform.Release) string {
	link := fmt.Sprintf("[%s](docs/platforms/%s)", gendoc.Escape(r.Name), r.Page)
	if r.Version.Rule == platform.VersionAbsent || r.Version.Rule == platform.VersionSnapshot {
		link += " (rolling)"
	}
	return link
}

func supportPassed(c *Cell) bool {
	return c.Entry != nil && c.Entry.GetVerdict() == labv1.MatrixVerdict_MATRIX_VERDICT_PASS
}

func supportFeatureText(r *platform.Release, cells []*Cell, index int, feature supportFeature) (string, []string) {
	if index == 0 && strings.Contains(r.LaneGateOn(platform.LaneEnrollFromConsole, "x86_64"), "console's pacman install command needs synced databases") {
		return "✗", []string{"Console enrollment is unavailable on fresh installs without synced package databases."}
	}
	var restrictions []string
	available := 0
	for _, capability := range feature.capabilities {
		if reason := r.GateReasonOn(capability, "x86_64"); reason != "" {
			restrictions = appendUnique(restrictions, publicSupportReason(capability, reason))
		} else {
			available++
		}
	}
	if available == 0 {
		return "✗", restrictions
	}
	var passed []*Cell
	for _, c := range cells {
		if c.Spec.GetName() != feature.cell || !supportPassed(c) {
			continue
		}
		scope := strings.ToLower(c.Entry.GetScope())
		if index == 3 && (c.Spec.GetCinnamonLockConfirmation() || c.Entry.GetScope() == CinnamonLockConfirmationScope) {
			continue
		}
		if index == 3 && (strings.Contains(scope, "report-loss") || strings.Contains(scope, "report loss")) &&
			!strings.HasPrefix(scope, "lock") && !strings.Contains(scope, " lock") && !strings.Contains(scope, "erase") && !strings.Contains(scope, "wipe") {
			continue
		}
		passed = append(passed, c)
	}
	if len(passed) == 0 {
		return "not yet tested", restrictions
	}
	scopeContains := func(text string) bool {
		return slices.ContainsFunc(passed, func(c *Cell) bool { return strings.Contains(strings.ToLower(c.Entry.GetScope()), text) })
	}
	switch index {
	case 2:
		if r.Lab.TPM.Unsupported != "" {
			restrictions = appendUnique(restrictions, "TPM2 unattended unlock is unavailable with this boot setup.")
		} else if !slices.ContainsFunc(cells, func(c *Cell) bool {
			return supportPassed(c) && (c.Spec.GetName() == "tpm-unattended-boots" ||
				(c.Spec.GetName() == "encrypted" && strings.Contains(strings.ToLower(c.Entry.GetScope()), "unattended")))
		}) {
			restrictions = appendUnique(restrictions, "TPM2 unattended unlock has not yet been tested.")
		}
	case 3:
		_, cinnamon := r.Lab.Session.Desktops["cinnamon"]
		nativeConfirmation := slices.ContainsFunc(cells, func(c *Cell) bool {
			return cinnamon && c.Spec.GetCinnamonLockConfirmation() && c.State == Pass && supportPassed(c) &&
				c.Entry.GetVerified() && c.Entry.GetScope() == CinnamonLockConfirmationScope
		})
		if nativeConfirmation {
			restrictions = appendUnique(restrictions, "Native screen-lock confirmation passed for the Cinnamon package version recorded in its dedicated cell (minimum "+platform.CinnamonLockMinimumVersion+"); older packages remain unconfirmed. This does not qualify wipe, quarantine or assistance.")
		} else if scopeContains("lock unverifiable") || scopeContains("session_lock_state_unreported") {
			restrictions = appendUnique(restrictions, "Account locks and wipe work; the desktop does not report its screen-lock state.")
		} else if scopeContains("session lock unsupported") {
			restrictions = appendUnique(restrictions, "Account locks and wipe work; screen locking is unavailable.")
		}
	case 5:
		if r.BaseCoverage() != nil {
			restrictions = appendUnique(restrictions, "Findings cover upstream base packages only.")
		}
	}
	return "✓", restrictions
}

func publicSupportReason(capability platform.Capability, reason string) string {
	switch {
	case strings.Contains(reason, "no ScreenCast or RemoteDesktop"):
		return "The desktop has no screen-sharing or remote-control portal."
	case strings.Contains(reason, "notification_actions_hidden"):
		return "The desktop cannot show the required consent buttons."
	case strings.Contains(reason, "session_lock_state_unreported"):
		return "The desktop does not report screen-lock state for safe sharing."
	case strings.Contains(reason, "no vendor advisory feed"):
		return "No vendor advisory feed covers this distribution."
	case strings.Contains(reason, "Origins-Pattern"):
		return "Security-origin selection is not implemented for this update runner."
	case strings.Contains(reason, "ALPM guard"):
		return "System upgrades must use the distribution's own updater."
	case strings.Contains(reason, "definition provider floor"):
		return "Systemd unit definitions require a newer systemd."
	case strings.Contains(reason, "store a transaction without privileges"):
		return "Package profiles require a newer DNF."
	case strings.Contains(reason, "Omarchy") && capability == platform.Firewall:
		return "Firewall profiles require firewalld rather than the installed ufw."
	case capability == platform.Password:
		return "Password-policy profiles are unavailable with this PAM stack."
	case capability == platform.OSUpdate:
		return "Automatic OS updates are not supported on this release."
	default:
		return fmt.Sprintf("The %s integration is unavailable on this release.", gendoc.Escape(string(capability)))
	}
}
