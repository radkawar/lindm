// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"slices"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

func supportFixture() (*platform.Release, []*Cell) {
	r := &platform.Release{Key: "fixture", Name: "Fixture Linux 1", Page: "fixture.md", Architectures: []string{"x86_64", "aarch64"}, Supports: slices.Clone(platform.Capabilities)}
	var cells []*Cell
	for _, arch := range r.Architectures {
		for _, name := range []string{"enroll-from-console", "resources", "encrypted", "device-actions", "os-update", "advisories", "assistance", "tpm-unattended-boots"} {
			cells = append(cells, &Cell{Release: r, Architecture: arch, Spec: &labv1.MatrixCell{Name: name}, State: Pass, Entry: entry(r.Key, name, arch, labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now())})
		}
	}
	return r, cells
}

func supportCell(t *testing.T, cells []*Cell, name, arch string) *Cell {
	t.Helper()
	for _, c := range cells {
		if c.Spec.GetName() == name && c.Architecture == arch {
			return c
		}
	}
	t.Fatalf("missing %s %s", name, arch)
	return nil
}

func supportRow(t *testing.T, body string) []string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "| [") {
			parts := strings.Split(line, "|")[1:9]
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
	}
	t.Fatal("missing x86_64 feature row")
	return nil
}

func TestRenderSupportOneRowAndSeparateArmBuilds(t *testing.T) {
	_, cells := supportFixture()
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(body, "| [Fixture") != 1 || !strings.Contains(body, "arm64 builds are available for") {
		t.Fatal("architecture rows were not replaced by a separate arm64 summary")
	}
	for _, value := range supportRow(t, body)[1:] {
		if value != "✓" {
			t.Errorf("supported feature = %q", value)
		}
	}
	if strings.Contains(body, " / not yet tested") || strings.Contains(body, "✓ / ") {
		t.Fatal("paired status values leaked into the table")
	}
}

func TestRenderSupportScopedPassesCountForFeatures(t *testing.T) {
	_, cells := supportFixture()
	for _, name := range []string{"resources", "encrypted", "device-actions", "advisories", "assistance"} {
		supportCell(t, cells, name, "x86_64").Entry.Scope = "selected phases"
	}
	supportCell(t, cells, "advisories", "x86_64").Entry.Scope = "native feed matching; not complete device coverage"
	supportCell(t, cells, "assistance", "x86_64").Entry.Scope = "KDE Plasma Wayland; view and control"
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range supportRow(t, body)[1:] {
		if !strings.HasPrefix(value, "✓") {
			t.Errorf("scoped success became %q", value)
		}
	}
	if !strings.Contains(body, "Findings cover packages in the vendor's advisory feed.") || !strings.Contains(body, "Extra assistance tools depend on the desktop.") {
		t.Fatal("missing general feed and desktop statements")
	}
	if strings.Contains(supportRow(t, body)[6], "[^support-") || strings.Contains(supportRow(t, body)[7], "[^support-") {
		t.Fatal("common feed or desktop limits created noisy row footnotes")
	}
}

func TestRenderSupportNamesRHELPackageCoverageLimit(t *testing.T) {
	r, cells := supportFixture()
	r.Advisory.RPMHeaderAuthority = true
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[6]; !strings.HasPrefix(got, "✓ [^support-") || !strings.Contains(body, "verified Red Hat packages declared for the selected product stream") || !strings.Contains(body, "unusable vendor components are listed as unchecked") {
		t.Fatalf("RHEL product and uncovered-package limits were omitted: %s", body)
	}
}

func TestRenderSupportProviderRestrictionIsFeatureFootnote(t *testing.T) {
	r, cells := supportFixture()
	r.Gates = map[platform.Capability]string{platform.Definitions: "definition provider floor", platform.Password: "PAM stack unavailable"}
	r.Supports = slices.DeleteFunc(r.Supports, func(c platform.Capability) bool { return c == platform.Definitions || c == platform.Password })
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if value := supportRow(t, body)[2]; !strings.HasPrefix(value, "✓ [^support-") {
		t.Fatalf("one unavailable provider changed Profiles to %q", value)
	}
	if !strings.Contains(body, "Systemd unit definitions require a newer systemd.") || !strings.Contains(body, "Password-policy profiles are unavailable") {
		t.Fatal("missing named provider limits")
	}
}

func TestRenderSupportDeduplicatesProviderFootnotes(t *testing.T) {
	r, cells := supportFixture()
	other, more := supportFixture()
	other.Key, other.Name = "other", "Other Linux 1"
	for _, c := range more {
		c.Entry.Platform = other.Key
	}
	for _, release := range []*platform.Release{r, other} {
		release.Gates = map[platform.Capability]string{platform.Password: "PAM stack unavailable"}
		release.Supports = slices.DeleteFunc(release.Supports, func(c platform.Capability) bool { return c == platform.Password })
	}
	body, err := RenderSupport(append(cells, more...))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(body, "Password-policy profiles are unavailable with this PAM stack.") != 1 {
		t.Fatal("shared provider restriction produced duplicate footnotes")
	}
}

func TestRenderSupportMissingAndFailedAreNeutral(t *testing.T) {
	for _, verdict := range []labv1.MatrixVerdict{labv1.MatrixVerdict_MATRIX_VERDICT_UNSPECIFIED, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL} {
		_, cells := supportFixture()
		c := supportCell(t, cells, "enroll-from-console", "x86_64")
		if verdict == labv1.MatrixVerdict_MATRIX_VERDICT_UNSPECIFIED {
			c.Entry = nil
		} else {
			c.Entry.Verdict = verdict
			c.State = Fail
		}
		body, err := RenderSupport(cells)
		if err != nil {
			t.Fatal(err)
		}
		if got := supportRow(t, body)[1]; got != "not yet tested" {
			t.Fatalf("missing or failed result became %q", got)
		}
	}
}

func TestRenderSupportWholeUnsupportedFeatureAndDeduplication(t *testing.T) {
	r, cells := supportFixture()
	r.Gates = map[platform.Capability]string{platform.Assistance: "no ScreenCast or RemoteDesktop"}
	r.Supports = slices.DeleteFunc(r.Supports, func(c platform.Capability) bool { return c == platform.Assistance })
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[7]; !strings.HasPrefix(got, "✗ [^support-") {
		t.Fatalf("unavailable desktop sharing became %q", got)
	}
	if strings.Count(body, "The desktop has no screen-sharing or remote-control portal.") != 1 {
		t.Fatal("duplicate desktop footnotes")
	}
}

func TestRenderSupportTPMAndScreenLockLimitsDoNotEraseFeature(t *testing.T) {
	r, cells := supportFixture()
	r.Lab.TPM.Unsupported = "vendor boot hook cannot unlock systemd TPM2 tokens"
	supportCell(t, cells, "device-actions", "x86_64").Entry.Scope = "crypto-erase, lock unverifiable (no LockedHint), account locks"
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	row := supportRow(t, body)
	if !strings.HasPrefix(row[3], "✓ [^support-") || !strings.HasPrefix(row[4], "✓ [^support-") {
		t.Fatalf("subfeature limits erased encryption or lock/wipe: %v", row)
	}
	if !strings.Contains(body, "TPM2 unattended unlock is unavailable") || !strings.Contains(body, "desktop does not report its screen-lock state") {
		t.Fatal("missing TPM or screen-lock limits")
	}
}

func TestSupportHistoryRetainsOlderSuccessfulSubsets(t *testing.T) {
	r, cells := supportFixture()
	c := supportCell(t, cells, "device-actions", "x86_64")
	c.Entry.Scope = "report-loss blocks the original device"
	older := entry(r.Key, "device-actions", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now().Add(-time.Hour))
	older.Scope = "lock, release, crypto-erase"
	in := &Inputs{Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{older, c.Entry}}}
	body, err := RenderSupport(in.supportHistory(cells))
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[4]; got != "✓" {
		t.Fatalf("later loss-reporting subset erased tested lock/wipe: %q", got)
	}
	in.superseded = map[*labv1.MatrixLedgerEntry]bool{older: true}
	body, err = RenderSupport(in.supportHistory(cells))
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[4]; got != "not yet tested" {
		t.Fatalf("superseded subset counted as support: %q", got)
	}
	older.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_PASS
	c.Entry.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
	in.superseded = nil
	body, err = RenderSupport(in.supportHistory(cells))
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[4]; got != "not yet tested" {
		t.Fatalf("latest failure was hidden by an old success: %q", got)
	}
}

func TestRenderSupportLabelsRollingReleases(t *testing.T) {
	for _, version := range []platform.Version{platform.Absent(), platform.Snapshot()} {
		r, cells := supportFixture()
		r.Version = version
		body, err := RenderSupport(cells)
		if err != nil {
			t.Fatal(err)
		}
		if got := supportRow(t, body)[0]; got != "[Fixture Linux 1](docs/platforms/fixture.md) (rolling)" {
			t.Fatalf("rolling release label = %q", got)
		}
	}
}

func TestRenderSupportDoesNotDescribeProfileTestCompleteness(t *testing.T) {
	_, cells := supportFixture()
	supportCell(t, cells, "resources", "x86_64").Entry.Scope = "seven kinds, no firewall"
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[2]; got != "✓" {
		t.Fatalf("profile run scope produced testing-talk footnote: %q", got)
	}
}

func TestRenderSupportFreshInstallEnrollmentRestriction(t *testing.T) {
	r, cells := supportFixture()
	r.Lab.LaneGates = map[platform.LabLane]platform.LaneGate{
		platform.LaneEnrollFromConsole: {Reason: "the console's pacman install command needs synced databases"},
	}
	supportCell(t, cells, "enroll-from-console", "x86_64").Entry = nil
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[1]; !strings.HasPrefix(got, "✗ [^support-") {
		t.Fatalf("known fresh-install failure remained %q", got)
	}
	if !strings.Contains(body, "Console enrollment is unavailable on fresh installs without synced package databases.") {
		t.Fatal("missing narrow fresh-install prerequisite")
	}
	r.Lab.LaneGates[platform.LaneEnrollFromConsole] = platform.LaneGate{Reason: "lab-only: no immutable image available"}
	body, err = RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[1]; got != "not yet tested" {
		t.Fatalf("lab-only restriction became product unsupported: %q", got)
	}
}

func TestCinnamonNativeConfirmationIsVersionQualifiedNotWholeFeatureSupport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		verdict   labv1.MatrixVerdict
		verified  bool
		scope     string
		qualified bool
	}{
		{"native fixed-version pass", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, true, CinnamonLockConfirmationScope, true},
		{"old package gate", labv1.MatrixVerdict_MATRIX_VERDICT_GATED, true, CinnamonLockConfirmationScope, false},
		{"native cleanup failure", labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, true, CinnamonLockConfirmationScope, false},
		{"unverified claim", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, false, CinnamonLockConfirmationScope, false},
		{"unscoped claim", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, true, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cells := supportFixture()
			r.Lab.Session.Desktops = release(t, "linuxmint-22.3").Lab.Session.Desktops
			supportCell(t, cells, "device-actions", "x86_64").Entry.Scope = "crypto-erase, lock unverifiable (no LockedHint), account locks"
			e := entry(r.Key, "cinnamon-lock-confirmation", "x86_64", tc.verdict, time.Now())
			e.Verified, e.Scope = tc.verified, tc.scope
			state := Fail
			if tc.verdict == labv1.MatrixVerdict_MATRIX_VERDICT_PASS {
				state = Pass
			}
			native := &Cell{Release: r, Architecture: "x86_64", Spec: cinnamonSpec(), State: state, Entry: e}
			body, err := RenderSupport(append(cells, native))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(body, "Native screen-lock confirmation passed for the Cinnamon package version recorded in its dedicated cell (minimum 6.7.9)") != tc.qualified ||
				strings.Contains(body, "desktop does not report its screen-lock state") == tc.qualified {
				t.Fatalf("native version-qualified warning changed incorrectly:\n%s", body)
			}
			if tc.qualified && (!strings.Contains(body, "older packages remain unconfirmed") || !strings.Contains(body, "does not qualify wipe, quarantine or assistance")) {
				t.Fatal("native confirmation was advertised as a stock-release or whole-feature fix")
			}
			// Remove the complete action and assistance evidence. The narrow
			// pass cannot supply either missing feature's qualification.
			supportCell(t, cells, "device-actions", "x86_64").Entry = nil
			supportCell(t, cells, "assistance", "x86_64").Entry = nil
			body, err = RenderSupport(append(cells, native))
			if err != nil {
				t.Fatal(err)
			}
			row := supportRow(t, body)
			if row[4] != "not yet tested" || row[7] != "not yet tested" {
				t.Fatalf("native-lock-only evidence inflated lock/wipe or assistance: %v", row)
			}
		})
	}
}

func TestRenderSupportDoesNotTreatNewCosmicPortalAsSafeConsent(t *testing.T) {
	r, cells := supportFixture()
	r.Supports = slices.DeleteFunc(r.Supports, func(c platform.Capability) bool { return c == platform.Assistance })
	r.Gates = map[platform.Capability]string{platform.Assistance: "notification_actions_hidden: stock COSMIC; notification_actions_unverified: other versions"}
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body)[7]; !strings.HasPrefix(got, "✗ [^support-") {
		t.Fatalf("unsafe consent became supported: %q", got)
	}
	if !strings.Contains(body, "Stock COSMIC hides consent buttons; newer portal support alone does not enable assistance.") {
		t.Fatal("missing separate portal and consent restriction")
	}
}
