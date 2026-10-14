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
	specs := []*labv1.MatrixCell{
		{Name: "enroll-from-console", Capabilities: []string{"lifecycle"}},
		{Name: "resources", Capabilities: []string{"packages", "accounts", "sysctl", "definitions", "password", "firewall"}, CapabilityKinds: true},
		{Name: "dispatch", Capabilities: []string{"dispatch"}},
		{Name: "services", Capabilities: []string{"dispatch"}},
		{Name: "encrypted", Capabilities: []string{"encryption"}},
		{Name: "tpm-unattended-boots", Capabilities: []string{"encryption"}, Tpm: true},
		{Name: "device-actions", Capabilities: []string{"lock", "wipe", "report-loss"}},
		{Name: "os-update", Capabilities: []string{"os-update"}},
		{Name: "advisories", Capabilities: []string{"advisories"}},
		{Name: "assistance", Capabilities: []string{"assistance"}},
		{Name: "desktop-controls", Capabilities: []string{"assistance-clipboard", "assistance-keyboard", "assistance-displays", "assistance-messages"}},
	}
	var cells []*Cell
	for _, arch := range r.Architectures {
		for _, spec := range specs {
			c := &Cell{Release: r, Architecture: arch, Spec: spec, State: Pass, Entry: entry(r.Key, spec.GetName(), arch, labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now())}
			for _, capability := range spec.GetCapabilities() {
				c.Kinds = append(c.Kinds, platform.Capability(capability))
			}
			cells = append(cells, c)
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

func supportRow(t *testing.T, body, arch string) []string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		parts := strings.Split(line, "|")
		if len(parts) == 11 && strings.TrimSpace(parts[2]) == arch {
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts[1:10]
		}
	}
	t.Fatalf("missing %s row", arch)
	return nil
}

func TestRenderSupportCompleteOutcomesAndArchitectures(t *testing.T) {
	_, cells := supportFixture()
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x86_64", "arm64"} {
		row := supportRow(t, body, arch)
		if row[0] != "[Fixture Linux 1](docs/platforms/fixture.md)" {
			t.Fatalf("distribution page = %q", row[0])
		}
		for _, text := range row[2:] {
			if text != "✓" {
				t.Errorf("%s status = %q, want recorded support", arch, text)
			}
		}
	}
}

func TestRenderSupportUnrecordedStatesAreNotUnsupported(t *testing.T) {
	for _, state := range []State{Fail, NotRun, Gated, NoLane, NoImage} {
		t.Run(string(state), func(t *testing.T) {
			_, cells := supportFixture()
			c := supportCell(t, cells, "enroll-from-console", "aarch64")
			c.State, c.Reason = state, "internal execution restriction"
			body, err := RenderSupport(cells)
			if err != nil {
				t.Fatal(err)
			}
			if got := supportRow(t, body, "arm64")[2]; got != "not yet tested" {
				t.Fatalf("%s = %q, want neutral", state, got)
			}
			if got := supportRow(t, body, "x86_64")[2]; got != "✓" {
				t.Fatalf("arm64 state changed x86_64 to %q", got)
			}
			if strings.Contains(body, "internal execution restriction") {
				t.Fatal("public body exposed execution details")
			}
		})
	}
}

func TestRenderSupportRequiresRecordsAndCapabilityCoverage(t *testing.T) {
	for _, change := range []string{"absent entry", "absent outcome", "partial scope", "missing provider"} {
		t.Run(change, func(t *testing.T) {
			_, cells := supportFixture()
			c := supportCell(t, cells, "resources", "x86_64")
			switch change {
			case "absent entry":
				c.Entry = nil
			case "absent outcome":
				cells = slices.DeleteFunc(cells, func(c *Cell) bool { return c.Spec.GetName() == "resources" && c.Architecture == "x86_64" })
			case "partial scope":
				c.Entry.Scope = "seven kinds, no firewall"
			case "missing provider":
				c.Kinds = slices.DeleteFunc(c.Kinds, func(capability platform.Capability) bool { return capability == platform.Firewall })
			}
			body, err := RenderSupport(cells)
			if err != nil {
				t.Fatal(err)
			}
			if got := supportRow(t, body, "x86_64")[3]; got != "not yet tested" {
				t.Fatalf("%s gave profile status %q", change, got)
			}
		})
	}
}

func TestRenderSupportUnsupportedAndArchitectureRestrictions(t *testing.T) {
	r, cells := supportFixture()
	r.ArchitectureGates = map[string]map[platform.Capability]string{"aarch64": {platform.Wipe: "not implemented on this architecture"}}
	r.Supports = slices.DeleteFunc(r.Supports, func(c platform.Capability) bool { return c == platform.Assistance })
	r.Gates = map[platform.Capability]string{platform.Assistance: "portal_screencast_unavailable: no ScreenCast or RemoteDesktop; internal lane unavailable"}
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body, "arm64")[5]; !strings.HasPrefix(got, "✓ / ✗ [^support-") {
		t.Fatalf("architecture-restricted wipe = %q", got)
	}
	if got := supportRow(t, body, "x86_64")[5]; got != "✓" {
		t.Fatalf("unrestricted lock/wipe = %q", got)
	}
	if got := supportRow(t, body, "x86_64")[8]; !strings.HasPrefix(got, "✗ [^support-") {
		t.Fatalf("unsupported assistance = %q", got)
	}
	if !strings.Contains(body, "The desktop portal provides neither screen capture nor remote control.") || strings.Contains(body, "internal lane") {
		t.Fatal("missing factual public restriction or leaked execution detail")
	}
}

func TestRenderSupportEncryptionTPMAndDesktopComposites(t *testing.T) {
	r, cells := supportFixture()
	supportCell(t, cells, "tpm-unattended-boots", "aarch64").State = Gated
	supportCell(t, cells, "assistance", "x86_64").Entry.Scope = "GNOME"
	cells = slices.DeleteFunc(cells, func(c *Cell) bool { return c.Spec.GetName() == "desktop-controls" })
	body, err := RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body, "arm64")[4]; got != "✓ / not yet tested" {
		t.Fatalf("TPM execution restriction changed disk support: %q", got)
	}
	if got := supportRow(t, body, "x86_64")[8]; got != "✓ / not yet tested" {
		t.Fatalf("desktop result implied independently unrecorded controls: %q", got)
	}
	r.Lab.TPM.Unsupported = "vendor boot hook cannot unlock systemd TPM2 tokens"
	body, err = RenderSupport(cells)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportRow(t, body, "x86_64")[4]; !strings.HasPrefix(got, "✓ / ✗ [^support-") {
		t.Fatalf("real TPM incompatibility = %q", got)
	}
	if !strings.Contains(body, "installed boot configuration cannot unlock systemd TPM2 tokens") {
		t.Fatal("missing TPM requirement explanation")
	}
}

func TestRenderSupportCompositeNeedsEveryRequiredOutcome(t *testing.T) {
	for _, name := range []string{"dispatch", "services", "encrypted", "device-actions"} {
		t.Run(name, func(t *testing.T) {
			_, cells := supportFixture()
			supportCell(t, cells, name, "x86_64").State = Fail
			body, err := RenderSupport(cells)
			if err != nil {
				t.Fatal(err)
			}
			row := supportRow(t, body, "x86_64")
			column := 3
			if name == "encrypted" || name == "device-actions" {
				column = 5
			}
			if !strings.Contains(row[column], "not yet tested") || strings.Contains(row[column], "✗") {
				t.Fatalf("failed %s gave complete composite status %q", name, row[column])
			}
		})
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
		if got := supportRow(t, body, "x86_64")[0]; got != "[Fixture Linux 1](docs/platforms/fixture.md) (rolling)" {
			t.Fatalf("rolling release label = %q", got)
		}
	}
}
