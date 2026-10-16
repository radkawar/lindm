// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"lindm/internal/platform"
)

const cosmicAssistanceProfile = "pop-cosmic-actions-v1"

// These are a disposable fork qualification, not archive release support.
// Fork package versions identify the patched binaries; SHA256SUMS binds the
// explicit local inputs, whose digests are retained in the native record.
var cosmicAssistancePins = []string{
	"xdg-desktop-portal-cosmic=1.10.0+lindm.lifetime.3",
	"cosmic-comp=0.1~1791491785~24.04~4d14528",
	"cosmic-notifications=1.10.0+lindm.actions.1",
	"cosmic-greeter=1.10.0~1791400742~24.04~98df07d",
	"cosmic-greeter-daemon=1.10.0~1791400742~24.04~98df07d",
	"libspa-0.2-modules=1.6.8-1pop1~1787688714~24.04~fdff050",
	"libpipewire-0.3-0t64=1.6.8-1pop1~1787688714~24.04~fdff050",
	"libpipewire-0.3-modules=1.6.8-1pop1~1787688714~24.04~fdff050",
	"pipewire-bin=1.6.8-1pop1~1787688714~24.04~fdff050",
	"pipewire=1.6.8-1pop1~1787688714~24.04~fdff050",
	"pipewire-jack=1.6.8-1pop1~1787688714~24.04~fdff050",
	"libspa-0.2-jack=1.6.8-1pop1~1787688714~24.04~fdff050",
	"libspa-0.2-bluetooth=1.6.8-1pop1~1787688714~24.04~fdff050",
	"pipewire-alsa=1.6.8-1pop1~1787688714~24.04~fdff050",
	"pipewire-pulse=1.6.8-1pop1~1787688714~24.04~fdff050",
	"gstreamer1.0-pipewire=1.6.8-1pop1~1787688714~24.04~fdff050",
	"libpipewire-0.3-common=1.6.8-1pop1~1787688714~24.04~fdff050",
	"cosmic-term=1.10.0~1791316259~24.04~3bfca1e",
}

var cosmicForkPackages = []string{"xdg-desktop-portal-cosmic", "cosmic-notifications"}

type assistancePackageProfileEvidence struct {
	Name         string                   `json:"name"`
	Experimental bool                     `json:"experimental_fork_only"`
	Required     []string                 `json:"required_packages"`
	Observed     []string                 `json:"observed_packages"`
	Artifacts    []assistanceForkArtifact `json:"fork_artifacts"`
}

type assistanceForkArtifact struct {
	Package string `json:"package"`
	SHA256  string `json:"sha256"`
}

// cosmicAssistanceDesktop never changes the baseline profile or registry. Only
// this named disposable experiment runs real local consent and portal scenarios.
func cosmicAssistanceDesktop(options VMAssistanceOptions, release *platform.Release, desktop *labDesktop, architecture string) (*labDesktop, error) {
	if options.CosmicPackageProfile == "" {
		if options.CosmicForkArtifacts != "" {
			return nil, errors.New("-cosmic-fork-artifacts requires -cosmic-package-profile")
		}
		return desktop, nil
	}
	if options.CosmicPackageProfile != cosmicAssistanceProfile {
		return nil, fmt.Errorf("unknown COSMIC package profile %q", options.CosmicPackageProfile)
	}
	if release.Key != "pop-24.04" || architecture != "amd64" || desktop.name != "cosmic" || options.X11 || options.Hold != nil || options.PersistentDir != "" || options.RebootPolicy != nil {
		return nil, errors.New("COSMIC fork profile requires a disposable Pop!_OS 24.04 x86_64 COSMIC Wayland assistance run; never a held demo or registry qualification")
	}
	if options.CosmicForkArtifacts == "" {
		return nil, errors.New("COSMIC fork profile requires -cosmic-fork-artifacts DIR with both exact-version .debs and SHA256SUMS; public notifications remain unsafe")
	}
	variant := *desktop
	variant.ocrConsent = true
	variant.area = bannerTopRight
	var err error
	variant.assistance, err = selectAssistanceScenarios(assistanceScenarios, []string{"control", "view", "decline", "portal-cancel"})
	return &variant, err
}

func readCosmicForkArtifacts(dir string) ([]assistanceForkArtifact, error) {
	file, err := openRegular(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, fmt.Errorf("COSMIC fork SHA256SUMS: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if len(data) > 4096 {
		return nil, errors.New("COSMIC fork SHA256SUMS exceeds 4096 bytes")
	}
	checksums := make(map[string]string, 2)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, errors.New("COSMIC fork SHA256SUMS must name exactly the two fork .debs")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if !slices.Contains(cosmicForkPackages, strings.TrimSuffix(name, ".deb")) || !strings.HasSuffix(name, ".deb") || checksums[name] != "" {
			return nil, fmt.Errorf("unexpected or duplicate COSMIC fork artifact %q", name)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return nil, fmt.Errorf("invalid COSMIC artifact checksum: %w", err)
		}
		checksums[name] = fields[0]
	}
	artifacts := make([]assistanceForkArtifact, 0, 2)
	for _, name := range cosmicForkPackages {
		expected := checksums[name+".deb"]
		if expected == "" {
			return nil, fmt.Errorf("missing COSMIC fork checksum for %s.deb", name)
		}
		observed, err := dispatchFileDigest(filepath.Join(dir, name+".deb"))
		if err != nil {
			return nil, err
		}
		if observed != expected {
			return nil, fmt.Errorf("COSMIC fork artifact %s checksum mismatch: got %s, require %s", name, observed, expected)
		}
		artifacts = append(artifacts, assistanceForkArtifact{Package: name, SHA256: expected})
	}
	return artifacts, nil
}

// cosmicPackagePinScript locks every native version before any subsequent
// capture/agent install can resolve dependencies. Missing exact archive versions
// fail; neither apt upgrade nor an unversioned fallback is permitted.
func cosmicPackagePinScript() string {
	var script strings.Builder
	script.WriteString(labQuiescePackageUnits + "; " + labAPTInstallPrelude + "\n")
	script.WriteString("install -d -m 0755 /etc/apt/preferences.d\ncat > /etc/apt/preferences.d/lindm-cosmic-assistance <<'LINDM_PINS'\n")
	for _, pin := range cosmicAssistancePins {
		name, version, _ := strings.Cut(pin, "=")
		fmt.Fprintf(&script, "Package: %s\nPin: version %s\nPin-Priority: 1001\n\n", name, version)
	}
	script.WriteString("LINDM_PINS\napt-get -o DPkg::Lock::Timeout=600 update\napt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends --allow-downgrades")
	for _, pin := range cosmicAssistancePins {
		name, _, _ := strings.Cut(pin, "=")
		if slices.Contains(cosmicForkPackages, name) {
			script.WriteString(" /tmp/lindm-cosmic-" + name + ".deb")
		} else {
			script.WriteByte(' ')
			script.WriteString(nativeQuote(pin))
		}
	}
	script.WriteString("\napt-mark hold")
	for _, pin := range cosmicAssistancePins {
		name, _, _ := strings.Cut(pin, "=")
		script.WriteString(" " + name)
	}
	script.WriteString("\n")
	return script.String()
}

func installCosmicAssistanceProfile(ctx context.Context, vm *guestVM, options VMAssistanceOptions) (*assistancePackageProfileEvidence, error) {
	artifacts, err := readCosmicForkArtifacts(options.CosmicForkArtifacts)
	if err != nil {
		return nil, err
	}
	evidence := &assistancePackageProfileEvidence{Name: options.CosmicPackageProfile, Experimental: true, Required: slices.Clone(cosmicAssistancePins), Artifacts: artifacts}
	for _, artifact := range artifacts {
		path := filepath.Join(options.CosmicForkArtifacts, artifact.Package+".deb")
		destination := "/tmp/lindm-cosmic-" + artifact.Package + ".deb"
		if err := uploadActionBootFile(ctx, vm, path, destination); err != nil {
			return evidence, err
		}
		version := ""
		for _, pin := range cosmicAssistancePins {
			name, value, _ := strings.Cut(pin, "=")
			if name == artifact.Package {
				version = value
			}
		}
		// Check the uploaded bytes against the reviewed input, not just the
		// upload helper's own digest (the source could change after reading).
		command := "printf '%s  %s\\n' " + nativeQuote(artifact.SHA256) + " " + nativeQuote(destination) + " | sha256sum --check --status\n" +
			"test \"$(dpkg-deb -f " + nativeQuote(destination) + " Package)\" = " + nativeQuote(artifact.Package) + "\n" +
			"test \"$(dpkg-deb -f " + nativeQuote(destination) + " Version)\" = " + nativeQuote(version) + "\n" +
			"test \"$(dpkg-deb -f " + nativeQuote(destination) + " Architecture)\" = amd64"
		if _, err := vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), nil, 4096, time.Minute); err != nil {
			return evidence, fmt.Errorf("verify COSMIC fork package %s: %w", artifact.Package, err)
		}
	}
	result, err := vm.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(cosmicPackagePinScript()), nil, 1<<20, 15*time.Minute)
	if err != nil {
		return evidence, fmt.Errorf("install exact COSMIC package profile: %w", err)
	}
	if result.ExitCode != 0 {
		return evidence, fmt.Errorf("install exact COSMIC package profile: guest exit %d\nstdout: %s\nstderr: %s", result.ExitCode, strings.TrimSpace(string(result.Stdout)), strings.TrimSpace(string(result.Stderr)))
	}
	return evidence, observeCosmicAssistancePins(ctx, vm, evidence)
}

func observeCosmicAssistancePins(ctx context.Context, vm *guestVM, evidence *assistancePackageProfileEvidence) error {
	names := make([]string, 0, len(cosmicAssistancePins))
	for _, pin := range cosmicAssistancePins {
		name, _, _ := strings.Cut(pin, "=")
		names = append(names, name)
	}
	out, err := vm.run(ctx, `dpkg-query -W -f='${Package}=${Version}\n' `+strings.Join(names, " "), nil, 16384, 30*time.Second)
	if err != nil {
		return err
	}
	evidence.Observed = strings.Split(strings.TrimSpace(string(out)), "\n")
	return verifyCosmicAssistancePins(evidence.Observed)
}

func verifyCosmicAssistancePins(observed []string) error {
	if len(observed) != len(cosmicAssistancePins) {
		return fmt.Errorf("COSMIC native package evidence has %d entries, require %d", len(observed), len(cosmicAssistancePins))
	}
	for _, pin := range cosmicAssistancePins {
		if !slices.Contains(observed, pin) {
			return fmt.Errorf("COSMIC native package drift: require exact %s; observed %v", pin, observed)
		}
	}
	return nil
}

// cosmicPortal uses the fork's native source picker, not the Plasma or GNOME
// dialog. Its monitor name is observed from the sole connected native DRM
// connector, then must be visible in QMP pixels before it can be selected.
func (r *assistanceRun) cosmicPortal(ctx context.Context, spec assistanceScenarioSpec, control bool, scenario *assistanceScenarioEvidence) error {
	title, allow, cancel := cosmicPortalLabels(control)
	labels := []string{title, allow, cancel}
	if control {
		labels = append(labels, "Keyboard", "Pointer")
	}
	portal, found, err := r.screen.waitText(ctx, nil, 45*time.Second, "portal-dialog", labels...)
	if err != nil {
		return err
	}
	// The body also contains "Allow". Anchor the action row to its visible
	// Deny/Cancel label so only the actual grant button can satisfy OCR.
	actions := func(display image.Rectangle) image.Rectangle {
		return cosmicPortalActionRegion(display, found[cancel])
	}
	if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
		return err
	}
	if spec.portalCancel {
		return r.screen.clickText(ctx, actions, cancel, "portal-cancel", scenario)
	}
	const connectors = `for status in /sys/class/drm/card*-*/status; do
test -f "$status" || continue
test "$(cat "$status")" = connected || continue
name=${status%/status}; name=${name##*/}; printf '%s\n' "${name#*-}"
done`
	out, err := r.vm.guest.run(ctx, connectors, nil, 4096, 30*time.Second)
	if err != nil {
		return fmt.Errorf("observe COSMIC portal output: %w", err)
	}
	output, err := cosmicPortalOutput(string(out))
	if err != nil {
		return err
	}
	if err := r.screen.clickLabel(ctx, nil, output, "portal-source-"+output, scenario, true, ocrSourcePoint); err != nil {
		return err
	}
	selected, _, err := r.screen.waitText(ctx, actions, 15*time.Second, "portal-source-selected", allow, cancel)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "portal-source-selected", selected); err != nil {
		return err
	}
	return r.screen.clickText(ctx, actions, allow, "portal-share", scenario)
}

func cosmicPortalLabels(control bool) (title, allow, cancel string) {
	if control {
		return "Allow remote control", "Allow", "Deny"
	}
	return "Share your screen", "Share", "Cancel"
}

func cosmicPortalOutput(observed string) (string, error) {
	outputs := strings.Fields(observed)
	if len(outputs) != 1 {
		return "", fmt.Errorf("COSMIC pinned cell requires exactly one connected native output, observed %q", observed)
	}
	return outputs[0], nil
}

func cosmicPortalActionRegion(display, cancel image.Rectangle) image.Rectangle {
	return image.Rect(display.Min.X, cancel.Min.Y-12, display.Max.X, cancel.Max.Y+12).Intersect(display)
}
