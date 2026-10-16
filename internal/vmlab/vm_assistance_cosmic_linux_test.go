// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"image"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"lindm/internal/platform"
)

func TestCOSMICForkProfileRequiresExplicitDisposableInputs(t *testing.T) {
	pop, ok := platform.Lookup("pop-24.04")
	if !ok {
		t.Fatal("missing Pop registry row")
	}
	base := mustLabDesktop(t, "cosmic")
	options := VMAssistanceOptions{CosmicPackageProfile: cosmicAssistanceProfile, CosmicForkArtifacts: t.TempDir()}
	desktop, err := cosmicAssistanceDesktop(options, pop, base, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if desktop == base || desktop.refusalOnly() || !base.refusalOnly() || !desktop.ocrConsent || desktop.area != bannerTopRight {
		t.Fatal("fork profile mutated baseline refusals or bypassed visible consent")
	}
	var names []string
	for _, scenario := range desktop.assistance {
		if scenario.detail != "" || scenario.capability != "" {
			t.Fatalf("fork scenario silently tests refusal or unqualified extra capability: %+v", scenario)
		}
		names = append(names, scenario.name)
	}
	if !slices.Equal(names, []string{"control", "view", "decline", "portal-cancel"}) {
		t.Fatalf("fork scenarios %v", names)
	}
	if pop.Gate(platform.Assistance) == nil {
		t.Fatal("experimental fork must not admit public Pop registry assistance")
	}
	for name, mutate := range map[string]func(*VMAssistanceOptions){
		"unknown profile":           func(o *VMAssistanceOptions) { o.CosmicPackageProfile = "latest" },
		"public only":               func(o *VMAssistanceOptions) { o.CosmicForkArtifacts = "" },
		"persistent":                func(o *VMAssistanceOptions) { o.PersistentDir = "/retained" },
		"held":                      func(o *VMAssistanceOptions) { o.Hold = func(*AssistanceHold) error { return nil } },
		"reboot":                    func(o *VMAssistanceOptions) { o.RebootPolicy = new(VMRebootPolicyResult) },
		"x11":                       func(o *VMAssistanceOptions) { o.X11 = true },
		"artifacts without profile": func(o *VMAssistanceOptions) { o.CosmicPackageProfile = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := options
			mutate(&invalid)
			if _, err := cosmicAssistanceDesktop(invalid, pop, base, "amd64"); err == nil {
				t.Fatal("unsafe or unbounded fork profile accepted")
			}
		})
	}
	if _, err := cosmicAssistanceDesktop(options, pop, base, "arm64"); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	ubuntu, _ := platform.Lookup("ubuntu-24.04")
	if _, err := cosmicAssistanceDesktop(options, ubuntu, base, "amd64"); err == nil {
		t.Fatal("profile crossed release boundary")
	}
	if got, err := cosmicAssistanceDesktop(VMAssistanceOptions{}, pop, base, "amd64"); err != nil || got != base {
		t.Fatalf("ordinary COSMIC profile changed: %v", err)
	}
}

func TestCOSMICNativeVersionEvidenceRejectsDriftAndPublicNotifications(t *testing.T) {
	expected := []string{
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
	if !slices.Equal(cosmicAssistancePins, expected) {
		t.Fatalf("profile pins changed without explicit requalification: %v", cosmicAssistancePins)
	}
	if err := verifyCosmicAssistancePins(expected); err != nil {
		t.Fatal(err)
	}
	invalid := [][]string{nil, expected[:len(expected)-1], append(slices.Clone(expected), "extra=1")}
	for i, pin := range expected {
		drifted := slices.Clone(expected)
		name, _, _ := strings.Cut(pin, "=")
		drifted[i] = name + "=archive-next"
		invalid = append(invalid, drifted)
	}
	publicNotifications := slices.Clone(expected)
	publicNotifications[2] = "cosmic-notifications=1.10.0~1791314632~24.04~1e4c1f1"
	duplicate := slices.Clone(expected)
	duplicate[3] = expected[2]
	invalid = append(invalid, publicNotifications, duplicate)
	for _, rejected := range []string{"1.10.0+lindm.lifetime.1", "1.10.0+lindm.lifetime.2"} {
		oldPortal := slices.Clone(expected)
		oldPortal[0] = "xdg-desktop-portal-cosmic=" + rejected
		invalid = append(invalid, oldPortal)
	}
	for _, observed := range invalid {
		if err := verifyCosmicAssistancePins(observed); err == nil {
			t.Fatalf("accepted drifting/incomplete native evidence: %v", observed)
		}
	}
	script := cosmicPackagePinScript()
	if !strings.HasPrefix(script, labQuiescePackageUnits+"; "+labAPTInstallPrelude) {
		t.Fatal("profile bypasses existing disposable package-manager readiness")
	}
	if !strings.Contains(script, "apt-get -o DPkg::Lock::Timeout=600 update") ||
		!strings.Contains(script, "apt-get -o DPkg::Lock::Timeout=600 install") {
		t.Fatal("profile does not wait for dpkg's native lock")
	}
	names := make([]string, 0, len(expected))
	for _, pin := range expected {
		name, version, _ := strings.Cut(pin, "=")
		names = append(names, name)
		if !strings.Contains(script, "Package: "+name+"\nPin: version "+version+"\nPin-Priority: 1001") {
			t.Errorf("missing apt lock for %s", pin)
		}
		if !slices.Contains(cosmicForkPackages, name) && !strings.Contains(script, "'"+pin+"'") {
			t.Errorf("missing exact native installation argument for %s", pin)
		}
	}
	if !strings.Contains(script, "apt-mark hold "+strings.Join(names, " ")+"\n") {
		t.Fatal("not every pinned native package is held")
	}
	for _, required := range []string{
		"/tmp/lindm-cosmic-xdg-desktop-portal-cosmic.deb", "/tmp/lindm-cosmic-cosmic-notifications.deb",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("missing exact installation constraint %q", required)
		}
	}
	if strings.Contains(script, "apt-get upgrade") || strings.Contains(script, "|| apt-get") || strings.Contains(script, "allow-change-held-packages") {
		t.Fatal("pin script permits drift or masks missing exact packages")
	}
}

func TestCOSMICForkArtifactsRequireCompleteMatchingDigests(t *testing.T) {
	dir := t.TempDir()
	var manifest strings.Builder
	for _, name := range cosmicForkPackages {
		data := []byte("test digest input: " + name)
		if err := os.WriteFile(filepath.Join(dir, name+".deb"), data, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		manifest.WriteString(hex.EncodeToString(digest[:]) + "  " + name + ".deb\n")
	}
	path := filepath.Join(dir, "SHA256SUMS")
	writeManifest := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest(manifest.String())
	artifacts, err := readCosmicForkArtifacts(dir)
	if err != nil || len(artifacts) != 2 {
		t.Fatalf("read explicit fork checksums: %v, %v", artifacts, err)
	}
	for name, invalid := range map[string]string{
		"missing":   strings.Split(manifest.String(), "\n")[0],
		"duplicate": manifest.String() + strings.Split(manifest.String(), "\n")[0],
		"traversal": strings.Replace(manifest.String(), "cosmic-notifications.deb", "../cosmic-notifications.deb", 1),
		"nonhex":    strings.Repeat("z", 64) + "  cosmic-notifications.deb\n",
		"unbounded": strings.Repeat("x", 4097),
	} {
		t.Run(name, func(t *testing.T) {
			writeManifest(invalid)
			if _, err := readCosmicForkArtifacts(dir); err == nil {
				t.Fatal("accepted invalid artifact pin manifest")
			}
		})
	}
	writeManifest(manifest.String())
	if err := os.WriteFile(filepath.Join(dir, "cosmic-notifications.deb"), []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCosmicForkArtifacts(dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("artifact replacement was not rejected: %v", err)
	}
}

func TestCOSMICPortalUsesNativePickerLabelsAndObservedSingleOutput(t *testing.T) {
	if title, allow, cancel := cosmicPortalLabels(true); title != "Allow remote control" || allow != "Allow" || cancel != "Deny" {
		t.Fatalf("wrong RemoteDesktop consent: %q %q %q", title, allow, cancel)
	}
	if title, allow, cancel := cosmicPortalLabels(false); title != "Share your screen" || allow != "Share" || cancel != "Cancel" {
		t.Fatalf("wrong ScreenCast consent: %q %q %q", title, allow, cancel)
	}
	if output, err := cosmicPortalOutput("Virtual-1\n"); err != nil || output != "Virtual-1" {
		t.Fatalf("native output not retained: %q %v", output, err)
	}
	for _, outputs := range []string{"", "Virtual-1\nVirtual-2\n"} {
		if _, err := cosmicPortalOutput(outputs); err == nil {
			t.Fatalf("guessed portal source from %q", outputs)
		}
	}
}

// The first native profile install returned apt status 100 but vm.run hid all
// diagnostics behind a byte count. A real lane failure must retain the bounded
// package-manager explanation, never retry or silently fall back to the archive.
func TestCOSMICPackageInstallFailureRetainsGuestDiagnostics(t *testing.T) {
	dir := t.TempDir()
	var manifest strings.Builder
	for _, name := range cosmicForkPackages {
		data := []byte("checksum fixture " + name)
		if err := os.WriteFile(filepath.Join(dir, name+".deb"), data, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		manifest.WriteString(hex.EncodeToString(digest[:]) + "  " + name + ".deb\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
	calls := new(atomic.Int32)
	guest, _ := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		calls.Store(int32(call))
		if call == 5 {
			return "native apt dependency explanation", 100, false
		}
		return "", 0, false
	})
	profile, err := installCosmicAssistanceProfile(t.Context(), guest, VMAssistanceOptions{
		CosmicPackageProfile: cosmicAssistanceProfile, CosmicForkArtifacts: dir,
	})
	if err == nil || !strings.Contains(err.Error(), "guest exit 100") || !strings.Contains(err.Error(), "native apt dependency explanation") {
		t.Fatalf("lost native package failure: %v", err)
	}
	if calls.Load() != 5 || profile == nil || len(profile.Observed) != 0 {
		t.Fatalf("failed install retried or invented package evidence: calls=%d profile=%+v", calls.Load(), profile)
	}
}

func TestCOSMICPortalGrantRequiresVisibleActionRow(t *testing.T) {
	display := image.Rect(0, 0, 1280, 800)
	cancel := image.Rect(778, 663, 808, 677)
	actions := cosmicPortalActionRegion(display, cancel)
	grant := image.Rect(849, 663, 883, 677)
	bodyAllow := image.Rect(781, 121, 814, 134)
	titleAllow := image.Rect(378, 79, 442, 98)
	if !cancel.In(actions) || !grant.In(actions) || bodyAllow.Overlaps(actions) || titleAllow.Overlaps(actions) {
		t.Fatalf("grant region %v includes non-action Allow or excludes real action row", actions)
	}
	if got := cosmicPortalActionRegion(display, image.Rect(0, 0, 30, 10)); !got.In(display) {
		t.Fatalf("action region escaped native display: %v", got)
	}
}
