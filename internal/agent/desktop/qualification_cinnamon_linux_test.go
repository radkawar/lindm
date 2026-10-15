// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func cinnamonNativeStatus() string {
	var status strings.Builder
	for _, item := range cinnamonPackages {
		fmt.Fprintf(&status, "Package: %s\nStatus: install ok installed\nArchitecture: %s\nVersion: %s\nDescription: native fixed tuple\n continued description\n\n", item.name, item.architecture, item.version)
	}
	return status.String()
}

func TestCinnamonReviewedPackageTuple(t *testing.T) {
	want := map[string]string{
		"cinnamon":                 "6.6.4+zena",
		"xdg-desktop-portal":       "1.20.0+ds-2ubuntu1+lindm.lifetime.1",
		"xdg-desktop-portal-xapp":  "1.1.4+lindm.rd.3",
		"libmuffin0":               "6.6.3+lindm.rd.2",
		"muffin":                   "6.6.3+lindm.rd.2",
		"muffin-common":            "6.6.3+lindm.rd.2",
		"cinnamon-screensaver":     "6.6.1+lindm.lock.1",
		"cinnamon-settings-daemon": "6.6.2+lindm.lock.1",
	}
	if len(cinnamonPackages) != len(want) {
		t.Fatal("reviewed tuple does not cover all native packages")
	}
	for _, item := range cinnamonPackages {
		if want[item.name] != item.version {
			t.Fatalf("unreviewed package pin %s=%s", item.name, item.version)
		}
	}
	if err := cinnamonPackageStatus(strings.NewReader(cinnamonNativeStatus())); err != nil {
		t.Fatal(err)
	}
	if err := cinnamonPackageStatus(strings.NewReader(strings.ReplaceAll(cinnamonNativeStatus(), "install ok installed", "hold ok installed"))); err != nil {
		t.Fatal("held but fully installed native packages refused:", err)
	}
}

func TestCinnamonStockAndAmbiguousPackagesRefused(t *testing.T) {
	valid := cinnamonNativeStatus()
	for _, test := range []struct {
		name, old, replacement string
	}{
		{"stock-frontend", "Version: 1.20.0+ds-2ubuntu1+lindm.lifetime.1", "Version: 1.20.0+ds-2ubuntu1"},
		{"stock-portal", "Version: 1.1.4+lindm.rd.3", "Version: 1.1.4"},
		{"stock-compositor", "Version: 6.6.3+lindm.rd.2", "Version: 6.6.3+zena"},
		{"stock-locker", "Version: 6.6.1+lindm.lock.1", "Version: 6.6.1+zena"},
		{"stock-activation", "Version: 6.6.2+lindm.lock.1", "Version: 6.6.2+zena"},
		{"missing-activation", "Package: cinnamon-settings-daemon", "Package: unrelated-daemon"},
		{"not-configured", "Status: install ok installed", "Status: install ok unpacked"},
		{"wrong-architecture", "Architecture: amd64", "Architecture: arm64"},
		{"duplicate-version", "Version: 1.1.4+lindm.rd.3", "Version: 1.1.4+lindm.rd.3\nVersion: 1.1.4+lindm.rd.3"},
		{"duplicate-status", "Status: install ok installed", "Status: install ok installed\nStatus: install ok installed"},
		{"duplicate-architecture", "Architecture: amd64", "Architecture: amd64\nArchitecture: amd64"},
		{"duplicate-identity", "Package: muffin\n", "Package: muffin\nPackage: muffin\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := cinnamonPackageStatus(strings.NewReader(strings.Replace(valid, test.old, test.replacement, 1))); err == nil {
				t.Fatal("unreviewed package tuple admitted")
			}
		})
	}
	for _, data := range []string{"", valid + valid, valid + strings.Repeat("x", 65537)} {
		if err := cinnamonPackageStatus(strings.NewReader(data)); err == nil {
			t.Fatal("missing, duplicate or unbounded package evidence admitted")
		}
	}
}

func TestCinnamonScreensaverTitleMatchesNativeProgram(t *testing.T) {
	for _, command := range []string{"cinnamon-screensaver\x00", "cinnamon-screensaver" + strings.Repeat("\x00", 57)} {
		if !cinnamonScreensaverTitle([]byte(command)) {
			t.Fatal("native rewritten screensaver title refused")
		}
	}
	for _, command := range []string{
		"", "cinnamon-screensaver", "python3\x00", "cinnamon-screensaver-other\x00",
		"cinnamon-screensaver\x00unexpected\x00", "cinnamon-screensaver \x00",
		"/usr/bin/python3\x00/usr/share/cinnamon-screensaver/cinnamon-screensaver-main.py\x00",
	} {
		if cinnamonScreensaverTitle([]byte(command)) {
			t.Fatal("non-native locker title admitted")
		}
	}
}

func TestCinnamonManifestPinsNativeRootChain(t *testing.T) {
	seen := make(map[string]bool)
	for _, artifact := range cinnamonRootFiles {
		if seen[artifact.path] || !strings.HasPrefix(artifact.path, "/") {
			t.Fatal("ambiguous reviewed artifact path:", artifact.path)
		}
		seen[artifact.path] = true
		digest, err := hex.DecodeString(artifact.sha256)
		if err != nil || len(digest) != 32 {
			t.Fatal("invalid reviewed artifact digest:", artifact.path)
		}
		if artifact.mappedProcess < cinnamonNoProcess || artifact.mappedProcess >= cinnamonProcessCount {
			t.Fatal("invalid reviewed artifact process:", artifact.path)
		}
	}
	for _, path := range []string{
		cinnamonPortalPreference,
		"/usr/bin/cinnamon-screensaver",
		"/usr/share/dbus-1/services/org.cinnamon.ScreenSaver.service",
		"/usr/share/cinnamon-screensaver/cinnamon-screensaver-main.py",
		"/usr/share/cinnamon-screensaver/manager.py",
		"/usr/share/cinnamon-screensaver/singletons.py",
		"/usr/share/cinnamon-screensaver/dbusdepot/logindClient.py",
		"/usr/libexec/cinnamon-screensaver/libcscreensaver.so",
		"/usr/libexec/cinnamon-screensaver/girepository-1.0/CScreensaver-1.0.typelib",
		"/usr/libexec/csd-screensaver-proxy",
		"/usr/share/xdg-desktop-portal/portals/xapp-screencast.portal",
		"/usr/lib/systemd/user/xdg-desktop-portal.service.d/50-lindm-native-selection.conf",
	} {
		if !seen[path] {
			t.Fatal("reviewed native activation or lock-reporting artifact missing:", path)
		}
	}
}

func TestCinnamonManifestIdentifiesEachMainImageBeforeItsLibraries(t *testing.T) {
	want := [cinnamonProcessCount]string{
		cinnamonFrontendProcess:   "/usr/libexec/xdg-desktop-portal",
		cinnamonBackendProcess:    "/usr/libexec/xdg-desktop-portal-xapp",
		cinnamonCompositorProcess: "/usr/bin/cinnamon",
		cinnamonProxyProcess:      "/usr/libexec/csd-screensaver-proxy",
		cinnamonLockerProcess:     "/usr/bin/python3.12",
	}
	var actual [cinnamonProcessCount]string
	for _, artifact := range cinnamonRootFiles {
		if role := artifact.mappedProcess; role != cinnamonNoProcess && actual[role] == "" {
			actual[role] = artifact.path
		}
	}
	if actual != want {
		t.Fatalf("first reviewed images = %q; want main executables %q", actual, want)
	}
}
