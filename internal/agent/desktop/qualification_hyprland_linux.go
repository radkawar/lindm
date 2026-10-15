// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
)

const (
	fixedHyprlandBackend  = "org.freedesktop.impl.portal.desktop.hyprland"
	fixedHyprlandFrontend = "/usr/lib/xdg-desktop-portal"
	fixedHyprlandPortal   = "/opt/lindm-hyprland-portal-runtime/bin/xdg-desktop-portal-hyprland.elf"
	fixedHyprlandLoader   = "/opt/lindm-hyprland-portal-runtime/lib/ld-linux-x86-64.so.2"
	fixedOmarchyShell     = "/usr/share/omarchy/shell/shell.qml"
	fixedQuickshell       = "/usr/bin/quickshell"
)

var fixedHyprlandRootFiles = [...]struct {
	path, sha string
	consumer  string
}{
	{"/etc/os-release", "e2376e8da5ce0d34cd64640e1ae934252315fef833f0db8e2ecc41bcf7238ccf", ""},
	{fixedHyprlandFrontend, "e1429fbe1bf6c2203ba07f478b9e92e9221437b13a92eebafb0982748583a4f8", "frontend"},
	{fixedHyprlandPortal, "5eb6bd7f944e1b5fa5d04311ce553631bf096a9a3f2c50980d0472d479547457", "portal"},
	{fixedHyprlandLoader, "f5e11cc62f8f2c24dff532982559f4303dba3b17e7450551372a88c8e7ea8757", "portal"},
	{"/usr/share/xdg-desktop-portal/hyprland-portals.conf", "aa061ba0530569907cf280870cc2b86333e0d7c2965d9ac020f5b3e05e9bd2e2", "frontend"},
	{"/usr/share/xdg-desktop-portal/portals/hyprland.portal", "054d52a93274bcf6a7c79cf42938cfb33c721d303bb0965f3b592155fa461d77", "frontend"},
	{fixedQuickshell, "2dc99382c032710fe495ed115cdee9dc9c69bdb3a21af4d86a9a8ea16733069b", "shell"},
	{fixedOmarchyShell, "4a4b7694e5b9e0bd952ce0efa2d6dc2cea44cdfa98cc2f442e40fe41cbc1beab", "shell"},
	{"/usr/share/omarchy/shell/services/PluginRegistry.qml", "8466127c53037b80b582544610b0bdf78a86764e4f037a3b9ce360d107359803", "shell"},
	{"/usr/share/omarchy/config/omarchy/shell.json", "b16dc9646bf68e81643522cef504795d97cb5016d80d8b65784bde44f2c0883f", "shell"},
	{"/usr/share/omarchy/shell/Ui/Button.qml", "fda48672cc11dba109acea1cc98eb4b29746e5ce09f90a47f487b776ff99e799", "shell"},
	{"/usr/share/omarchy/shell/Ui/BorderSurface.qml", "e17d8150d0b0e60f431bd6df5e661f5d9fe1f5eec9c2e2420f6eff2179a45baf", "shell"},
	{"/usr/share/omarchy/shell/plugins/notifications/Service.qml", "6bd0c86bcf814a23b578ae1e7be4b575151ce41a25350e686bd8fa544b239b97", "shell"},
	{"/usr/share/omarchy/shell/plugins/notifications/NotificationLogic.js", "db0f4b680f6b40d8a54d300371765d9629df1f9f47c2925bceebe31494d91c9d", "shell"},
	{"/usr/share/omarchy/shell/plugins/notifications/components/NotificationCard.qml", "366a5aa93e3753dacaca5147239cd8abb29044e142dcb77be39aa03c3197041b", "shell"},
	{"/usr/share/omarchy/shell/plugins/lock/manifest.json", "58af8610a79045dfc09b541a5c2fdfd2e8886624549a49114ba424b4833cc546", "shell"},
	{"/usr/share/omarchy/shell/plugins/lock/Service.qml", "25be2b64fbf2cd1928a8e9c03fe62bdb35fffa942a5635a4b3252795dd81b852", "shell"},
	{"/usr/share/omarchy/shell/plugins/lock/login-session.sh", "f338b0df710df14d014d3bb5a81da12caa2862c0f76f1bdc74366cfe3dd8b0ce", "shell"},
	{"/usr/share/omarchy/shell/plugins/lock/watch-login-session.sh", "85d4d79eb2748a7557d23014eb8d3dfb9ca6ade578d3d299b465bbc0d275c07d", "shell"},
}

// This is the individually deployed Omarchy 4.0.4 / Quickshell 0.3.1 tuple,
// not a claim about stock Omarchy or another Hyprland locker. The portal ELF
// is fork commit 0adbaa4433771019c7030f5f2853fae450dcd76b, based on PR 426.
// Root configuration and the live processes must agree with the reviewed files.
func (q *FixedDesktopVerifier) verifyHyprland(ctx context.Context) error {
	frontendPID, err := q.fixedPortalSelection(ctx, "Hyprland", "/usr/share/xdg-desktop-portal/hyprland-portals.conf")
	if err != nil {
		return err
	}
	var frontend, portal, loader, shellBinary fixedRuntimeArtifact
	var portalDeployed, frontendDeployed, shellDeployed time.Time
	for _, item := range fixedHyprlandRootFiles {
		artifact, err := fixedRootArtifact(item.path, item.sha)
		if err != nil {
			return err
		}
		if item.path == fixedHyprlandFrontend {
			frontend = artifact
		}
		if item.path == fixedHyprlandPortal {
			portal = artifact
		}
		if item.path == fixedHyprlandLoader {
			loader = artifact
		}
		if item.path == fixedQuickshell {
			shellBinary = artifact
		}
		switch item.consumer {
		case "portal":
			if artifact.modified.After(portalDeployed) {
				portalDeployed = artifact.modified
			}
		case "frontend":
			if artifact.modified.After(frontendDeployed) {
				frontendDeployed = artifact.modified
			}
		case "shell":
			if artifact.modified.After(shellDeployed) {
				shellDeployed = artifact.modified
			}
		}
	}
	if err := fixedProcessExecutableArtifact(frontendPID, frontend); err != nil {
		return err
	}
	if err := fixedProcessAfter(frontendPID, frontendDeployed); err != nil {
		return err
	}
	backendPID, err := q.fixedBackendPID(ctx, fixedHyprlandBackend)
	if err != nil {
		return err
	}
	if err := fixedProcessExecutableArtifact(backendPID, loader); err != nil {
		return err
	}
	command, err := fixedReadProc(fmt.Sprintf("/proc/%d/cmdline", backendPID), 4096)
	if err != nil {
		return err
	}
	if err := fixedHyprlandPortalCommand(command); err != nil {
		return err
	}
	if err := fixedProcessMapsArtifact(backendPID, portal); err != nil {
		return err
	}
	if err := fixedProcessAfter(backendPID, portalDeployed); err != nil {
		return err
	}
	listing, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: fixedQuickshell, Args: []string{"list", "-a", "-j"},
		Timeout: 10 * time.Second, StdoutLimit: 64 << 10, StderrLimit: 4 << 10,
	})
	if err != nil {
		return fmt.Errorf("identify active Omarchy shell: %w", err)
	}
	shellPID, err := fixedHyprlandShellPID(listing.Stdout)
	if err != nil {
		return err
	}
	if err := fixedProcessExecutableArtifact(shellPID, shellBinary); err != nil {
		return err
	}
	if err := fixedProcessMapsArtifact(shellPID, shellBinary); err != nil {
		return err
	}
	if err := fixedProcessAfter(shellPID, shellDeployed); err != nil {
		return err
	}
	environ, err := fixedReadProc(fmt.Sprintf("/proc/%d/environ", shellPID), 1<<20)
	if err != nil {
		return err
	}
	home, err := fixedHyprlandShellEnvironment(environ, os.Getenv("HOME"), os.Getenv("WAYLAND_DISPLAY"))
	if err != nil {
		return err
	}
	if err := fixedHyprlandNoUserPlugins(filepath.Join(home, ".config/omarchy/plugins")); err != nil {
		return err
	}
	config, err := fixedReadProc(filepath.Join(home, ".config/omarchy/shell.json"), 64<<10)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := fixedHyprlandShellConfig(config); err != nil {
			return err
		}
	}
	// Do not accept a replacement backend that appeared during source proof.
	currentPID, err := q.fixedBackendPID(ctx, fixedHyprlandBackend)
	if err != nil {
		return err
	}
	if currentPID != backendPID {
		return errors.New("hyprland backend changed during qualification")
	}
	return q.fixedHyprlandNotificationOwner(ctx, shellPID)
}

// The reviewed consent QML must belong to the actual notification server, not
// an unrelated Quickshell instance. The bus resolves the well-known name and
// connection credentials atomically; the shell's image and environment have
// already been checked above.
func (q *FixedDesktopVerifier) fixedHyprlandNotificationOwner(ctx context.Context, shellPID uint32) error {
	var pid uint32
	if err := q.bus.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, notificationsName).Store(&pid); err != nil {
		return fmt.Errorf("identify reviewed shell notification owner: %w", err)
	}
	if pid != shellPID {
		return errors.New("notification server is not the reviewed shell process")
	}
	return nil
}

// Match the native observed invocation byte-for-byte, including its empty
// --inhibit-rpath argument. Environment checks alone do not reject ld.so's
// --preload, --audit or additional --library-path command-line overrides.
func fixedHyprlandPortalCommand(data []byte) error {
	const command = "/opt/lindm-hyprland-portal-runtime/bin/../lib/ld-linux-x86-64.so.2\x00" +
		"--argv0\x00/opt/lindm-hyprland-portal-runtime/bin/xdg-desktop-portal-hyprland\x00" +
		"--library-path\x00/opt/lindm-hyprland-portal-runtime/bin/../lib\x00" +
		"--inhibit-cache\x00--inhibit-rpath\x00\x00" + fixedHyprlandPortal + "\x00"
	if !bytes.Equal(data, []byte(command)) {
		return errors.New("hyprland backend has an unreviewed explicit-loader invocation")
	}
	return nil
}

func fixedHyprlandShellPID(data []byte) (uint32, error) {
	var instances []struct {
		ConfigPath string `json:"config_path"`
		PID        uint32 `json:"pid"`
	}
	if err := json.Unmarshal(data, &instances); err != nil {
		return 0, fmt.Errorf("decode active Quickshell instances: %w", err)
	}
	if len(instances) != 1 || instances[0].PID == 0 || instances[0].ConfigPath != fixedOmarchyShell {
		return 0, errors.New("active Quickshell does not uniquely use the reviewed root Omarchy config")
	}
	return instances[0].PID, nil
}

func fixedHyprlandNoUserPlugins(path string) (err error) {
	directory, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	_, err = directory.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("unreviewed Omarchy user plugins are installed")
}

func fixedHyprlandShellEnvironment(data []byte, wantHome, wantDisplay string) (string, error) {
	values := make(map[string]string, 12)
	for field := range bytes.SplitSeq(data, []byte{0}) {
		if len(field) == 0 {
			continue
		}
		key, value, ok := bytes.Cut(field, []byte{'='})
		if !ok {
			return "", errors.New("invalid Omarchy process environment")
		}
		switch string(key) {
		case "HOME", "WAYLAND_DISPLAY", "OMARCHY_PATH", "QML_IMPORT_PATH", "QML2_IMPORT_PATH", "QT_PLUGIN_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "XDG_CONFIG_HOME", "USER", "XDG_SESSION_ID":
		default:
			continue
		}
		name := string(key)
		if _, duplicate := values[name]; duplicate {
			return "", errors.New("ambiguous Omarchy process environment")
		}
		values[name] = string(value)
	}
	if values["OMARCHY_PATH"] != "/usr/share/omarchy" || wantHome == "" || !filepath.IsAbs(wantHome) || values["HOME"] != wantHome || wantDisplay == "" || values["WAYLAND_DISPLAY"] != wantDisplay {
		return "", errors.New("omarchy shell source or graphical session differs from the reviewed tuple")
	}
	for _, key := range [...]string{"QML_IMPORT_PATH", "QML2_IMPORT_PATH", "QT_PLUGIN_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		if values[key] != "" {
			return "", fmt.Errorf("omarchy shell has an unreviewed %s override", key)
		}
	}
	if value := values["XDG_CONFIG_HOME"]; value != "" && value != filepath.Join(wantHome, ".config") {
		return "", errors.New("omarchy shell has an unreviewed configuration home")
	}
	if value := values["USER"]; value == "" {
		return "", errors.New("omarchy shell has no PAM username")
	}
	if value := values["XDG_SESSION_ID"]; value == "" {
		return "", errors.New("omarchy shell has no logind session identity")
	}
	return wantHome, nil
}

func fixedHyprlandShellConfig(data []byte) error {
	var config struct {
		Version  int               `json:"version"`
		Disabled []string          `json:"disabledPlugins"`
		Plugins  []json.RawMessage `json:"plugins"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("decode Omarchy shell configuration: %w", err)
	}
	if config.Version != 1 || len(config.Plugins) != 0 {
		return errors.New("unreviewed Omarchy shell configuration or user services")
	}
	for _, disabled := range config.Disabled {
		if value := strings.TrimSpace(disabled); value == "lock" || value == "omarchy.lock" {
			return errors.New("reviewed Omarchy lock plugin is disabled")
		}
	}
	return nil
}
