// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedHyprlandPortalCommandRequiresObservedLoaderInvocation(t *testing.T) {
	// Native Omarchy record reviewed-live-processes.json, backend.cmdline_base64.
	command, err := base64.StdEncoding.DecodeString("L29wdC9saW5kbS1oeXBybGFuZC1wb3J0YWwtcnVudGltZS9iaW4vLi4vbGliL2xkLWxpbnV4LXg4Ni02NC5zby4yAC0tYXJndjAAL29wdC9saW5kbS1oeXBybGFuZC1wb3J0YWwtcnVudGltZS9iaW4veGRnLWRlc2t0b3AtcG9ydGFsLWh5cHJsYW5kAC0tbGlicmFyeS1wYXRoAC9vcHQvbGluZG0taHlwcmxhbmQtcG9ydGFsLXJ1bnRpbWUvYmluLy4uL2xpYgAtLWluaGliaXQtY2FjaGUALS1pbmhpYml0LXJwYXRoAAAvb3B0L2xpbmRtLWh5cHJsYW5kLXBvcnRhbC1ydW50aW1lL2Jpbi94ZGctZGVza3RvcC1wb3J0YWwtaHlwcmxhbmQuZWxmAA==")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(command)
	for _, tc := range []struct {
		name, command string
		ok            bool
	}{
		{"observed_native", valid, true},
		{"preload", strings.Replace(valid, fixedHyprlandPortal, "--preload\x00/home/alice/inject.so\x00"+fixedHyprlandPortal, 1), false},
		{"audit", strings.Replace(valid, fixedHyprlandPortal, "--audit\x00/home/alice/audit.so\x00"+fixedHyprlandPortal, 1), false},
		{"library_override", strings.Replace(valid, "/opt/lindm-hyprland-portal-runtime/bin/../lib\x00", "/home/alice/lib\x00", 1), false},
		{"additional_library_override", strings.Replace(valid, fixedHyprlandPortal, "--library-path\x00/home/alice/lib\x00"+fixedHyprlandPortal, 1), false},
		{"missing_empty_rpath", strings.Replace(valid, "--inhibit-rpath\x00\x00", "--inhibit-rpath\x00", 1), false},
		{"additional_argument", valid + "--preload\x00/home/alice/inject.so\x00", false},
		{"different_loader", strings.Replace(valid, "/opt/lindm-hyprland-portal-runtime/bin/../lib/ld-linux-x86-64.so.2", "/home/alice/ld.so", 1), false},
		{"truncated", strings.TrimSuffix(valid, "\x00"), false},
		{"direct_executable", fixedHyprlandPortal + "\x00", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := fixedHyprlandPortalCommand([]byte(tc.command)); (err == nil) != tc.ok {
				t.Fatalf("invocation admission error = %v; want admitted %v", err, tc.ok)
			}
		})
	}
}

func TestFixedHyprlandShellPIDRequiresUniqueRootConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, listing string
		want          uint32
	}{
		{"reviewed", `[{"config_path":"/usr/share/omarchy/shell/shell.qml","pid":8418}]`, 8418},
		{"no_instance", `[]`, 0},
		{"null", `null`, 0},
		{"zero_pid", `[{"config_path":"/usr/share/omarchy/shell/shell.qml","pid":0}]`, 0},
		{"user_configuration", `[{"config_path":"/home/alice/.config/quickshell/shell.qml","pid":8418}]`, 0},
		{"other_root_configuration", `[{"config_path":"/usr/share/quickshell/shell.qml","pid":8418}]`, 0},
		{"ambiguous_instances", `[{"config_path":"/usr/share/omarchy/shell/shell.qml","pid":8418},{"config_path":"/usr/share/omarchy/shell/shell.qml","pid":8419}]`, 0},
		{"malformed", `[`, 0},
		{"negative_pid", `[{"config_path":"/usr/share/omarchy/shell/shell.qml","pid":-1}]`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fixedHyprlandShellPID([]byte(tc.listing))
			if tc.want == 0 {
				if err == nil {
					t.Fatalf("unreviewed instance admitted with PID %d", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PID = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestFixedHyprlandShellEnvironmentRejectsSourceOverrides(t *testing.T) {
	const home = "/home/alice"
	const display = "wayland-1"
	base := "HOME=" + home + "\x00WAYLAND_DISPLAY=" + display + "\x00OMARCHY_PATH=/usr/share/omarchy\x00USER=alice\x00XDG_SESSION_ID=4\x00"
	for _, tc := range []struct {
		name, environment, wantHome, wantDisplay string
		ok                                       bool
	}{
		{"reviewed", base, home, display, true},
		{"standard_config_home", base + "XDG_CONFIG_HOME=/home/alice/.config\x00", home, display, true},
		{"other_source", strings.Replace(base, "OMARCHY_PATH=/usr/share/omarchy", "OMARCHY_PATH=/home/alice/omarchy", 1), home, display, false},
		{"other_display", base, home, "wayland-2", false},
		{"other_home", base, "/home/bob", display, false},
		{"relative_home", strings.Replace(base, "HOME=/home/alice", "HOME=alice", 1), "alice", display, false},
		{"empty_display", base, home, "", false},
		{"qml_import_override", base + "QML_IMPORT_PATH=/home/alice/qml\x00", home, display, false},
		{"qml2_import_override", base + "QML2_IMPORT_PATH=/home/alice/qml\x00", home, display, false},
		{"qt_plugin_override", base + "QT_PLUGIN_PATH=/home/alice/plugins\x00", home, display, false},
		{"loader_override", base + "LD_PRELOAD=/home/alice/inject.so\x00", home, display, false},
		{"loader_audit_override", base + "LD_AUDIT=/home/alice/audit.so\x00", home, display, false},
		{"library_override", base + "LD_LIBRARY_PATH=/home/alice/lib\x00", home, display, false},
		{"config_override", base + "XDG_CONFIG_HOME=/tmp/config\x00", home, display, false},
		{"duplicate_identity", base + "HOME=/home/alice\x00", home, display, false},
		{"malformed", base + "not-an-assignment\x00", home, display, false},
		{"missing_pam_user", strings.Replace(base, "USER=alice\x00", "", 1), home, display, false},
		{"missing_logind_session", strings.Replace(base, "XDG_SESSION_ID=4\x00", "", 1), home, display, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fixedHyprlandShellEnvironment([]byte(tc.environment), tc.wantHome, tc.wantDisplay)
			if !tc.ok {
				if err == nil {
					t.Fatalf("unreviewed environment admitted with home %q", got)
				}
				return
			}
			if err != nil || got != home {
				t.Fatalf("home = %q, %v; want %q", got, err, home)
			}
		})
	}
}

func TestFixedHyprlandShellConfigRejectsDisabledOrSubstitutedLocker(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		ok           bool
	}{
		{"stock_shape", `{"version":1,"idle":{"lock":300},"plugins":[]}`, true},
		{"other_builtin_disabled", `{"version":1,"disabledPlugins":["omarchy.weather"],"plugins":[]}`, true},
		{"lock_disabled", `{"version":1,"disabledPlugins":["omarchy.lock"]}`, false},
		{"short_lock_disabled", `{"version":1,"disabledPlugins":["lock"]}`, false},
		{"whitespace_lock_disabled", `{"version":1,"disabledPlugins":[" omarchy.lock "]}`, false},
		{"replacement_service", `{"version":1,"plugins":[{"id":"local.lock"}]}`, false},
		{"other_user_service", `{"version":1,"plugins":["local.plugin"]}`, false},
		{"unknown_version", `{"version":2}`, false},
		{"missing_version", `{}`, false},
		{"null", `null`, false},
		{"wrong_disabled_type", `{"version":1,"disabledPlugins":"omarchy.lock"}`, false},
		{"malformed", `{`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := fixedHyprlandShellConfig([]byte(tc.config))
			if (err == nil) != tc.ok {
				t.Fatalf("configuration admission error = %v; want admitted %v", err, tc.ok)
			}
		})
	}
}

func TestFixedHyprlandNoUserPluginsChecksBoundedDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := fixedHyprlandNoUserPlugins(directory); err != nil {
		t.Fatalf("empty user plugin directory refused: %v", err)
	}
	if err := fixedHyprlandNoUserPlugins(filepath.Join(directory, "absent")); err != nil {
		t.Fatalf("absent user plugin directory refused: %v", err)
	}
	entry := filepath.Join(directory, "local.lock")
	if err := os.WriteFile(entry, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := fixedHyprlandNoUserPlugins(directory); err == nil {
		t.Fatal("user plugin entry admitted")
	}
	if err := fixedHyprlandNoUserPlugins(entry); err == nil {
		t.Fatal("regular file substituted for plugin directory admitted")
	}
}
