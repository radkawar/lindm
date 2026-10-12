//go:build linux

package osupdate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// Every Ubuntu row carries the registry's reboot signal, so the runner does
// not need needrestart: the stock Ubuntu 24.04 desktop ships
// update-notifier-common but not needrestart
// (ubuntu-24.04.5.1-desktop-amd64.manifest).
func TestDetectBackendCarriesUbuntuRebootSignal(t *testing.T) {
	for _, version := range []string{"22.04", "24.04", "26.04"} {
		native, err := detectBackend([]byte("ID=ubuntu\nVERSION_ID=\"" + version + "\"\n"))
		apt, ok := native.(aptBackend)
		if err != nil || !ok || apt.needrestart != needrestartPath || apt.signal == nil {
			t.Fatalf("ubuntu %s backend = %#v, %v", version, native, err)
		}
		if apt.signal.Marker != "/run/reboot-required" || apt.signal.Package != "update-notifier-common" || len(apt.signal.Writers) != 2 {
			t.Fatalf("ubuntu %s reboot signal = %+v", version, apt.signal)
		}
	}
}

// fixtureSignal lays out update-notifier-common's writers as the noble
// 3.192.68.2 deb ships them: an executable script and the kernel
// postinst.d symlink to it.
func fixtureSignal(t *testing.T) (string, *platform.RebootSignal) {
	t.Helper()
	root := t.TempDir()
	script := filepath.Join(root, "usr/share/update-notifier/notify-reboot-required")
	hook := filepath.Join(root, "etc/kernel/postinst.d/update-notifier")
	for _, dir := range []string{filepath.Dir(script), filepath.Dir(hook), filepath.Join(root, "run")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(script, hook); err != nil {
		t.Fatal(err)
	}
	return root, &platform.RebootSignal{Marker: filepath.Join(root, "run/reboot-required"), Package: "update-notifier-common", Writers: []string{script, hook}}
}

func TestAPTRebootSignalWithoutNeedrestart(t *testing.T) {
	root, signal := fixtureSignal(t)
	b := aptBackend{needrestart: filepath.Join(root, "usr/sbin/needrestart"), signal: signal}
	if tool, pkg := b.missingOracle(); pkg != "" {
		t.Fatalf("installed marker writers refused: %v %q", tool, pkg)
	}
	if required, err := b.rebootRequired(t.Context()); err != nil || required {
		t.Fatalf("absent marker = %v, %v", required, err)
	}
	if err := os.WriteFile(signal.Marker, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if required, err := b.rebootRequired(t.Context()); err != nil || !required {
		t.Fatalf("present marker = %v, %v", required, err)
	}
}

// An absent marker proves nothing once a writer is gone: a kernel installed
// without its postinst.d hook leaves no marker.
func TestAPTRebootSignalNeedsEveryWriter(t *testing.T) {
	for name, drop := range map[string]func(*platform.RebootSignal) error{
		"hook removed":          func(s *platform.RebootSignal) error { return os.Remove(s.Writers[1]) },
		"script not executable": func(s *platform.RebootSignal) error { return os.Chmod(s.Writers[0], 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			root, signal := fixtureSignal(t)
			b := aptBackend{needrestart: filepath.Join(root, "usr/sbin/needrestart"), signal: signal}
			if err := drop(signal); err != nil {
				t.Fatal(err)
			}
			if tool, pkg := b.missingOracle(); tool != agentv1.PatchRunTool_PATCH_RUN_TOOL_UPDATE_NOTIFIER || pkg != "update-notifier-common" {
				t.Fatalf("missing writer = %v %q", tool, pkg)
			}
			var failed *nativeFailure
			if _, err := b.rebootRequired(t.Context()); !errors.As(err, &failed) || failed.reason != reasonOracleFailed {
				t.Fatalf("oracle without writers = %v", err)
			}
		})
	}
	// A release without a registry signal still names needrestart.
	if tool, pkg := (aptBackend{needrestart: filepath.Join(t.TempDir(), "needrestart")}).missingOracle(); tool != agentv1.PatchRunTool_PATCH_RUN_TOOL_NEEDRESTART || pkg != "needrestart" {
		t.Fatalf("no signal = %v %q", tool, pkg)
	}
}

func TestAPTRebootSignalUnreadableMarker(t *testing.T) {
	root, signal := fixtureSignal(t)
	blocker := filepath.Join(root, "run/blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	signal.Marker = filepath.Join(blocker, "reboot-required")
	b := aptBackend{needrestart: filepath.Join(root, "usr/sbin/needrestart"), signal: signal}
	var failed *nativeFailure
	if _, err := b.rebootRequired(t.Context()); !errors.As(err, &failed) || failed.reason != reasonOracleFailed {
		t.Fatalf("unreadable marker = %v", err)
	}
}
