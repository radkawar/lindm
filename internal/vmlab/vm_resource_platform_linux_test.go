//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// resourceLanePlatforms are the products whose native fixture branches exist.
var resourceLanePlatforms = []struct{ id, version, tool string }{
	{"ubuntu", "22.04", "apt-get"}, {"ubuntu", "24.04", "apt-get"}, {"ubuntu", "26.04", "apt-get"},
	{"debian", "12", "apt-get"}, {"debian", "13", "apt-get"},
	{"fedora", "43", "dnf5"}, {"fedora", "44", "dnf5"},
	{"rhel", "9.8", "dnf"}, {"almalinux", "9.8", "dnf"}, {"rocky", "9.8", "dnf"},
	{"rhel", "10.2", "dnf"}, {"almalinux", "10.2", "dnf"}, {"rocky", "10.2", "dnf"},
	{"almalinux", "8.10", "dnf"}, {"rocky", "8.10", "dnf"},
}

func TestResourceLanePlatformAdmitsOnlyBuiltFixtures(t *testing.T) {
	for _, p := range resourceLanePlatforms {
		if err := manifestRelease(&labv1.ImageManifest{Distribution: p.id, Version: p.version}).LabLane(platform.LaneResources); err != nil {
			t.Errorf("%s %s refused", p.id, p.version)
		}
	}
	for _, p := range [][2]string{{"arch", "rolling"}, {"opensuse-tumbleweed", "20261007"}} {
		if err := manifestRelease(&labv1.ImageManifest{Distribution: p[0], Version: p[1]}).LabLane(platform.LaneResources); err != nil {
			t.Error(err)
		}
	}
	for _, p := range [][2]string{{"ubuntu", "25.10"}, {"ubuntu", "20.04"}, {"debian", "11"}, {"debian", "14"}, {"fedora", "42"}, {"rhel", "8.10"}, {"opensuse-leap", "16.0"}} {
		if manifestRelease(&labv1.ImageManifest{Distribution: p[0], Version: p[1]}).LabLane(platform.LaneResources) == nil {
			t.Errorf("%s %s admitted without a native fixture", p[0], p[1])
		}
	}
}

// Every admitted product reaches its own native package-tool branch of the
// fixture builder, not the refusal; its package format follows the family.
func TestResourceFixtureSelectsNativeToolPerAdmittedPlatform(t *testing.T) {
	start := strings.Index(resourceFixtureScript, `case "$LINDM_RESOURCE_BACKEND:$ID:${VERSION_ID:-}" in`)
	end := strings.Index(resourceFixtureScript, "\nesac\n")
	if start < 0 || end < start {
		t.Fatal("fixture platform selection not found")
	}
	selection := resourceFixtureScript[start:end+len("\nesac\n")] + `case "$ID" in
 ubuntu|debian) echo deb ;;
 *) echo rpm ;;
esac
`
	bin := t.TempDir()
	for _, tool := range []string{"apt-get", "dnf", "dnf5"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho "+tool+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range resourceLanePlatforms {
		cmd := exec.Command("/bin/sh", "-eu", "-c", selection)
		cmd.Env, cmd.Dir = []string{"PATH=" + bin, "ID=" + p.id, "VERSION_ID=" + p.version, "LINDM_RESOURCE_BACKEND="}, t.TempDir()
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v: %s", p.id, p.version, err, output)
		}
		lines := strings.Fields(string(output))
		format := "rpm"
		if p.tool == "apt-get" {
			format = "deb"
		}
		if len(lines) < 2 || lines[0] != p.tool || lines[len(lines)-1] != format {
			t.Fatalf("%s %s selected %q", p.id, p.version, output)
		}
	}
	cmd := exec.Command("/bin/sh", "-eu", "-c", selection)
	cmd.Env, cmd.Dir = []string{"PATH=" + bin, "ID=debian", "VERSION_ID=11", "LINDM_RESOURCE_BACKEND="}, t.TempDir()
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("unbuilt platform accepted: %s", output)
	}
}

func TestResourceLaneScriptsParse(t *testing.T) {
	scripts := map[string]string{
		"fixture": resourceFixtureScript, "password-probe": passwordUnmanagedProbe,
		"link": firewallLinkScript, "native-manager": firewallNativeManagerScript, "host": resourceHostFixtureScript, "root-login": rootRecoveryLoginScript, "crash-watch": firewallCrashWatch,
	}
	for _, manager := range []platform.PAMManager{platform.PAMManagerPamAuthUpdate, platform.PAMManagerAuthselect, platform.PAMManagerNative, platform.PAMManagerPamConfig} {
		script, err := passwordFixtureCommand(manager)
		if err != nil {
			t.Fatal(err)
		}
		scripts["password-"+string(manager)] = script
	}
	for name, script := range scripts {
		cmd := exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", name, err, output)
		}
	}
}

// Installer-built goldens deny root SSH in the lab's own sshd drop-in; the
// password lane's root recovery login turns exactly that line key-only and
// reloads sshd, while a cloud image without the drop-in is left untouched.
func TestRootRecoveryLoginAllowsOnlyKeyRootOnInstallerGoldens(t *testing.T) {
	const conf = "/etc/ssh/sshd_config.d/00-lindm-lab.conf"
	start := strings.Index(rootRecoveryLoginScript, "conf=")
	if start < 0 || !strings.Contains(rootRecoveryLoginScript, conf) {
		t.Fatal("root recovery login no longer edits the lab sshd drop-in")
	}
	original := "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
	for _, tc := range []struct {
		name, content, want string
		reload              bool
	}{
		{"installer", original, strings.Replace(original, "PermitRootLogin no", "PermitRootLogin prohibit-password", 1), true},
		{"cloud", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "00-lindm-lab.conf")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			bin := t.TempDir()
			calls := filepath.Join(dir, "calls")
			if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", "-eu", "-c", strings.ReplaceAll(rootRecoveryLoginScript[start:], conf, path))
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, output)
			}
			got, err := os.ReadFile(path)
			if tc.content == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("cloud image gained a lab sshd drop-in: %q %v", got, err)
				}
			} else if string(got) != tc.want {
				t.Fatalf("sshd drop-in = %q", got)
			}
			reloads, _ := os.ReadFile(calls)
			if (string(reloads) == "reload ssh.service\n") != tc.reload {
				t.Fatalf("sshd reloads = %q", reloads)
			}
		})
	}
}

// Ubuntu 22.04's systemd 249 rejects --kill-whom= (systemd 252's new name for
// --kill-who=), which aborted the package interruption scenario; newer systemd
// keeps the new name.
func TestSystemctlKillOptionFollowsNativeSystemd(t *testing.T) {
	for _, tc := range []struct {
		version, want string
	}{{"249", "kill --kill-who=main --signal=KILL lindm-executor.service"}, {"255", "kill --kill-whom=main --signal=KILL lindm-executor.service"}} {
		bin, dir := t.TempDir(), t.TempDir()
		calls := filepath.Join(dir, "calls")
		stub := "#!/bin/sh\nif [ \"$1\" = --kill-whom=main ] && [ \"$2\" = --version ]; then [ " + tc.version + " -ge 252 ]; exit; fi\nif [ \"$1\" = --kill-who=main ] && [ \"$2\" = --version ]; then exit 0; fi\necho \"$*\" >> " + calls + "\n"
		if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-eu", "-c", "systemctl kill "+systemctlKillWhom+"=main --signal=KILL lindm-executor.service")
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("systemd %s: %v: %s", tc.version, err, output)
		}
		got, err := os.ReadFile(calls)
		if err != nil || strings.TrimSpace(string(got)) != tc.want {
			t.Fatalf("systemd %s ran %q: %v", tc.version, got, err)
		}
	}
}

func TestNativePasswordPrerequisitesUseWholeSnapshotUpgrade(t *testing.T) {
	command, err := passwordFixtureCommand(platform.PAMManagerNative)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "pacman -Syu --needed --noconfirm ") {
		t.Fatal("native PAM prerequisite installation permits an Arch partial upgrade")
	}
}

func TestPasswordConversationBoundariesRejectDefaultPolicyFalsePositive(t *testing.T) {
	for _, managed := range []uint32{14, 16} {
		candidate, err := passwordConversationBoundary(managed)
		if err != nil {
			t.Fatal(err)
		}
		if len(candidate) != int(managed)-1 {
			t.Fatalf("minlen=%d did not probe its immediate boundary", managed)
		}
		// A native minlen=8 stack would accept this candidate, so it cannot
		// satisfy the conversation's required failure for minlen=14 or 16.
		if len(candidate) < 8 {
			t.Fatalf("default native policy also rejects minlen=%d probe", managed)
		}
		classes := 0
		for _, alphabet := range []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"} {
			if strings.ContainsAny(candidate, alphabet) {
				classes++
			}
		}
		if classes != 3 {
			t.Fatalf("minlen=%d candidate violates the independent class policy", managed)
		}
	}
}

func TestPasswordConversationReleaseRejectsRetainedManagedPolicy(t *testing.T) {
	candidate, err := passwordConversationBoundary(0)
	if err != nil {
		t.Fatal(err)
	}
	// This successful ordinary-user change must accept exactly the candidate
	// rejected by the preceding managed minlen=16 conversations.
	managed, err := passwordConversationBoundary(16)
	if err != nil {
		t.Fatal(err)
	}
	if candidate != managed || len(candidate) < 8 || len(candidate) >= 16 {
		t.Fatal("release probe does not distinguish baseline from managed policy")
	}
}
