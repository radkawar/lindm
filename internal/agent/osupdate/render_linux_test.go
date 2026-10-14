// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"errors"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestRenderAPTMain(t *testing.T) {
	security := string(renderAPTMain(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, true, []packageKey{{"libstdc++6", "amd64"}, {"libstdc++6", "i386"}, {"python3.12", "amd64"}}))
	want := `// lindm os-update per-run unattended-upgrade policy.
#include "/etc/apt/apt.conf";
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
	"${distro_id}ESMApps:${distro_codename}-apps-security";
	"${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
	"^libstdc[+][+]6$";
	"^python3[.]12$";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::MinimalSteps "true";
`
	if security != want {
		t.Fatalf("security main:\n%s\nwant:\n%s", security, want)
	}
	all := string(renderAPTMain(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, false, nil))
	if strings.Contains(all, "#include") || strings.Contains(all, "Package-Blacklist") ||
		!strings.Contains(all, "\t\"${distro_id}:${distro_codename}-updates\";\n\t\"${distro_id}:${distro_codename}\";\n") {
		t.Fatalf("all main:\n%s", all)
	}
	if got := string(renderAPTConfig(aptMainPath)); got != "// lindm os-update per-run APT configuration.\nDir::Etc::main \"/run/lindm-os-update/apt-main.conf\";\n" {
		t.Fatalf("APT_CONFIG = %q", got)
	}
}

func TestRenderDNFAutomatic(t *testing.T) {
	got := string(renderDNFAutomatic(resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, []packageKey{{"kernel", "x86_64"}, {"tzdata", "noarch"}}))
	want := "# lindm os-update per-run dnf-automatic configuration.\n[commands]\nupgrade_type = security\nrandom_sleep = 0\nnetwork_online_timeout = 60\ndownload_updates = yes\napply_updates = yes\nreboot = never\n[emitters]\nemit_via = stdio\n[base]\nexcludepkgs = kernel.x86_64,tzdata.noarch\n"
	if got != want {
		t.Fatalf("dnf-automatic config:\n%s\nwant:\n%s", got, want)
	}
	// An empty excludepkgs value would clear dnf.conf's excludes.
	if got := string(renderDNFAutomatic(resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, nil)); strings.Contains(got, "excludepkgs") || !strings.Contains(got, "upgrade_type = default\n") {
		t.Fatalf("all config:\n%s", got)
	}
}

func TestDNF5ExcludeArgsStayBelowArgumentLimit(t *testing.T) {
	if args := dnf5ExcludeArgs(nil); len(args) != 0 {
		t.Fatalf("empty excludes rendered %v", args)
	}
	keys := make([]packageKey, 0, maxLedger)
	for i := range maxLedger {
		keys = append(keys, packageKey{name: "package-with-a-long-name-" + strings.Repeat("x", 40) + string(rune('a'+i%26)), arch: "x86_64"})
	}
	args := dnf5ExcludeArgs(keys)
	if len(args) < 2 {
		t.Fatalf("expected several arguments, got %d", len(args))
	}
	total := 0
	for _, arg := range args {
		if len(arg) > maxExcludeArg+len("--exclude=") || !strings.HasPrefix(arg, "--exclude=") || strings.HasSuffix(arg, "=") {
			t.Fatalf("argument of %d bytes", len(arg))
		}
		total += strings.Count(arg, ",") + 1
	}
	if total != len(keys) {
		t.Fatalf("excluded %d of %d", total, len(keys))
	}
}

func TestEffectiveDNF5AutomaticReadOrder(t *testing.T) {
	shipped := []byte("[commands]\nupgrade_type = default\napply_updates = no\nreboot = never\n[emitters]\nemit_via = stdio\n")
	deprecated := []byte("[commands]\nreboot = when-needed\n[emitters]\nemit_via = email\n")
	owned := []byte("# Managed by lindm os.update.v1.\n[commands]\nupgrade_type = security\nrandom_sleep = 0\ndownload_updates = yes\napply_updates = yes\nreboot = never\nnetwork_online_timeout = 60\n[emitters]\nemit_via = stdio\n")
	security := resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY
	if err := checkDNF5Automatic(effectiveDNF5Automatic(shipped, deprecated, owned), security); err != nil {
		t.Fatalf("owned file must win: %v", err)
	}
	if err := checkDNF5Automatic(effectiveDNF5Automatic(shipped, owned), resourcev1.UpdateSelection_UPDATE_SELECTION_ALL); !errors.Is(err, errDNF5AutomaticConfig) {
		t.Fatalf("selection mismatch = %v", err)
	}
	// Without the owned file the deprecated reboot and mail settings win.
	if err := checkDNF5Automatic(effectiveDNF5Automatic(shipped, deprecated), resourcev1.UpdateSelection_UPDATE_SELECTION_ALL); !errors.Is(err, errDNF5AutomaticConfig) {
		t.Fatalf("native reboot accepted: %v", err)
	}
	if err := checkDNF5Automatic(effectiveDNF5Automatic(shipped, []byte("[emitters]\nemit_via = stdio,command_email\n")), resourcev1.UpdateSelection_UPDATE_SELECTION_ALL); !errors.Is(err, errDNF5AutomaticConfig) {
		t.Fatalf("command emitter accepted: %v", err)
	}
	if err := checkDNF5Automatic(effectiveDNF5Automatic(shipped, []byte("[emitters]\nemit_via = stdio motd\n")), resourcev1.UpdateSelection_UPDATE_SELECTION_ALL); err != nil {
		t.Fatalf("local emitters rejected: %v", err)
	}
}

func TestNativeDiagnosticIsSanitizedAndBounded(t *testing.T) {
	stdout := newOutputCapture()
	stderr := newOutputCapture()
	_, _ = stdout.Write([]byte("Reading package lists...\nGet:1 http://mirroruser:s3cr3tpw@mirror.example/ubuntu noble-security InRelease [126 kB]\n\x1b]8;;http://evil.example\x07click\x1b]8;;\x07 here \x1b[31mred\x1b[0m\n"))
	_, _ = stderr.Write([]byte("E: Failed to fetch https://esm.ubuntu.com/apps/ubuntu/dists/noble-apps-security/InRelease  401  Unauthorized\nhttp_proxy=http://proxy:3128\nPassword: hunter2\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----\n" + strings.Repeat("é", 400) + "\nline a\nline b\nline c\nE: Sub-process /usr/bin/dpkg returned an error code (1)\n"))
	diagnostic := nativeDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_UNATTENDED_UPGRADE, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, 1, stdout, stderr)
	if len(diagnostic.GetErrorLines()) != diagnosticLines || !diagnostic.GetTruncated() || diagnostic.GetExitCode() != 1 {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
	if last := diagnostic.GetErrorLines()[diagnosticLines-1]; last != "E: Sub-process /usr/bin/dpkg returned an error code (1)" {
		t.Fatalf("final native error lost: %q", last)
	}
	for _, line := range append(diagnostic.GetErrorLines(), sanitizeLinesOnly(t, stdout)...) {
		for _, leaked := range []string{"s3cr3tpw", "mirroruser", "hunter2", "lQOYBF", "evil.example", "proxy:3128", "\x1b", "esm.ubuntu.com"} {
			if strings.Contains(line, leaked) {
				t.Errorf("leaked %q in %q", leaked, line)
			}
		}
		if len(line) > diagnosticLineBytes {
			t.Errorf("line of %d bytes", len(line))
		}
	}
	if got := sanitizeLinesOnly(t, stdout); got[1] != "Get:1 [redacted-url] noble-security InRelease [126 kB]" || got[2] != "click here red" {
		t.Fatalf("sanitized stdout = %q", got)
	}
}

func sanitizeLinesOnly(t *testing.T, capture *outputCapture) []string {
	t.Helper()
	lines, _ := sanitizeLines(capture.tailLines())
	return lines
}

func TestOutputCaptureKeepsCompleteTailLines(t *testing.T) {
	capture := newOutputCapture()
	_, _ = capture.Write([]byte("0123456789"))
	_, _ = capture.Write([]byte(strings.Repeat("x", outputTailBytes) + "\nfinal error\n"))
	if !capture.cut() || capture.buf.Len() != outputTailBytes {
		t.Fatalf("tail = %d cut=%v", capture.buf.Len(), capture.cut())
	}
	lines := capture.tailLines()
	if lines[0] != "final error" {
		t.Fatalf("partial first line kept: %q", lines[0][:min(16, len(lines[0]))])
	}
}
