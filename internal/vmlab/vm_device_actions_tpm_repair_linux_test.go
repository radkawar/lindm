//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestValidateEncryptionPhase(t *testing.T) {
	tpm := EncryptedVMOptions{Hardware: &VMHardwareOptions{TPM: true}}
	const revision = "ced6d20902921a0ff66fd9a87085400fac006b08"
	for _, test := range []struct {
		name    string
		options VMDeviceActionsOptions
		valid   bool
	}{
		{"all phases", VMDeviceActionsOptions{Scenario: "encryption", TPMBoots: 1}, true},
		{"tpm boots", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm", TPMBoots: 30}, true},
		{"repair boots", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 30, LegacyAgentRevision: revision, Encrypted: tpm}, true},
		{"repair ref name", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, LegacyAgentRevision: "release/0.1", Encrypted: tpm}, true},
		{"unknown phase", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-other"}, false},
		{"repair outside encryption", VMDeviceActionsOptions{Scenario: "wipe", EncryptionPhase: "tpm-repair", LegacyAgentRevision: revision, Encrypted: tpm}, false},
		{"boots without phase", VMDeviceActionsOptions{Scenario: "encryption", TPMBoots: 2}, false},
		{"too many boots", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: maxTPMBoots + 1, LegacyAgentRevision: revision, Encrypted: tpm}, false},
		{"repair without revision", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, Encrypted: tpm}, false},
		{"revision without repair", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm", TPMBoots: 1, LegacyAgentRevision: revision}, false},
		{"revision option", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, LegacyAgentRevision: "--output=/tmp/x", Encrypted: tpm}, false},
		{"revision range", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, LegacyAgentRevision: "main..HEAD", Encrypted: tpm}, false},
		{"revision expression", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, LegacyAgentRevision: "HEAD^", Encrypted: tpm}, false},
		{"repair without TPM", VMDeviceActionsOptions{Scenario: "encryption", EncryptionPhase: "tpm-repair", TPMBoots: 1, LegacyAgentRevision: revision, Encrypted: EncryptedVMOptions{Hardware: &VMHardwareOptions{}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateEncryptionPhase(test.options); (err == nil) != test.valid {
				t.Fatalf("validateEncryptionPhase = %v, want valid %v", err, test.valid)
			}
		})
	}
}

// legacyGitRepository is a one-commit checkout whose working tree has since
// diverged, so an export proves it reads the commit, not the files.
func legacyGitRepository(t *testing.T) (repository, commit string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repository = t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repository, "-c", "user.name=lab", "-c", "user.email=lab@example.invalid"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if err := os.MkdirAll(filepath.Join(repository, "cmd", "lindm-agent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "cmd", "lindm-agent", "main.go"), []byte("legacy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "legacy")
	commit = git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repository, "cmd", "lindm-agent", "main.go"), []byte("current\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return repository, commit
}

func TestExportLegacySourceReadsTheCommit(t *testing.T) {
	repository, commit := legacyGitRepository(t)
	work := t.TempDir()
	resolved, source, err := exportLegacySource(t.Context(), repository, commit[:12], work)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != commit || source != filepath.Join(work, "legacy-source") {
		t.Fatalf("export = %s %s, want %s under %s", resolved, source, commit, work)
	}
	data, err := os.ReadFile(filepath.Join(source, "cmd", "lindm-agent", "main.go"))
	if err != nil || string(data) != "legacy\n" {
		t.Fatalf("exported %q, %v; want the committed legacy tree", data, err)
	}
	if info, err := os.Stat(source); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("export directory is not private: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(work, "legacy-source.tar")); !os.IsNotExist(err) {
		t.Fatalf("intermediate archive retained: %v", err)
	}
}

func TestExportLegacySourceRefusals(t *testing.T) {
	repository, commit := legacyGitRepository(t)
	plain := t.TempDir()
	for _, test := range []struct{ name, repository, revision, want string }{
		{"not a checkout", plain, commit, "is not a git checkout"},
		{"checkout subdirectory", filepath.Join(repository, "cmd"), commit, "is not the root of a git checkout"},
		{"unresolved revision", repository, strings.Repeat("0", 40), "does not resolve to a commit"},
		{"unknown ref", repository, "no-such-branch", "does not resolve to a commit"},
		{"option", repository, "--output=x", "is not a commit ID or ref name"},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := t.TempDir()
			_, _, err := exportLegacySource(t.Context(), test.repository, test.revision, work)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("export error = %v, want %q", err, test.want)
			}
			if _, err := os.Stat(filepath.Join(work, "legacy-source")); !os.IsNotExist(err) {
				t.Fatalf("refused export left source: %v", err)
			}
		})
	}
}

func tpm2Token(id uint32, keyslots ...uint32) *agentv1.LUKSTokenObservation {
	return &agentv1.LUKSTokenObservation{TokenId: id, Type: "systemd-tpm2", Keyslots: keyslots}
}

func TestTPMBoundKeyslot(t *testing.T) {
	recovery := &agentv1.LUKSTokenObservation{TokenId: 0, Type: "lindm-recovery", Keyslots: []uint32{0}}
	slot, references, err := tpmBoundKeyslot([]*agentv1.LUKSTokenObservation{recovery, tpm2Token(1, 2), tpm2Token(2, 2)})
	if err != nil || slot != 2 || references != 2 {
		t.Fatalf("bound keyslot = %d x%d, %v", slot, references, err)
	}
	for name, tokens := range map[string][]*agentv1.LUKSTokenObservation{
		"none":           {recovery},
		"several slots":  {tpm2Token(1, 1, 2)},
		"different slot": {tpm2Token(1, 2), tpm2Token(2, 3)},
	} {
		if _, _, err := tpmBoundKeyslot(tokens); err == nil {
			t.Fatalf("%s accepted as one bind", name)
		}
	}
}

func TestVerifyTPMReferenceRepair(t *testing.T) {
	legacy := &actionEncryptionEvidence{LUKSUUID: "root", Keyslots: []uint32{0, 2}, Tokens: []*agentv1.LUKSTokenObservation{tpm2Token(1, 2)}}
	repaired := func() *actionEncryptionEvidence {
		return &actionEncryptionEvidence{LUKSUUID: "root", Keyslots: []uint32{2, 0}, Tokens: []*agentv1.LUKSTokenObservation{tpm2Token(1, 2), tpm2Token(2, 2), tpm2Token(3, 2), tpm2Token(4, 2)}}
	}
	if err := verifyTPMReferenceRepair(legacy, repaired(), 2, 4); err != nil {
		t.Fatalf("repaired bind rejected: %v", err)
	}
	for name, mutate := range map[string]func(*actionEncryptionEvidence){
		"other volume":    func(e *actionEncryptionEvidence) { e.LUKSUUID = "other" },
		"new keyslot":     func(e *actionEncryptionEvidence) { e.Keyslots = append(e.Keyslots, 3) },
		"removed keyslot": func(e *actionEncryptionEvidence) { e.Keyslots = []uint32{0} },
		"too few":         func(e *actionEncryptionEvidence) { e.Tokens = e.Tokens[:3] },
		"too many":        func(e *actionEncryptionEvidence) { e.Tokens = append(e.Tokens, tpm2Token(5, 2)) },
		"rebound": func(e *actionEncryptionEvidence) {
			e.Keyslots = []uint32{0, 3}
			e.Tokens = e.Tokens[:1]
			e.Tokens[0].Keyslots = []uint32{3}
		},
		"split": func(e *actionEncryptionEvidence) { e.Tokens[3].Keyslots = []uint32{0} },
	} {
		evidence := repaired()
		mutate(evidence)
		if err := verifyTPMReferenceRepair(legacy, evidence, 2, 4); err == nil {
			t.Fatalf("%s accepted as a reference repair", name)
		}
	}
	if err := verifyTPMReferenceRepair(legacy, legacy, 2, 1); err != nil {
		t.Fatalf("single-reference release rejected its legacy bind: %v", err)
	}
}
