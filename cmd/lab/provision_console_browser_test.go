// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func writeProvisioningBrowserConfig(t *testing.T, path string, cfg acceptanceBrowserConfig) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestProvisioningBrowserRequiresPublicHostOrigin(t *testing.T) {
	good := acceptanceBrowserConfig{Origin: "https://lindm-console.test:37429", HostResolverRules: "MAP lindm-console.test 127.0.0.1", EvidenceDirectory: "/private/screenshots", Password: "private-owner-secret"}
	path := filepath.Join(t.TempDir(), "provision.json")
	writeProvisioningBrowserConfig(t, path, good)
	if host, err := consoleProvisioningHost(path); err != nil || host != "lindm-console.test" {
		t.Fatalf("public host origin refused: %q %v", host, err)
	}
	for name, mutate := range map[string]func(*acceptanceBrowserConfig){
		"localhost origin": func(c *acceptanceBrowserConfig) {
			c.Origin, c.HostResolverRules = "https://localhost:37429", "MAP localhost 127.0.0.1"
		},
		"address origin": func(c *acceptanceBrowserConfig) {
			c.Origin, c.HostResolverRules = "https://10.0.2.2:37429", "MAP 10.0.2.2 127.0.0.1"
		},
		"single label": func(c *acceptanceBrowserConfig) {
			c.Origin, c.HostResolverRules = "https://lindm:37429", "MAP lindm 127.0.0.1"
		},
		"plain http":        func(c *acceptanceBrowserConfig) { c.Origin = "http://lindm-console.test:37429" },
		"missing port":      func(c *acceptanceBrowserConfig) { c.Origin = "https://lindm-console.test" },
		"origin path":       func(c *acceptanceBrowserConfig) { c.Origin = "https://lindm-console.test:37429/enroll" },
		"no resolver rule":  func(c *acceptanceBrowserConfig) { c.HostResolverRules = "" },
		"other host rule":   func(c *acceptanceBrowserConfig) { c.HostResolverRules = "MAP other.test 127.0.0.1" },
		"non-loopback rule": func(c *acceptanceBrowserConfig) { c.HostResolverRules = "MAP lindm-console.test 10.0.0.1" },
		"multiple rules": func(c *acceptanceBrowserConfig) {
			c.HostResolverRules = "MAP lindm-console.test 127.0.0.1,MAP * 127.0.0.1"
		},
		"no screenshot custody": func(c *acceptanceBrowserConfig) { c.EvidenceDirectory = "" },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := provisioningBrowserHost(&cfg); err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "private-owner-secret") {
			t.Fatalf("%s disclosed the owner password", name)
		}
	}
}

func TestProvisioningApproverIsDistinctEnrolledHuman(t *testing.T) {
	root := t.TempDir()
	approverState := filepath.Join(root, "approver-credential.json")
	state := func(origin, username string) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"origin": origin, "username": username, "credentials": []map[string]string{{"credentialId": "private"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(approverState, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const origin = "https://lindm-console.test:37429"
	state(origin, "console-approver")
	base := acceptanceBrowserConfig{Origin: origin, Username: "console-owner", CredentialPath: filepath.Join(root, "owner-credential.json")}
	approver := acceptanceBrowserAccount{Username: "console-approver", Password: "private-approver-secret", CredentialPath: approverState}
	cfg := base
	cfg.Approver = &approver
	if err := validateConsoleApprover(&cfg); err != nil {
		t.Fatalf("distinct enrolled approver refused: %v", err)
	}
	for name, mutate := range map[string]func(*acceptanceBrowserAccount){
		"same human":          func(a *acceptanceBrowserAccount) { a.Username = "console-owner" },
		"shared passkey file": func(a *acceptanceBrowserAccount) { a.CredentialPath = base.CredentialPath },
		"missing password":    func(a *acceptanceBrowserAccount) { a.Password = "" },
		"missing credential":  func(a *acceptanceBrowserAccount) { a.CredentialPath = "" },
		"other account state": func(a *acceptanceBrowserAccount) { a.Username = "someone-else" },
	} {
		candidate := approver
		mutate(&candidate)
		cfg := base
		cfg.Approver = &candidate
		if err := validateConsoleApprover(&cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	cfg = base
	if err := validateConsoleApprover(&cfg); err == nil {
		t.Fatal("approval without an approver accepted")
	}
	state("https://localhost:37429", "console-approver")
	cfg.Approver = &approver
	if err := validateConsoleApprover(&cfg); err == nil {
		t.Fatal("approver passkey enrolled for another origin accepted")
	}
	if err := os.Chmod(approverState, 0644); err != nil {
		t.Fatal(err)
	}
	state(origin, "console-approver")
	if err := validateConsoleApprover(&cfg); err == nil {
		t.Fatal("public approver passkey state accepted")
	}
}

func TestCaptureConsoleProvisioningRefusesBeforeBrowser(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "provision.json")
	writeProvisioningBrowserConfig(t, path, acceptanceBrowserConfig{Origin: "https://lindm-console.test:37429", HostResolverRules: "MAP lindm-console.test 127.0.0.1", EvidenceDirectory: filepath.Join(root, "screenshots")})
	release := &platform.Release{Name: "Fedora 44", Provisioning: []platform.Provisioning{platform.ProvisionCloudInit, platform.ProvisionKickstart}}
	existing := filepath.Join(root, "existing-snippet")
	if err := os.WriteFile(existing, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		format, snippet string
		release         *platform.Release
	}{
		"format not offered": {"autoyast", filepath.Join(root, "snippet"), release},
		"nixos module":       {"nixos", filepath.Join(root, "snippet"), &platform.Release{Name: "NixOS", Provisioning: []platform.Provisioning{platform.ProvisionNixOS}}},
		"no release":         {"kickstart", filepath.Join(root, "snippet"), nil},
		"existing snippet":   {"kickstart", existing, release},
		"relative snippet":   {"kickstart", "snippet", release},
	} {
		// The repository has no runner: reaching the browser would also fail,
		// so only an early refusal leaves no evidence directory behind.
		if _, err := captureConsoleProvisioning(t.Context(), root, root, path, test.snippet, test.format, test.release); err == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := os.Lstat(filepath.Join(root, "screenshots")); err == nil {
			t.Fatalf("%s reached the browser runner", name)
		}
	}
}

func TestConsoleSnippetDigestBindsPrivateClipboardBytes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "snippet")
	snippet := []byte("#cloud-config\nwrite_files: []\n")
	if err := os.WriteFile(path, snippet, 0600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(snippet)
	if got, err := consoleSnippetDigest(path); err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("snippet digest = %q %v", got, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := consoleSnippetDigest(link); err == nil {
		t.Fatal("symlinked snippet accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := consoleSnippetDigest(path); err == nil {
		t.Fatal("public snippet accepted")
	}
}

func TestCanonicalUUID(t *testing.T) {
	if !canonicalUUID("0b6c0a64-5a1e-4c84-9f39-7f2f1f1e2d3c") {
		t.Fatal("canonical UUID refused")
	}
	for _, value := range []string{"", "0B6C0A64-5A1E-4C84-9F39-7F2F1F1E2D3C", "{0b6c0a64-5a1e-4c84-9f39-7f2f1f1e2d3c}", "urn:uuid:0b6c0a64-5a1e-4c84-9f39-7f2f1f1e2d3c", "0b6c0a645a1e4c849f397f2f1f1e2d3c"} {
		if canonicalUUID(value) {
			t.Errorf("%q accepted", value)
		}
	}
}
