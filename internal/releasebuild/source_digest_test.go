// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceDigestMatchesCapturedTreeAndChanges(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	for _, name := range []string{"a/file.go", "a.c", "a-/file.go", "web/source.js", "web/dist/ignored.js", ".cache/ignored"} {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := SourceDigest(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(capture, 0700); err != nil {
		t.Fatal(err)
	}
	if err := snapshot(t.Context(), source, capture); err != nil {
		t.Fatal(err)
	}
	captured, err := treeDigest(capture)
	if err != nil || captured != digest {
		t.Fatalf("streamed digest %s does not match captured tree %s: %v", digest, captured, err)
	}
	if err := os.WriteFile(filepath.Join(source, "web/dist/ignored.js"), []byte("different generated output"), 0600); err != nil {
		t.Fatal(err)
	}
	ignored, err := SourceDigest(t.Context(), source)
	if err != nil || ignored != digest {
		t.Fatalf("generated output changed source digest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "a/file.go"), []byte("changed source"), 0755); err != nil {
		t.Fatal(err)
	}
	changed, err := SourceDigest(t.Context(), source)
	if err != nil || changed == digest {
		t.Fatalf("source change did not invalidate digest: %v", err)
	}
}

func TestSourceDigestRefusesLinksAndHonorsCancellation(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	if err := os.Symlink("outside", filepath.Join(source, "source.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := SourceDigest(t.Context(), source); err == nil {
		t.Fatal("accepted a source symlink")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := SourceDigest(ctx, source); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestSourceCaptureHonorsUnstagedTrackedDeletion(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	for _, name := range []string{"current.go", "retired.json"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.CommandContext(t.Context(), "git", "-C", source, "add", "--all").CombinedOutput(); err != nil {
		t.Fatalf("track source: %v: %s", err, output)
	}
	original, err := SourceDigest(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "retired.json")); err != nil {
		t.Fatal(err)
	}
	unstaged, err := SourceDigest(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if unstaged == original {
		t.Fatal("removing tracked source did not change its digest")
	}
	capture := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(capture, 0700); err != nil {
		t.Fatal(err)
	}
	if err := snapshot(t.Context(), source, capture); err != nil {
		t.Fatal(err)
	}
	captured, err := treeDigest(capture)
	if err != nil || captured != unstaged {
		t.Fatalf("unstaged removal digest %s differs from captured tree %s: %v", unstaged, captured, err)
	}
	if _, err := os.Stat(filepath.Join(capture, "retired.json")); !os.IsNotExist(err) {
		t.Fatalf("removed source remains in capture: %v", err)
	}
	if output, err := exec.CommandContext(t.Context(), "git", "-C", source, "add", "--all").CombinedOutput(); err != nil {
		t.Fatalf("stage source removal: %v: %s", err, output)
	}
	staged, err := SourceDigest(t.Context(), source)
	if err != nil || staged != unstaged {
		t.Fatalf("staging the same removal changed source digest: %v", err)
	}
}

// A miniature module with the real input layout: the agent, its in-module
// dependency, the packaging and release-build packages, the lab packages
// helper, a console-only lab file and web sources.
func TestAgentInputDigestFollowsOnlyArtifactInputs(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	files := map[string]string{
		"go.mod":                           "module lindm\n\ngo 1.22\n",
		"go.sum":                           "",
		".node-version":                    "24.0.0\n",
		"cmd/lindm-agent/main.go":          "package main\n\nimport _ \"lindm/internal/agent\"\n\nfunc main() {}\n",
		"internal/agent/agent.go":          "package agent\n",
		"internal/agent/assets/unit.txt":   "embedded asset\n",
		"internal/packaging/packaging.go":  "package packaging\n",
		"internal/releasebuild/release.go": "package releasebuild\n",
		"cmd/lab/main.go":                  "package main\n\nfunc main() {}\n",
		"cmd/lab/packages.go":              "package main\n",
		"cmd/lab/console.go":               "package main\n",
		"internal/loadlab/demo.go":         "package loadlab\n",
		"web/src/app.tsx":                  "export {}\n",
		"docs/engineering.md":              "# Engineering\n",
	}
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		write(name, body)
	}
	digest := func() string {
		t.Helper()
		value, err := AgentInputDigest(t.Context(), source, "internal/devlab/cache.go")
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base := digest()
	for _, change := range []struct{ name, body string }{
		{"web/src/app.tsx", "export const changed = 1\n"},
		{"web/src/new.tsx", "export {}\n"},
		{"cmd/lab/console.go", "package main\n\n// console-only change\n"},
		{"internal/loadlab/demo.go", "package loadlab\n\n// seed change\n"},
		{"docs/engineering.md", "# Changed\n"},
	} {
		write(change.name, change.body)
		if got := digest(); got != base {
			t.Fatalf("%s is not an agent artifact input but changed the key", change.name)
		}
	}
	for _, change := range []struct{ name, body string }{
		{"internal/agent/agent.go", "package agent\n\n// agent change\n"},
		{"internal/agent/assets/unit.txt", "changed asset\n"},
		{"cmd/lindm-agent/main.go", "package main\n\nimport _ \"lindm/internal/agent\"\n\nfunc main() { println() }\n"},
		{"internal/packaging/packaging.go", "package packaging\n\n// packaging change\n"},
		{"internal/releasebuild/release.go", "package releasebuild\n\n// release change\n"},
		{"cmd/lab/packages.go", "package main\n\n// helper change\n"},
		{"go.sum", "example.com/m v1.0.0 h1:AAAA=\n"},
		{".node-version", "24.1.0\n"},
		{"internal/devlab/cache.go", "package devlab\n"},
	} {
		write(change.name, change.body)
		got := digest()
		if got == base {
			t.Fatalf("agent artifact input %s did not change the key", change.name)
		}
		base = got
	}
}
