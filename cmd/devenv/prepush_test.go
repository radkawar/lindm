// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPushedCommitsGatesEachPushedTipOnce(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	const zero = "0000000000000000000000000000000000000000"
	input := strings.Join([]string{
		"refs/heads/main " + a + " refs/heads/main " + zero,
		"refs/tags/v1 " + a + " refs/tags/v1 " + zero,
		"(delete) " + zero + " refs/heads/old " + b,
		"refs/heads/topic " + b + " refs/heads/topic " + a,
		"",
	}, "\n")
	shas, err := pushedCommits(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(shas, []string{a, b}) {
		t.Fatalf("gated %v", shas)
	}
	if _, err := pushedCommits(strings.NewReader("refs/heads/main " + a + "\n")); err == nil {
		t.Fatal("accepted a malformed ref line")
	}
}

func TestPushedCommitTipsPeelsTagInsteadOfUsingHEAD(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--quiet")
	git("config", "user.name", "Release test")
	git("config", "user.email", "release@example.invalid")
	git("config", "commit.gpgsign", "false")
	git("config", "tag.gpgsign", "false")
	git("commit", "--quiet", "--allow-empty", "-m", "tagged")
	tagged := git("rev-parse", "HEAD")
	git("tag", "-a", "v-test", "-m", "release")
	object := git("rev-parse", "refs/tags/v-test")
	git("commit", "--quiet", "--allow-empty", "-m", "later HEAD")
	tip := git("rev-parse", "HEAD")
	if tagged == tip || object == tagged {
		t.Fatal("fixture did not separate HEAD, tag object and tagged commit")
	}
	input := "refs/tags/v-test " + object + " refs/tags/v-test " + strings.Repeat("0", 40) + "\n" +
		"refs/heads/release " + tagged + " refs/heads/release " + tip + "\n"
	commits, err := pushedCommitTips(t.Context(), root, strings.NewReader(input))
	if err != nil || !slices.Equal(commits, []string{tagged}) {
		t.Fatalf("pushed commits=%v err=%v; want tagged commit, not HEAD or tag object", commits, err)
	}
	if _, err := pushedCommitTips(t.Context(), root, strings.NewReader("refs/tags/bad "+strings.Repeat("1", 40)+" refs/tags/bad "+tip+"\n")); err == nil {
		t.Fatal("accepted an unavailable pushed object")
	}
}

func TestPrePushClearsGitEnvironmentForNestedRepositories(t *testing.T) {
	// Restore all inherited Git settings after the hook-specific scrub.
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "GIT_") {
			t.Setenv(name, value)
		}
	}
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "wrong.git"))
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "wrong-index"))
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "init.defaultBranch")
	t.Setenv("GIT_CONFIG_VALUE_0", "redirected")
	t.Setenv("LINDM_PREPUSH_ENV_TEST", "retained")
	if err := clearPrePushGitEnvironment(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "GIT_") {
			t.Fatalf("retained hook variable %q", entry)
		}
	}
	if os.Getenv("LINDM_PREPUSH_ENV_TEST") != "retained" {
		t.Fatal("scrub removed unrelated gate environment")
	}
	root := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "git", "init", "--quiet", root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nested git init: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, ".git", "HEAD")); err != nil {
		t.Fatalf("nested repository was redirected by hook environment: %v", err)
	}
}
