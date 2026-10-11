//go:build linux

package config

import (
	"path/filepath"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestFileProviderExcludesResolvedAuthorityNamespaces(t *testing.T) {
	root := t.TempDir()
	state, runtime, spool := filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "spool")
	base := filepath.Join(root, "config")
	for _, allowed := range []string{root, state, filepath.Join(state, "child"), base, filepath.Join(base, "child"), runtime, spool} {
		cfg := &agentv1.AgentConfig{FileProvider: &agentv1.NativeFileProviderConfig{AllowedRoots: []string{allowed}}}
		if _, err := resourceProtectedPaths(base, cfg, state, runtime, spool); err == nil {
			t.Fatalf("allowed protected namespace %q", allowed)
		}
	}
	cfg := &agentv1.AgentConfig{FileProvider: &agentv1.NativeFileProviderConfig{AllowedRoots: []string{filepath.Join(root, "managed")}}}
	paths, err := resourceProtectedPaths(base, cfg, state, runtime, spool)
	if err != nil || len(paths) != 4 {
		t.Fatalf("disjoint root: %v %v", paths, err)
	}
}

func TestFileProviderExcludesCustomSigningKeyParent(t *testing.T) {
	root := t.TempDir()
	cfg := &agentv1.AgentConfig{
		FileProvider:    &agentv1.NativeFileProviderConfig{AllowedRoots: []string{filepath.Join(root, "keys")}},
		PackageProvider: &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{{SigningKeyFile: filepath.Join(root, "keys", "repo.asc")}}},
	}
	if _, err := resourceProtectedPaths(filepath.Join(root, "config"), cfg, filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "spool")); err == nil {
		t.Fatal("signing key namespace allowed")
	}
}

func TestFileProviderExcludesEnabledSessionRuntimeDirectory(t *testing.T) {
	root := t.TempDir()
	session := filepath.Join(root, "session")
	cfg := &agentv1.AgentConfig{
		FileProvider:     &agentv1.NativeFileProviderConfig{AllowedRoots: []string{session}},
		RemoteAssistance: &agentv1.RemoteAssistanceConfig{Enabled: true, SessionRuntimeDirectory: session},
	}
	if _, err := resourceProtectedPaths(filepath.Join(root, "config"), cfg, filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "spool")); err == nil {
		t.Fatal("session socket namespace allowed")
	}
	cfg.RemoteAssistance.Enabled = false
	if _, err := resourceProtectedPaths(filepath.Join(root, "config"), cfg, filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "spool")); err != nil {
		t.Fatalf("disabled assistance protected its unused directory: %v", err)
	}
}

func TestRootConfigurationParentDoesNotRejectDisabledFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := resourceProtectedPaths("/", &agentv1.AgentConfig{}, filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "spool")); err != nil {
		t.Fatal(err)
	}
}
