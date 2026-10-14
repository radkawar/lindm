// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"path/filepath"
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/platform"
)

// effectHost qualifies FILES with standard roots below root, so the merged
// configuration's overlap checks run against real paths.
func effectHost(t *testing.T, roots ...string) Host {
	t.Helper()
	host := testHost(t, "ubuntu-24.04")
	release := *host.Release
	release.StandardFileRoots = roots
	host.Release = &release
	return host
}

func TestEffectBindsMergedProviders(t *testing.T) {
	root := t.TempDir()
	document := &config.Document{Proto: &agentv1.AgentConfig{}, StateDirectory: filepath.Join(root, "state"), RuntimeDirectory: filepath.Join(root, "run"), SpoolDirectory: filepath.Join(root, "spool"), ConfigDirectory: filepath.Join(root, "etc")}
	managed := filepath.Join(root, "motd.d")
	effective, err := Effect(t.Context(), document, testRecord(true, capFiles, capAccounts), effectHost(t, managed))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, effective, capFiles, statusEnabled, "")
	if effective.Document == nil || effective.Document.Proto != effective.Config || document.Proto.GetFileProvider() != nil {
		t.Fatal("effective document does not carry the merged configuration")
	}
	if !slices.Equal(effective.Document.ProtectedPaths, []string{document.ConfigDirectory, document.StateDirectory, document.RuntimeDirectory, document.SpoolDirectory}) {
		t.Fatalf("protected paths = %v", effective.Document.ProtectedPaths)
	}
}

func TestEffectRejectsProtectedOverlap(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	document := &config.Document{Proto: &agentv1.AgentConfig{}, StateDirectory: state, RuntimeDirectory: filepath.Join(root, "run"), SpoolDirectory: filepath.Join(root, "spool"), ConfigDirectory: filepath.Join(root, "etc")}
	for name, managed := range map[string]string{"state root": state, "state parent": root, "inside state": filepath.Join(state, "drop.d")} {
		t.Run(name, func(t *testing.T) {
			effective, err := Effect(t.Context(), document, testRecord(true, capFiles, capAccounts), effectHost(t, managed))
			if err != nil {
				t.Fatal(err)
			}
			wantStatus(t, effective, capFiles, statusUnavailable, DetailProtectedPathOverlap)
			wantStatus(t, effective, capAccounts, statusUnavailable, DetailProtectedPathOverlap)
			if effective.Config.GetFileProvider() != nil || effective.Config.GetAccountProvider() != nil || effective.Document.Proto.GetFileProvider() != nil {
				t.Fatal("overlapping derived providers became effective")
			}
		})
	}
}

func TestEffectRejectsNonProviderChanges(t *testing.T) {
	document := &config.Document{Proto: &agentv1.AgentConfig{SocketName: "executor.sock"}}
	changed := &agentv1.AgentConfig{SocketName: "other.sock"}
	if _, err := document.WithProviders(changed); err == nil {
		t.Fatal("merged configuration changed a non-provider setting")
	}
}

func TestDetectHost(t *testing.T) {
	host, err := DetectHost(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if host.Release == nil || host.Architecture == "" || host.Interfaces == nil || host.ReadVendorKey == nil || host.FirewallRestoreReady == nil {
		t.Fatalf("incomplete host: %+v", host)
	}
	interfaces, err := host.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSortedFunc(interfaces, func(a, b Interface) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	}) {
		t.Fatal("interfaces are not sorted")
	}
	for _, item := range interfaces {
		if item.Loopback && item.PermanentMAC != "" {
			t.Fatalf("loopback %s reports a permanent address", item.Name)
		}
	}
	if host.Release.Key != "" && host.Release.Key != platform.Identify(platform.OSRelease{ID: host.Release.ID, VersionID: host.Release.Version.Value}).Key {
		t.Fatalf("host release %s not identified from the registry", host.Release.Key)
	}
}
