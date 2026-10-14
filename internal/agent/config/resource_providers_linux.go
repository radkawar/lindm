// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"errors"
	"fmt"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// ErrProtectedOverlap reports a file provider root that overlaps protected
// agent authority.
var ErrProtectedOverlap = errors.New("native_file_root_protected_overlap")

// WithProviders returns a copy of the document whose provider settings are
// those of cfg: the local configuration merged with providers derived from a
// signed capability policy. Only provider fields may differ from the loaded
// configuration. Package signing keys are re-read under the same custody and
// digest rules, and the protected-path overlap checks run on the merged
// configuration, so derived authority never overlaps local agent custody.
func (d *Document) WithProviders(cfg *agentv1.AgentConfig) (*Document, error) {
	if d == nil || d.Proto == nil || cfg == nil {
		return nil, errors.New("merged provider configuration requires a loaded document")
	}
	if !proto.Equal(withoutProviders(d.Proto), withoutProviders(cfg)) {
		return nil, errors.New("merged provider configuration changed non-provider settings")
	}
	merged := proto.CloneOf(cfg)
	for _, message := range []proto.Message{merged.GetPackageProvider(), merged.GetFileProvider(), merged.GetSysctlProvider(), merged.GetAccountProvider(), merged.GetFirewallProvider(), merged.GetConnectivityGuard(), merged.GetOsUpdateProvider()} {
		if !message.ProtoReflect().IsValid() {
			continue
		}
		if err := validateMessage(message); err != nil {
			return nil, fmt.Errorf("merged provider configuration: %w", err)
		}
	}
	if err := resolvePackageProvider(d.ConfigDirectory, merged.GetPackageProvider(), !d.ownerRelaxed); err != nil {
		return nil, err
	}
	paths, err := resourceProtectedPaths(d.ConfigDirectory, merged, d.StateDirectory, d.RuntimeDirectory, d.SpoolDirectory)
	if err != nil {
		return nil, err
	}
	result := *d
	result.Proto = merged
	result.ProtectedPaths = paths
	return &result, nil
}

// withoutProviders clears the fields a capability policy may derive.
func withoutProviders(cfg *agentv1.AgentConfig) *agentv1.AgentConfig {
	c := proto.CloneOf(cfg)
	c.PackageProvider, c.FileProvider, c.SysctlProvider, c.AccountProvider = nil, nil, nil, nil
	c.FirewallProvider, c.ConnectivityGuard, c.OsUpdateProvider = nil, nil, nil
	return c
}

// resourceProtectedPaths is local configuration custody, not profile authority.
// Parents of authority files are protected because replacing a sibling may
// replace the native namespace or a future generation of the same authority.
func resourceProtectedPaths(base string, cfg *agentv1.AgentConfig, state, runtime, spool string) ([]string, error) {
	// Load always resolves all four; a partial in-memory document (executor
	// tests) protects the directories it has.
	var paths []string
	for _, path := range []string{base, state, runtime, spool} {
		if path != "" {
			paths = append(paths, path)
		}
	}
	if recovery := cfg.GetRecoveryBoot(); recovery != nil {
		paths = append(paths, recovery.GetStateDirectory(), recovery.GetEspDirectory(), filepath.Dir(recovery.GetImageFile()))
		if signer := recovery.GetSignerCertificateFile(); signer != "" {
			paths = append(paths, filepath.Dir(signer))
		}
	}
	if assistance := cfg.GetRemoteAssistance(); assistance.GetEnabled() {
		paths = append(paths, sessionRuntimeDirectory(base, assistance))
	}
	if protected := cfg.GetActionProvider().GetProtectedStateDirectory(); protected != "" {
		paths = append(paths, resolve(base, protected))
	}
	for _, source := range cfg.GetPackageProvider().GetSources() {
		paths = append(paths, filepath.Dir(source.GetSigningKeyFile()))
	}
	if probe := cfg.GetConnectivityProbe(); probe != nil {
		for _, path := range []string{probe.GetTlsCertificateFile(), probe.GetTlsPrivateKeyFile(), probe.GetDeviceCaFile(), probe.GetProofKeyFile()} {
			paths = append(paths, filepath.Dir(path))
		}
	}
	for i, path := range paths {
		if path == string(filepath.Separator) {
			continue
		}
		canonical, err := canonicalDirectory(path)
		if err != nil {
			return nil, fmt.Errorf("native resource authority path: %w", err)
		}
		paths[i] = canonical
	}
	for _, root := range cfg.GetFileProvider().GetAllowedRoots() {
		canonical, err := canonicalDirectory(root)
		if err != nil || canonical != root {
			return nil, errors.New("native file root must be canonical")
		}
		for _, protected := range paths {
			if canonical == protected || nestedPath(canonical, protected) || nestedPath(protected, canonical) {
				return nil, fmt.Errorf("%w: native file root %s overlaps protected agent authority", ErrProtectedOverlap, canonical)
			}
		}
	}
	return paths, nil
}
