//go:build linux

package config

import (
	"errors"
	"fmt"
	"path/filepath"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// resourceProtectedPaths is local configuration custody, not profile authority.
// Parents of authority files are protected because replacing a sibling may
// replace the native namespace or a future generation of the same authority.
func resourceProtectedPaths(base string, cfg *agentv1.AgentConfig, state, runtime, spool string) ([]string, error) {
	paths := []string{base, state, runtime, spool}
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
				return nil, errors.New("native file root overlaps protected agent authority")
			}
		}
	}
	return paths, nil
}
