//go:build linux

package packaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Build creates DEB and/or RPM artifacts for one agent binary. RPM artifacts
// are signed and checked in a private rpmdb. DEB authentication is PublishAPT,
// not this function.
func Build(ctx context.Context, req BuildRequest) (result *BuildResult, err error) {
	version, err := parseVersion(req.Version)
	if err != nil {
		return nil, err
	}
	formats, err := normalizeFormats(req.Formats)
	if err != nil {
		return nil, err
	}
	binaryPath, err := cleanAbsolute(req.AgentBinary)
	if err != nil {
		return nil, err
	}
	if err := rejectMacroUnsafe(binaryPath); err != nil {
		return nil, err
	}
	out, err := openPrivate(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	binary, err := openRegular(binaryPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = binary.Close() }()
	arch, err := inspectELF(binary)
	if err != nil {
		return nil, err
	}
	goVersion, err := confirmModule(binary)
	if err != nil {
		return nil, err
	}
	if !arch.hostMatch() {
		return nil, fmt.Errorf("%w: binary is %s and was not executed on this host", ErrVersion, arch.GOARCH)
	}
	epoch, err := epochOf(req.SourceDateEpoch)
	if err != nil {
		return nil, err
	}
	work, cleanup, err := privateWork(req.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	stdout, stderr, err := runTool(ctx, work, toolCmd{
		Path:    binary.Name(),
		Args:    []string{"version"},
		Dir:     "/",
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVersion, err)
	}
	if err := parseVersionOutput(stdout, stderr, version); err != nil {
		return nil, err
	}
	if _, err := binary.Seek(0, 0); err != nil {
		return nil, err
	}
	binarySHA, _, err := hashReader(binary)
	if err != nil {
		return nil, err
	}
	var signer SigningKey
	var guard *signerGuard
	if wants(formats, FormatRPM) {
		signer, guard, err = validateSigner(ctx, work, req.Signer)
		if err != nil {
			return nil, err
		}
		defer func() {
			err = errors.Join(err, guard.close(ctx, work))
			if err != nil {
				result = nil
			}
		}()
	}
	syntaxOK, executableChecked, err := verifyUnits(ctx, work)
	if err != nil {
		return nil, err
	}
	payload, staged, payloadSHA, err := stagePayload(work, binary, epoch)
	if err != nil {
		return nil, err
	}
	if payloadSHA != binarySHA {
		return nil, fmt.Errorf("%w: staged binary does not match the opened input", ErrArtifact)
	}
	var artifacts []Artifact
	for _, format := range formats {
		var artifact Artifact
		switch format {
		case FormatDEB:
			artifact, err = buildDEB(ctx, work, payload, version, arch, epoch, staged, payloadSHA)
		case FormatRPM:
			artifact, err = buildRPM(ctx, work, payload, version, arch, epoch, signer, payloadSHA, staged)
		default:
			err = fmt.Errorf("%w: unknown format", ErrArtifact)
		}
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	result = &BuildResult{
		Artifacts:                 artifacts,
		BinarySHA256:              binarySHA,
		Architecture:              arch,
		Version:                   version,
		GoVersion:                 goVersion,
		UnitSyntaxOK:              syntaxOK,
		ExecutablePresenceChecked: executableChecked,
		CreaterepoC:               createrepoStatus(ctx, work),
		Tools: []ToolVersion{
			toolVersion(ctx, work, "dpkg-deb", "--version"),
			toolVersion(ctx, work, "rpmbuild", "--version"),
			toolVersion(ctx, work, "gpg", "--version"),
			toolVersion(ctx, work, "systemd-analyze", "--version"),
		},
	}
	var binaryKey, armorKey string
	if signer.Fingerprint != "" {
		result.SignerFingerprint = signer.Fingerprint
		result.Custody = signer.Custody
		binaryKey, armorKey, err = exportPublicKeys(ctx, work, signer, work)
		if err != nil {
			return nil, err
		}
		result.PublicKey = filepath.Join(req.OutputDir, filepath.Base(armorKey))
	}
	// Agent cleanup is part of signing success, before any artifacts become
	// public. The deferred close handles every earlier failure and cancellation.
	if err := guard.close(ctx, work); err != nil {
		return nil, err
	}
	if signer.Fingerprint != "" {
		for _, keyPath := range [2]string{binaryKey, armorKey} {
			data, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, err
			}
			if err := writeMatching(filepath.Join(req.OutputDir, filepath.Base(keyPath)), data, 0o644); err != nil {
				return nil, err
			}
		}
	}
	for i := range result.Artifacts {
		final, err := moveArtifact(result.Artifacts[i].Path, req.OutputDir)
		if err != nil {
			return nil, err
		}
		result.Artifacts[i].Path = final
	}
	if err := writeManifest(req.OutputDir, version, result); err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeFormats(formats []Format) ([]Format, error) {
	if len(formats) == 0 {
		return []Format{FormatDEB, FormatRPM}, nil
	}
	var out []Format
	seen := map[Format]bool{}
	for _, format := range formats {
		if format != FormatDEB && format != FormatRPM {
			return nil, fmt.Errorf("%w: unknown package format", ErrArtifact)
		}
		if !seen[format] {
			out = append(out, format)
			seen[format] = true
		}
	}
	return out, nil
}

func moveArtifact(src, dir string) (string, error) {
	dst := filepath.Join(dir, filepath.Base(src))
	if _, err := os.Lstat(dst); err == nil {
		return "", fmt.Errorf("%w: %s already exists", ErrArtifact, filepath.Base(src))
	}
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return dst, nil
}

func writeManifest(dir, version string, result *BuildResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(dir, fmt.Sprintf("%s_%s_manifest.json", PackageName, version))
	return writeFile(path, data, 0o644, DefaultSourceDateEpoch)
}

func createrepoStatus(ctx context.Context, work string) string {
	if _, err := lookupTool("createrepo_c"); err != nil {
		return "not-installed"
	}
	found := toolVersion(ctx, work, "createrepo_c", "--version")
	return "installed-unused: " + found.Version
}

func verifyUnits(ctx context.Context, work string) (bool, bool, error) {
	executor, err := asset("lindm-executor.service")
	if err != nil {
		return false, false, err
	}
	network, err := asset("lindm-agent.service")
	if err != nil {
		return false, false, err
	}
	execPath := filepath.Join(work, executorUnit)
	netPath := filepath.Join(work, agentUnit)
	if err := writeFile(execPath, executor, 0o644, DefaultSourceDateEpoch); err != nil {
		return false, false, err
	}
	if err := writeFile(netPath, network, 0o644, DefaultSourceDateEpoch); err != nil {
		return false, false, err
	}
	stdout, stderr, runErr := runTool(ctx, work, toolCmd{
		Name:    "systemd-analyze",
		Args:    []string{"verify", execPath, netPath},
		Timeout: 30 * time.Second,
	})
	missing, classErr := classifyUnitOutput(string(stdout) + "\n" + string(stderr))
	if classErr != nil {
		return false, false, classErr
	}
	if runErr != nil && !missing {
		return false, false, fmt.Errorf("%w: systemd-analyze verify failed", ErrArtifact)
	}
	return true, runErr == nil && !missing, nil
}

func classifyUnitOutput(output string) (bool, error) {
	missing := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Accepting user/group name") && !strings.Contains(line, "lindm") {
			continue
		}
		if strings.Contains(line, "Command "+BinaryPath+" is not executable") {
			missing = true
			continue
		}
		if strings.Contains(line, "lindm") {
			return missing, fmt.Errorf("%w: %s", ErrArtifact, line)
		}
	}
	return missing, nil
}
