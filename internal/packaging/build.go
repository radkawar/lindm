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

// Build creates DEB, RPM and/or Arch agent artifacts. RPM and Arch signatures
// are verified before publication. DEB authentication is PublishAPT.
func Build(ctx context.Context, req BuildRequest) (result *BuildResult, err error) {
	return build(ctx, req, agentProduct())
}

// BuildServer packages a prebuilt lindmd, including its embedded console.
// AgentBinary carries the server executable. RPM is signed here; DEBs are
// authenticated by PublishAPT. No host service or database is modified.
func BuildServer(ctx context.Context, req BuildRequest) (*BuildResult, error) {
	return build(ctx, req, serverProduct())
}

// BuildCLI packages lindmctl without service units or lifecycle scripts.
func BuildCLI(ctx context.Context, req BuildRequest) (*BuildResult, error) {
	return build(ctx, req, cliProduct())
}

func build(ctx context.Context, req BuildRequest, p product) (result *BuildResult, err error) {
	version, err := parseVersion(req.Version)
	if err != nil {
		return nil, err
	}
	formats, err := normalizeFormats(req.Formats)
	if err != nil {
		return nil, err
	}
	if wants(formats, FormatArch) && p.name != PackageName {
		return nil, fmt.Errorf("%w: Arch packaging supports the agent only", ErrArtifact)
	}
	target, err := targetArchitecture(req.TargetArchitecture)
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
	if arch.GOARCH != target {
		return nil, fmt.Errorf("%w: binary %s does not match requested %s", ErrArchitecture, arch.GOARCH, target)
	}
	goVersion, err := confirmModule(binary, p, arch, version)
	if err != nil {
		return nil, err
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
	versionValidation := "embedded-build-metadata"
	if arch.hostMatch() {
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
		versionValidation = "native-execution"
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
	if wants(formats, FormatRPM) || wants(formats, FormatArch) {
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
	syntaxOK, executableChecked, err := verifyUnits(ctx, work, p)
	if err != nil {
		return nil, err
	}
	payload, staged, payloadSHA, err := stagePayload(work, binary, epoch, p)
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
			artifact, err = buildDEB(ctx, work, payload, version, arch, epoch, staged, payloadSHA, p)
		case FormatRPM:
			artifact, err = buildRPM(ctx, work, payload, version, arch, epoch, signer, payloadSHA, staged, p)
		case FormatArch:
			artifact, err = buildArch(ctx, work, payload, version, arch, epoch, signer, payloadSHA, staged)
		default:
			err = fmt.Errorf("%w: unknown format", ErrArtifact)
		}
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	result = &BuildResult{
		Product:                   p.name,
		Artifacts:                 artifacts,
		BinarySHA256:              binarySHA,
		Architecture:              arch,
		Version:                   version,
		GoVersion:                 goVersion,
		VersionValidation:         versionValidation,
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
	if wants(formats, FormatArch) {
		result.Tools = append(result.Tools, archBuildToolVersion(), toolVersion(ctx, work, "gpgv", "--version"))
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
		if result.Artifacts[i].SignaturePath != "" {
			signature, err := moveArtifact(result.Artifacts[i].SignaturePath, req.OutputDir)
			if err != nil {
				return nil, err
			}
			result.Artifacts[i].SignaturePath = signature
		}
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
		if format != FormatDEB && format != FormatRPM && format != FormatArch {
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
	path := filepath.Join(dir, fmt.Sprintf("%s_%s_manifest.json", result.Product, version))
	return writeFile(path, data, 0o644, DefaultSourceDateEpoch)
}

func createrepoStatus(ctx context.Context, work string) string {
	if _, err := lookupTool("createrepo_c"); err != nil {
		return "not-installed"
	}
	found := toolVersion(ctx, work, "createrepo_c", "--version")
	return "installed-unused: " + found.Version
}

func verifyUnits(ctx context.Context, work string, p product) (bool, bool, error) {
	if len(p.units) == 0 {
		return true, false, nil
	}
	args := []string{"verify"}
	for _, name := range p.units {
		data, err := asset(name)
		if err != nil {
			return false, false, err
		}
		path := filepath.Join(work, name)
		if err := writeFile(path, data, 0o644, DefaultSourceDateEpoch); err != nil {
			return false, false, err
		}
		args = append(args, path)
	}
	stdout, stderr, runErr := runTool(ctx, work, toolCmd{
		Name:    "systemd-analyze",
		Args:    args,
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
		if strings.Contains(line, "Command "+BinaryPath+" is not executable") || strings.Contains(line, "Command "+ServerBinaryPath+" is not executable") {
			missing = true
			continue
		}
		if strings.Contains(line, "lindm") {
			return missing, fmt.Errorf("%w: %s", ErrArtifact, line)
		}
	}
	return missing, nil
}
