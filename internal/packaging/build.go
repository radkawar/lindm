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
	arch, goVersion, err := inspectBinary(binary, target, p, version)
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
	versionValidation, err := validateBinaryVersion(ctx, work, binary, arch, version)
	if err != nil {
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
	artifacts, err := buildArtifacts(ctx, work, formats, payload, version, arch, epoch, signer, payloadSHA, staged, p)
	if err != nil {
		return nil, err
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
		Tools:                     buildToolVersions(ctx, work, formats),
	}
	var keyPaths []string
	if signer.Fingerprint != "" {
		result.SignerFingerprint = signer.Fingerprint
		result.Custody = signer.Custody
		binaryKey, armorKey, err := exportPublicKeys(ctx, work, signer, work)
		if err != nil {
			return nil, err
		}
		result.PublicKey = filepath.Join(req.OutputDir, filepath.Base(armorKey))
		keyPaths = []string{binaryKey, armorKey}
	}
	// Agent cleanup is part of signing success, before any artifacts become
	// public. The deferred close handles every earlier failure and cancellation.
	if err := guard.close(ctx, work); err != nil {
		return nil, err
	}
	if err := publishBuild(req.OutputDir, version, result, keyPaths); err != nil {
		return nil, err
	}
	return result, nil
}

// inspectBinary requires an ELF executable for the target architecture whose
// embedded module build info names product p at version. It returns the
// architecture and the Go version that built it.
func inspectBinary(binary *os.File, target string, p product, version string) (Architecture, string, error) {
	arch, err := inspectELF(binary)
	if err != nil {
		return Architecture{}, "", err
	}
	if arch.GOARCH != target {
		return Architecture{}, "", fmt.Errorf("%w: binary %s does not match requested %s", ErrArchitecture, arch.GOARCH, target)
	}
	goVersion, err := confirmModule(binary, p, arch, version)
	if err != nil {
		return Architecture{}, "", err
	}
	return arch, goVersion, nil
}

// validateBinaryVersion runs `version` on a host-executable binary and requires
// the requested version; other binaries rely on embedded build metadata. It
// returns the validation method recorded in the result.
func validateBinaryVersion(ctx context.Context, work string, binary *os.File, arch Architecture, version string) (string, error) {
	if !arch.hostMatch() {
		return "embedded-build-metadata", nil
	}
	stdout, stderr, err := runTool(ctx, work, toolCmd{
		Path:    binary.Name(),
		Args:    []string{"version"},
		Dir:     "/",
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrVersion, err)
	}
	if err := parseVersionOutput(stdout, stderr, version); err != nil {
		return "", err
	}
	return "native-execution", nil
}

// buildArtifacts builds one artifact per requested format, in order, from the
// staged payload.
func buildArtifacts(ctx context.Context, work string, formats []Format, payload, version string, arch Architecture, epoch int64, signer SigningKey, payloadSHA string, staged []stagedFile, p product) ([]Artifact, error) {
	var artifacts []Artifact
	for _, format := range formats {
		var artifact Artifact
		var err error
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
	return artifacts, nil
}

func buildToolVersions(ctx context.Context, work string, formats []Format) []ToolVersion {
	tools := []ToolVersion{
		toolVersion(ctx, work, "dpkg-deb", "--version"),
		toolVersion(ctx, work, "rpmbuild", "--version"),
		toolVersion(ctx, work, "gpg", "--version"),
		toolVersion(ctx, work, "systemd-analyze", "--version"),
	}
	if wants(formats, FormatArch) {
		tools = append(tools, archBuildToolVersion(), toolVersion(ctx, work, "gpgv", "--version"))
	}
	return tools
}

// publishBuild copies the exported public keys and moves every artifact and
// signature into outputDir, then writes the manifest that describes them.
func publishBuild(outputDir, version string, result *BuildResult, keyPaths []string) error {
	for _, keyPath := range keyPaths {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		if err := writeMatching(filepath.Join(outputDir, filepath.Base(keyPath)), data, 0o644); err != nil {
			return err
		}
	}
	for i := range result.Artifacts {
		final, err := moveArtifact(result.Artifacts[i].Path, outputDir)
		if err != nil {
			return err
		}
		result.Artifacts[i].Path = final
		if result.Artifacts[i].SignaturePath != "" {
			signature, err := moveArtifact(result.Artifacts[i].SignaturePath, outputDir)
			if err != nil {
				return err
			}
			result.Artifacts[i].SignaturePath = signature
		}
	}
	return writeManifest(outputDir, version, result)
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
	if len(p.units) == 0 && len(p.userUnits) == 0 {
		return true, false, nil
	}
	executableChecked := true
	for _, scope := range []struct {
		units []string
		dir   string
		user  bool
	}{{p.units, "units-system", false}, {p.userUnits, "units-user", true}} {
		if len(scope.units) == 0 {
			continue
		}
		checked, err := verifyUnitScope(ctx, work, scope.dir, scope.units, scope.user)
		if err != nil {
			return false, false, err
		}
		executableChecked = executableChecked && checked
	}
	return true, executableChecked, nil
}

// verifyUnitScope runs systemd-analyze verify for one manager scope. A user
// manager needs a runtime directory and also loads the host's user units,
// whose %t sockets must fit sockaddr_un. A short private 0700 directory keeps
// those host units quiet and the build independent of any login session.
func verifyUnitScope(ctx context.Context, work, dir string, units []string, user bool) (_ bool, err error) {
	scopeDir := filepath.Join(work, dir)
	if err := os.Mkdir(scopeDir, 0o700); err != nil {
		return false, err
	}
	args := []string{"verify"}
	var env []string
	if user {
		var runtimeDir string
		runtimeDir, err = os.MkdirTemp("", "unit-run-")
		if err != nil {
			return false, err
		}
		defer func() { err = errors.Join(err, os.RemoveAll(runtimeDir)) }()
		args = []string{"--user", "verify"}
		env = []string{"XDG_RUNTIME_DIR=" + runtimeDir}
	}
	for _, name := range units {
		data, err := asset(name)
		if err != nil {
			return false, err
		}
		path := filepath.Join(scopeDir, name)
		if err := writeFile(path, data, 0o644, DefaultSourceDateEpoch); err != nil {
			return false, err
		}
		args = append(args, path)
	}
	stdout, stderr, runErr := runTool(ctx, work, toolCmd{
		Name:     "systemd-analyze",
		Args:     args,
		ExtraEnv: env,
		Timeout:  30 * time.Second,
	})
	missing, classErr := classifyUnitOutput(string(stdout) + "\n" + string(stderr))
	if classErr != nil {
		return false, classErr
	}
	if runErr != nil && !missing {
		return false, fmt.Errorf("%w: systemd-analyze verify failed", ErrArtifact)
	}
	return runErr == nil && !missing, nil
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
