//go:build linux

package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

type buildToolchain struct {
	goBinary, goRoot, nodeBinary, npmCLI, npmBinary string
	goVersion, nodeVersion                          string
}

// Resolve shims while the caller's HOME still exists. A shim's own realpath can
// be mise, not Node; process.execPath identifies the runtime it actually starts.
// Both clean builds then invoke these verified real executables directly.
func resolveBuildToolchain(ctx context.Context, repository, capturedSource string) (buildToolchain, error) {
	tools, err := pinnedBuildToolchain(capturedSource)
	if err != nil {
		return tools, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return tools, err
	}
	environment := []string{"HOME=" + home, "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off"}
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "MISE_DATA_DIR", "MISE_CONFIG_DIR"} {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	root, err := toolchainProbe(ctx, repository, environment, "go", "env", "GOROOT")
	if err != nil {
		return tools, fmt.Errorf("releasebuild: resolve expected Go %s before HOME isolation: %w", tools.goVersion, err)
	}
	tools.goRoot, err = filepath.EvalSymlinks(strings.TrimSpace(string(root)))
	if err == nil {
		tools.goBinary, err = realToolFile(filepath.Join(tools.goRoot, "bin", "go"), true)
	}
	if err != nil {
		return tools, fmt.Errorf("releasebuild: resolve expected Go %s: %w", tools.goVersion, err)
	}
	node, err := toolchainProbe(ctx, repository, environment, "node", "-p", "process.execPath")
	if err != nil {
		return tools, fmt.Errorf("releasebuild: resolve expected Node %s before HOME isolation: %w", tools.nodeVersion, err)
	}
	tools.nodeBinary, err = realToolFile(strings.TrimSpace(string(node)), true)
	if err == nil {
		err = resolveNPM(&tools)
	}
	if err != nil {
		return tools, fmt.Errorf("releasebuild: resolve expected Node %s and its npm CLI: %w", tools.nodeVersion, err)
	}
	if err := verifyResolvedToolchain(ctx, repository, environment, tools); err != nil {
		return tools, err
	}
	return tools, nil
}

func pinnedBuildToolchain(source string) (buildToolchain, error) {
	var tools buildToolchain
	goMod, err := readBounded(filepath.Join(source, "go.mod"), maxDocument)
	if err != nil {
		return tools, err
	}
	pin := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)(?:[ \t]*(?://[^\n]*)?)?$`).FindSubmatch(goMod)
	if len(pin) != 2 {
		return tools, errors.New("releasebuild: go.mod requires an exact go X.Y.Z version")
	}
	tools.goVersion = "go" + string(pin[1])
	node, err := readBounded(filepath.Join(source, ".node-version"), 128)
	if err != nil {
		return tools, err
	}
	tools.nodeVersion = "v" + strings.TrimPrefix(strings.TrimSpace(string(node)), "v")
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(tools.nodeVersion) {
		return tools, errors.New("releasebuild: .node-version requires an exact X.Y.Z version")
	}
	return tools, nil
}

func verifyResolvedToolchain(ctx context.Context, repository string, environment []string, tools buildToolchain) error {
	goVersion, err := toolchainProbe(ctx, repository, environment, tools.goBinary, "version")
	if err != nil {
		return fmt.Errorf("releasebuild: expected Go %s at %q: %w", tools.goVersion, tools.goBinary, err)
	}
	nodeVersion, err := toolchainProbe(ctx, repository, environment, tools.nodeBinary, "--version")
	if err != nil {
		return fmt.Errorf("releasebuild: expected Node %s at %q: %w", tools.nodeVersion, tools.nodeBinary, err)
	}
	return checkBuildToolVersions(tools, string(goVersion), string(nodeVersion))
}

func checkBuildToolVersions(tools buildToolchain, goVersion, nodeVersion string) error {
	fields := strings.Fields(goVersion)
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || fields[2] != tools.goVersion {
		return fmt.Errorf("releasebuild: expected Go %s from go.mod at %q; got %q", tools.goVersion, tools.goBinary, strings.TrimSpace(goVersion))
	}
	if strings.TrimSpace(nodeVersion) != tools.nodeVersion {
		return fmt.Errorf("releasebuild: expected Node %s from .node-version at %q; got %q", tools.nodeVersion, tools.nodeBinary, strings.TrimSpace(nodeVersion))
	}
	return nil
}

func realToolFile(path string, executable bool) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("tool path %q is not absolute", path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || executable && info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("tool path %q is not a regular executable/CLI file", real)
	}
	return real, nil
}

func resolveNPM(tools *buildToolchain) error {
	prefix := filepath.Dir(filepath.Dir(tools.nodeBinary))
	cli := filepath.Join(prefix, "lib", "node_modules", "npm", "bin", "npm-cli.js")
	var err error
	tools.npmCLI, err = realToolFile(cli, false)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Distro layouts need not have the upstream lib/node_modules location.
	// Execute their npm command directly; never interpret a shell wrapper as JS.
	tools.npmBinary, err = realToolFile(filepath.Join(filepath.Dir(tools.nodeBinary), "npm"), true)
	return err
}

func runNPM(ctx context.Context, directory string, environment []string, tools buildToolchain, args ...string) ([]byte, error) {
	if tools.npmCLI != "" {
		return command(ctx, directory, environment, tools.nodeBinary, append([]string{tools.npmCLI}, args...)...)
	}
	return command(ctx, directory, environment, tools.npmBinary, args...)
}

func toolchainProbe(ctx context.Context, directory string, environment []string, name string, args ...string) ([]byte, error) {
	stdout, stderr := nativeexec.NewBuffer(64<<10), nativeexec.NewBuffer(64<<10)
	env := append([]string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C", "TZ=UTC"}, environment...)
	err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: directory, Stdout: stdout, Stderr: stderr, Timeout: 30 * time.Second})
	if err == nil && (stdout.Truncated() || stderr.Truncated()) {
		err = errors.New("toolchain probe output exceeds bound")
	}
	if err != nil {
		return nil, fmt.Errorf("probe %q: %w; stderr: %s", name, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
