//go:build linux

package releasebuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These executable fixtures exercise shim resolution/version admission only.
// They do not compile or qualify a release or substitute for the native VM lane.
func toolchainShimFixture(t *testing.T, goVersion, nodeVersion string) (string, buildToolchain) {
	t.Helper()
	root := t.TempDir()
	tools := buildToolchain{goRoot: filepath.Join(root, "real-go"), nodeBinary: filepath.Join(root, "real-node", "node")}
	tools.goBinary = filepath.Join(tools.goRoot, "bin", "go")
	tools.npmCLI = filepath.Join(filepath.Dir(tools.nodeBinary), "npm-cli.js")
	shim := filepath.Join(root, "shims")
	for _, path := range []string{filepath.Dir(tools.goBinary), filepath.Dir(tools.nodeBinary), shim} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	quote := func(text string) string { return "'" + strings.ReplaceAll(text, "'", "'\\''") + "'" }
	write(filepath.Join(root, "go.mod"), "module toolchain.test\n\ngo 1.26.9\n", 0600)
	write(filepath.Join(root, ".node-version"), "24.21.0\n", 0600)
	write(tools.goBinary, "#!/bin/sh\nprintf '%s\\n' "+quote("go version "+goVersion+" linux/amd64")+"\n", 0700)
	write(tools.nodeBinary, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' "+quote(nodeVersion)+"; else printf '%s\\n' '11.19.0'; fi\n", 0700)
	write(tools.npmCLI, "// npm CLI admission fixture\n", 0600)
	if err := os.Symlink(tools.npmCLI, filepath.Join(filepath.Dir(tools.nodeBinary), "npm")); err != nil {
		t.Fatal(err)
	}
	homeGuard := "#!/bin/sh\nif [ \"$HOME\" != " + quote(root) + " ]; then printf '%s\\n' 'shim cannot run in isolated HOME' >&2; exit 9; fi\n"
	write(filepath.Join(shim, "go"), homeGuard+"printf '%s\\n' "+quote(tools.goRoot)+"\n", 0700)
	write(filepath.Join(shim, "node"), homeGuard+"printf '%s\\n' "+quote(tools.nodeBinary)+"\n", 0700)
	t.Setenv("PATH", shim+string(os.PathListSeparator)+"/usr/bin:/bin")
	t.Setenv("HOME", root)
	return root, tools
}

func TestResolvePinnedToolsBeforeIsolatedHomeAndInvokeRealBinaries(t *testing.T) {
	source, expected := toolchainShimFixture(t, "go1.26.9", "v24.21.0")
	tools, err := resolveBuildToolchain(t.Context(), source, source)
	if err != nil {
		t.Fatal(err)
	}
	if tools.goBinary != expected.goBinary || tools.nodeBinary != expected.nodeBinary || tools.npmCLI != expected.npmCLI {
		t.Fatalf("retained shim instead of resolved runtime: %+v", tools)
	}
	isolated := filepath.Join(t.TempDir(), "builder")
	environment := builderEnvironment(isolated, 1760000000, tools)
	goVersion, err := command(t.Context(), source, environment, tools.goBinary, "version")
	if err != nil {
		t.Fatalf("real Go required original HOME: %v", err)
	}
	nodeVersion, err := command(t.Context(), source, environment, tools.nodeBinary, "--version")
	if err != nil {
		t.Fatalf("real Node required original HOME: %v", err)
	}
	if err := checkBuildToolVersions(tools, string(goVersion), string(nodeVersion)); err != nil {
		t.Fatal(err)
	}
	npmVersion, err := command(t.Context(), source, environment, tools.nodeBinary, tools.npmCLI, "--version")
	if err != nil || strings.TrimSpace(string(npmVersion)) != "11.19.0" {
		t.Fatalf("npm shim used in isolated HOME: %v", err)
	}
	if _, err := command(t.Context(), source, environment, "go", "version"); err == nil {
		t.Fatal("HOME-dependent shim unexpectedly remained usable")
	}
}

func TestResolvedToolchainReportsExpectedPinOnMismatch(t *testing.T) {
	for _, test := range []struct{ name, goVersion, nodeVersion, expected string }{
		{"go", "go1.26.5", "v24.21.0", "expected Go go1.26.9"},
		{"node", "go1.26.9", "v26.1.0", "expected Node v24.21.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := toolchainShimFixture(t, test.goVersion, test.nodeVersion)
			if _, err := resolveBuildToolchain(t.Context(), source, source); err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("missing explicit expected pin %q: %v", test.expected, err)
			}
		})
	}
}
