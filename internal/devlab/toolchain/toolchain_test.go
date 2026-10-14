package toolchain

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTool writes an executable tool into dir that reports version the way
// node --version or go env GOVERSION does.
func fakeTool(t *testing.T, dir, tool, version string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	report := "v" + version
	if tool == "go" {
		// Like a real go with GOTOOLCHAIN=local: it names itself; without it
		// a go would switch, so the fake fails to show the caller set it.
		report = `$(test "$GOTOOLCHAIN" = local && echo go` + version + `)`
	}
	script := "#!/bin/sh\necho \"" + report + "\"\n"
	path := filepath.Join(dir, tool)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func checkout(t *testing.T, node, goMod string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{".node-version": node, "go.mod": goMod} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPinnedReadsExactVersions(t *testing.T) {
	for _, tc := range []struct{ node, mod, wantNode, wantGo string }{
		{"24.21.0\n", "module m\n\ngo 1.26.9\n", "24.21.0", "1.26.9"},
		{"v24.21.0", "module m\n\ngo 1.26\n\ntoolchain go1.26.9\n", "24.21.0", "1.26.9"},
	} {
		pins, err := Pinned(checkout(t, tc.node, tc.mod))
		if err != nil || pins.Node != tc.wantNode || pins.Go != tc.wantGo {
			t.Fatalf("pins %+v, %v", pins, err)
		}
	}
	for _, bad := range []struct{ node, mod string }{{"24\n", "go 1.26.9\n"}, {"24.21.0\n", "module m\n\ngo 1.26\n"}} {
		if _, err := Pinned(checkout(t, bad.node, bad.mod)); err == nil {
			t.Fatalf("accepted %q / %q", bad.node, bad.mod)
		}
	}
}

func TestEnvironPutsPinnedToolchainsFirst(t *testing.T) {
	root := checkout(t, "24.21.0\n", "module m\n\ngo 1.26.9\n")
	tools := t.TempDir()
	// The shell's PATH: a mise global Node 26 and a stale Go come first; the
	// pinned versions are installed further down, and Node 24.21.0 also
	// through mise.
	globalNode := fakeTool(t, filepath.Join(tools, "global-node"), "node", "26.1.0")
	staleGo := fakeTool(t, filepath.Join(tools, "stale-go"), "go", "1.26.5")
	pinnedGo := fakeTool(t, filepath.Join(tools, "go-1.26.9", "bin"), "go", "1.26.9")
	miseNode := fakeTool(t, filepath.Join(tools, "mise", "node-24.21.0", "bin"), "node", "24.21.0")
	miseDir := filepath.Join(tools, "mise-bin")
	if err := os.MkdirAll(miseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mise := "#!/bin/sh\ncase \"$2\" in node@24.21.0) echo " + filepath.Dir(miseNode) + " ;; *) exit 1 ;; esac\n"
	if err := os.WriteFile(filepath.Join(miseDir, "mise"), []byte(mise), 0o755); err != nil {
		t.Fatal(err)
	}
	path := strings.Join([]string{globalNode, staleGo, miseDir, pinnedGo}, string(os.PathListSeparator))
	environ := []string{"PATH=" + path, "GOROOT=" + staleGo, "HOME=" + t.TempDir()}
	got, err := Environ(t.Context(), root, environ)
	if err != nil {
		t.Fatal(err)
	}
	if want := "PATH=" + miseNode + ":" + pinnedGo + ":" + path; lookup(got, "PATH") != strings.TrimPrefix(want, "PATH=") {
		t.Fatalf("PATH %q, want %q", lookup(got, "PATH"), want)
	}
	if lookup(got, "GOROOT") != "" || lookup(got, "HOME") == "" {
		t.Fatalf("environment %v", got)
	}

	// Only the wrong versions installed: a refusal naming them and the fix.
	environ = []string{"PATH=" + strings.Join([]string{globalNode, staleGo}, string(os.PathListSeparator))}
	_, err = Environ(t.Context(), root, environ)
	if err == nil || !strings.Contains(err.Error(), "node 24.21.0 (pinned by .node-version) is not installed") || !strings.Contains(err.Error(), "is 26.1.0") || !strings.Contains(err.Error(), "mise install node@24.21.0") {
		t.Fatalf("missing pinned node: %v", err)
	}
	environ = []string{"PATH=" + strings.Join([]string{miseNode, staleGo}, string(os.PathListSeparator))}
	_, err = Environ(t.Context(), root, environ)
	if err == nil || !strings.Contains(err.Error(), "go 1.26.9 (pinned by go.mod) is not installed") || !strings.Contains(err.Error(), "mise install go@1.26.9") {
		t.Fatalf("missing pinned go: %v", err)
	}
}

func TestModuleRootWalksUp(t *testing.T) {
	root := checkout(t, "24.21.0\n", "module m\n\ngo 1.26.9\n")
	nested := filepath.Join(root, "cmd", "tool")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ModuleRoot(nested); err != nil || got != root {
		t.Fatalf("module root %q, %v", got, err)
	}
}

// Apply changes what this process's subprocesses run: a gate started after it
// resolves node and go to the pinned versions and inherits no GOROOT.
func TestApplyGovernsSubprocesses(t *testing.T) {
	root := checkout(t, "24.21.0\n", "module m\n\ngo 1.26.9\n")
	tools := t.TempDir()
	global := fakeTool(t, filepath.Join(tools, "global"), "node", "26.1.0")
	fakeTool(t, global, "go", "1.26.5")
	pinned := fakeTool(t, filepath.Join(tools, "pinned"), "node", "24.21.0")
	fakeTool(t, pinned, "go", "1.26.9")
	t.Setenv("PATH", global+string(os.PathListSeparator)+pinned)
	t.Setenv("GOROOT", global)
	if err := Apply(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"node", "go"} {
		if got, err := exec.LookPath(tool); err != nil || got != filepath.Join(pinned, tool) {
			t.Fatalf("%s resolves to %q, %v", tool, got, err)
		}
	}
	if _, set := os.LookupEnv("GOROOT"); set {
		t.Fatal("GOROOT still set")
	}
}
