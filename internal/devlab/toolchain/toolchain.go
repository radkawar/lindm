// SPDX-License-Identifier: Apache-2.0

// Package toolchain puts the repository's pinned Node (.node-version) and Go
// (go.mod's toolchain or go line) first on the PATH of development gates, so
// a gate never runs, or refuses, whatever version happens to be first on the
// invoking shell's PATH (a mise global, a distribution package). It finds the
// exact versions with mise when present, else among PATH candidates, and never
// installs, downloads or accepts another version. It imports only the
// standard library: cmd/dev uses it while the shared tree may not compile.
package toolchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	exactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	goLine       = regexp.MustCompile(`(?m)^go[ \t]+([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$`)
	toolchainRe  = regexp.MustCompile(`(?m)^toolchain[ \t]+go([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$`)
)

// Pins are the exact versions a checkout requires.
type Pins struct{ Node, Go string }

// Pinned reads the checkout's pinned versions: .node-version (exact X.Y.Z)
// and go.mod's toolchain line, or its go line when it has none.
func Pinned(root string) (Pins, error) {
	var pins Pins
	node, err := os.ReadFile(filepath.Join(root, ".node-version"))
	if err != nil {
		return pins, fmt.Errorf("toolchain: read .node-version: %w", err)
	}
	pins.Node = strings.TrimPrefix(strings.TrimSpace(string(node)), "v")
	if !exactVersion.MatchString(pins.Node) {
		return pins, fmt.Errorf("toolchain: .node-version %q is not an exact X.Y.Z version", pins.Node)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return pins, fmt.Errorf("toolchain: read go.mod: %w", err)
	}
	if match := toolchainRe.FindSubmatch(mod); match != nil {
		pins.Go = string(match[1])
	} else if match := goLine.FindSubmatch(mod); match != nil {
		pins.Go = string(match[1])
	} else {
		return pins, errors.New("toolchain: go.mod has no exact go X.Y.Z or toolchain goX.Y.Z line")
	}
	return pins, nil
}

// Environ returns environ with the bin directories of the checkout's pinned
// Node and Go first on PATH and GOROOT removed (the located go knows its own
// root; a stale GOROOT would make it use another version's standard
// library). It fails, naming how to install it, when a pinned version is not
// installed.
func Environ(ctx context.Context, root string, environ []string) ([]string, error) {
	pins, err := Pinned(root)
	if err != nil {
		return nil, err
	}
	environ = slices.DeleteFunc(slices.Clone(environ), func(entry string) bool { return strings.HasPrefix(entry, "GOROOT=") })
	path := lookup(environ, "PATH")
	node, err := locate(ctx, "node", pins.Node, path, environ)
	if err != nil {
		return nil, err
	}
	goBin, err := locate(ctx, "go", pins.Go, path, environ)
	if err != nil {
		return nil, err
	}
	dirs := []string{node}
	if goBin != node {
		dirs = append(dirs, goBin)
	}
	environ = slices.DeleteFunc(environ, func(entry string) bool { return strings.HasPrefix(entry, "PATH=") })
	return append(environ, "PATH="+strings.Join(append(dirs, path), string(os.PathListSeparator))), nil
}

// Node returns the checkout's pinned node binary and environ with its bin
// directory first on PATH, for running node (and the npm, npx or node it
// starts) on a host that need not have Go, such as a lab host. Pass the
// returned binary as the command path: exec resolves a bare "node" against
// this process's PATH, not the child's.
func Node(ctx context.Context, root string, environ []string) (binary string, env []string, err error) {
	pins, err := Pinned(root)
	if err != nil {
		return "", nil, err
	}
	path := lookup(environ, "PATH")
	dir, err := locate(ctx, "node", pins.Node, path, environ)
	if err != nil {
		return "", nil, err
	}
	env = slices.DeleteFunc(slices.Clone(environ), func(entry string) bool { return strings.HasPrefix(entry, "PATH=") })
	return filepath.Join(dir, "node"), append(env, "PATH="+dir+string(os.PathListSeparator)+path), nil
}

// Apply makes this process, and every subprocess it starts with an inherited
// environment, use the checkout's pinned toolchains (see Environ).
func Apply(ctx context.Context, root string) error {
	environ, err := Environ(ctx, root, os.Environ())
	if err != nil {
		return err
	}
	if err := os.Unsetenv("GOROOT"); err != nil {
		return err
	}
	return os.Setenv("PATH", lookup(environ, "PATH"))
}

func lookup(environ []string, key string) string {
	for i := len(environ) - 1; i >= 0; i-- {
		if value, ok := strings.CutPrefix(environ[i], key+"="); ok {
			return value
		}
	}
	return ""
}

// locate returns the bin directory of tool at exactly version: mise's install
// when mise has it, else the first PATH directory whose tool reports it.
func locate(ctx context.Context, tool, version, path string, environ []string) (string, error) {
	var seen []string
	if mise := findExecutable("mise", path); mise != "" {
		if dir, err := run(ctx, environ, mise, "where", tool+"@"+version); err == nil && dir != "" {
			bin := filepath.Join(dir, "bin")
			if got := reported(ctx, tool, filepath.Join(bin, tool), environ); got == version {
				return bin, nil
			}
		}
	}
	for _, dir := range filepath.SplitList(path) {
		candidate := findExecutable(tool, dir)
		if candidate == "" {
			continue
		}
		got := reported(ctx, tool, candidate, environ)
		if got == version {
			return filepath.Dir(candidate), nil
		}
		seen = append(seen, candidate+" is "+orUnknown(got))
	}
	hint := fmt.Sprintf("mise install %s@%s", tool, version)
	source := ".node-version"
	if tool == "go" {
		source = "go.mod"
	}
	found := "none on PATH"
	if len(seen) != 0 {
		found = strings.Join(seen, "; ")
	}
	return "", fmt.Errorf("toolchain: %s %s (pinned by %s) is not installed (%s); install it with `%s` or put it on PATH; no other version is used", tool, version, source, found, hint)
}

func orUnknown(version string) string {
	if version == "" {
		return "an unknown version"
	}
	return version
}

// reported is the version binary reports, "" when it cannot say. go is asked
// with GOTOOLCHAIN=local, so it names itself, not a toolchain it would switch to.
func reported(ctx context.Context, tool, binary string, environ []string) string {
	switch tool {
	case "node":
		out, err := run(ctx, environ, binary, "--version")
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(out, "v")
	case "go":
		out, err := run(ctx, append(slices.Clone(environ), "GOTOOLCHAIN=local"), binary, "env", "GOVERSION")
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(out, "go")
	}
	return ""
}

func run(ctx context.Context, environ []string, binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = environ
	var out bytes.Buffer
	cmd.Stdout = &limited{buffer: &out, limit: 4096}
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// findExecutable returns name's path in the first of path's directories that
// holds it as a regular executable file, or "".
func findExecutable(name, path string) string {
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // relative PATH entries depend on the working directory
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

type limited struct {
	buffer *bytes.Buffer
	limit  int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.limit - l.buffer.Len(); room > 0 {
		l.buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// ModuleRoot returns the nearest directory at or above dir holding go.mod.
func ModuleRoot(dir string) (string, error) {
	current, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("toolchain: no go.mod at or above %s", dir)
		}
		current = parent
	}
}
