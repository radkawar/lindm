// SPDX-License-Identifier: Apache-2.0

// Package dnf identifies installed native DNF managers. Identity is not a claim
// of transaction capabilities: callers must separately qualify store/replay and
// other required operations. DNF4 transactions must never use DNF5 semantics.
package dnf

import (
	"bytes"
	"errors"
	"io/fs"
	"strconv"
	"strings"
)

// Kind is a native manager generation, independent of distribution identity.
type Kind string

const (
	DNF4 Kind = "dnf4"
	DNF5 Kind = "dnf5"
)

// Manager is the native executable identity, not a policy capability report.
type Manager struct {
	Kind    Kind
	Version string
}

// AtLeast reports whether the manager is the same generation and its dotted
// numeric version is not older than minimum. ParseVersion validated the shape.
func (m Manager) AtLeast(kind Kind, minimum string) bool {
	if m.Kind != kind {
		return false
	}
	have, want := strings.Split(m.Version, "."), strings.Split(minimum, ".")
	for i := range max(len(have), len(want)) {
		var a, b int
		if i < len(have) {
			a, _ = strconv.Atoi(have[i])
		}
		if i < len(want) {
			b, _ = strconv.Atoi(want[i])
		}
		if a != b {
			return a > b
		}
	}
	return true
}

// Executable chooses the explicit DNF5 executable before the generic DNF
// entrypoint. The caller must verify --version; /usr/bin/dnf may be a symlink to
// either generation. Errors other than absence never silently select a fallback.
func Executable(stat func(string) (fs.FileInfo, error)) (string, error) {
	for _, path := range []string{"/usr/bin/dnf5", "/usr/bin/dnf"} {
		info, err := stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return "", fs.ErrPermission
		}
		return path, nil
	}
	return "", fs.ErrNotExist
}

// VersionArgs disables plugins and confines native CLI logging to a caller-owned
// private directory. DNF5 initializes its logger even for --version.
func VersionArgs(logDirectory string) []string {
	return []string{"--noplugins", "--setopt=logdir=" + logDirectory, "--version"}
}

// Interpreter returns the Python interpreter named by the native DNF4
// entrypoint's own shebang (#!/usr/bin/python3.9 on EL9, platform-python on
// EL8, "#! /usr/bin/python3 -s" on EL10), so API adapters run under exactly the
// interpreter that owns the native dnf module. Only fixed system interpreter
// paths qualify; the only accepted option is -s, which the adapter's -I
// (isolated mode) already implies.
func Interpreter(entrypoint []byte) (string, error) {
	line, _, found := bytes.Cut(entrypoint, []byte{'\n'})
	command, ok := strings.CutPrefix(string(line), "#!")
	if !found || !ok {
		return "", errors.New("dnf: native entrypoint has no interpreter line")
	}
	fields := strings.Fields(command)
	if len(fields) == 0 || len(fields) > 2 || len(fields) == 2 && fields[1] != "-s" {
		return "", errors.New("dnf: unsupported native interpreter")
	}
	interpreter := fields[0]
	if interpreter == "/usr/libexec/platform-python" || interpreter == "/usr/bin/python3" {
		return interpreter, nil
	}
	minor, ok := strings.CutPrefix(interpreter, "/usr/bin/python3.")
	if !ok || len(minor) == 0 || len(minor) > 3 || strings.Trim(minor, "0123456789") != "" {
		return "", errors.New("dnf: unsupported native interpreter")
	}
	return interpreter, nil
}

// ParseVersion reads the native LC_ALL=C --version identity line. Subsequent
// library/plugin diagnostics are bounded but are not a manager identity. The
// caller owns bounded execution, stderr handling and exit-status verification.
func ParseVersion(output []byte) (Manager, error) {
	if len(output) == 0 || len(output) > 64<<10 {
		return Manager{}, errors.New("dnf: invalid version output size")
	}
	line, _, _ := bytes.Cut(output, []byte{'\n'})
	version := string(line)
	kind := DNF4
	parts := 3
	if strings.HasPrefix(version, "dnf5 version ") {
		kind, parts = DNF5, 4
		version = strings.TrimPrefix(version, "dnf5 version ")
	}
	components := strings.Split(version, ".")
	major := "4"
	if kind == DNF5 {
		major = "5"
	}
	if len(components) != parts || components[0] != major {
		return Manager{}, errors.New("dnf: unsupported native manager identity")
	}
	for _, component := range components {
		if len(component) == 0 || len(component) > 5 {
			return Manager{}, errors.New("dnf: invalid native version component")
		}
		for _, digit := range component {
			if digit < '0' || digit > '9' {
				return Manager{}, errors.New("dnf: invalid native version component")
			}
		}
	}
	return Manager{Kind: kind, Version: version}, nil
}
