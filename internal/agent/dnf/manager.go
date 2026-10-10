// Package dnf identifies installed native DNF managers. Identity is not a claim
// of transaction capabilities: callers must separately qualify store/replay and
// other required operations. DNF4 transactions must never use DNF5 semantics.
package dnf

import (
	"bytes"
	"errors"
	"io/fs"
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
