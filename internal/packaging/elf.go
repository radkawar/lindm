//go:build linux

package packaging

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const maxBinaryBytes = 256 << 20

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func parseVersion(version string) (string, error) {
	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("%w: version must be three numeric components", ErrVersion)
	}
	return version, nil
}

// UpgradeOrdered reports whether newer is a strict upgrade of older under the
// numeric version subset shared by Debian and RPM.
func UpgradeOrdered(older, newer string) error {
	left, err := parseVersion(older)
	if err != nil {
		return err
	}
	right, err := parseVersion(newer)
	if err != nil {
		return err
	}
	if compareVersions(left, right) >= 0 {
		return fmt.Errorf("%w: %s is not an upgrade over %s", ErrVersion, newer, older)
	}
	return nil
}

func compareVersions(left, right string) int {
	a := splitVersion(left)
	b := splitVersion(right)
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func splitVersion(version string) [3]uint64 {
	var out [3]uint64
	for i, part := range strings.Split(version, ".") {
		out[i], _ = strconv.ParseUint(part, 10, 64)
	}
	return out
}

func inspectELF(file io.ReaderAt) (Architecture, error) {
	parsed, err := elf.NewFile(file)
	if err != nil {
		return Architecture{}, fmt.Errorf("%w: not an ELF", ErrArchitecture)
	}
	defer func() { _ = parsed.Close() }()
	if parsed.Class != elf.ELFCLASS64 || parsed.Data != elf.ELFDATA2LSB {
		return Architecture{}, fmt.Errorf("%w: unsupported ELF class or endianness", ErrArchitecture)
	}
	if parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return Architecture{}, fmt.Errorf("%w: unsupported ELF type", ErrArchitecture)
	}
	switch parsed.Machine {
	case elf.EM_X86_64:
		return Architecture{ELF: "EM_X86_64", GOARCH: "amd64", Debian: "amd64", RPM: "x86_64"}, nil
	case elf.EM_AARCH64:
		return Architecture{ELF: "EM_AARCH64", GOARCH: "arm64", Debian: "arm64", RPM: "aarch64"}, nil
	default:
		return Architecture{}, fmt.Errorf("%w: unsupported machine", ErrArchitecture)
	}
}

func confirmModule(file io.ReaderAt) (string, error) {
	info, err := buildinfo.Read(file)
	if err != nil {
		return "", fmt.Errorf("%w: Go build info is unavailable", ErrArchitecture)
	}
	if info.Main.Path != "lindm" && info.Path != "lindm" {
		return "", fmt.Errorf("%w: binary module is not lindm", ErrArchitecture)
	}
	return info.GoVersion, nil
}

func (a Architecture) hostMatch() bool {
	return a.GOARCH == runtime.GOARCH
}

func parseVersionOutput(stdout, stderr []byte, want string) error {
	if len(stderr) != 0 {
		return fmt.Errorf("%w: version command wrote stderr", ErrVersion)
	}
	if string(stdout) != want+"\n" {
		return fmt.Errorf("%w: version command did not print the package version", ErrVersion)
	}
	return nil
}
