//go:build linux

package packaging

import (
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

func targetArchitecture(requested string) (string, error) {
	if requested == "" {
		requested = runtime.GOARCH
	}
	switch requested {
	case "amd64", "arm64":
		return requested, nil
	default:
		return "", fmt.Errorf("%w: target must be amd64 or arm64", ErrArchitecture)
	}
}

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
		return Architecture{ELF: "EM_X86_64", GOARCH: "amd64", Debian: "amd64", RPM: "x86_64", Arch: "x86_64"}, nil
	case elf.EM_AARCH64:
		return Architecture{ELF: "EM_AARCH64", GOARCH: "arm64", Debian: "arm64", RPM: "aarch64", Arch: "aarch64"}, nil
	default:
		return Architecture{}, fmt.Errorf("%w: unsupported machine", ErrArchitecture)
	}
}

func confirmModule(file io.ReaderAt, p product, arch Architecture, version string) (string, error) {
	info, err := buildinfo.Read(file)
	if err != nil {
		return "", fmt.Errorf("%w: Go build info is unavailable", ErrArchitecture)
	}
	if info.Main.Path != "lindm" || info.Path != "lindm/cmd/"+p.name {
		return "", fmt.Errorf("%w: binary is not lindm/cmd/%s", ErrArchitecture, p.name)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return "", fmt.Errorf("%w: duplicate Go build setting", ErrArchitecture)
		}
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != arch.GOARCH {
		return "", fmt.Errorf("%w: ELF and Go target settings disagree", ErrArchitecture)
	}
	if !arch.hostMatch() {
		if settings["CGO_ENABLED"] != "0" {
			return "", fmt.Errorf("%w: foreign target requires CGO_ENABLED=0", ErrArchitecture)
		}
		stamp, err := elfVersionStamp(file)
		if err != nil {
			return "", err
		}
		if stamp != version {
			return "", fmt.Errorf("%w: embedded version stamp does not match package version", ErrVersion)
		}
	}
	return info.GoVersion, nil
}

// Go intentionally omits -ldflags from build settings when -trimpath is used.
// Read the actual stamped string through the ELF symbol and load segments instead
// of guessing compiler arguments or executing a foreign architecture. Foreign
// prebuilt inputs must retain their symbol table; maintained source builds do.
func elfVersionStamp(reader io.ReaderAt) (string, error) {
	file, err := elf.NewFile(reader)
	if err != nil {
		return "", fmt.Errorf("%w: cannot read ELF version stamp", ErrVersion)
	}
	defer func() { _ = file.Close() }()
	symbols, err := file.Symbols()
	if err != nil {
		return "", fmt.Errorf("%w: foreign binary must retain ELF symbols", ErrVersion)
	}
	for _, symbol := range symbols {
		if symbol.Name != "lindm/internal/agent/buildinfo.Version" {
			continue
		}
		if symbol.Size != 16 {
			return "", fmt.Errorf("%w: invalid version string header", ErrVersion)
		}
		var header [16]byte
		if err := readELFVirtual(file, symbol.Value, header[:]); err != nil {
			return "", err
		}
		address, length := binary.LittleEndian.Uint64(header[:8]), binary.LittleEndian.Uint64(header[8:])
		var stamp [128]byte
		if length == 0 || length > uint64(len(stamp)) {
			return "", fmt.Errorf("%w: invalid version string length", ErrVersion)
		}
		if err := readELFVirtual(file, address, stamp[:length]); err != nil {
			return "", err
		}
		return string(stamp[:length]), nil
	}
	return "", fmt.Errorf("%w: embedded version symbol is absent", ErrVersion)
}

func readELFVirtual(file *elf.File, address uint64, value []byte) error {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr {
			continue
		}
		offset := address - program.Vaddr
		if offset > program.Filesz || offset > maxBinaryBytes || uint64(len(value)) > program.Filesz-offset {
			continue
		}
		if _, err := program.ReadAt(value, int64(offset)); err != nil {
			return fmt.Errorf("%w: unreadable ELF version data", ErrVersion)
		}
		return nil
	}
	return fmt.Errorf("%w: version data is outside ELF load segments", ErrVersion)
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
