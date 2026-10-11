//go:build linux

package osupdateprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	lindmplatform "lindm/internal/platform"
	"lindm/internal/resource"
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// errNotInstalled is the native query's documented "not installed" result.
var errNotInstalled = errors.New("osupdateprovider: package_not_installed")

func runNative(ctx context.Context, path string, args ...string) ([]byte, error) {
	return runNativeEnv(ctx, nil, path, args...)
}

// runNativeEnv runs a fixed native executable through nativeexec with its
// fixed environment plus provider-chosen allowlisted variables (never values
// from the desired policy). Exit status 1 is the native query's documented
// "not installed" result.
func runNativeEnv(ctx context.Context, env []string, path string, args ...string) ([]byte, error) {
	result, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: path, Args: args, Env: env,
		Timeout: 30 * time.Second, StdoutLimit: 64 << 10, StderrLimit: 64 << 10,
	})
	if err != nil {
		if exit := (*nativeexec.ExitError)(nil); errors.As(err, &exit) && exit.Code == 1 && !errors.Is(err, nativeexec.ErrOutputLimit) {
			return result.Stdout, errors.Join(errNotInstalled, fmt.Errorf("os update native %s: %w", filepath.Base(path), err))
		}
		return nil, fmt.Errorf("os update native %s: %w", filepath.Base(path), err)
	}
	return result.Stdout, nil
}

func protectedOpen(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsupported
	}
	parent, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	rest := strings.TrimPrefix(path, "/")
	for {
		var st unix.Stat_t
		if err := unix.Fstat(parent, &st); err != nil {
			return nil, errors.Join(err, unix.Close(parent))
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			return nil, errors.Join(fmt.Errorf("%w: replaceable ancestry of %s", ErrUnsupported, path), unix.Close(parent))
		}
		name, next, more := strings.Cut(rest, "/")
		if !more {
			break
		}
		fd, openErr := unix.Openat(parent, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(parent)
		if openErr != nil {
			return nil, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return nil, errors.Join(closeErr, unix.Close(fd))
		}
		parent = fd
		rest = next
	}
	fd, openErr := unix.Openat(parent, rest, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	closeErr := unix.Close(parent)
	if openErr != nil {
		return nil, errors.Join(openErr, closeErr)
	}
	f := os.NewFile(uintptr(fd), path)
	if closeErr != nil {
		return nil, errors.Join(closeErr, f.Close())
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, errors.Join(fmt.Errorf("%w: unprotected native file %s", ErrUnsupported, path), f.Close())
	}
	return f, nil
}

func readNative(path string, limit int64) (data []byte, err error) {
	f, err := protectedOpen(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrUnsupported
	}
	return data, nil
}

func digestMessage(m proto.Message) ([]byte, error) {
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(m)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// productBackend maps a product the platform registry admits for
// platform.OSUpdate to its native automatic-update tool. Everything else,
// including image-based variants and derivatives, is unsupported.
func productBackend(p *resourcev1.PlatformProduct) (resourcev1.OSUpdateBackend, resourcev1.Backend, bool) {
	release := lindmplatform.Of(p)
	if release.Gate(lindmplatform.OSUpdate) != nil {
		return 0, 0, false
	}
	switch release.Native().Packages.Backend {
	case lindmplatform.BackendAPT:
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, resourcev1.Backend_BACKEND_APT, true
	case lindmplatform.BackendDNF5:
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, resourcev1.Backend_BACKEND_DNF5, true
	case lindmplatform.BackendDNF4:
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, resourcev1.Backend_BACKEND_DNF4, true
	case lindmplatform.BackendPacman:
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN, resourcev1.Backend_BACKEND_ALPM, release.Native().RollingUpdate != nil
	case lindmplatform.BackendZypper:
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER, resourcev1.Backend_BACKEND_ZYPPER, release.Native().RollingUpdate != nil
	default:
		return 0, 0, false
	}
}

// aptProduct reports the dpkg-based backend.
func aptProduct(p *resourcev1.PlatformProduct) bool {
	update, _, ok := productBackend(p)
	return ok && update == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES
}

func checkPlatform(p *resourcev1.PlatformProduct) error {
	if _, _, ok := productBackend(p); !ok {
		return ErrUnsupported
	}
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	content, err := readNative("/usr/lib/os-release", 32768)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"")
		}
	}
	if values["ID"] != p.GetOsId() || values["VERSION_ID"] != p.GetVersion() {
		return ErrUnsupported
	}
	return nil
}

func rpmArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

// packageVersion queries one fixed native package. Not installed is reported
// as errNotInstalled; any other failure or ambiguous output is an error.
func packageVersion(ctx context.Context, platform *resourcev1.PlatformProduct, name string, run commandRunner) (string, error) {
	switch name {
	case "unattended-upgrades", "needrestart", "dnf5-plugin-automatic", "dnf5-plugins", "dnf-automatic", "dnf-plugins-core", "pacman", "zypper":
	default:
		return "", ErrUnsupported
	}
	var output []byte
	var err error
	if aptProduct(platform) {
		// dpkg status distinguishes installed from merely retained config.
		output, err = run(ctx, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}\n", name)
	} else if name == "pacman" {
		output, err = run(ctx, "/usr/bin/pacman", "-Q", name)
	} else {
		output, err = run(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", name)
	}
	if err != nil {
		return "", err
	}
	version := strings.TrimSuffix(string(output), "\n")
	if strings.Contains(version, "\n") {
		return "", fmt.Errorf("%w: ambiguous native package %s", ErrUnsupported, name)
	}
	if name == "pacman" {
		var ok bool
		version, ok = strings.CutPrefix(version, "pacman ")
		if !ok {
			return "", ErrUnsupported
		}
	}
	if aptProduct(platform) {
		status, value, ok := strings.Cut(version, "\t")
		if !ok {
			return "", ErrUnsupported
		}
		if status != "ii " && status != "hi " {
			return "", errNotInstalled
		}
		version = value
	}
	if version == "" || len(version) > 96 {
		return "", ErrUnsupported
	}
	for _, c := range version {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune(".+:~_^-", c) {
			return "", ErrUnsupported
		}
	}
	return version, nil
}

// nativeTools reports the automatic-update tool version ("name version") and
// whether the native reboot oracle is installed. The runner needs the oracle
// on every run, so it is a prerequisite like the tool itself: a missing
// package is a typed precondition naming it, never a policy that converges
// while every window run fails.
func nativeTools(ctx context.Context, platform *resourcev1.PlatformProduct, run commandRunner) (string, bool, error) {
	var tool, oracle string
	update, _, _ := productBackend(platform)
	switch update {
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES:
		tool, oracle = "unattended-upgrades", "needrestart"
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC:
		// `dnf5 needs-restarting` is a dnf5-plugins command.
		tool, oracle = "dnf5-plugin-automatic", "dnf5-plugins"
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC:
		tool, oracle = "dnf-automatic", "dnf-plugins-core"
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN:
		tool = "pacman"
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER:
		tool = "zypper"
	default:
		return "", false, ErrUnsupported
	}
	version, err := packageVersion(ctx, platform, tool, run)
	if errors.Is(err, errNotInstalled) {
		return "", false, missingPackage(platform, tool, err)
	}
	if err != nil {
		return "", false, err
	}
	if oracle == "" {
		return tool + " " + version, true, nil
	}
	if _, err := packageVersion(ctx, platform, oracle, run); errors.Is(err, errNotInstalled) {
		return "", false, missingPackage(platform, oracle, err)
	} else if err != nil {
		return "", false, err
	}
	return tool + " " + version, true, nil
}

// aptPeriodicUpgrade reads APT's effective APT::Periodic::Unattended-Upgrade
// exactly as apt.systemd.daily does. Unset means disabled.
func aptPeriodicUpgrade(ctx context.Context, run commandRunner) (string, error) {
	output, err := run(ctx, "/usr/bin/apt-config", "shell", "Value", "APT::Periodic::Unattended-Upgrade")
	if err != nil {
		return "", err
	}
	return parseAPTShell(output)
}

func parseAPTShell(output []byte) (string, error) {
	line := strings.TrimSuffix(string(output), "\n")
	if line == "" {
		return "", nil
	}
	value, ok := strings.CutPrefix(line, "Value='")
	if !ok || strings.Contains(line, "\n") || !strings.HasSuffix(value, "'") {
		return "", fmt.Errorf("%w: unexpected apt-config output", ErrUnsupported)
	}
	value = strings.TrimSuffix(value, "'")
	if strings.ContainsAny(value, "'\\$`") || len(value) > 64 {
		return "", fmt.Errorf("%w: unexpected apt-config value", ErrUnsupported)
	}
	return value, nil
}

// parentsPresent refuses before observation when a package-created parent is
// missing: the provider never creates or removes these directories.
func parentsPresent(kinds []resourcev1.OSUpdateNativeFile) error {
	for _, kind := range kinds {
		parent := filepath.Dir(resource.OSUpdateNativePath(kind))
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: missing package directory %s", ErrMissingPrerequisite, parent)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrConflict, parent)
		}
	}
	return nil
}
