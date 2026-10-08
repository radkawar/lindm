//go:build linux

package inventory

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const (
	maxRecords     = 100000
	maxOutputBytes = 64 << 20
	maxLineBytes   = 16 << 10
	commandTimeout = 30 * time.Second
	success        = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	unavailable    = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	invalid        = inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
	capacity       = inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED
	commandFailure = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
)

type backend struct {
	name string
	path string
	args []string
}

var dpkg = backend{
	name: "dpkg", path: "/usr/bin/dpkg-query",
	args: []string{"--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n"},
}
var rpm = backend{
	name: "rpm", path: "/usr/bin/rpm",
	args: []string{"--query", "--all", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"},
}

// selectBackend requires explicit vendor/version and native database evidence.
// ID_LIKE is deliberately not a provider selector. Immutable variants require a
// dedicated provider even when they expose an RPM database.
func selectBackend(release map[string]string, stat func(string) (fs.FileInfo, error)) (backend, inventoryv1.CollectionStatus) {
	if release["VERSION_ID"] == "" {
		return backend{}, unavailable
	}
	var selected backend
	var databases []string
	switch release["ID"] {
	case "ubuntu", "debian":
		selected = dpkg
		databases = []string{"/var/lib/dpkg/status"}
	case "fedora", "rhel", "rocky", "almalinux", "centos", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled":
		selected = rpm
		databases = []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages"}
		if release["ID"] == "fedora" {
			switch release["VARIANT_ID"] {
			case "", "workstation", "server", "cloud", "container":
			default:
				return backend{}, unavailable
			}
		}
		for _, marker := range []string{"/run/ostree-booted", "/ostree/repo", "/sysroot/ostree/repo", "/etc/transactional-update.conf"} {
			_, err := stat(marker)
			if err == nil {
				return backend{}, unavailable
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return backend{}, statusFor(err)
			}
		}
	default:
		return backend{}, unavailable
	}
	for _, path := range databases {
		info, err := stat(path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return selected, invalid
			}
			return selected, success
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return selected, statusFor(err)
		}
	}
	return selected, unavailable
}

// runNative never inherits PATH, HOME, RPM/Dpkg overrides, or the caller's cwd.
// The runner boundary is private: callers cannot choose a tool or arguments.
func runNative(ctx context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
	cmd := exec.CommandContext(ctx, selected.path, selected.args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/", "TZ=UTC"}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	return runCommand(ctx, cmd, consume)
}

// runCommand is also exercised with a fixed test subprocess (never a shell).
func runCommand(ctx context.Context, cmd *exec.Cmd, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
	stderr := &boundedDiscard{remaining: 64 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return commandFailure
	}
	if err = cmd.Start(); err != nil {
		_ = stdout.Close() // Start failed; preserve its collection failure.
		if ctx.Err() != nil {
			return statusFor(ctx.Err())
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return statusFor(err)
		}
		return commandFailure
	}
	stop := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	defer stop()
	status := consume(stdout)
	if status != success {
		_ = cmd.Process.Kill()
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return statusFor(ctx.Err())
	}
	if stderr.exceeded {
		return capacity
	}
	if status != success {
		return status
	}
	// Warnings may describe unreadable/ignored database records. Even a zero
	// exit is not accepted as a complete snapshot when the native tool warns.
	if err != nil || stderr.remaining != 64<<10 {
		return commandFailure
	}
	return success
}

type boundedDiscard struct {
	remaining int
	exceeded  bool
}

func (w *boundedDiscard) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		w.exceeded = true
		return 0, errCapacity
	}
	w.remaining -= len(p)
	return len(p), nil
}

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]*$`)
var architecture = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
var epoch = regexp.MustCompile(`^[0-9]+$`)

func validVersion(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c <= ' ' || c == 127 {
			return false
		}
	}
	return true
}

func parsePackageLine(line, manager string) (*inventoryv1.Package, error) {
	fields := strings.Split(line, "\t")
	var name, version, arch string
	switch manager {
	case "dpkg":
		if len(fields) != 4 || len(fields[0]) != 3 {
			return nil, errInvalid
		}
		state := fields[0]
		if !strings.ContainsRune("uihrp", rune(state[0])) || !strings.ContainsRune("ncHUFWti", rune(state[1])) || !strings.ContainsRune(" R", rune(state[2])) {
			return nil, errInvalid
		}
		// Known non-installed states (including residual config-files) are not
		// installed packages. Selection 'hold' does not exclude an installed row.
		if state[1] != 'i' {
			if len(fields[1]) > 512 || !packageName.MatchString(fields[1]) ||
				(fields[2] != "" && !validVersion(fields[2])) ||
				(fields[3] != "" && (len(fields[3]) > 64 || !architecture.MatchString(fields[3]))) {
				return nil, errInvalid
			}
			return nil, nil
		}
		if state[2] != ' ' {
			return nil, errInvalid
		}
		name, version, arch = fields[1], fields[2], fields[3]
	case "rpm":
		if len(fields) != 5 || !epoch.MatchString(fields[1]) || !validVersion(fields[2]) || !validVersion(fields[3]) {
			return nil, errInvalid
		}
		name, version, arch = fields[0], fields[1]+":"+fields[2]+"-"+fields[3], fields[4]
	default:
		return nil, errInvalid
	}
	// RPM renders an absent header tag as "(none)", notably ARCH on imported
	// signing-key records. Preserve absence without inventing an architecture;
	// empty or malformed native fields remain invalid.
	absentArchitecture := manager == "rpm" && arch == "(none)"
	if len(name) > 512 || !packageName.MatchString(name) || !validVersion(version) || len(arch) > 64 || (!absentArchitecture && !architecture.MatchString(arch)) {
		return nil, errInvalid
	}
	if absentArchitecture {
		arch = ""
	}
	return &inventoryv1.Package{Name: name, Version: version, Architecture: arch, Manager: manager}, nil
}

type parseLimits struct {
	records int
	bytes   int64
}

func parsePackages(ctx context.Context, input io.Reader, manager string, limits parseLimits) ([]*inventoryv1.Package, inventoryv1.CollectionStatus) {
	limited := &io.LimitedReader{R: input, N: limits.bytes + 1}
	reader := bufio.NewReaderSize(limited, maxLineBytes)
	var packages []*inventoryv1.Package
	var count, encodedBytes int
	for {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		line, err := reader.ReadSlice('\n')
		if limited.N == 0 {
			return nil, capacity
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, capacity
		}
		if errors.Is(err, io.EOF) {
			if len(line) != 0 {
				return nil, invalid // A final incomplete record is never a snapshot.
			}
			break
		}
		if err != nil {
			return nil, invalid
		}
		count++
		if count > limits.records {
			return nil, capacity
		}
		pkg, err := parsePackageLine(string(line[:len(line)-1]), manager)
		if err != nil {
			return nil, invalid
		}
		if pkg != nil {
			// Include field tag and a conservative length-prefix allowance.
			encodedBytes += proto.Size(pkg) + 6
			if int64(encodedBytes) > limits.bytes {
				return nil, capacity
			}
			packages = append(packages, pkg)
		}
	}
	if ctx.Err() != nil {
		return nil, statusFor(ctx.Err())
	}
	slices.SortFunc(packages, func(a, b *inventoryv1.Package) int {
		if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Version, b.Version); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Architecture, b.Architecture)
	})
	// Do not deduplicate: multiversion/kernel and multiarch records are evidence.
	return packages, success
}

type nativeRunner func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus

func collectPackages(ctx context.Context, release map[string]string, stat func(string) (fs.FileInfo, error), run nativeRunner) *inventoryv1.PackageObservation {
	result := &inventoryv1.PackageObservation{StartedAt: timestamppb.Now()}
	defer func() { result.FinishedAt = timestamppb.Now() }()
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	if ctx.Err() != nil {
		result.Status = statusFor(ctx.Err())
		return result
	}
	selected, status := selectBackend(release, stat)
	result.Backend, result.Status = selected.name, status
	if status != success {
		return result
	}
	var packages []*inventoryv1.Package
	result.Status = run(ctx, selected, func(reader io.Reader) inventoryv1.CollectionStatus {
		var parsed inventoryv1.CollectionStatus
		packages, parsed = parsePackages(ctx, reader, selected.name, parseLimits{maxRecords, maxOutputBytes})
		return parsed
	})
	if ctx.Err() != nil {
		result.Status = statusFor(ctx.Err())
	}
	if result.Status == success {
		result.Packages = packages
	}
	return result
}
