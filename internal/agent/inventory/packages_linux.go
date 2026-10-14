// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/platform"
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
	args: []string{"--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"},
}
var rpm = backend{
	name: "rpm", path: "/usr/bin/rpm",
	args: []string{"--query", "--all", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\n"},
}

// selectBackend requires a registry release with inventory and native database
// evidence. ID_LIKE is never a provider selector. Image-based variants are
// separate registry rows (by VARIANT_ID) and require a dedicated provider even
// when they expose an RPM database.
func selectBackend(release map[string]string, stat func(string) (fs.FileInfo, error)) (backend, inventoryv1.CollectionStatus) {
	r := platform.Identify(platform.OSRelease{ID: release["ID"], VersionID: release["VERSION_ID"], VariantID: release["VARIANT_ID"]})
	if r.Gate(platform.Inventory) != nil {
		return backend{}, unavailable
	}
	var selected backend
	var databases []string
	switch r.Native().Packages.Backend.PackageDB() {
	case platform.PackageDBPacman:
		selected = backend{name: "pacman", path: "/var/lib/pacman/local"}
		databases = []string{selected.path}
	case platform.PackageDBDpkg:
		selected = dpkg
		databases = []string{"/var/lib/dpkg/status"}
	case platform.PackageDBRPM:
		selected = rpm
		// openSUSE Leap 16 and Tumbleweed default to rpm's ndb backend
		// (Packages.db); Fedora/EL use sqlite and older SUSE BerkeleyDB.
		databases = []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages.db", "/var/lib/rpm/Packages.db", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages"}
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
			if (selected.name == "pacman" && !info.IsDir()) || (selected.name != "pacman" && !info.Mode().IsRegular()) {
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

// nativeStderrLimit bounds retained native diagnostics; overflow is capacity.
const nativeStderrLimit = 64 << 10

// runNative never inherits PATH, HOME, RPM/Dpkg overrides, or the caller's cwd.
// The runner boundary is private: callers cannot choose a tool or arguments.
func runNative(ctx context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
	return runCommand(ctx, nativeexec.Command{Path: selected.path, Args: selected.args, Env: []string{"HOME=/", "TZ=UTC"}}, consume)
}

// runCommand streams stdout to consume through nativeexec. Every collector
// already bounds ctx (at most commandTimeout); commandTimeout is the backstop.
// It is also exercised with a fixed test subprocess (never a shell).
func runCommand(ctx context.Context, c nativeexec.Command, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
	status, consumed := commandFailure, false
	c.Timeout, c.StderrLimit = commandTimeout, nativeStderrLimit
	c.Stream = func(reader io.Reader) { consumed, status = true, consume(reader) }
	result, err := nativeexec.Run(ctx, c)
	if ctx.Err() != nil {
		return statusFor(ctx.Err())
	}
	if errors.Is(err, nativeexec.ErrDeadline) {
		return statusFor(context.DeadlineExceeded)
	}
	if !consumed {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return statusFor(err)
		}
		return commandFailure
	}
	if result.StderrTruncated {
		return capacity
	}
	if status != success {
		// A native tool that exited on its own with a failure status (for
		// example EL8 util-linux 2.32 lsblk rejecting a newer --output column)
		// is a native command failure, not malformed output. Only our own kill
		// of a stopped consumer leaves the parser's verdict authoritative.
		var exited *nativeexec.ExitError
		if !result.Stopped && errors.As(err, &exited) {
			return commandFailure
		}
		return status
	}
	// Warnings may describe unreadable/ignored database records. Even a zero
	// exit is not accepted as a complete snapshot when the native tool warns.
	if err != nil || len(result.Stderr) != 0 {
		return commandFailure
	}
	return success
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
	var name, version, arch, sourceName, sourceVersion string
	var module *inventoryv1.ModuleObservation
	switch manager {
	case "dpkg":
		if len(fields) != 6 || len(fields[0]) != 3 {
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
		sourceName, sourceVersion = fields[4], fields[5]
		if len(sourceName) > 512 || !packageName.MatchString(sourceName) || !validVersion(sourceVersion) {
			return nil, errInvalid
		}
		module = &inventoryv1.ModuleObservation{Status: unavailable}
	case "pacman":
		if len(fields) != 3 {
			return nil, errInvalid
		}
		name, version, arch = fields[0], fields[1], fields[2]
		if prefix, _, found := strings.Cut(version, ":"); found && !epoch.MatchString(prefix) {
			return nil, errInvalid
		}
		module = &inventoryv1.ModuleObservation{Status: unavailable}
	case "rpm":
		if len(fields) != 6 || !epoch.MatchString(fields[1]) || !validVersion(fields[2]) || !validVersion(fields[3]) {
			return nil, errInvalid
		}
		name, version, arch = fields[0], fields[1]+":"+fields[2]+"-"+fields[3], fields[4]
		module = parseModuleLabel(fields[5])
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
	return &inventoryv1.Package{Name: name, Version: version, Architecture: arch, Manager: manager, SourceName: sourceName, SourceVersion: sourceVersion, Module: module}, nil
}

func parseModuleLabel(label string) *inventoryv1.ModuleObservation {
	if label == "(none)" {
		return &inventoryv1.ModuleObservation{Status: success}
	}
	parts := strings.Split(label, ":")
	if len(parts) != 4 || len(parts[0]) > 256 || !packageName.MatchString(parts[0]) ||
		len(parts[1]) > 256 || !packageName.MatchString(parts[1]) ||
		len(parts[2]) > 32 || !epoch.MatchString(parts[2]) ||
		len(parts[3]) > 256 || !packageName.MatchString(parts[3]) {
		return &inventoryv1.ModuleObservation{Status: invalid}
	}
	return &inventoryv1.ModuleObservation{
		Status: success, Modular: true, Name: parts[0], Stream: parts[1],
		Version: parts[2], Context: parts[3],
	}
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

// collectPackages attaches APT origin evidence to dpkg packages and an
// UNAVAILABLE origin to every other backend's packages. Origin reading has
// its own deadline: slow lists degrade origin evidence, never package evidence.
func collectPackages(parent context.Context, release map[string]string, stat func(string) (fs.FileInfo, error), run nativeRunner, apt aptSources) *inventoryv1.PackageObservation {
	result := &inventoryv1.PackageObservation{StartedAt: timestamppb.Now()}
	defer func() { result.FinishedAt = timestamppb.Now() }()
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
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
	if selected.name == "pacman" {
		packages, result.Status = collectPacman(ctx, selected.path, parseLimits{maxRecords, maxOutputBytes})
	} else {
		result.Status = run(ctx, selected, func(reader io.Reader) inventoryv1.CollectionStatus {
			var parsed inventoryv1.CollectionStatus
			packages, parsed = parsePackages(ctx, reader, selected.name, parseLimits{maxRecords, maxOutputBytes})
			return parsed
		})
	}
	if ctx.Err() != nil {
		result.Status = statusFor(ctx.Err())
	}
	if result.Status != success {
		return result
	}
	if selected.name == "dpkg" {
		originCtx, cancelOrigin := context.WithTimeout(parent, commandTimeout)
		defer cancelOrigin()
		attachAptOrigins(originCtx, packages, apt, maxOutputBytes)
	} else {
		for _, pkg := range packages {
			pkg.Origin = &inventoryv1.PackageOrigin{Status: unavailable}
		}
	}
	result.Packages = packages
	return result
}
