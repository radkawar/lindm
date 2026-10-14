// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

// Per-step bounds. The worst-case sum of every step of a run (asserted by
// TestRunStepBoundsFitTheUnitTimeout) stays below runBudget, the overall
// deadline of a run, which leaves lindm-os-update{,-now}.service's
// TimeoutStartSec=6h a margin of runTermGrace for a package manager to finish
// after SIGTERM. The runner never SIGKILLs a native tool; only systemd does
// at the unit timeout.
const (
	refreshTimeout   = 30 * time.Minute
	listTimeout      = 10 * time.Minute
	snapshotTimeout  = 5 * time.Minute
	installTimeout   = 3*time.Hour + 30*time.Minute
	restartTimeout   = 15 * time.Minute
	oracleTimeout    = 5 * time.Minute
	listOutputLimit  = 32 << 20
	oracleOutputMax  = 1 << 20
	snapshotOutput   = 64 << 20
	maxMetadataFiles = 4096
	// Per-run native configuration (never under /etc). Created 0700 root by
	// the runner while it holds the run lock.
	runtimeDir    = "/run/lindm-os-update"
	aptConfigPath = runtimeDir + "/apt.conf"
	aptMainPath   = runtimeDir + "/apt-main.conf"
	dnfAutoPath   = runtimeDir + "/automatic.conf"
)

// Status reasons published on unavailable observations.
const (
	reasonPlatform     = "native_platform_unsupported"
	reasonToolMissing  = "native_tool_missing"
	reasonMetadata     = "native_metadata_unavailable"
	reasonListFailed   = "native_list_failed"
	reasonOracleFailed = "reboot_oracle_failed"
)

// nativeFailure carries the sanitized diagnostic of a failed native step and
// the patch-status reason it maps to.
type nativeFailure struct {
	reason     string
	diagnostic *agentv1.PatchRunDiagnostic
}

func (f *nativeFailure) Error() string { return f.reason }

// commandResult is a finished native command: the bounded stdout used for
// parsing and independent diagnostic tails. exitCode is -1 when the process
// did not exit normally.
type commandResult struct {
	stdout                 []byte
	stdoutTail, stderrTail *outputCapture
	exitCode               int
}

// step is one native invocation's policy. stdoutLimit > 0 marks output that
// is parsed and must be complete; 0 means the output only feeds diagnostics.
// mutating marks package-database transactions (TerminateOnly).
type step struct {
	timeout     time.Duration
	stdoutLimit int
	mutating    bool
	env         []string
}

const (
	diagnosticOutputLimit = 4 << 10
	parsedStderrLimit     = 1 << 20
)

// runCommand runs a fixed native executable through nativeexec: argv only,
// custody-checked executable, fixed environment plus allowlisted keys, own
// process group, bounded streams. Queries are group-killed at their deadline;
// mutating steps only get SIGTERM, because a package manager killed by
// SIGKILL may leave dpkg or rpm half-configured, and the unit timeout bounds
// that wait. Output beyond the limits only fails parsed steps.
func runCommand(ctx context.Context, s step, path string, args ...string) (commandResult, error) {
	out := commandResult{stdoutTail: newOutputCapture(), stderrTail: newOutputCapture(), exitCode: -1}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	command := nativeexec.Command{
		Path: path, Args: args, Env: append([]string{"HOME=/root"}, s.env...),
		Timeout: s.timeout, StdoutLimit: diagnosticOutputLimit, StderrLimit: diagnosticOutputLimit,
		StdoutTee: out.stdoutTail, StderrTee: out.stderrTail, TerminateOnly: s.mutating,
	}
	if s.stdoutLimit > 0 {
		command.StdoutLimit, command.StderrLimit = s.stdoutLimit, parsedStderrLimit
	}
	result, err := nativeexec.Run(ctx, command)
	out.stdout, out.exitCode = result.Stdout, result.ExitCode
	var exit *nativeexec.ExitError
	if errors.Is(err, nativeexec.ErrOutputLimit) && result.ExitCode == 0 && !errors.As(err, &exit) && !errors.Is(err, nativeexec.ErrDeadline) && ctx.Err() == nil {
		err = nil
		if s.stdoutLimit > 0 && (result.StdoutTruncated || result.StderrTruncated) {
			err = errNativeOutput
		}
	}
	return out, err
}

func failure(reason string, tool agentv1.PatchRunTool, phase agentv1.PatchRunPhase, result commandResult) *nativeFailure {
	return &nativeFailure{reason: reason, diagnostic: nativeDiagnostic(tool, phase, result.exitCode, result.stdoutTail, result.stderrTail)}
}

// backend is the per-distribution native mechanism.
type backend interface {
	kind() resourcev1.OSUpdateBackend
	// missingTool names the native package providing a required tool that is
	// absent; run additionally requires the installing tools.
	missingTool(run bool) (tool agentv1.PatchRunTool, pkg string)
	refresh(ctx context.Context) error
	// pending lists upgrades offline from the refreshed native cache.
	pending(ctx context.Context) ([]pendingPackage, error)
	installed(ctx context.Context) (map[packageKey]string, error)
	install(ctx context.Context, run installRequest) error
	// rebootRequired is the native reboot oracle (offline).
	rebootRequired(ctx context.Context) (bool, error)
	// metadataPatterns locate repository metadata in the native cache.
	metadataPatterns() []string
}

type installRequest struct {
	selection resourcev1.UpdateSelection
	deferred  []packageKey
	patchNow  bool
}

// detectBackend maps /etc/os-release through the platform registry to the
// qualified native mechanism; releases gated on platform.OSUpdate are refused.
func detectBackend(osRelease []byte) (backend, error) {
	values := parseOSRelease(osRelease)
	release := platform.Identify(platform.OSRelease{ID: values["ID"], VersionID: values["VERSION_ID"], VariantID: values["VARIANT_ID"]})
	if release.Gate(platform.OSUpdate) != nil {
		return nil, errors.New(reasonPlatform)
	}
	switch release.Native().Packages.Backend {
	case platform.BackendAPT:
		return aptBackend{needrestart: needrestartPath, signal: release.Native().RebootSignal}, nil
	case platform.BackendDNF5:
		return dnfBackend{dnf5: true}, nil
	case platform.BackendDNF4:
		return dnfBackend{}, nil
	case platform.BackendPacman, platform.BackendZypper:
		if release.Native().RollingUpdate == nil {
			return nil, errors.New(reasonPlatform)
		}
		return &rollingBackend{release: release.Native()}, nil
	default:
		return nil, errors.New(reasonPlatform)
	}
}

func executable(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o111 != 0
}

func anyRegular(patterns ...string) bool {
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			if info, err := os.Lstat(match); err == nil && info.Mode().IsRegular() {
				return true
			}
		}
	}
	return false
}

// metadataRefreshedAt returns the newest repository metadata mtime, or false
// when the cache holds none (zero pending must never be inferred from it).
func metadataRefreshedAt(patterns []string) (time.Time, bool) {
	var newest time.Time
	seen := 0
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			if seen++; seen > maxMetadataFiles {
				return newest, !newest.IsZero()
			}
			info, err := os.Lstat(match)
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				continue
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	return newest, !newest.IsZero()
}

// prepareRuntimeDir creates the per-run configuration directory or accepts an
// existing private root-owned one.
func prepareRuntimeDir() error {
	if err := unix.Mkdir(runtimeDir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return checkPrivateDir(runtimeDir)
}

// aptBackend drives unattended-upgrade(8) on Ubuntu. needrestart(1), when
// installed, restarts services after a run and reports a pending kernel; the
// registry's reboot signal (Ubuntu's update-notifier marker) is the reboot
// oracle without it. Either suffices: a stock Ubuntu desktop ships only the
// marker writers.
type aptBackend struct {
	needrestart string
	signal      *platform.RebootSignal
}

const (
	aptGet          = "/usr/bin/apt-get"
	unattended      = "/usr/bin/unattended-upgrade"
	needrestartPath = "/usr/sbin/needrestart"
	dpkgQuery       = "/usr/bin/dpkg-query"
	aptListsGlob    = "/var/lib/apt/lists/*Release"
)

func (aptBackend) kind() resourcev1.OSUpdateBackend {
	return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES
}

func (b aptBackend) missingTool(run bool) (agentv1.PatchRunTool, string) {
	if !executable(aptGet) {
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_APT_GET, "apt"
	}
	if tool, pkg := b.missingOracle(); pkg != "" {
		return tool, pkg
	}
	switch {
	case run && !executable(unattended):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_UNATTENDED_UPGRADE, "unattended-upgrades"
	case run && !executable(dpkgQuery):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_APT_GET, "dpkg"
	}
	return agentv1.PatchRunTool_PATCH_RUN_TOOL_UNSPECIFIED, ""
}

// missingOracle names the package to install when no reboot oracle is: the
// registry's reboot-signal package, or needrestart on a release without one.
func (b aptBackend) missingOracle() (agentv1.PatchRunTool, string) {
	switch {
	case b.hasNeedrestart() || b.signalWritten():
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_UNSPECIFIED, ""
	case b.signal != nil:
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_UPDATE_NOTIFIER, b.signal.Package
	default:
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_NEEDRESTART, "needrestart"
	}
}

func (b aptBackend) hasNeedrestart() bool { return executable(b.needrestart) }

// signalWritten reports that every registry writer of the reboot-required
// marker is installed; a partial set could miss a kernel installation.
func (b aptBackend) signalWritten() bool {
	if b.signal == nil || len(b.signal.Writers) == 0 {
		return false
	}
	for _, writer := range b.signal.Writers {
		if !executable(writer) {
			return false
		}
	}
	return true
}

func (aptBackend) metadataPatterns() []string { return []string{aptListsGlob} }

func (aptBackend) refresh(ctx context.Context) error {
	result, err := runCommand(ctx, step{timeout: refreshTimeout}, aptGet, "-q", "update")
	if err != nil {
		return failure("native_refresh_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_APT_GET, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REFRESH, result)
	}
	return nil
}

func (aptBackend) pending(ctx context.Context) ([]pendingPackage, error) {
	result, err := runCommand(ctx, step{timeout: listTimeout, stdoutLimit: listOutputLimit}, aptGet, "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err == nil {
		var pending []pendingPackage
		if pending, err = parseAptSimulation(result.stdout); err == nil {
			return pending, nil
		}
	}
	return nil, failure(reasonListFailed, agentv1.PatchRunTool_PATCH_RUN_TOOL_APT_GET, agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, result)
}

func (aptBackend) installed(ctx context.Context) (map[packageKey]string, error) {
	result, err := runCommand(ctx, step{timeout: snapshotTimeout, stdoutLimit: snapshotOutput}, dpkgQuery, "-W", "-f=${Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n")
	if err == nil {
		var installed map[packageKey]string
		if installed, err = parseInstalled(result.stdout, true); err == nil {
			return installed, nil
		}
	}
	return nil, failure("native_snapshot_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_APT_GET, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
}

// install runs unattended-upgrade with the per-run APT configuration, then,
// when installed, lets needrestart restart affected services.
// NEEDRESTART_MODE=a also covers needrestart's dpkg Post-Invoke hook during
// the run. The explicit pass uses -l (libraries and services only): the
// kernel verdict is the reboot oracle's job and must not prompt. Without
// needrestart the run restarts exactly what Ubuntu's own unattended-upgrades
// does: the units the upgraded packages' maintainer scripts restart.
func (b aptBackend) install(ctx context.Context, run installRequest) error {
	if err := prepareRuntimeDir(); err != nil {
		return &nativeFailure{reason: "native_install_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, "per-run configuration directory unavailable")}
	}
	defer func() { _ = unix.Unlink(aptConfigPath); _ = unix.Unlink(aptMainPath) }()
	// A present (or unreadable) system main file stays included; APT
	// itself reports an unreadable one.
	_, statErr := os.Lstat("/etc/apt/apt.conf")
	includeMain := !errors.Is(statErr, fs.ErrNotExist)
	if err := errors.Join(writeAtomic(aptMainPath, renderAPTMain(run.selection, includeMain, run.deferred)), writeAtomic(aptConfigPath, renderAPTConfig(aptMainPath))); err != nil {
		return &nativeFailure{reason: "native_install_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, "per-run APT configuration could not be written")}
	}
	env := []string{"APT_CONFIG=" + aptConfigPath, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"}
	result, err := runCommand(ctx, step{timeout: installTimeout, mutating: true, env: env}, unattended, "-v")
	if err != nil {
		return failure("native_install_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_UNATTENDED_UPGRADE, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
	}
	if !b.hasNeedrestart() {
		return nil
	}
	result, err = runCommand(ctx, step{timeout: restartTimeout, mutating: true, env: []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"}}, b.needrestart, "-r", "a", "-l")
	if err != nil {
		return failure("native_restart_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_NEEDRESTART, agentv1.PatchRunPhase_PATCH_RUN_PHASE_RESTART_SERVICES, result)
	}
	return nil
}

// rebootRequired: the registry's reboot-required marker, else a pending
// kernel upgrade from `needrestart -b -k` (KSTA 2 or 3) when needrestart is
// installed. An absent marker means no reboot only while its writers are
// installed.
func (b aptBackend) rebootRequired(ctx context.Context) (bool, error) {
	if b.signal != nil {
		if _, err := os.Lstat(b.signal.Marker); err == nil {
			return true, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, &nativeFailure{reason: reasonOracleFailed, diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, "reboot-required marker unreadable")}
		}
	}
	if !b.hasNeedrestart() {
		if b.signalWritten() {
			return false, nil
		}
		return false, &nativeFailure{reason: reasonOracleFailed, diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, "no native reboot oracle is installed")}
	}
	result, err := runCommand(ctx, step{timeout: oracleTimeout, stdoutLimit: oracleOutputMax}, b.needrestart, "-b", "-k")
	if err == nil {
		var status int
		if status, err = parseNeedrestartKernel(result.stdout); err == nil {
			return status == 2 || status == 3, nil
		}
	}
	return false, failure(reasonOracleFailed, agentv1.PatchRunTool_PATCH_RUN_TOOL_NEEDRESTART, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, result)
}

// dnfBackend drives dnf5 (Fedora 43/44) or dnf 4 with dnf-automatic (EL 9/10).
type dnfBackend struct{ dnf5 bool }

const (
	dnf5Binary   = "/usr/bin/dnf5"
	dnf4Binary   = "/usr/bin/dnf"
	dnfAutomatic = "/usr/bin/dnf-automatic"
	rpmBinary    = "/usr/bin/rpm"
)

// dnf5 command plugins. A stock Fedora 44 Workstation ships neither
// dnf5-plugin-automatic nor dnf5-plugins, so the runner then reaches the same
// upgrade goal through `dnf5 upgrade` and the same reboot verdict through rpm;
// the plugin paths are used whenever the plugins are installed.
var (
	dnf5AutomaticPlugin       = []string{"/usr/lib64/dnf5/plugins/automatic_cmd_plugin.so", "/usr/lib/dnf5/plugins/automatic_cmd_plugin.so"}
	dnf5NeedsRestartingPlugin = []string{"/usr/lib64/dnf5/plugins/needs_restarting_cmd_plugin.so", "/usr/lib/dnf5/plugins/needs_restarting_cmd_plugin.so"}
)

// dnf5 automatic accepts no configuration path and reads, in order,
// /usr/share/dnf5/dnf5-plugins/automatic.conf, /etc/dnf/dnf5-plugins/
// automatic.conf (deprecated) and /etc/dnf/automatic.conf, later keys
// winning (dnf5-plugins/automatic_plugin/automatic.cpp pre_configure). The
// last one is owned by the os.update.v1 provider on Fedora.
var dnf5AutomaticFiles = []string{
	"/usr/share/dnf5/dnf5-plugins/automatic.conf",
	"/etc/dnf/dnf5-plugins/automatic.conf",
	resource.OSUpdateDNF5AutomaticPath,
}

func (b dnfBackend) binary() string {
	if b.dnf5 {
		return dnf5Binary
	}
	return dnf4Binary
}

func (b dnfBackend) tool() agentv1.PatchRunTool {
	if b.dnf5 {
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF5
	}
	return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF
}

func (b dnfBackend) kind() resourcev1.OSUpdateBackend {
	if b.dnf5 {
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC
	}
	return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC
}

func (b dnfBackend) missingTool(run bool) (agentv1.PatchRunTool, string) {
	if b.dnf5 {
		switch {
		case !executable(dnf5Binary):
			return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF5, "dnf5"
		// Runs snapshot the rpmdb; without dnf5-plugins rpm is the reboot
		// oracle too.
		case (run || !anyRegular(dnf5NeedsRestartingPlugin...)) && !executable(rpmBinary):
			return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF5, "rpm"
		}
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_UNSPECIFIED, ""
	}
	switch {
	case !executable(dnf4Binary):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF, "dnf"
	case !anyRegular("/usr/lib/python3*/site-packages/dnf-plugins/needs_restarting.py"):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF, "dnf-plugins-core"
	case run && !executable(dnfAutomatic):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF_AUTOMATIC, "dnf-automatic"
	case run && !executable(rpmBinary):
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF, "rpm"
	}
	return agentv1.PatchRunTool_PATCH_RUN_TOOL_UNSPECIFIED, ""
}

func (b dnfBackend) metadataPatterns() []string {
	if b.dnf5 {
		return []string{"/var/cache/libdnf5/*/repodata/repomd.xml"}
	}
	return []string{"/var/cache/dnf/*/repodata/repomd.xml"}
}

func (b dnfBackend) refresh(ctx context.Context) error {
	result, err := runCommand(ctx, step{timeout: refreshTimeout}, b.binary(), "-q", "makecache", "--refresh")
	if err != nil {
		return failure("native_refresh_failed", b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_REFRESH, result)
	}
	return nil
}

// pending lists the newest upgrade per package from the cache only: once in
// full and once restricted to security advisories. dnf5's queryformat needs
// an explicit newline; dnf 4 appends one per package. The tab and newline
// are literal argv bytes, as no shell is involved.
func (b dnfBackend) pending(ctx context.Context) ([]pendingPackage, error) {
	format := "--queryformat=%{name}\t%{arch}"
	if b.dnf5 {
		format += "\n"
	}
	var lists [2][]packageKey
	for i, security := range []bool{false, true} {
		args := []string{"--cacheonly", "-q", "repoquery", "--upgrades", "--latest-limit=1", format}
		if security {
			args = append(args, "--security")
		}
		result, err := runCommand(ctx, step{timeout: listTimeout, stdoutLimit: listOutputLimit}, b.binary(), args...)
		if err == nil {
			lists[i], err = parseRepoquery(result.stdout)
		}
		if err != nil {
			return nil, failure(dnfListReason(result), b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, result)
		}
	}
	pending, err := mergeRepoquery(lists[0], lists[1])
	if err != nil {
		return nil, &nativeFailure{reason: reasonListFailed, diagnostic: runnerDiagnostic(b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, "security upgrade list is not a subset of the upgrade list")}
	}
	return pending, nil
}

// dnfListReason classifies a failed cache-only listing. A repository whose
// metadata was never downloaded (dnf5: `Cache-only enabled but no cache for
// repository "fedora"`, dnf 4: `Cache-only enabled but no cache for
// 'fedora'`) is missing metadata, not a listing failure; zero pending is
// never inferred from it.
func dnfListReason(result commandResult) string {
	for _, output := range []*outputCapture{result.stdoutTail, result.stderrTail} {
		if output != nil && strings.Contains(output.buf.String(), "Cache-only enabled but no cache for") {
			return reasonMetadata
		}
	}
	return reasonListFailed
}

func (b dnfBackend) installed(ctx context.Context) (map[packageKey]string, error) {
	result, err := runCommand(ctx, step{timeout: snapshotTimeout, stdoutLimit: snapshotOutput}, rpmBinary, "-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
	if err == nil {
		var installed map[packageKey]string
		if installed, err = parseInstalled(result.stdout, false); err == nil {
			return installed, nil
		}
	}
	return nil, failure("native_snapshot_failed", b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
}

func (b dnfBackend) install(ctx context.Context, run installRequest) error {
	if b.dnf5 {
		return b.installDNF5(ctx, run)
	}
	if err := prepareRuntimeDir(); err != nil {
		return &nativeFailure{reason: "native_install_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, "per-run configuration directory unavailable")}
	}
	defer func() { _ = unix.Unlink(dnfAutoPath) }()
	if err := writeAtomic(dnfAutoPath, renderDNFAutomatic(run.selection, run.deferred)); err != nil {
		return &nativeFailure{reason: "native_install_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, "per-run dnf-automatic configuration could not be written")}
	}
	// dnf-automatic [--installupdates] [conf_path]: the positional path
	// replaces /etc/dnf/automatic.conf; --installupdates implies download.
	result, err := runCommand(ctx, step{timeout: installTimeout, mutating: true}, dnfAutomatic, dnfAutoPath, "--installupdates")
	if err != nil {
		return failure("native_install_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF_AUTOMATIC, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
	}
	return nil
}

// installDNF5 runs window updates through `dnf5 automatic` when
// dnf5-plugin-automatic is installed; its provider-owned configuration must
// select exactly this run's upgrade type and never reboot on its own.
func (b dnfBackend) installDNF5(ctx context.Context, run installRequest) error {
	args, automatic := dnf5InstallArgs(run, anyRegular(dnf5AutomaticPlugin...))
	if automatic {
		files := make([][]byte, 0, len(dnf5AutomaticFiles))
		for _, path := range dnf5AutomaticFiles {
			data, err := readProtected(path, 64<<10)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return &nativeFailure{reason: "native_install_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "dnf5 automatic configuration unreadable")}
			}
			files = append(files, data)
		}
		if err := checkDNF5Automatic(effectiveDNF5Automatic(files...), run.selection); err != nil {
			return &nativeFailure{reason: errDNF5AutomaticConfig.Error(), diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, errDNF5AutomaticConfig.Error())}
		}
	}
	result, err := runCommand(ctx, step{timeout: installTimeout, mutating: true}, dnf5Binary, args...)
	if err != nil {
		return failure("native_install_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_DNF5, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
	}
	return nil
}

// dnf5InstallArgs selects the dnf5 transaction and reports whether it is
// `dnf5 automatic`. Patch now carries its own selection, which no fixed
// configuration file can express, and a window run without
// dnf5-plugin-automatic has no automatic command; both use the same solver
// goal through `dnf5 upgrade [--security]` (automatic's run() builds
// add_rpm_upgrade with a security advisory filter, and upgrade --security
// sets the same filter, in 5.4.1.0 as in later releases). Global --exclude
// options apply to either.
func dnf5InstallArgs(run installRequest, automaticPlugin bool) ([]string, bool) {
	args := dnf5ExcludeArgs(run.deferred)
	if automaticPlugin && !run.patchNow {
		return append(args, "automatic", "--installupdates"), true
	}
	args = append(args, "--assumeyes", "upgrade")
	if run.selection == resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY {
		args = append(args, "--security")
	}
	return args, false
}

// oracleArgs runs needs-restarting -r against the rpmdb alone: every
// repository is disabled (dnf5 `--disable-repo=*`, a glob over repo ids,
// dnf5/main.cpp; dnf 4 `--disablerepo=*`). needs-restarting otherwise loads
// the enabled repositories and requests filelists and updateinfo metadata,
// which a cache-only run fails on when that metadata was never downloaded
// ("Cache-only enabled but no cache for repository"). The verdict then comes
// from the installed reboot-suggesting core packages (kernel, glibc,
// systemd, ..., plus suggest-reboot drop-ins) installed after boot; reboot
// hints carried only by repository advisories are not consulted.
func (b dnfBackend) oracleArgs() []string {
	if b.dnf5 {
		return []string{"-q", "--disable-repo=*", "needs-restarting", "-r"}
	}
	return []string{"-q", "--disablerepo=*", "needs-restarting", "-r"}
}

func (b dnfBackend) rebootRequired(ctx context.Context) (bool, error) {
	if b.dnf5 && !anyRegular(dnf5NeedsRestartingPlugin...) {
		return b.rpmRebootRequired(ctx)
	}
	result, err := runCommand(ctx, step{timeout: oracleTimeout, stdoutLimit: oracleOutputMax}, b.binary(), b.oracleArgs()...)
	var exit *nativeexec.ExitError
	if err == nil || (errors.As(err, &exit) && result.exitCode == 1) {
		required, parseErr := needsRestartingResult(result.exitCode, result.stdout)
		if parseErr == nil {
			return required, nil
		}
	}
	return false, failure(reasonOracleFailed, b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, result)
}

// rpmRebootRequired is `needs-restarting -r` without dnf5-plugins: the same
// rpmdb-only verdict the repository-disabled plugin run gives (see
// oracleArgs), from the install times of the reboot-suggesting core packages.
func (b dnfBackend) rpmRebootRequired(ctx context.Context) (bool, error) {
	boot, err := bootUnixSeconds()
	if err != nil {
		return false, &nativeFailure{reason: reasonOracleFailed, diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, "boot time unavailable")}
	}
	result, err := runCommand(ctx, step{timeout: oracleTimeout, stdoutLimit: snapshotOutput}, rpmBinary, "-qa", "--qf", "%{NAME}\t%{INSTALLTIME}\n")
	if err == nil {
		required, parseErr := rebootSuggestedSince(result.stdout, boot)
		if parseErr == nil {
			return required, nil
		}
	}
	return false, failure(reasonOracleFailed, b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_CHECK, result)
}

// bootUnixSeconds is the wall-clock second the kernel booted under the
// current clock (the /proc/stat btime derivation), so a clock step after
// boot moves it with the install times rpm records.
func bootUnixSeconds() (int64, error) {
	var realtime, boottime unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return 0, err
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boottime); err != nil {
		return 0, err
	}
	return (realtime.Nano() - boottime.Nano()) / int64(time.Second), nil
}
