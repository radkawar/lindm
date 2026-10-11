package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
	"lindm/internal/platform"
)

const installedBinary = "/usr/libexec/lindm/lindm-agent"

var errNativePayloadMismatch = errors.New("native agent payload mismatch")
var errTransactionExpired = errors.New("verified update expired before native effect")

func expiryNeedsPredecessorProof(now time.Time, tx *agentv1.AgentUpdateTransaction, prior installedPackage, helperPhase string) (bool, error) {
	if !now.Before(tx.GetAdmittedAt().AsTime()) && now.Before(tx.GetVerifiedExpiresAt().AsTime()) {
		return false, nil
	}
	if helperPhase != "installing" && helperPhase != "recovery_required" {
		return false, errTransactionExpired
	}
	// A target DB row, incomplete package status, or authoritative absence after
	// consumption establishes an owned effect. An intact predecessor does not.
	return prior.version != tx.GetNativeVersion() && prior.state == "installed", nil
}

func authorizeNativeEffect(ctx context.Context, tx *agentv1.AgentUpdateTransaction, prior installedPackage, helperPhase string) error {
	proof, err := expiryNeedsPredecessorProof(time.Now(), tx, prior, helperPhase)
	if err != nil || !proof {
		return err
	}
	// A fully configured predecessor with intact payload is not evidence that
	// this transaction started. Do not convert an expired staged plan into work.
	err = verifyInstalledPayload(ctx, &agentv1.AgentUpdateTransaction{Version: tx.GetPreviousVersion(), Manager: tx.GetManager()})
	if errors.Is(err, errNativePayloadMismatch) {
		return nil
	}
	if err != nil {
		return err
	}
	return errTransactionExpired
}

type installedPackage struct{ name, version, architecture, state string }

func recoverablePredecessor(prior installedPackage, tx *agentv1.AgentUpdateTransaction, helperPhase string) bool {
	if prior.name != "lindm-agent" {
		return false
	}
	// An authoritative native 'not installed' observation is recoverable only
	// after this exact durable transaction crossed its installing boundary.
	if prior.state == "absent" {
		return helperPhase == "installing"
	}
	return prior.architecture == nativeArchitecture(tx.GetArchitecture(), packageDB(tx.GetManager())) && (prior.version == tx.GetNativeVersion() || prior.version == tx.GetPreviousNativeVersion())
}

// packageDB is the installed-package database a native update manager drives.
func packageDB(manager agentv1.NativeUpdateManager) platform.PackageDB {
	switch manager {
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT:
		return platform.PackageDBDpkg
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_DNF, agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_ZYPPER:
		return platform.PackageDBRPM
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_PACMAN:
		return platform.PackageDBPacman
	default:
		return platform.PackageDBNone
	}
}

func packagePath(directory string, tx *agentv1.AgentUpdateTransaction) string {
	switch db := packageDB(tx.GetManager()); db {
	case platform.PackageDBDpkg:
		// APT --no-download requires the verified archive to already occupy its
		// canonical cache filename. The validated native version admits no
		// path separators; APT percent-escapes ':' and '_' in this component.
		version := strings.ReplaceAll(strings.ReplaceAll(tx.GetNativeVersion(), ":", "%3a"), "_", "%5f")
		return filepath.Join(directory, "lindm-agent_"+version+"_"+tx.GetArchitecture()+".deb")
	case platform.PackageDBPacman:
		return filepath.Join(directory, "agent.pkg.tar.zst")
	default:
		return filepath.Join(directory, "agent."+db.PackageFormat())
	}
}

func nativeArchitecture(arch string, db platform.PackageDB) string {
	if db == platform.PackageDBDpkg {
		return arch
	}
	if arch == "amd64" {
		return "x86_64"
	}
	if arch == "arm64" {
		return "aarch64"
	}
	return "unsupported"
}

func mutablePlatform(manager agentv1.NativeUpdateManager) error {
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS"} {
		if _, err := os.Stat(marker); err == nil {
			return errors.New("native self-update requires a mutable OS; use its distinct image/generation provider")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if packageDB(manager) == platform.PackageDBNone {
		return errors.New("native update manager unsupported")
	}
	return nil
}

func (p installedPackage) matchesRunning(version, arch string) error {
	if p.name != "lindm-agent" || p.state != "installed" || (p.architecture != arch && p.architecture != nativeArchitecture(arch, platform.PackageDBRPM)) || (p.version != version && !strings.HasPrefix(p.version, version+"-")) {
		return errors.New("running agent does not match configured native package state")
	}
	return nil
}

func (p installedPackage) matchesTransaction(tx *agentv1.AgentUpdateTransaction) error {
	if p.name != "lindm-agent" || p.state != "installed" || p.version != tx.GetNativeVersion() || p.architecture != nativeArchitecture(tx.GetArchitecture(), packageDB(tx.GetManager())) {
		return errors.New("installed native package does not match update transaction")
	}
	return nil
}

func observeInstalled(ctx context.Context, manager agentv1.NativeUpdateManager, phase string) (p installedPackage, resultErr error) {
	defer func() { resultErr = withNativeDiagnostic(resultErr, managerExecutable(manager), phase) }()
	var output []byte
	var err error
	switch packageDB(manager) {
	case platform.PackageDBDpkg:
		output, err = nativeCommand(ctx, phase, "/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\t${Status}\n", "lindm-agent")
	case platform.PackageDBRPM:
		output, err = nativeCommand(ctx, phase, "/usr/bin/rpm", "-q", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\tinstalled\n", "lindm-agent")
	case platform.PackageDBPacman:
		output, err = nativeCommand(ctx, phase, "/usr/bin/pacman", "-Q", "lindm-agent")
		if err == nil {
			fields := strings.Fields(string(output))
			if len(fields) != 2 || fields[0] != "lindm-agent" {
				return p, errors.New("ambiguous pacman package observation")
			}
			// Architecture comes from the local database metadata, not uname.
			info, infoErr := nativeCommand(ctx, phase, "/usr/bin/pacman", "-Qi", "lindm-agent")
			if infoErr != nil {
				return p, infoErr
			}
			arch := colonFields(info)["Architecture"]
			return installedPackage{name: fields[0], version: fields[1], architecture: arch, state: "installed"}, nil
		}
	default:
		return p, errors.New("unknown native package manager")
	}
	if err != nil {
		var failure *nativeFailure
		var exit *nativeexec.ExitError
		if errors.As(err, &failure) && !failure.outputOverflow && errors.As(err, &exit) && missingNativePackage(packageDB(manager), output, failure.stderr, exit.ExitCode()) {
			return installedPackage{name: "lindm-agent", state: "absent"}, nil
		}
		return p, err
	}
	fields := strings.Split(strings.TrimSpace(string(output)), "\t")
	if len(fields) != 4 || strings.Contains(fields[3], "\n") {
		return p, errors.New("ambiguous native package observation")
	}
	state := fields[3]
	if state == "install ok installed" {
		state = "installed"
	}
	return installedPackage{name: fields[0], version: fields[1], architecture: fields[2], state: state}, nil
}

func missingNativePackage(db platform.PackageDB, stdout []byte, stderr string, exitCode int) bool {
	if exitCode != 1 {
		return false
	}
	switch db {
	case platform.PackageDBDpkg:
		return len(stdout) == 0 && strings.TrimSpace(stderr) == "dpkg-query: no packages found matching lindm-agent"
	case platform.PackageDBRPM:
		return strings.TrimSpace(string(stdout)) == "package lindm-agent is not installed" && strings.TrimSpace(stderr) == ""
	case platform.PackageDBPacman:
		return len(stdout) == 0 && strings.TrimSpace(stderr) == "error: package 'lindm-agent' was not found"
	default:
		return false
	}
}

func colonFields(data []byte) map[string]string {
	result := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			result[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return result
}

func validatePackage(ctx context.Context, directory string, tx *agentv1.AgentUpdateTransaction) (resultErr error) {
	defer func() { resultErr = withNativeDiagnostic(resultErr, managerExecutable(tx.GetManager()), "validation") }()
	path := packagePath(directory, tx)
	if err := verifyFile(path, tx); err != nil {
		return err
	}
	var name, version, arch string
	switch packageDB(tx.GetManager()) {
	case platform.PackageDBDpkg:
		out, err := nativeCommand(ctx, "validation", "/usr/bin/dpkg-deb", "--field", path, "Package", "Version", "Architecture")
		if err != nil {
			return err
		}
		fields := colonFields(out)
		name, version, arch = fields["Package"], fields["Version"], fields["Architecture"]
	case platform.PackageDBRPM:
		out, err := nativeCommand(ctx, "validation", "/usr/bin/rpm", "-qp", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", path)
		if err != nil {
			return err
		}
		fields := strings.Split(strings.TrimSpace(string(out)), "\t")
		if len(fields) != 3 {
			return errors.New("ambiguous RPM target")
		}
		name, version, arch = fields[0], fields[1], fields[2]
	case platform.PackageDBPacman:
		if err := admitSignature(path + ".sig"); err != nil {
			return err
		}
		out, err := nativeCommand(ctx, "validation", "/usr/bin/pacman", "-Qip", path)
		if err != nil {
			return err
		}
		fields := colonFields(out)
		name, version, arch = fields["Name"], fields["Version"], fields["Architecture"]
	default:
		return errors.New("unsupported package format")
	}
	if name != "lindm-agent" || version != tx.GetNativeVersion() || arch != nativeArchitecture(tx.GetArchitecture(), packageDB(tx.GetManager())) {
		return errors.New("signed target mismatches native package identity")
	}
	return nil
}

// admitSignature adds the staged signature's exact custody to custody.Owned.
func admitSignature(path string) error {
	stat, err := custody.Owned(path, false)
	if err != nil {
		return err
	}
	if stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64<<10 {
		return errors.New("native package signature is not a bounded protected file")
	}
	return nil
}

func verifyFile(path string, tx *agentv1.AgentUpdateTransaction) (resultErr error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "verified-update-package")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(tx.GetLength()) {
		return errors.New("staged package length mismatch")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&07777 != 0600 {
		return errors.New("staged package is not protected")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, int64(tx.GetLength())+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != tx.GetSha256() {
		return errors.New("staged package digest mismatch")
	}
	return nil
}

func verifyInstalledPayload(ctx context.Context, tx *agentv1.AgentUpdateTransaction) (resultErr error) {
	defer func() {
		resultErr = withNativeDiagnostic(resultErr, managerExecutable(tx.GetManager()), "payload_verify")
	}()
	var err error
	switch packageDB(tx.GetManager()) {
	case platform.PackageDBDpkg:
		var out []byte
		out, err = nativeCommand(ctx, "payload_verify", "/usr/bin/dpkg", "--verify", "lindm-agent")
		err = verificationResult(out, err, true)
	case platform.PackageDBRPM:
		var out []byte
		out, err = nativeCommand(ctx, "payload_verify", "/usr/bin/rpm", "-V", "--noconfig", "lindm-agent")
		err = verificationResult(out, err, false)
	case platform.PackageDBPacman:
		_, err = nativeCommand(ctx, "payload_verify", "/usr/bin/pacman", "-Qk", "lindm-agent")
	}
	if err != nil {
		return err
	}
	out, err := nativeCommand(ctx, "payload_verify", installedBinary, "version")
	if err != nil {
		return err
	}
	if string(out) != tx.GetVersion()+"\n" {
		return errNativePayloadMismatch
	}
	return nil
}

// Native verify commands use nine-character difference markers or a literal
// missing-file record. Diagnostics/errors are not proof of interrupted effects.
func verificationDifference(data []byte) (changed, conffiles bool, resultErr error) {
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		marker, rest, ok := strings.Cut(line, " ")
		if !ok {
			return false, false, errors.New("ambiguous native payload verification")
		}
		if marker != "missing" {
			if len(marker) != 9 {
				return false, false, errors.New("ambiguous native payload verification")
			}
			for index, c := range marker {
				if c != '.' && c != '?' && c != rune("SM5DLUGTP"[index]) {
					return false, false, errors.New("ambiguous native payload verification")
				}
			}
		}
		rest = strings.TrimSpace(rest)
		config := false
		if kind, path, ok := strings.Cut(rest, " "); ok && len(kind) == 1 && strings.ContainsAny(kind, "cdglr") {
			config, rest = kind == "c", strings.TrimSpace(path)
		}
		if !strings.HasPrefix(rest, "/") || strings.ContainsRune(rest, 0) {
			return false, false, errors.New("ambiguous native payload verification")
		}
		if config {
			conffiles = true
		} else {
			changed = true
		}
	}
	return changed, conffiles, nil
}

func verificationResult(data []byte, commandErr error, allowConffiles bool) error {
	changed, conffiles, err := verificationDifference(data)
	if err != nil {
		return errors.Join(commandErr, err)
	}
	if commandErr == nil {
		if changed {
			return errNativePayloadMismatch
		}
		return nil
	}
	var failure *nativeFailure
	var exit interface{ ExitCode() int }
	// dpkg returns 1 for listed verification differences, including deliberate
	// owner conffile edits. Only a parsed conffile-only report explains that exit;
	// operational failures, exit 2, stderr diagnostics and empty output do not.
	if !errors.As(commandErr, &failure) || failure.stderr != "" || !errors.As(commandErr, &exit) || exit.ExitCode() != 1 {
		return commandErr
	}
	if changed {
		return errors.Join(commandErr, errNativePayloadMismatch)
	}
	if allowConffiles && conffiles {
		return nil
	}
	return commandErr
}

func applyPackage(ctx context.Context, directory string, tx *agentv1.AgentUpdateTransaction, prior installedPackage, interrupted bool, authorize func() error) (resultErr error) {
	phase := "apply"
	if interrupted {
		phase = "recovery"
	}
	defer func() { resultErr = withNativeDiagnostic(resultErr, managerExecutable(tx.GetManager()), phase) }()
	path := packagePath(directory, tx)
	var err error
	switch tx.GetManager() {
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT:
		if prior.version == tx.GetNativeVersion() && (prior.state == "install ok unpacked" || prior.state == "install ok half-configured" || prior.state == "install ok triggers-pending" || prior.state == "install ok triggers-awaited") {
			if err := authorize(); err != nil {
				return err
			}
			_, err = mutatingCommand(ctx, "configure", "/usr/bin/dpkg", "--force-confold", "--no-triggers", "--configure", "lindm-agent")
			return err
		}
		if interrupted {
			// APT refuses globally interrupted dpkg state. Re-unpack only our
			// admitted package, then configure only its exact package name.
			if err := authorize(); err != nil {
				return err
			}
			if _, err := mutatingCommand(ctx, "recovery", "/usr/bin/dpkg", "--force-confold", "--no-triggers", "--unpack", path); err != nil {
				return err
			}
			_, err = mutatingCommand(ctx, "configure", "/usr/bin/dpkg", "--force-confold", "--no-triggers", "--configure", "lindm-agent")
			return err
		}
		// The protected transaction directory is the entire private archive
		// cache and contains only our verified, canonically named DEB. An
		// empty separate cache with --no-download leaves APT's install pathname
		// unresolved even when the local input DEB exists. No copies, links or
		// other cached packages are admitted; missing dependencies fail.
		if err := os.MkdirAll(filepath.Join(directory, "partial"), 0700); err != nil {
			return err
		}
		args := []string{"--assume-yes", "--no-download", "--no-remove", "--no-install-recommends", "-o", "Dir::Cache::archives=" + directory, "-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Dir::Etc::sourceparts=-", "-o", "Dpkg::Options::=--force-confold", "install", path}
		preview, err := nativeCommand(ctx, "simulate", "/usr/bin/apt-get", append([]string{"--simulate"}, args...)...)
		if err != nil {
			return err
		}
		if err := ownedAPTPreview(preview); err != nil {
			return withNativeDiagnostic(err, "apt-get", "simulate")
		}
		if err := authorize(); err != nil {
			return err
		}
		_, err = mutatingCommand(ctx, "apply", "/usr/bin/apt-get", args...)
		return err
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_DNF:
		action := "install"
		if interrupted && prior.version == tx.GetNativeVersion() {
			action = "reinstall"
		}
		if err := authorize(); err != nil {
			return err
		}
		_, err = mutatingCommand(ctx, phase, "/usr/bin/dnf", "--assumeyes", "--disablerepo=*", "--setopt=install_weak_deps=False", "--setopt=obsoletes=False", "--setopt=plugins=0", action, path)
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_ZYPPER:
		args := []string{"--non-interactive", "--no-refresh", "--disable-repositories", "install", "--no-recommends", "--no-allow-vendor-change"}
		if interrupted && prior.version == tx.GetNativeVersion() {
			args = append(args, "--force")
		}
		if err := authorize(); err != nil {
			return err
		}
		_, err = mutatingCommand(ctx, phase, "/usr/bin/zypper", append(args, path)...)
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_PACMAN:
		preview, err := nativeCommand(ctx, "simulate", "/usr/bin/pacman", "-U", "--print", "--print-format", "%n", path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(preview)) != "lindm-agent" {
			return withNativeDiagnostic(errors.New("pacman transaction selects unrelated packages"), "pacman", "simulate")
		}
		if err := authorize(); err != nil {
			return err
		}
		_, err = mutatingCommand(ctx, phase, "/usr/bin/pacman", "-U", "--noconfirm", "--noprogressbar", path)
		return err
	default:
		return errors.New("native package manager unsupported")
	}
	return err
}

func ownedAPTPreview(data []byte) error {
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Remv" || ((fields[0] == "Inst" || fields[0] == "Conf") && (len(fields) < 2 || fields[1] != "lindm-agent")) {
			return errors.New("APT transaction selects unrelated packages")
		}
	}
	return nil
}

// Preserve bounded diagnostics internally to distinguish actual absence from a
// corrupt native database. Error strings deliberately exclude command output.
type nativeFailure struct {
	program, stderr string
	cause           error
	diagnostic      *agentv1.NativeUpdateDiagnostic
	outputOverflow  bool
}

func (e *nativeFailure) Error() string {
	// Even exec's start error can contain a pathname. Never append a raw cause,
	// output, argv or environment to a public-facing error string.
	return fmt.Sprintf("native %s %s failed (exit %d)", e.program, e.diagnostic.GetPhase(), e.diagnostic.GetExitCode())
}
func (e *nativeFailure) Unwrap() error { return e.cause }

// tailWriter feeds the diagnostic ring from nativeexec's tees.
type tailWriter struct{ tail *nativeOutputTail }

func (w tailWriter) Write(p []byte) (int, error) { w.tail.write(p); return len(p), nil }

func nativeCommand(ctx context.Context, phase, executable string, args ...string) ([]byte, error) {
	return runNative(ctx, phase, false, executable, args...)
}

// mutatingCommand runs a step that changes the package database: on deadline
// or cancellation it is terminated, never SIGKILLed mid-transaction.
func mutatingCommand(ctx context.Context, phase, executable string, args ...string) ([]byte, error) {
	return runNative(ctx, phase, true, executable, args...)
}

func runNative(ctx context.Context, phase string, terminateOnly bool, executable string, args ...string) ([]byte, error) {
	var stdoutTail, stderrTail nativeOutputTail
	result, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: executable, Args: args, Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Dir: "/",
		Timeout: 20 * time.Minute, StdoutLimit: nativeOutputLimit, StderrLimit: nativeOutputLimit,
		StdoutTee: tailWriter{&stdoutTail}, StderrTee: tailWriter{&stderrTail}, TerminateOnly: terminateOnly,
	})
	if err == nil {
		return result.Stdout, nil
	}
	overflow := result.StdoutTruncated || result.StderrTruncated
	program := filepath.Base(executable)
	failure := &nativeFailure{program: program, stderr: string(result.Stderr), cause: err, diagnostic: commandDiagnostic(program, phase, err, overflow, &stdoutTail, &stderrTail), outputOverflow: overflow}
	if overflow {
		// Keep the existing fail-closed parser bound; a partial native reply
		// is never valid package observation or transaction authorization.
		return nil, failure
	}
	return result.Stdout, failure
}
