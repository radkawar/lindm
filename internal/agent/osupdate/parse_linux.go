//go:build linux

package osupdate

import (
	"bufio"
	"bytes"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const maxInstalledPackages = 200000

var (
	errNativeOutput = errors.New("native_output_malformed")
	// Same bounds as OSUpdateDeferralEntry, so every listed package can be
	// recorded in the deferral ledger.
	packageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._~-]*$`)
	packageArchPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// `apt-get -s` prints upgrades as
	//   Inst NAME[:ARCH] [OLD] (NEW ORIGIN[, ORIGIN...] [ARCH]) [BROKEN...]
	// where ORIGIN is Label:Version/Archive, Label:Archive or Version/Archive
	// (pkgCache::VerIterator::RelStr). A line without [OLD] installs a new
	// package; that is a dependency of an upgrade, not a pending update.
	aptInstPattern = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+) (.+) \[([A-Za-z0-9_-]+)\]\)(?: \[[^\]]*\])?$`)
)

func validPackageKey(key packageKey) bool {
	return len(key.name) <= 256 && len(key.arch) <= 64 && packageNamePattern.MatchString(key.name) && packageArchPattern.MatchString(key.arch)
}

func scanLines(data []byte, line func(string) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	for scanner.Scan() {
		if err := line(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// parseAptSimulation lists upgrades from `apt-get -s dist-upgrade`. An
// upgrade is security when any candidate origin's archive ends in -security
// (noble-security, noble-apps-security, noble-infra-security).
func parseAptSimulation(data []byte) ([]pendingPackage, error) {
	var pending []pendingPackage
	err := scanLines(data, func(line string) error {
		if !strings.HasPrefix(line, "Inst ") {
			return nil
		}
		if aptNewInstall(line) {
			return nil
		}
		match := aptInstPattern.FindStringSubmatch(line)
		if match == nil {
			return errNativeOutput
		}
		name, _, _ := strings.Cut(match[1], ":")
		key := packageKey{name: name, arch: match[5]}
		if !validPackageKey(key) {
			return errNativeOutput
		}
		security := false
		for origin := range strings.SplitSeq(match[4], ", ") {
			archive := origin
			if i := strings.LastIndexByte(archive, '/'); i >= 0 {
				archive = archive[i+1:]
			} else if i := strings.LastIndexByte(archive, ':'); i >= 0 {
				archive = archive[i+1:]
			}
			if strings.HasSuffix(archive, "-security") {
				security = true
			}
		}
		pending = append(pending, pendingPackage{key: key, security: security})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dedupePending(pending), nil
}

// aptNewInstall recognizes `Inst NAME (NEW ...)`: no installed version.
func aptNewInstall(line string) bool {
	fields := strings.SplitN(line, " ", 3)
	return len(fields) == 3 && strings.HasPrefix(fields[2], "(")
}

// parseRepoquery reads `NAME\tARCH` records from a dnf repoquery queryformat.
// Lines without a tab are plugin chatter (e.g. subscription-manager) and are
// ignored; a tab-separated line that is not a valid package fails closed.
func parseRepoquery(data []byte) ([]packageKey, error) {
	var keys []packageKey
	err := scanLines(data, func(line string) error {
		name, arch, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			return nil
		}
		key := packageKey{name: name, arch: arch}
		if !validPackageKey(key) {
			return errNativeOutput
		}
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(keys, comparePackageKeys)
	return slices.Compact(keys), nil
}

// mergeRepoquery combines `repoquery --upgrades` with its `--security` subset.
// A security key absent from the full list makes the listing inconsistent.
func mergeRepoquery(all, security []packageKey) ([]pendingPackage, error) {
	secure := make(map[packageKey]bool, len(security))
	for _, key := range security {
		secure[key] = true
	}
	pending := make([]pendingPackage, 0, len(all))
	for _, key := range all {
		pending = append(pending, pendingPackage{key: key, security: secure[key]})
		delete(secure, key)
	}
	if len(secure) != 0 {
		return nil, errNativeOutput
	}
	return pending, nil
}

func dedupePending(pending []pendingPackage) []pendingPackage {
	slices.SortFunc(pending, func(a, b pendingPackage) int { return comparePackageKeys(a.key, b.key) })
	out := pending[:0]
	for _, p := range pending {
		if n := len(out); n > 0 && out[n-1].key == p.key {
			out[n-1].security = out[n-1].security || p.security
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseNeedrestartKernel returns NEEDRESTART-KSTA from `needrestart -b -k`:
// 0 unknown, 1 current, 2 ABI-compatible upgrade pending, 3 version upgrade
// pending.
func parseNeedrestartKernel(data []byte) (int, error) {
	status := -1
	err := scanLines(data, func(line string) error {
		value, ok := strings.CutPrefix(line, "NEEDRESTART-KSTA:")
		if !ok {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 || n > 3 || status != -1 {
			return errNativeOutput
		}
		status = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	if status == -1 {
		return 0, errNativeOutput
	}
	return status, nil
}

// needsRestartingResult interprets `needs-restarting -r` (dnf-plugins-core
// and dnf5-plugins). Both exit 1 for a required reboot and for any error,
// so the fixed C-locale verdict line must agree with the exit status.
func needsRestartingResult(exitCode int, stdout []byte) (bool, error) {
	required := bytes.Contains(stdout, []byte("Reboot is required to fully utilize these updates."))
	notRequired := bytes.Contains(stdout, []byte("Reboot should not be necessary."))
	switch {
	case exitCode == 1 && required && !notRequired:
		return true, nil
	case exitCode == 0 && notRequired && !required:
		return false, nil
	default:
		return false, errNativeOutput
	}
}

// rebootSuggestingPackages are libdnf5's CORE_PACKAGE_NAMES (5.4.1.0
// libdnf5/rpm/package_query.cpp, filter_reboot_suggested): the installed
// packages `needs-restarting -r` weighs when no repository is loaded.
var rebootSuggestingPackages = map[string]bool{
	"kernel": true, "kernel-core": true, "kernel-PAE": true, "kernel-rt": true, "kernel-smp": true, "kernel-xen": true,
	"linux-firmware": true, "microcode_ctl": true, "dbus": true, "glibc": true, "hal": true, "systemd": true, "udev": true,
	"gnutls": true, "openssl-libs": true, "dbus-broker": true, "dbus-daemon": true,
}

// rebootSuggestedSince reads `rpm -qa --qf '%{NAME}\t%{INSTALLTIME}\n'`: a
// reboot is required when a reboot-suggesting package was installed after
// boot (needs-restarting compares install_time > boot_time in seconds). Any
// malformed row, or an empty database, fails the oracle.
func rebootSuggestedSince(data []byte, bootUnix int64) (bool, error) {
	rows, required := 0, false
	err := scanLines(data, func(line string) error {
		if line == "" {
			return nil
		}
		if rows++; rows > maxInstalledPackages {
			return errNativeOutput
		}
		name, installed, ok := strings.Cut(line, "\t")
		if !ok || name == "" {
			return errNativeOutput
		}
		seconds, err := strconv.ParseInt(installed, 10, 64)
		if err != nil || seconds < 0 {
			return errNativeOutput
		}
		if rebootSuggestingPackages[name] && seconds > bootUnix {
			required = true
		}
		return nil
	})
	if err != nil || rows == 0 {
		return false, errNativeOutput
	}
	return required, nil
}

// parseInstalled reads `NAME\tARCH\tVERSION[\tSTATUS]` rows into a map of
// sorted, joined versions per package key (installonly packages such as
// kernels have several). For dpkg only the "ii " (installed) state counts.
func parseInstalled(data []byte, dpkg bool) (map[packageKey]string, error) {
	versions := make(map[packageKey][]string)
	rows := 0
	err := scanLines(data, func(line string) error {
		if line == "" {
			return nil
		}
		rows++
		if rows > maxInstalledPackages {
			return errNativeOutput
		}
		fields := strings.Split(line, "\t")
		want := 3
		if dpkg {
			want = 4
		}
		if len(fields) != want || fields[0] == "" || fields[2] == "" {
			return errNativeOutput
		}
		if dpkg && fields[3] != "ii " {
			return nil
		}
		key := packageKey{name: fields[0], arch: fields[1]}
		versions[key] = append(versions[key], fields[2])
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, errNativeOutput
	}
	installed := make(map[packageKey]string, len(versions))
	for key, list := range versions {
		slices.Sort(list)
		installed[key] = strings.Join(list, " ")
	}
	return installed, nil
}

// changedPackages counts package keys whose installed version set differs.
// Removed packages count too; the result never exceeds the proto bound.
func changedPackages(before, after map[packageKey]string) uint32 {
	var changed uint32
	for key, version := range after {
		if before[key] != version {
			changed++
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			changed++
		}
	}
	return min(changed, 100000)
}

// parseOSRelease returns the unquoted KEY=VALUE pairs of os-release(5).
func parseOSRelease(data []byte) map[string]string {
	values := make(map[string]string)
	_ = scanLines(data, func(line string) error {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(key, "#") {
			return nil
		}
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `'"`)
		}
		values[key] = value
		return nil
	})
	return values
}
