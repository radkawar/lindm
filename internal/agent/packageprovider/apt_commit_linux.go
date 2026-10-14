// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"lindm/internal/custody"

	"golang.org/x/sys/unix"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

const dpkgFrontendLock = "/var/lib/dpkg/lock-frontend"

// POSIX frontend locking follows dpkg's documented frontend protocol. The helper
// retains this lock while each dpkg child takes its own inner database lock;
// DPKG_FRONTEND_LOCKED=true delegates only the already-held frontend dimension.
// Contention is ErrBusy: another frontend owns the database and nothing changed.
func lockDPKGFrontend() (*os.File, error) {
	fd, err := unix.Open(dpkgFrontendLock, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("packageprovider: unsafe dpkg frontend lock")
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("%w: dpkg frontend lock held: %v", ErrBusy, err)
		}
		return nil, fmt.Errorf("%w: dpkg frontend lock: %v", ErrConflict, err)
	}
	return os.NewFile(uintptr(fd), "dpkg frontend lock"), nil
}

// dpkgFrontendHeld reports whether another process holds the frontend write
// lock at path. It only tests (F_GETLK); it takes and changes nothing, so a
// read-only view of the dpkg database suffices.
func dpkgFrontendHeld(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &lock); err != nil {
		return false, err
	}
	return lock.Type != unix.F_UNLCK, nil
}

// classifyDPKGBusy turns a native failure observed while another frontend
// holds the dpkg lock into ErrBusy; APT reports that contention only as text.
func classifyDPKGBusy(err error) error {
	if err == nil || errors.Is(err, ErrBusy) {
		return err
	}
	if held, probe := dpkgFrontendHeld(dpkgFrontendLock); probe == nil && held {
		return errors.Join(ErrBusy, err)
	}
	return err
}

type aptStep struct{ operation, name, architecture, version string }

var aptConfigure = regexp.MustCompile(`^Conf ([^ ]+) \(([^ ]+) .*\[([^\]]+)\]\)$`)

// Inst/Conf order is native APT solver output. In particular an early Conf is a
// Pre-Depends barrier, not a line that can be reordered to the transaction tail.
func parseAPTSteps(output []byte) ([]aptStep, error) {
	var steps []aptStep
	for line := range strings.SplitSeq(string(output), "\n") {
		var match []string
		operation := ""
		switch {
		case strings.HasPrefix(line, "Inst "):
			match = aptInstall.FindStringSubmatch(line)
			operation = "--unpack"
		case strings.HasPrefix(line, "Conf "):
			match = aptConfigure.FindStringSubmatch(line)
			operation = "--configure"
		case strings.HasPrefix(line, "Remv "):
			m := aptRemove.FindStringSubmatch(line)
			if m == nil {
				return nil, errors.New("packageprovider: malformed native remove step")
			}
			name, arch, _ := strings.Cut(m[1], ":")
			steps = append(steps, aptStep{operation: "--remove", name: name, architecture: arch, version: m[2]})
			continue
		case strings.HasPrefix(line, "Purg "), strings.HasPrefix(line, "E:"):
			return nil, errors.New("packageprovider: unsafe native APT step")
		default:
			continue
		}
		if match == nil {
			return nil, errors.New("packageprovider: malformed native APT step")
		}
		name, arch, _ := strings.Cut(match[1], ":")
		if arch != "" && arch != match[3] {
			return nil, ErrConflict
		}
		steps = append(steps, aptStep{operation: operation, name: name, architecture: match[3], version: match[2]})
		if len(steps) > 8192 {
			return nil, errors.New("packageprovider: native step capacity")
		}
	}
	return steps, nil
}
func dpkgTransactionArgs(directory string, d *resourcev1.NativePackageDesired, manifest *resourcev1.PackageTransactionManifest) ([][]string, error) {
	data, err := custody.ReadRoot(filepath.Join(directory, "native-transaction.txt"), maxOutput, false)
	if err != nil {
		return nil, err
	}
	steps, err := parseAPTSteps(data)
	if err != nil {
		return nil, err
	}
	unpacked, configured, removed := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	var groups [][]string
	previous := ""
	for _, step := range steps {
		var entry *resourcev1.PackageTransactionEntry
		for _, candidate := range manifest.GetEntries() {
			if candidate.GetPackage().GetNativeName() == step.name && (step.architecture == "" || candidate.GetPackage().GetArchitecture() == step.architecture) {
				if entry != nil {
					return nil, ErrConflict
				}
				entry = candidate
			}
		}
		if entry == nil {
			return nil, errors.New("packageprovider: native step lacks manifest entry")
		}
		key := packageKey(entry.GetPackage())
		argument := entry.GetPackage().GetNativeName() + ":" + entry.GetPackage().GetArchitecture()
		switch step.operation {
		case "--unpack":
			if unpacked[key] || entry.GetAfter().GetDeb() != step.version || entry.GetArtifact() == nil {
				return nil, ErrConflict
			}
			unpacked[key] = true
			argument = filepath.Join(directory, "archives", hex.EncodeToString(entry.GetArtifact().GetSha256())+".deb")
		case "--configure":
			if !unpacked[key] || configured[key] || entry.GetAfter().GetDeb() != step.version {
				return nil, ErrConflict
			}
			configured[key] = true
		case "--remove":
			if removed[key] || entry.GetAfter() != nil || entry.GetBefore().GetDeb() != step.version || !entry.GetDirectRequest() || d.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT {
				return nil, ErrConflict
			}
			removed[key] = true
		default:
			return nil, ErrConflict
		}
		if step.operation != previous {
			groups = append(groups, []string{"--refuse-downgrade", "--force-confdef", "--force-confold", step.operation})
			previous = step.operation
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], argument)
	}
	for _, entry := range manifest.GetEntries() {
		key := packageKey(entry.GetPackage())
		if entry.GetAfter() != nil {
			if !unpacked[key] || !configured[key] {
				return nil, errors.New("packageprovider: incomplete native configuration transaction")
			}
		} else if !removed[key] {
			return nil, ErrConflict
		}
	}
	return groups, nil
}
