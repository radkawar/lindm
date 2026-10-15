// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// FixedDesktopVerifier admits only the individually reviewed experimental
// desktop tuples below. Neither a desktop name nor an installed fork alone
// proves which backend and locker the running session actually uses.
type FixedDesktopVerifier struct {
	bus *SessionBus
}

// NewFixedDesktopVerifier binds runtime qualification to the actual session bus.
func NewFixedDesktopVerifier(bus *SessionBus) (*FixedDesktopVerifier, error) {
	if bus == nil {
		return nil, errors.New("desktop: missing fixed desktop session bus")
	}
	return &FixedDesktopVerifier{bus: bus}, nil
}

// Verify corroborates root-owned reviewed artifacts with the active native
// processes. Unknown desktops and stock tuples remain unqualified.
func (q *FixedDesktopVerifier) Verify(ctx context.Context, sessionType, currentDesktop string) error {
	if q == nil || q.bus == nil {
		return errors.New("fixed desktop verifier unavailable")
	}
	switch fixedDesktopProfileFor(sessionType, currentDesktop) {
	case hyprlandWayland:
		return q.verifyHyprland(ctx)
	case cinnamonX11Fixed:
		return q.verifyCinnamon(ctx)
	default:
		return errors.New("no reviewed fixed desktop tuple")
	}
}

type fixedRuntimeArtifact struct {
	path     string
	stat     unix.Stat_t
	modified time.Time
}

// fixedRootArtifact streams rather than copies executable images. Custody
// pins every root-protected path component, including distribution symlinks.
func fixedRootArtifact(path, wantSHA string) (_ fixedRuntimeArtifact, err error) {
	var zero fixedRuntimeArtifact
	if len(wantSHA) != sha256.Size*2 {
		return zero, errors.New("invalid reviewed artifact digest")
	}
	want, err := hex.DecodeString(wantSHA)
	if err != nil {
		return zero, err
	}
	const maxArtifact = 256 << 20
	file, resolved, before, err := custody.OpenResolvedRoot(path, maxArtifact, unix.PathMax, 40)
	if err != nil {
		return zero, fmt.Errorf("fixed desktop artifact %s: %w", path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > maxArtifact {
		return zero, fmt.Errorf("fixed desktop artifact %s is not a bounded regular file", path)
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(file, maxArtifact+1))
	if err != nil {
		return zero, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return zero, err
	}
	if n != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Mtim != after.Mtim || before.Ctim != after.Ctim || !custody.RootProtected(&after) {
		return zero, fmt.Errorf("fixed desktop artifact changed while read: %s", path)
	}
	if !bytes.Equal(digest.Sum(nil), want) {
		return zero, fmt.Errorf("fixed desktop artifact digest mismatch: %s", path)
	}
	// ctime catches deployment by an installer that preserves an old mtime.
	modified := time.Unix(before.Mtim.Sec, before.Mtim.Nsec)
	if changed := time.Unix(before.Ctim.Sec, before.Ctim.Nsec); changed.After(modified) {
		modified = changed
	}
	return fixedRuntimeArtifact{path: resolved, stat: before, modified: modified}, nil
}

func (q *FixedDesktopVerifier) fixedBackendPID(ctx context.Context, name string) (uint32, error) {
	return q.fixedServicePID(ctx, name, portalPath)
}

func (q *FixedDesktopVerifier) fixedServicePID(ctx context.Context, name string, path dbus.ObjectPath) (uint32, error) {
	// Standard Peer.Ping activates the implementation without opening a
	// session or displaying a consent dialog.
	if err := q.bus.call(ctx, name, path, "org.freedesktop.DBus.Peer.Ping").Err; err != nil {
		return 0, err
	}
	owner, err := q.bus.nameOwner(ctx, name)
	if err != nil {
		return 0, err
	}
	var pid uint32
	if err := q.bus.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&pid); err != nil {
		return 0, err
	}
	// The frontend is checked with its complete portal search environment
	// below. Every other reviewed service must also reject loader overrides:
	// mapping a reviewed ELF does not rule out a preloaded user library.
	if name != portalName && pid != 0 {
		environ, err := fixedReadProc(fmt.Sprintf("/proc/%d/environ", pid), 128<<10)
		if err != nil {
			return 0, err
		}
		if err := fixedLoaderEnvironment(environ); err != nil {
			return 0, err
		}
	}
	current, err := q.bus.nameOwner(ctx, name)
	if err != nil {
		return 0, err
	}
	if current != owner || pid == 0 {
		return 0, errors.New("fixed desktop service owner changed")
	}
	return pid, nil
}

func fixedLoaderEnvironment(data []byte) error {
	var seen uint8
	for entry := range bytes.SplitSeq(data, []byte{0}) {
		key, value, ok := bytes.Cut(entry, []byte{'='})
		if !ok {
			continue
		}
		var flag uint8
		switch string(key) {
		case "LD_PRELOAD":
			flag = 1
		case "LD_AUDIT":
			flag = 2
		case "LD_LIBRARY_PATH":
			flag = 4
		default:
			continue
		}
		if seen&flag != 0 || len(value) != 0 {
			return fmt.Errorf("fixed desktop service has an unreviewed %s override", key)
		}
		seen |= flag
	}
	return nil
}

func fixedReadProc(path string, limit int64) (_ []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("fixed desktop process data exceeds bound: %s", path)
	}
	return data, err
}

// fixedProcessExecutableArtifact distinguishes an ordinary reviewed executable
// from an explicit loader that merely maps it. Only the Hyprland backend has a
// separately reviewed explicit-loader invocation.
func fixedProcessExecutableArtifact(pid uint32, artifact fixedRuntimeArtifact) error {
	var actual unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &actual); err != nil {
		return err
	}
	if actual.Dev != artifact.stat.Dev || actual.Ino != artifact.stat.Ino {
		return fmt.Errorf("process %d does not directly execute reviewed artifact %s", pid, artifact.path)
	}
	return nil
}

// fixedProcessMapsArtifact checks the executing image, not merely its installed
// pathname. Explicit dynamic-loader invocations can make /proc/PID/exe point at
// the loader; the executable mapping still identifies the reviewed ELF inode.
func fixedProcessMapsArtifact(pid uint32, artifact fixedRuntimeArtifact) error {
	data, err := fixedReadProc(fmt.Sprintf("/proc/%d/maps", pid), 1<<20)
	if err != nil {
		return err
	}
	return fixedProcessMapsArtifactData(pid, data, artifact)
}

// fixedProcessMapsArtifactData also accepts a maps snapshot already read by a
// multi-artifact qualifier. Btrfs reports a subvolume's virtual st_dev in stat,
// but maps reports the backing superblock's device. In that case the kernel's
// map_files link must identify the exact reviewed path in the same mount
// namespace, and that path through the target's root must retain the hashed
// artifact's identity and metadata. An inode or a maps pathname alone is not
// sufficient; following map_files itself would require unavailable privileges.
func fixedProcessMapsArtifactData(pid uint32, data []byte, artifact fixedRuntimeArtifact) error {
	var identityErr error
	if fixedMapsArtifact(data, artifact.stat, func(address []byte) bool {
		identityErr = fixedMappedArtifactPath(pid, address, artifact)
		return identityErr == nil
	}) {
		return nil
	}
	return errors.Join(
		fmt.Errorf("process %d does not execute reviewed artifact %s", pid, artifact.path),
		identityErr,
	)
}

func fixedMappedArtifactPath(pid uint32, address []byte, artifact fixedRuntimeArtifact) error {
	start, end, ok := bytes.Cut(address, []byte{'-'})
	if !ok {
		return errors.New("invalid executable mapping address range")
	}
	first, firstErr := strconv.ParseUint(string(start), 16, 64)
	last, lastErr := strconv.ParseUint(string(end), 16, 64)
	if firstErr != nil || lastErr != nil || first >= last {
		return errors.New("invalid executable mapping address range")
	}
	// maps pads low addresses with zeroes; map_files names do not.
	mappedPath, err := os.Readlink(fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, first, last))
	if err != nil {
		return fmt.Errorf("reading kernel mapped artifact path: %w", err)
	}
	if mappedPath != artifact.path {
		return errors.New("kernel mapped artifact path does not match reviewed artifact")
	}
	var currentMount, targetMount unix.Stat_t
	if err := unix.Stat("/proc/self/ns/mnt", &currentMount); err != nil {
		return err
	}
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &targetMount); err != nil {
		return err
	}
	if currentMount.Dev != targetMount.Dev || currentMount.Ino != targetMount.Ino {
		return errors.New("mapped artifact device differs across mount namespaces")
	}
	var actual unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/root%s", pid, artifact.path), &actual); err != nil {
		return err
	}
	expected := artifact.stat
	if actual.Dev != expected.Dev || actual.Ino != expected.Ino ||
		actual.Mode != expected.Mode || actual.Uid != expected.Uid || actual.Gid != expected.Gid ||
		actual.Size != expected.Size || actual.Mtim != expected.Mtim || actual.Ctim != expected.Ctim {
		return errors.New("mapped artifact path no longer identifies unchanged reviewed artifact")
	}
	return nil
}

func fixedMapsArtifact(data []byte, artifact unix.Stat_t, alternate func(address []byte) bool) bool {
	for line := range bytes.Lines(data) {
		var address, permissions, device, inode []byte
		i := 0
		for field := range bytes.FieldsSeq(line) {
			switch i {
			case 0:
				address = field
			case 1:
				permissions = field
			case 3:
				device = field
			case 4:
				inode = field
			}
			i++
			if i == 5 {
				break
			}
		}
		if !bytes.ContainsRune(permissions, 'x') {
			continue
		}
		major, minor, ok := bytes.Cut(device, []byte{':'})
		if !ok {
			continue
		}
		maj, majErr := strconv.ParseUint(string(major), 16, 32)
		min, minErr := strconv.ParseUint(string(minor), 16, 32)
		ino, inoErr := strconv.ParseUint(string(inode), 10, 64)
		if majErr != nil || minErr != nil || inoErr != nil || ino != artifact.Ino {
			continue
		}
		if uint32(maj) == unix.Major(artifact.Dev) && uint32(min) == unix.Minor(artifact.Dev) {
			return true
		}
		if alternate != nil && alternate(address) {
			return true
		}
	}
	return false
}

// Linux publishes USER_HZ as AT_CLKTCK in this process's auxiliary vector.
// Reading it avoids spawning an environment-sensitive getconf executable.
var fixedClockTicks = sync.OnceValues(func() (uint64, error) {
	data, err := fixedReadProc("/proc/self/auxv", 4096)
	if err != nil {
		return 0, err
	}
	return fixedAuxClockTicks(data, strconv.IntSize/8)
})

func fixedAuxClockTicks(data []byte, wordSize int) (uint64, error) {
	if (wordSize != 4 && wordSize != 8) || len(data)%(wordSize*2) != 0 {
		return 0, errors.New("invalid process auxiliary vector")
	}
	word := func(data []byte) uint64 {
		if wordSize == 4 {
			return uint64(binary.NativeEndian.Uint32(data))
		}
		return binary.NativeEndian.Uint64(data)
	}
	for len(data) >= wordSize*2 {
		kind, value := word(data), word(data[wordSize:])
		if kind == 17 && value > 0 && value <= 1_000_000 { // AT_CLKTCK
			return value, nil
		}
		if kind == 0 { // AT_NULL
			break
		}
		data = data[wordSize*2:]
	}
	return 0, errors.New("process auxiliary vector lacks AT_CLKTCK")
}

func fixedProcessAfter(pid uint32, deployed time.Time) error {
	stat, err := fixedReadProc(fmt.Sprintf("/proc/%d/stat", pid), 16384)
	if err != nil {
		return err
	}
	boot, err := fixedReadProc("/proc/stat", 1<<20)
	if err != nil {
		return err
	}
	ticks, err := fixedClockTicks()
	if err != nil {
		return err
	}
	started, err := fixedProcessStarted(stat, boot, ticks)
	if err != nil {
		return err
	}
	// btime and start ticks are truncated. Their lower bound must still
	// prove this process is newer than the deployment.
	if !started.After(deployed) {
		return fmt.Errorf("process %d predates fixed desktop deployment", pid)
	}
	return nil
}

func fixedProcessStarted(stat, boot []byte, ticks uint64) (time.Time, error) {
	if ticks == 0 || ticks > 1_000_000 {
		return time.Time{}, errors.New("invalid process clock ticks")
	}
	// comm may contain spaces and ')' characters; fields after its final
	// parenthesis begin at field 3, so starttime (field 22) is index 19.
	end := bytes.LastIndex(stat, []byte(") "))
	if end < 0 {
		return time.Time{}, errors.New("invalid process stat")
	}
	var startField []byte
	index := 0
	for field := range bytes.FieldsSeq(stat[end+2:]) {
		if index == 19 {
			startField = field
			break
		}
		index++
	}
	if len(startField) == 0 {
		return time.Time{}, errors.New("process stat lacks starttime")
	}
	startTicks, err := strconv.ParseUint(string(startField), 10, 64)
	if err != nil || startTicks/ticks > uint64(1<<63-1) {
		return time.Time{}, errors.New("invalid process starttime")
	}
	for line := range bytes.Lines(boot) {
		if value, ok := bytes.CutPrefix(line, []byte("btime ")); ok {
			seconds, err := strconv.ParseInt(string(bytes.TrimSpace(value)), 10, 64)
			if err != nil || seconds < 0 || int64(startTicks/ticks) > (1<<63-1)-seconds {
				return time.Time{}, errors.New("invalid process boot time")
			}
			return time.Unix(seconds+int64(startTicks/ticks), int64(startTicks%ticks)*int64(time.Second)/int64(ticks)), nil
		}
	}
	return time.Time{}, errors.New("process boot time unavailable")
}

// fixedPortalSelection examines the running frontend's honored search paths,
// not the helper's. Root-only search homes avoid accepting a frontend that
// loaded a subsequently deleted per-user override. Each tuple additionally
// pins the selected preference/descriptor and process deployment age.
func (q *FixedDesktopVerifier) fixedPortalSelection(ctx context.Context, currentDesktop, expectedPreference string) (uint32, error) {
	pid, err := q.fixedBackendPID(ctx, portalName)
	if err != nil {
		return 0, err
	}
	data, err := fixedReadProc(fmt.Sprintf("/proc/%d/environ", pid), 128<<10)
	if err != nil {
		return 0, err
	}
	configHome, dataHome, err := fixedPortalEnvironment(data, currentDesktop)
	if err != nil {
		return 0, err
	}
	for _, path := range []string{configHome, dataHome, filepath.Join(configHome, "xdg-desktop-portal"), filepath.Join(dataHome, "xdg-desktop-portal")} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			// A missing child of a root-protected search home cannot acquire
			// an untrusted override. The search homes themselves must exist.
			if path != configHome && path != dataHome {
				continue
			}
		}
		dir, stat, err := custody.OpenRoot(path, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return 0, err
		}
		if err := dir.Close(); err != nil {
			return 0, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return 0, fmt.Errorf("fixed desktop portal search path is not a root directory: %s", path)
		}
	}
	preference, err := fixedPortalPreference(configHome, dataHome, currentDesktop)
	if err != nil {
		return 0, err
	}
	if preference != expectedPreference {
		return 0, fmt.Errorf("fixed desktop frontend selects unreviewed preference %s", preference)
	}
	return pid, nil
}

func fixedPortalPreference(configHome, dataHome, desktop string) (string, error) {
	names := [...]string{strings.ToLower(desktop) + "-portals.conf", "portals.conf"}
	for _, root := range [...]string{configHome, dataHome} {
		for _, name := range names {
			path := filepath.Join(root, "xdg-desktop-portal", name)
			if _, err := os.Lstat(path); err == nil {
				return path, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
	}
	return "", errors.New("fixed desktop frontend has no reviewed portal preference")
}

func fixedPortalEnvironment(data []byte, currentDesktop string) (string, string, error) {
	var home, configHome, dataHome, configDirs, dataDirs, desktop string
	seen := make(map[string]bool, 9)
	for entry := range bytes.SplitSeq(data, []byte{0}) {
		key, value, ok := bytes.Cut(entry, []byte{'='})
		if !ok {
			continue
		}
		name := string(key)
		switch name {
		case "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS", "XDG_CURRENT_DESKTOP", "XDG_DESKTOP_PORTAL_DIR", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH":
			if seen[name] {
				return "", "", errors.New("ambiguous fixed desktop portal environment")
			}
			seen[name] = true
		default:
			continue
		}
		text := string(value)
		switch name {
		case "HOME":
			home = text
		case "XDG_CONFIG_HOME":
			configHome = text
		case "XDG_DATA_HOME":
			dataHome = text
		case "XDG_CONFIG_DIRS":
			configDirs = text
		case "XDG_DATA_DIRS":
			dataDirs = text
		case "XDG_CURRENT_DESKTOP":
			desktop = text
		default:
			if text != "" {
				return "", "", fmt.Errorf("fixed desktop portal environment overrides %s", name)
			}
		}
	}
	if !strings.EqualFold(desktop, currentDesktop) || desktop == "" {
		return "", "", errors.New("fixed desktop frontend selected another desktop")
	}
	if configDirs != "" && configDirs != "/etc/xdg" {
		return "", "", errors.New("fixed desktop frontend has unreviewed configuration search paths")
	}
	if dataDirs != "/usr/share" {
		return "", "", errors.New("fixed desktop frontend must use the reviewed root data search path")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", "", errors.New("fixed desktop frontend lacks an absolute home")
	}
	if configHome != "/etc/xdg" || dataHome != "/usr/share" {
		return "", "", errors.New("fixed desktop frontend requires root-only configuration and data homes")
	}
	return configHome, dataHome, nil
}
