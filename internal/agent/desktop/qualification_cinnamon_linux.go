// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// These are exact native Mint packages, not minimum upstream versions.
// Stock packages do not gain admission when an upstream version number changes.
var cinnamonPackages = [...]struct {
	name, version, architecture string
}{
	{"cinnamon", "6.6.4+zena", "amd64"},
	{"xdg-desktop-portal", "1.20.0+ds-2ubuntu1+lindm.lifetime.1", "amd64"},
	{"xdg-desktop-portal-xapp", "1.1.4+lindm.rd.3", "amd64"},
	{"libmuffin0", "6.6.3+lindm.rd.2", "amd64"},
	{"muffin", "6.6.3+lindm.rd.2", "amd64"},
	{"muffin-common", "6.6.3+lindm.rd.2", "all"},
	{"cinnamon-screensaver", "6.6.1+lindm.lock.1", "amd64"},
	{"cinnamon-settings-daemon", "6.6.2+lindm.lock.1", "amd64"},
}

// Read the root-controlled package database directly. Invoking dpkg-query would
// unnecessarily inherit a dynamic loader/environment and allocate its output.
func fixedCinnamonPackages(ctx context.Context) (err error) {
	const maxStatus = 64 << 20
	file, _, before, err := custody.OpenResolvedRoot("/var/lib/dpkg/status", maxStatus, unix.PathMax, 40)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cinnamonPackageStatus(io.LimitReader(file, maxStatus+1)); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || !custody.RootProtected(&after) {
		return errors.New("cinnamon package database changed during qualification")
	}
	return ctx.Err()
}

func cinnamonPackageStatus(reader io.Reader) error {
	var found [len(cinnamonPackages)]bool
	current := -1
	havePackage, haveVersion, haveStatus, haveArchitecture := false, false, false, false
	versionOK, statusOK, architectureOK := false, false, false
	finish := func() error {
		if current >= 0 {
			if found[current] || !versionOK || !statusOK || !architectureOK {
				return fmt.Errorf("unreviewed Cinnamon package state: %s", cinnamonPackages[current].name)
			}
			found[current] = true
		}
		current = -1
		havePackage, haveVersion, haveStatus, haveArchitecture = false, false, false, false
		versionOK, statusOK, architectureOK = false, false, false
		return nil
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			if err := finish(); err != nil {
				return err
			}
			continue
		}
		if value, ok := bytes.CutPrefix(line, []byte("Package: ")); ok {
			if havePackage {
				return errors.New("duplicate package identity in dpkg status")
			}
			havePackage = true
			for index := range cinnamonPackages {
				if bytes.Equal(value, []byte(cinnamonPackages[index].name)) {
					current = index
					break
				}
			}
			continue
		}
		if current < 0 {
			continue
		}
		if value, ok := bytes.CutPrefix(line, []byte("Version: ")); ok {
			if haveVersion {
				return errors.New("duplicate Cinnamon package version")
			}
			haveVersion = true
			versionOK = bytes.Equal(value, []byte(cinnamonPackages[current].version))
		} else if value, ok := bytes.CutPrefix(line, []byte("Status: ")); ok {
			if haveStatus {
				return errors.New("duplicate Cinnamon package status")
			}
			haveStatus = true
			statusOK = bytes.Equal(value, []byte("install ok installed")) || bytes.Equal(value, []byte("hold ok installed"))
		} else if value, ok := bytes.CutPrefix(line, []byte("Architecture: ")); ok {
			if haveArchitecture {
				return errors.New("duplicate Cinnamon package architecture")
			}
			haveArchitecture = true
			architectureOK = bytes.Equal(value, []byte(cinnamonPackages[current].architecture))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := finish(); err != nil {
		return err
	}
	for index, present := range found {
		if !present {
			return fmt.Errorf("missing reviewed Cinnamon package: %s", cinnamonPackages[index].name)
		}
	}
	return nil
}

// The native locker rewrites argv with setproctitle before owning its bus name.
// Its title corroborates the pinned root activation chain, interpreter and
// mapped CScreensaver library; it is not an unforgeable Python attestation.
func cinnamonScreensaverTitle(command []byte) bool {
	const title = "cinnamon-screensaver"
	return len(command) > len(title) && bytes.Equal(bytes.TrimRight(command, "\x00"), []byte(title))
}

const (
	cinnamonNoProcess = iota
	cinnamonFrontendProcess
	cinnamonBackendProcess
	cinnamonCompositorProcess
	cinnamonProxyProcess
	cinnamonLockerProcess
	cinnamonProcessCount
)

const cinnamonPortalPreference = "/etc/xdg/xdg-desktop-portal/x-cinnamon-portals.conf"

var cinnamonProcesses = [cinnamonProcessCount]struct {
	name string
	path dbus.ObjectPath
}{
	cinnamonFrontendProcess:   {portalName, portalPath},
	cinnamonBackendProcess:    {"org.freedesktop.impl.portal.desktop.xapp", portalPath},
	cinnamonCompositorProcess: {"org.Cinnamon", "/org/Cinnamon"},
	cinnamonProxyProcess:      {"org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver"},
	cinnamonLockerProcess:     {"org.cinnamon.ScreenSaver", "/org/cinnamon/ScreenSaver"},
}

// Recorded from the real Mint 22.3 X11 golden guest, not a version-only opt-in.
// Reviewed source: radkawar/xdg-desktop-portal-xapp@8578115,
// radkawar/muffin@eb6f5f6, radkawar/xdg-desktop-portal@b359a513,
// radkawar/cinnamon-screensaver@173641c and
// radkawar/cinnamon-settings-daemon@e6cd18e. Changes need new native evidence.
var cinnamonRootFiles = [...]struct {
	path, sha256  string
	mappedProcess int
}{
	{"/etc/os-release", "0882805ea1c7fa89e45228b326739a5c53556a3d29bbe4eb0f9bb1df67cab6da", cinnamonNoProcess},
	{"/usr/libexec/xdg-desktop-portal", "abd266e4ea5f01875ad0d47d09e8493ac0da60582d7128163ce76d52d1ef0717", cinnamonFrontendProcess},
	{"/usr/libexec/xdg-desktop-portal-xapp", "efb2e5d65e32059a4576dd1ce3854604dede9644c03006fbf2a7938884d0df0b", cinnamonBackendProcess},
	{"/usr/bin/cinnamon", "bee1d0d63394a23b12dfa2d970c2f07e9277bbaa14265fc7967190918083a6bb", cinnamonCompositorProcess},
	{"/usr/bin/python3.12", "1319c137ea5d30f1d7599943cb0e72666648c20a94cf5932dd095364d07dafeb", cinnamonLockerProcess},
	{"/usr/libexec/csd-screensaver-proxy", "9c53a7ae5cd4937754c4495b98fe3177be100be183e71cd3cb5439ca48442515", cinnamonProxyProcess},
	{"/usr/bin/cinnamon-screensaver-command", "480673fb26db5ed9ec436ed4b5297b09b870ef189a7204e4ddb679bd7fd55bff", cinnamonNoProcess},
	{"/usr/bin/cinnamon-screensaver", "4c5091b617c1ab21593879bee86e62b24244091559b4d552a2f4758f6ef633ee", cinnamonNoProcess},
	{"/usr/share/dbus-1/services/org.cinnamon.ScreenSaver.service", "58669b2dd64507eb4222e039b293ec536aaa6526766a4917ee8dfd6f8cd0d542", cinnamonNoProcess},
	{"/usr/share/cinnamon-screensaver/cinnamon-screensaver-main.py", "cdb2f6e265619e54ed021d181573b1d3ff75ac753e7ddfba239c3a3d9164da1f", cinnamonNoProcess},
	{"/usr/share/cinnamon-screensaver/manager.py", "e1c745c5a2250a873ee519e041902fda289b1336532ba060e68078dc123d85a6", cinnamonNoProcess},
	{"/usr/share/cinnamon-screensaver/singletons.py", "f1ed67fca31d26860580c67629b0f9169d9dc95ea2aa1d7bb27f341e0252afbf", cinnamonNoProcess},
	{"/usr/share/cinnamon-screensaver/dbusdepot/logindClient.py", "9f0f3340f78c78f560f7cfefda34d1fc22491d87708b0d8a00aaaec30e7147cc", cinnamonNoProcess},
	{"/usr/libexec/cinnamon-screensaver/libcscreensaver.so", "a57234b83c37ea81b03d7177f241a021b0669052c2b133f86d1c73eb5af5efa4", cinnamonLockerProcess},
	{"/usr/libexec/cinnamon-screensaver/girepository-1.0/CScreensaver-1.0.typelib", "6c9331947df6bb72b415bc896295fbcbf84c100406a347af40e7867149995660", cinnamonNoProcess},
	{"/usr/share/xdg-desktop-portal/portals/xapp.portal", "1e188f867a7204604eb3cdb614a6d75530f30deafe87cff1f8bcaaf704190a30", cinnamonNoProcess},
	{"/usr/share/xdg-desktop-portal/portals/xapp-screencast.portal", "da12531cf87d4396f41c4fcebfcc4629718b13608731d33b41b46b47958fd925", cinnamonNoProcess},
	{"/usr/share/xdg-desktop-portal/portals/xapp-gnome-keyring.portal", "1c4ba0bf1f98fe88637950c2ca4973aff5e7a778d077aee389d463877f1bc992", cinnamonNoProcess},
	{cinnamonPortalPreference, "f26b5b42602a10309ebabe45911d7503fc846e439ae1f3bf71dc97c526ee7f44", cinnamonNoProcess},
	{"/usr/lib/systemd/user/xdg-desktop-portal.service.d/50-lindm-native-selection.conf", "58c8ec7895c19049ed4cb82bff060ee23635723a59374ca5cb5188f371d9d69c", cinnamonNoProcess},
	{"/usr/lib/x86_64-linux-gnu/libmuffin.so.0.0.0", "60b526afd760d4319e70552b9faa71dd08955d254777fc4c5c13a9b4bc793bc1", cinnamonCompositorProcess},
	{"/usr/lib/x86_64-linux-gnu/muffin/libmuffin-clutter-0.so.0.0.0", "4ba73c0510e06bd04fd83daafa54ce68eacb587141c63a80a8e8bfede5f49d4b", cinnamonCompositorProcess},
	{"/usr/lib/x86_64-linux-gnu/muffin/libmuffin-cogl-0.so.0.0.0", "d2b1ef62d0cdf97217190aa8cf35b382cf11e7c7a3b5d216ab35fa77756c0a44", cinnamonCompositorProcess},
	{"/usr/lib/x86_64-linux-gnu/muffin/libmuffin-cogl-pango-0.so.0.0.0", "1442ff598d8d8be24b4d8cf265170863b7d7cb99caae709327d00cac684ee71b", cinnamonCompositorProcess},
	{"/usr/lib/x86_64-linux-gnu/muffin/libmuffin-cogl-path-0.so.0.0.0", "1b6a44c10940e100c1b4dae4d737adb44ee3eacbd561599ea287a29ec7e66d7c", cinnamonCompositorProcess},
}

var cinnamonBackendProperties = [...]struct {
	iface, name string
	want        uint32
}{
	{"org.freedesktop.impl.portal.RemoteDesktop", "version", 1},
	{"org.freedesktop.impl.portal.RemoteDesktop", "AvailableDeviceTypes", 3},
	{"org.freedesktop.impl.portal.ScreenCast", "version", 3},
	{"org.freedesktop.impl.portal.ScreenCast", "AvailableSourceTypes", 3},
	{"org.freedesktop.impl.portal.ScreenCast", "AvailableCursorModes", 7},
}

func (q *FixedDesktopVerifier) verifyCinnamon(ctx context.Context) error {
	if err := fixedCinnamonPackages(ctx); err != nil {
		return err
	}
	// GetActive is the ordinary non-locking activation of the short-lived
	// locker. Do not change its residency or use a private attestation API.
	locker := cinnamonProcesses[cinnamonLockerProcess]
	var active bool
	if err := q.bus.call(ctx, locker.name, locker.path, "org.cinnamon.ScreenSaver.GetActive").Store(&active); err != nil {
		return err
	}
	var pids [cinnamonProcessCount]uint32
	var maps [cinnamonProcessCount][]byte
	for role := 1; role < cinnamonProcessCount; role++ {
		service := cinnamonProcesses[role]
		var pid uint32
		var err error
		if role == cinnamonFrontendProcess {
			pid, err = q.fixedPortalSelection(ctx, "X-Cinnamon", cinnamonPortalPreference)
		} else {
			pid, err = q.fixedServicePID(ctx, service.name, service.path)
		}
		if err != nil {
			return err
		}
		pids[role] = pid
		maps[role], err = fixedReadProc(fmt.Sprintf("/proc/%d/maps", pid), 1<<20)
		if err != nil {
			return err
		}
	}
	var deployed time.Time
	// Each role's first mapped artifact is its main executable; subsequent
	// entries additionally pin its reviewed native libraries.
	var executableVerified [cinnamonProcessCount]bool
	for _, reviewed := range cinnamonRootFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		artifact, err := fixedRootArtifact(reviewed.path, reviewed.sha256)
		if err != nil {
			return err
		}
		if role := reviewed.mappedProcess; role != cinnamonNoProcess {
			if !executableVerified[role] {
				if err := fixedProcessExecutableArtifact(pids[role], artifact); err != nil {
					return err
				}
				executableVerified[role] = true
			}
			if err := fixedProcessMapsArtifactData(pids[role], maps[role], artifact); err != nil {
				return err
			}
		}
		if artifact.modified.After(deployed) {
			deployed = artifact.modified
		}
	}
	command, err := fixedReadProc(fmt.Sprintf("/proc/%d/cmdline", pids[cinnamonLockerProcess]), 4096)
	if err != nil {
		return err
	}
	if !cinnamonScreensaverTitle(command) {
		return errors.New("unexpected Cinnamon locker process title")
	}
	comm, err := fixedReadProc(fmt.Sprintf("/proc/%d/comm", pids[cinnamonLockerProcess]), 64)
	if err != nil {
		return err
	}
	if !bytes.Equal(comm, []byte("cinnamon-screen\n")) {
		return errors.New("unexpected Cinnamon locker task identity")
	}
	backend := cinnamonProcesses[cinnamonBackendProcess]
	for _, property := range cinnamonBackendProperties {
		value, err := q.bus.property(ctx, backend.name, backend.path, property.iface, property.name)
		if err != nil {
			return err
		}
		actual, ok := value.Value().(uint32)
		if !ok || actual != property.want {
			return fmt.Errorf("unreviewed Cinnamon backend property %s.%s", property.iface, property.name)
		}
	}
	for role := 1; role < cinnamonProcessCount; role++ {
		if err := fixedProcessAfter(pids[role], deployed); err != nil {
			return err
		}
		service := cinnamonProcesses[role]
		pid, err := q.fixedServicePID(ctx, service.name, service.path)
		if err != nil {
			return err
		}
		if pid != pids[role] {
			return fmt.Errorf("cinnamon service %s changed during qualification", service.name)
		}
	}
	return ctx.Err()
}
