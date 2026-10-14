// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"lindm/internal/custody"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

func (p *Provider) pinPath(ref *resourcev1.ResourceRef) string {
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		return pacmanConfigPath
	}
	if p.managerPath == "/usr/bin/zypper" {
		return zypperLocksPath
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		return dnf.VersionlockPathFor(p.manager)
	}
	digest := sha256.Sum256([]byte(ref.GetCanonicalKey()))
	return "/etc/apt/preferences.d/lindm-" + hex.EncodeToString(digest[:])
}
func readPin(path string) (*resourcev1.FileIdentity, []byte, error) {
	data, err := custody.ReadRoot(path, maxPin, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return nil, nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, nil, errors.New("packageprovider: pin identity changed")
	}
	digest := sha256.Sum256(data)
	return &resourcev1.FileIdentity{Path: path, Device: uint64(stat.Dev), Inode: stat.Ino, Uid: stat.Uid, Gid: stat.Gid, Mode: stat.Mode & 07777, Sha256: digest[:]}, data, nil
}

// pinClaimsPackage reports an existing native pin for this package. An APT pin
// file is per package; DNF's versionlock (DNF5 TOML or the DNF4 plugin list) is
// one shared document whose entries for other packages are not this package's
// pin. An unreadable document fails closed.
func pinClaimsPackage(ref *resourcev1.ResourceRef, o *resourcev1.NativePackageObservation) bool {
	if o.GetPinFile() == nil {
		return false
	}
	if o.GetPinFile().GetPath() == pacmanConfigPath || o.GetPinFile().GetPath() == zypperLocksPath {
		_, block, err := removeOwnedPin(o.GetPinContents(), ref)
		return err != nil || len(block) != 0
	}
	if o.GetPackage().GetEcosystem() != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		return true
	}
	return dnf.VersionlockClaims(o.GetPinFile().GetPath(), o.GetPinContents(), ref.GetCanonicalKey(), o.GetPackage().GetNativeName())
}

// Pins are rendered from the desired package alone, never from what happens
// to be installed, so plan, apply and verify agree. A package that follows the
// device's architecture is pinned with each tool's own native-name form: APT
// matches a bare name only at the native architecture (and `all`); RPM locks
// name the package without an architecture.
func aptPin(d *resourcev1.NativePackageDesired) []byte {
	if d.GetExact() == nil || d.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	return []byte("# Managed by lindm; exact native version, never implicit downgrade.\nPackage: " + nativeSpec(d.GetPackage(), ":") + "\nPin: version " + d.GetExact().GetDeb() + "\nPin-Priority: 1000\n")
}

// dnfPinConditions bind the exact EVR and, for a pinned package, its architecture.
func dnfPinConditions(d *resourcev1.NativePackageDesired) []dnf.VersionlockCondition {
	conditions := []dnf.VersionlockCondition{{Key: "evr", Comparator: "=", Value: nativeVersion(d.GetExact())}}
	if architecture := d.GetPackage().GetArchitecture(); architecture != "" {
		conditions = append(conditions, dnf.VersionlockCondition{Key: "arch", Comparator: "=", Value: architecture})
	}
	return conditions
}
func pinMarker(ref *resourcev1.ResourceRef) string {
	return dnf.VersionlockMarker(ref.GetCanonicalKey())
}
func renderDNFPin(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) ([]byte, error) {
	document, err := dnf.ParseVersionlock(current)
	if err != nil {
		return nil, err
	}
	marker := pinMarker(ref)
	entries := document.Packages[:0]
	for _, entry := range document.Packages {
		if entry.Comment == marker {
			continue
		}
		match, err := filepath.Match(entry.Name, d.GetPackage().GetNativeName())
		if err != nil {
			return nil, err
		}
		if match {
			return nil, errors.New("packageprovider: externally owned overlapping versionlock")
		}
		entries = append(entries, entry)
	}
	document.Packages = entries
	if d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		document.Packages = append(document.Packages, dnf.VersionlockPackage{Name: d.GetPackage().GetNativeName(), Comment: marker, Conditions: dnfPinConditions(d)})
	}
	if len(document.Packages) == 0 && len(current) == 0 {
		return nil, nil
	}
	data, err := toml.Marshal(document)
	if err != nil {
		return nil, err
	}
	if len(data) > maxPin {
		return nil, errors.New("packageprovider: native pin capacity")
	}
	return data, nil
}

// dnf4LockEntry is the plugin's own exact NEVRA lock form with an explicit
// architecture (the plugin's add command writes "*" for every architecture),
// or its NEVR form for a package that follows the device's architecture.
func dnf4LockEntry(d *resourcev1.NativePackageDesired) string {
	if d.GetExact() == nil || d.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return ""
	}
	return nativeSpec(&resourcev1.PackageIdentity{NativeName: d.GetPackage().GetNativeName() + "-" + nativeVersion(d.GetExact()), Architecture: d.GetPackage().GetArchitecture()}, ".")
}
func (p *Provider) renderPin(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) ([]byte, error) {
	switch {
	case p.rolling():
		return renderRollingPin(ref, d, current, p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM)
	case p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		return aptPin(d), nil
	case p.manager == dnf.DNF4:
		entry := dnf4LockEntry(d)
		if entry != "" && !p.versionlock {
			return nil, fmt.Errorf("%w: exact DNF4 version requires the enabled native versionlock plugin", ErrUnsupported)
		}
		pin, err := dnf.RenderVersionlockList(current, ref.GetCanonicalKey(), d.GetPackage().GetNativeName(), entry)
		if err != nil {
			return nil, err
		}
		if len(pin) > maxPin {
			return nil, errors.New("packageprovider: native pin capacity")
		}
		return pin, nil
	default:
		return renderDNFPin(ref, d, current)
	}
}
func pinMatches(backend resourcev1.Backend, ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) bool {
	switch backend {
	case resourcev1.Backend_BACKEND_ALPM, resourcev1.Backend_BACKEND_ZYPPER:
		return rollingPinMatches(ref, d, current, backend == resourcev1.Backend_BACKEND_ALPM)
	case resourcev1.Backend_BACKEND_APT:
		return bytes.Equal(aptPin(d), current)
	case resourcev1.Backend_BACKEND_DNF4:
		owned, ok := dnf.VersionlockListOwned(current, ref.GetCanonicalKey(), d.GetPackage().GetNativeName())
		if !ok {
			return false
		}
		if entry := dnf4LockEntry(d); entry != "" {
			return len(owned) == 1 && owned[0] == entry
		}
		return len(owned) == 0
	}
	document, err := dnf.ParseVersionlock(current)
	if err != nil {
		return false
	}
	want := d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	count := 0
	for _, entry := range document.Packages {
		if entry.Comment != pinMarker(ref) {
			continue
		}
		count++
		if !want {
			return false
		}
		conditions := dnfPinConditions(d)
		if entry.Name != d.GetPackage().GetNativeName() || len(entry.Conditions) != len(conditions) {
			return false
		}
		for _, condition := range conditions {
			if !slices.Contains(entry.Conditions, condition) {
				return false
			}
		}
	}
	return want && count == 1 || !want && count == 0
}
func (p *Provider) applyPin(plan *resourcev1.ResourcePlan) error {
	native := plan.GetNativePackage()
	if !native.GetChangePin() {
		return nil
	}
	path := p.pinPath(plan.GetRef())
	current, contents, err := readPin(path)
	if err != nil {
		return err
	}
	before := plan.GetBefore().GetNativePackage()
	if !proto.Equal(current, before.GetPinFile()) || !bytes.Equal(contents, before.GetPinContents()) {
		return fmt.Errorf("%w: native pin changed before replacement", ErrConflict)
	}
	if len(native.GetPinContents()) == 0 && p.manager != dnf.DNF4 {
		return removeFile(path)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return ErrConflict
	}
	if native.GetPinMode() == 0 || native.GetPinMode()&0022 != 0 {
		return errors.New("packageprovider: unsafe native pin mode")
	}
	// The DNF4 plugin's list is a packaged configuration file it requires to
	// exist; an empty rendering empties it rather than deleting it.
	return atomicFile(path, native.GetPinContents(), os.FileMode(native.GetPinMode()))
}

// pinProjection is the candidate lock document visible to staging. An empty
// rendering still projects a valid document of the generation's format.
func pinProjection(backend resourcev1.Backend, contents []byte) []byte {
	if len(contents) != 0 {
		return bytes.Clone(contents)
	}
	if backend == resourcev1.Backend_BACKEND_DNF4 {
		return []byte("\n")
	}
	return []byte("version = \"1.0\"\n")
}
