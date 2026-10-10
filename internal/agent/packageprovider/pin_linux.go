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
	"strings"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

type versionlockCondition struct {
	Key        string `toml:"key"`
	Comparator string `toml:"comparator"`
	Value      string `toml:"value"`
}
type versionlockPackage struct {
	Name       string                 `toml:"name"`
	Comment    string                 `toml:"comment,omitempty"`
	Conditions []versionlockCondition `toml:"conditions"`
}
type versionlockDocument struct {
	Version  string               `toml:"version"`
	Packages []versionlockPackage `toml:"packages,omitempty"`
}

func parseVersionlock(data []byte) (versionlockDocument, error) {
	if len(data) == 0 {
		return versionlockDocument{Version: "1.0"}, nil
	}
	var document versionlockDocument
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("packageprovider: invalid native versionlock: %w", err)
	}
	if document.Version != "1.0" {
		return document, errors.New("packageprovider: unsupported native versionlock version")
	}
	for _, entry := range document.Packages {
		if entry.Name == "" || len(entry.Conditions) == 0 {
			return document, errors.New("packageprovider: incomplete native versionlock entry")
		}
		for _, condition := range entry.Conditions {
			if condition.Key != "evr" && condition.Key != "epoch" && condition.Key != "arch" {
				return document, errors.New("packageprovider: unknown native versionlock dimension")
			}
			if condition.Comparator != "=" && condition.Comparator != "!=" && condition.Comparator != "<" && condition.Comparator != "<=" && condition.Comparator != ">" && condition.Comparator != ">=" {
				return document, errors.New("packageprovider: unknown native versionlock comparator")
			}
		}
	}
	return document, nil
}
func (p *Provider) pinPath(ref *resourcev1.ResourceRef) string {
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		return "/etc/dnf/versionlock.toml"
	}
	digest := sha256.Sum256([]byte(ref.GetCanonicalKey()))
	return "/etc/apt/preferences.d/lindm-" + hex.EncodeToString(digest[:])
}
func readPin(path string) (*resourcev1.FileIdentity, []byte, error) {
	data, err := protectedFile(path, maxPin)
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
func aptPin(d *resourcev1.NativePackageDesired) []byte {
	if d.GetExact() == nil || d.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	return []byte("# Managed by lindm; exact native version, never implicit downgrade.\nPackage: " + d.GetPackage().GetNativeName() + ":" + d.GetPackage().GetArchitecture() + "\nPin: version " + d.GetExact().GetDeb() + "\nPin-Priority: 1000\n")
}
func pinMarker(ref *resourcev1.ResourceRef) string { return "lindm:" + ref.GetCanonicalKey() }
func renderDNFPin(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) ([]byte, error) {
	document, err := parseVersionlock(current)
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
		document.Packages = append(document.Packages, versionlockPackage{Name: d.GetPackage().GetNativeName(), Comment: marker, Conditions: []versionlockCondition{{Key: "evr", Comparator: "=", Value: nativeVersion(d.GetExact())}, {Key: "arch", Comparator: "=", Value: d.GetPackage().GetArchitecture()}}})
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
func (p *Provider) renderPin(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) ([]byte, error) {
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		return aptPin(d), nil
	}
	return renderDNFPin(ref, d, current)
}
func pinMatches(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte) bool {
	if d.GetPackage().GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		return bytes.Equal(aptPin(d), current)
	}
	document, err := parseVersionlock(current)
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
		if !want || entry.Name != d.GetPackage().GetNativeName() || len(entry.Conditions) != 2 {
			return false
		}
		evr, arch := false, false
		for _, condition := range entry.Conditions {
			if condition.Key == "evr" && condition.Comparator == "=" && condition.Value == nativeVersion(d.GetExact()) {
				evr = true
			}
			if condition.Key == "arch" && condition.Comparator == "=" && condition.Value == d.GetPackage().GetArchitecture() {
				arch = true
			}
		}
		if !evr || !arch {
			return false
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
	if len(native.GetPinContents()) == 0 {
		return removeFile(path)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return ErrConflict
	}
	if native.GetPinMode() == 0 || native.GetPinMode()&0022 != 0 {
		return errors.New("packageprovider: unsafe native pin mode")
	}
	return atomicFile(path, native.GetPinContents(), os.FileMode(native.GetPinMode()))
}

func pinProjection(contents []byte) []byte {
	if len(contents) == 0 {
		return []byte("version = \"1.0\"\n")
	}
	return bytes.Clone(contents)
}
