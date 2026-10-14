// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverdeps

import (
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

const rpmMetadataLimit = 128 << 20

// repomd is an index authenticated at acquisition by vendor TLS and RHSM. Its
// checksums bind retained metadata; native RPM signatures bind every payload.
// These are different trust chains and neither implies a repomd.asc exists.
type rpmMetadataIndex struct {
	Data []rpmMetadataEntry `xml:"data"`
}

type rpmMetadataEntry struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
	Size uint64 `xml:"size"`
}

type rpmPrimaryPackage struct {
	Name    string `xml:"name"`
	Arch    string `xml:"arch"`
	Version struct {
		Epoch string `xml:"epoch,attr"`
		Ver   string `xml:"ver,attr"`
		Rel   string `xml:"rel,attr"`
	} `xml:"version"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Size struct {
		Package uint64 `xml:"package,attr"`
	} `xml:"size"`
}

func rpmSourceURL(source, id string) bool {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != "cdn.redhat.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	switch id {
	case "rhel-9-for-x86_64-baseos-rpms":
		return u.Path == "/content/dist/rhel9/9/x86_64/baseos/os"
	case "rhel-9-for-x86_64-appstream-rpms":
		return u.Path == "/content/dist/rhel9/9/x86_64/appstream/os"
	default:
		return false
	}
}

func validateRPMProvenance(root *os.File, m *serverdepsv1.Manifest) error {
	files := make(map[string]*serverdepsv1.File, len(m.GetFiles()))
	packages := map[string]map[string]*serverdepsv1.File{}
	for _, item := range m.GetFiles() {
		if files[item.GetPath()] != nil {
			return errors.New("serverdeps: duplicate RPM retained path")
		}
		files[item.GetPath()] = item
		if item.GetKind() == serverdepsv1.FileKind_FILE_KIND_PACKAGE {
			if item.GetVendorSha256() != item.GetSha256() || item.GetPackageIdentity() == "" {
				return errors.New("serverdeps: RPM package missing vendor checksum or native identity")
			}
			metadata := item.GetVendorMetadataPath()
			if packages[metadata] == nil {
				packages[metadata] = map[string]*serverdepsv1.File{}
			}
			if packages[metadata][item.GetPackageIdentity()] != nil {
				return errors.New("serverdeps: duplicate native RPM identity")
			}
			packages[metadata][item.GetPackageIdentity()] = item
		}
	}
	repositories := map[string]bool{}
	for _, repo := range m.GetRepositories() {
		if repositories[repo.GetId()] || !rpmSourceURL(repo.GetSourceUrl(), repo.GetId()) || repo.GetAuthentication() != "vendor-tls-rhsm" {
			return errors.New("serverdeps: RHEL repository lacks exact vendor TLS/RHSM provenance")
		}
		repositories[repo.GetId()] = true
		key := files[repo.GetSigningKeyPath()]
		if key == nil || key.GetKind() != serverdepsv1.FileKind_FILE_KIND_KEY || key.GetSignerFingerprint() != repo.GetSignerFingerprint() || key.GetSha256() != rpmVendorKeyDigest(repo.GetSignerFingerprint()) {
			return errors.New("serverdeps: RHEL repository signer differs from reviewed vendor key")
		}
		index := files[repo.GetMetadataPath()]
		if index == nil || index.GetKind() != serverdepsv1.FileKind_FILE_KIND_METADATA || index.GetSizeBytes() > rpmMetadataLimit {
			return errors.New("serverdeps: RHEL repository has no retained bounded repomd index")
		}
		entries, err := readRPMIndex(root, index)
		if err != nil {
			return err
		}
		primary := ""
		for _, item := range m.GetFiles() {
			if item.GetKind() != serverdepsv1.FileKind_FILE_KIND_METADATA || item.GetVendorMetadataPath() != index.GetPath() {
				continue
			}
			entry, ok := entries[path.Base(item.GetPath())]
			if !ok || item.GetVendorSha256() != item.GetSha256() || entry.Checksum.Type != "sha256" || strings.TrimSpace(entry.Checksum.Value) != item.GetSha256() || entry.Size != item.GetSizeBytes() || item.GetSizeBytes() > rpmMetadataLimit {
				return errors.New("serverdeps: retained RPM metadata differs from authenticated repomd checksum")
			}
			if err := CheckRetained(root, item); err != nil {
				return err
			}
			if entry.Type == "primary" {
				if primary != "" {
					return errors.New("serverdeps: duplicate RPM primary metadata")
				}
				primary = item.GetPath()
			}
		}
		if primary == "" {
			return errors.New("serverdeps: RPM primary metadata was not retained")
		}
		if err := checkRPMPrimary(root, files[primary], packages[primary]); err != nil {
			return err
		}
		delete(packages, primary)
	}
	if !repositories["rhel-9-for-x86_64-baseos-rpms"] || !repositories["rhel-9-for-x86_64-appstream-rpms"] || len(packages) != 0 {
		return errors.New("serverdeps: RPM package metadata is not bound to authenticated BaseOS/AppStream")
	}
	return nil
}

func readRPMIndex(root *os.File, item *serverdepsv1.File) (_ map[string]rpmMetadataEntry, err error) {
	file, err := sealRetained(root, item, rpmMetadataLimit)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var index rpmMetadataIndex
	if err := xml.NewDecoder(io.LimitReader(file, rpmMetadataLimit+1)).Decode(&index); err != nil {
		return nil, fmt.Errorf("serverdeps: decode vendor RPM metadata: %w", err)
	}
	entries := make(map[string]rpmMetadataEntry, len(index.Data))
	if len(index.Data) == 0 || len(index.Data) > 128 {
		return nil, errors.New("serverdeps: RPM metadata index exceeds bounds")
	}
	for _, entry := range index.Data {
		name := path.Base(entry.Location.Href)
		if !strings.HasPrefix(entry.Location.Href, "repodata/") || name == "." || entries[name].Type != "" {
			return nil, errors.New("serverdeps: invalid or duplicate vendor metadata location")
		}
		entries[name] = entry
	}
	return entries, nil
}

func checkRPMPrimary(root *os.File, item *serverdepsv1.File, selected map[string]*serverdepsv1.File) (err error) {
	file, err := sealRetained(root, item, rpmMetadataLimit)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var stream io.Reader = file
	if strings.HasSuffix(item.GetPath(), ".gz") {
		reader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, reader.Close()) }()
		stream = reader
	} else if !strings.HasSuffix(item.GetPath(), ".xml") {
		return errors.New("serverdeps: unsupported native primary metadata compression")
	}
	bounded := &io.LimitedReader{R: stream, N: 1 << 30}
	decoder := xml.NewDecoder(bounded)
	found := make(map[string]bool, len(selected))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}
		var pkg rpmPrimaryPackage
		if err := decoder.DecodeElement(&pkg, &start); err != nil {
			return err
		}
		identity := pkg.Name + "-" + pkg.Version.Epoch + ":" + pkg.Version.Ver + "-" + pkg.Version.Rel + "." + pkg.Arch
		selectedFile := selected[identity]
		if selectedFile == nil {
			continue
		}
		if found[identity] || pkg.Checksum.Type != "sha256" || strings.TrimSpace(pkg.Checksum.Value) != selectedFile.GetSha256() || pkg.Size.Package != selectedFile.GetSizeBytes() || (pkg.Arch != "x86_64" && pkg.Arch != "noarch") {
			return errors.New("serverdeps: RPM payload differs from authenticated primary metadata")
		}
		found[identity] = true
	}
	if bounded.N == 0 || len(found) != len(selected) {
		return errors.New("serverdeps: bounded vendor RPM metadata does not cover closure")
	}
	return nil
}
