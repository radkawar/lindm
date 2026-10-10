package feed

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"slices"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

type rpmUpdate struct {
	ID          string `xml:"id"`
	Type        string `xml:"type,attr"`
	Status      string `xml:"status,attr"`
	Release     string `xml:"release"`
	Severity    string `xml:"severity"`
	Summary     string `xml:"summary"`
	Description string `xml:"description"`
	Issued      struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	References []struct {
		Type string `xml:"type,attr"`
		ID   string `xml:"id,attr"`
	} `xml:"references>reference"`
	Collections []struct {
		Short    string     `xml:"short,attr"`
		Name     string     `xml:"name"`
		Modules  []struct{} `xml:"module"`
		Packages []struct {
			Name    string `xml:"name,attr"`
			Epoch   string `xml:"epoch,attr"`
			Version string `xml:"version,attr"`
			Release string `xml:"release,attr"`
			Arch    string `xml:"arch,attr"`
		} `xml:"package"`
	} `xml:"pkglist>collection"`
}

func parseUpdateinfo(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (doc *advisoryv1.FeedDocument, err error) {
	if config.GetDistro() != "fedora" {
		return nil, errors.New("feed: updateinfo adapter supports Fedora; other products require their own vendor mapping")
	}
	arch := canonicalArch(config.GetArchitecture())
	switch arch {
	case "x86_64", "aarch64", "ppc64le", "s390x", "riscv64":
	default:
		return nil, errors.New("feed: unsupported or missing repository architecture")
	}
	var reader io.Reader = bytes.NewReader(raw)
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		decoded, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("feed: open gzip: %w", err)
		}
		defer func() { err = errors.Join(err, decoded.Close()) }()
		reader = decoded
	} else if len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		decoded, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxExpandedBytes))
		if err != nil {
			return nil, fmt.Errorf("feed: open zstd: %w", err)
		}
		defer decoded.Close()
		reader = decoded
	}
	limited := &io.LimitedReader{R: reader, N: maxExpandedBytes + 1}
	decoder := xml.NewDecoder(limited)
	doc = &advisoryv1.FeedDocument{}
	root, err := xmlRoot(decoder)
	if err != nil {
		return nil, err
	}
	if root.Name.Space != "" {
		return nil, errors.New("feed: unsupported updateinfo namespace")
	}
	count := 0
	switch root.Name.Local {
	case "update":
		var update rpmUpdate
		if err := decoder.DecodeElement(&update, &root); err != nil {
			return nil, fmt.Errorf("feed: decode advisory: %w", err)
		}
		if err := appendUpdate(doc, config, &update, validator); err != nil {
			return nil, err
		}
	case "updates":
		doc.CompleteSnapshot = true
		matchedProduct := false
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, fmt.Errorf("feed: decode updateinfo: %w", err)
			}
			if end, ok := token.(xml.EndElement); ok && end.Name == root.Name {
				break
			}
			switch token := token.(type) {
			case xml.StartElement:
				if token.Name.Local != "update" || token.Name.Space != "" {
					return nil, errors.New("feed: unsupported updateinfo element")
				}
				count++
				if count > maxEntries {
					return nil, errors.New("feed: updateinfo entry limit")
				}
				var update rpmUpdate
				if err := decoder.DecodeElement(&update, &token); err != nil {
					return nil, fmt.Errorf("feed: decode advisory: %w", err)
				}
				// Repository metadata can contain explicitly labelled entries
				// for another Fedora release (e.g. shared shim builds). Never
				// apply those records to the configured release.
				if update.Release != "Fedora "+config.GetRelease() && otherFedoraRelease(update.Release) {
					continue
				}
				matchedProduct = true
				if err := appendUpdate(doc, config, &update, validator); err != nil {
					return nil, err
				}
			case xml.CharData:
				if len(bytes.TrimSpace(token)) != 0 {
					return nil, errors.New("feed: unexpected updateinfo text")
				}
			case xml.Directive:
				return nil, errors.New("feed: XML directives unsupported")
			}
		}
		if count == 0 || !matchedProduct {
			return nil, errors.New("feed: updateinfo cannot establish configured product coverage")
		}
	default:
		return nil, errors.New("feed: unsupported updateinfo root")
	}
	if err := xmlEnd(decoder); err != nil {
		return nil, err
	}
	if limited.N <= 0 {
		return nil, errors.New("feed: XML expansion limit")
	}
	return doc, nil
}

func appendUpdate(doc *advisoryv1.FeedDocument, config *advisoryv1.FeedSource, update *rpmUpdate, validator protovalidate.Validator) error {
	if update.ID == "" || update.Type == "" || update.Release != "Fedora "+config.GetRelease() {
		return errors.New("feed: unknown or mismatched updateinfo product")
	}
	if update.Type != "security" {
		if update.Type != "bugfix" && update.Type != "enhancement" && update.Type != "newpackage" && update.Type != "unspecified" {
			return errors.New("feed: unknown update type")
		}
		return nil
	}
	if update.Status != "stable" || !strings.HasPrefix(update.ID, "FEDORA-") || len(update.Collections) == 0 {
		return errors.New("feed: unsupported security advisory status or product")
	}
	published, err := timestamp(update.Issued.Date)
	if err != nil {
		return err
	}
	cves := make([]string, 0)
	for _, reference := range update.References {
		if reference.Type == "cve" {
			if !validCVE(reference.ID) {
				return errors.New("feed: malformed CVE reference")
			}
			if !slices.Contains(cves, reference.ID) {
				cves = append(cves, reference.ID)
			}
		}
	}
	cves = disclosedCVEs(update.Summary, cves)
	cves = disclosedCVEs(update.Description, cves)
	slices.Sort(cves)
	for _, collection := range update.Collections {
		if collection.Short != "F"+config.GetRelease() || collection.Name != "Fedora "+config.GetRelease() || len(collection.Modules) != 0 || len(collection.Packages) == 0 {
			return errors.New("feed: unsupported collection, release or module stream")
		}
		for _, pkg := range collection.Packages {
			if pkg.Arch == "src" || pkg.Arch == "nosrc" {
				continue
			}
			switch pkg.Arch {
			case "x86_64", "i686", "aarch64", "ppc64le", "s390x", "riscv64", "noarch":
			default:
				return errors.New("feed: unsupported package architecture")
			}
			if pkg.Arch != "noarch" && canonicalArch(pkg.Arch) != canonicalArch(config.GetArchitecture()) {
				continue
			}
			if pkg.Epoch == "" || pkg.Version == "" || pkg.Release == "" || strings.Contains(pkg.Release, ".module") {
				return errors.New("feed: unsupported package EVR or release stream")
			}
			fixed := pkg.Epoch + ":" + pkg.Version + "-" + pkg.Release
			record := &advisoryv1.Advisory{Id: update.ID, Cves: cves, PackageName: pkg.Name, Architecture: pkg.Arch, FixedVersion: fixed, Severity: update.Severity, PublishedAt: published, SourceUrl: "https://bodhi.fedoraproject.org/updates/" + url.PathEscape(update.ID)}
			if err := addRecord(doc, record, "rpm", validator); err != nil {
				return err
			}
		}
	}
	return nil
}

func otherFedoraRelease(product string) bool {
	release, ok := strings.CutPrefix(product, "Fedora ")
	if !ok || release == "" {
		return false
	}
	for i := range len(release) {
		if !digit(release[i]) {
			return false
		}
	}
	return true
}

func updateLocation(location string, raw []byte) (string, []byte, error) {
	if len(raw) > maxRecordBytes {
		return "", nil, errors.New("feed: repomd byte limit")
	}
	var metadata struct {
		XMLName xml.Name `xml:"http://linux.duke.edu/metadata/repo repomd"`
		Data    []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(raw, &metadata); err != nil {
		return "", nil, fmt.Errorf("feed: decode repomd: %w", err)
	}
	if len(metadata.Data) == 0 || len(metadata.Data) > 64 {
		return "", nil, errors.New("feed: invalid repomd entries")
	}
	var href string
	var checksum []byte
	for _, entry := range metadata.Data {
		if entry.Type != "updateinfo" {
			continue
		}
		if href != "" || entry.Checksum.Type != "sha256" {
			return "", nil, errors.New("feed: ambiguous or unprotected updateinfo location")
		}
		href = entry.Location.Href
		var err error
		checksum, err = hex.DecodeString(strings.TrimSpace(entry.Checksum.Value))
		if err != nil || len(checksum) != 32 {
			return "", nil, errors.New("feed: malformed updateinfo checksum")
		}
	}
	if href == "" || !strings.HasPrefix(href, "repodata/") || path.Clean(href) != href || strings.ContainsAny(href, "\\?#:") {
		return "", nil, errors.New("feed: unsupported updateinfo location")
	}
	base, err := url.Parse(location)
	if err != nil || httpsURL(base) != nil || !strings.HasSuffix(base.Path, "/repodata/repomd.xml") || base.RawQuery != "" {
		return "", nil, errors.New("feed: invalid repomd URL")
	}
	base.Path = strings.TrimSuffix(base.Path, "repodata/repomd.xml") + href
	base.RawPath = ""
	return base.String(), checksum, nil
}

func xmlRoot(decoder *xml.Decoder) (xml.StartElement, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, fmt.Errorf("feed: read XML root: %w", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			return token, nil
		case xml.Directive:
			return xml.StartElement{}, errors.New("feed: XML directives unsupported")
		case xml.CharData:
			if len(bytes.TrimSpace(token)) != 0 {
				return xml.StartElement{}, errors.New("feed: text before XML root")
			}
		}
	}
}

func xmlEnd(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("feed: finish XML: %w", err)
		}
		switch token := token.(type) {
		case xml.Comment:
		case xml.CharData:
			if len(bytes.TrimSpace(token)) != 0 {
				return errors.New("feed: trailing XML data")
			}
		default:
			return errors.New("feed: trailing XML element")
		}
	}
}

// disclosedCVEs retains exact vendor-disclosed CVE tokens even when updateinfo
// omits structured references. It does not infer CVEs from package identities.
func disclosedCVEs(text string, cves []string) []string {
	for offset := 0; offset < len(text); {
		relative := strings.Index(text[offset:], "CVE-")
		if relative < 0 {
			break
		}
		start := offset + relative
		end := start + 4
		for end < len(text) && (digit(text[end]) || text[end] == '-') {
			end++
		}
		offset = end
		if start > 0 && (letter(text[start-1]) || digit(text[start-1]) || text[start-1] == '_') {
			continue
		}
		if end < len(text) && (letter(text[end]) || text[end] == '_') {
			continue
		}
		id := text[start:end]
		if validCVE(id) && !slices.Contains(cves, id) {
			cves = append(cves, id)
		}
	}
	return cves
}
