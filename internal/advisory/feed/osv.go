package feed

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// These structs describe upstream OSV, not a second lindm serialization contract.
type osvRecord struct {
	ID            string   `json:"id"`
	SchemaVersion string   `json:"schema_version"`
	Published     string   `json:"published"`
	Withdrawn     string   `json:"withdrawn"`
	Aliases       []string `json:"aliases"`
	Related       []string `json:"related"`
	Upstream      []string `json:"upstream"`
	References    []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Binaries []struct {
			Name    string `json:"binary_name"`
			Version string `json:"binary_version"`
		} `json:"binaries"`
	} `json:"ecosystem_specific"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
		CVEsMap  struct {
			CVEs []struct {
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
			} `json:"cves"`
		} `json:"cves_map"`
	} `json:"database_specific"`
}

func parseOSV(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	ecosystem, err := osvEcosystem(config)
	if err != nil {
		return nil, err
	}
	doc := &advisoryv1.FeedDocument{}
	matched := false
	consume := func(reader io.Reader) error {
		data, err := boundedRead(reader, maxRecordBytes)
		if err != nil {
			return err
		}
		var record osvRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("feed: decode OSV: %w", err)
		}
		ok, err := appendOSV(doc, config, ecosystem, &record, validator)
		matched = matched || ok
		return err
	}
	if config.GetFormat() == advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON {
		if err := consume(bytes.NewReader(raw)); err != nil {
			return nil, err
		}
	} else {
		archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, fmt.Errorf("feed: open OSV ZIP: %w", err)
		}
		if len(archive.File) == 0 || len(archive.File) > maxEntries {
			return nil, errors.New("feed: OSV ZIP entry limit")
		}
		var expanded uint64
		names := make(map[string]bool, len(archive.File))
		for _, file := range archive.File {
			if file.FileInfo().IsDir() {
				continue
			}
			if !strings.HasSuffix(file.Name, ".json") || names[file.Name] || file.UncompressedSize64 > maxRecordBytes {
				return nil, errors.New("feed: unsupported or duplicate OSV ZIP entry")
			}
			names[file.Name] = true
			expanded += file.UncompressedSize64
			if expanded > maxExpandedBytes {
				return nil, errors.New("feed: OSV ZIP expansion limit")
			}
			reader, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("feed: open OSV ZIP entry: %w", err)
			}
			parseErr := consume(reader)
			if err := errors.Join(parseErr, reader.Close()); err != nil {
				return nil, err
			}
		}
		// Only the canonical OSV ecosystem export asserts full coverage;
		// naming a selected archive all.zip must not manufacture that claim.
		u, err := url.Parse(config.GetUrl())
		if err != nil {
			return nil, err
		}
		vendor, _, _ := strings.Cut(ecosystem, ":")
		doc.CompleteSnapshot = u.Host == "osv-vulnerabilities.storage.googleapis.com" && u.Path == "/"+vendor+"/all.zip" && u.RawQuery == ""
		// Rocky's export names source packages without a complete binary map.
		// Findings for named packages are useful; absence cannot prove clean.
		if config.GetDistro() == "rocky" {
			doc.CompleteSnapshot = false
		}
	}
	if !matched {
		return nil, errors.New("feed: OSV contains no matching supported product")
	}
	return doc, nil
}

func osvEcosystem(config *advisoryv1.FeedSource) (string, error) {
	release := config.GetRelease()
	switch config.GetDistro() {
	case "ubuntu":
		version, _, err := ubuntuRelease(release)
		if err != nil {
			return "", err
		}
		return "Ubuntu:" + version + ":LTS", nil
	case "debian":
		if release != "11" && release != "12" && release != "13" {
			return "", errors.New("feed: unsupported Debian release")
		}
		return "Debian:" + release, nil
	case "rocky", "almalinux":
		// These vendors publish major-release repositories, not RHEL EUS
		// streams. A configured minor still remains exact in Applies.
		major, _, _ := strings.Cut(release, ".")
		if major != "8" && major != "9" && major != "10" {
			return "", errors.New("feed: unsupported RPM product release")
		}
		if config.GetDistro() == "rocky" {
			return "Rocky Linux:" + major, nil
		}
		return "AlmaLinux:" + major, nil
	default:
		return "", errors.New("feed: unsupported OSV distro/product; no cross-vendor inference")
	}
}

func ubuntuRelease(release string) (version, codename string, err error) {
	switch release {
	case "22.04":
		return "22.04", "jammy", nil
	case "noble", "24.04":
		return "24.04", "noble", nil
	case "26.04":
		return "26.04", "resolute", nil
	default:
		return "", "", errors.New("feed: unsupported Ubuntu release")
	}
}

func appendOSV(doc *advisoryv1.FeedDocument, config *advisoryv1.FeedSource, ecosystem string, record *osvRecord, validator protovalidate.Validator) (bool, error) {
	if record.ID == "" || !strings.HasPrefix(record.SchemaVersion, "1.") {
		return false, errors.New("feed: unsupported OSV document shape")
	}
	if record.Withdrawn != "" {
		if _, err := time.Parse(time.RFC3339Nano, record.Withdrawn); err != nil {
			return false, errors.New("feed: invalid withdrawal timestamp")
		}
		return false, nil
	}
	if len(record.Affected) == 0 {
		return false, errors.New("feed: active OSV record lacks affected products")
	}
	published, err := timestamp(record.Published)
	if err != nil {
		return false, err
	}
	cves := make([]string, 0)
	for _, group := range [][]string{record.Aliases, record.Related, record.Upstream} {
		for _, id := range group {
			if validCVE(id) && !slices.Contains(cves, id) {
				cves = append(cves, id)
			}
		}
	}
	slices.Sort(cves)
	sourceURL := config.GetUrl()
	for _, reference := range record.References {
		if reference.Type == "ADVISORY" {
			u, err := url.Parse(reference.URL)
			if err != nil || httpsURL(u) != nil {
				return false, errors.New("feed: invalid advisory reference URL")
			}
			sourceURL = reference.URL
			break
		}
	}
	matched := false
	for _, affected := range record.Affected {
		if affected.Package.Ecosystem == "" {
			return false, errors.New("feed: OSV missing ecosystem")
		}
		if affected.Package.Ecosystem != ecosystem {
			continue
		}
		matched = true
		arch, source, err := osvIdentity(config, &affected)
		if err != nil {
			return false, err
		}
		if config.GetArchitecture() != "" && arch != "" && arch != "noarch" && arch != "all" && canonicalArch(arch) != canonicalArch(config.GetArchitecture()) {
			continue
		}
		severity := affected.DatabaseSpecific.Severity
		for _, cve := range affected.DatabaseSpecific.CVEsMap.CVEs {
			for _, value := range cve.Severity {
				if value.Type == "Ubuntu" && SeverityRank(value.Score) > SeverityRank(severity) {
					severity = value.Score
				}
			}
		}
		if len(affected.Ranges) == 0 {
			return false, errors.New("feed: OSV version-only set is unsupported")
		}
		for _, span := range affected.Ranges {
			if span.Type != "ECOSYSTEM" || len(span.Events) == 0 {
				return false, errors.New("feed: unsupported OSV range type")
			}
			var lower string
			open := false
			emit := func(fixed, last string) error {
				advisory := &advisoryv1.Advisory{Id: record.ID, Cves: cves, PackageName: affected.Package.Name, SourcePackage: source, Architecture: arch, IntroducedVersion: lower, FixedVersion: fixed, LastAffectedVersion: last, Severity: severity, PublishedAt: published, SourceUrl: sourceURL}
				if err := addRecord(doc, advisory, managerFor(config.GetDistro()), validator); err != nil {
					return err
				}
				// Ubuntu explicitly supplies binary fixed versions. A source
				// lower boundary cannot be translated without a version map.
				if source && lower == "" && fixed != "" {
					for _, binary := range affected.EcosystemSpecific.Binaries {
						if binary.Version == "" {
							return errors.New("feed: binary mapping lacks version")
						}
						binaryAdvisory := &advisoryv1.Advisory{Id: record.ID, Cves: cves, PackageName: binary.Name, Architecture: arch, FixedVersion: binary.Version, Severity: severity, PublishedAt: published, SourceUrl: sourceURL}
						if err := addRecord(doc, binaryAdvisory, managerFor(config.GetDistro()), validator); err != nil {
							return err
						}
					}
				}
				return nil
			}
			for _, event := range span.Events {
				if len(event) != 1 {
					return false, errors.New("feed: ambiguous OSV range event")
				}
				for kind, version := range event {
					if version == "" {
						return false, errors.New("feed: empty OSV range boundary")
					}
					if strings.Contains(version, ".module") {
						return false, errors.New("feed: module stream ranges are unsupported")
					}
					switch kind {
					case "introduced":
						if open {
							return false, errors.New("feed: overlapping OSV introductions")
						}
						lower, open = version, true
						if lower == "0" {
							lower = ""
						}
					case "fixed", "last_affected":
						if !open {
							return false, errors.New("feed: OSV upper bound without introduction")
						}
						fixed, last := "", ""
						if kind == "fixed" {
							fixed = version
						} else {
							last = version
						}
						if err := emit(fixed, last); err != nil {
							return false, err
						}
						open = false
					default:
						return false, errors.New("feed: unsupported OSV range event")
					}
				}
			}
			if open {
				if err := emit("", ""); err != nil {
					return false, err
				}
			}
		}
	}
	return matched, nil
}

func osvIdentity(config *advisoryv1.FeedSource, affected *osvAffected) (string, bool, error) {
	purl, query, _ := strings.Cut(affected.Package.PURL, "?")
	prefix := "pkg:deb/" + config.GetDistro() + "/"
	if managerFor(config.GetDistro()) == "rpm" {
		distro := config.GetDistro()
		if distro == "rocky" {
			distro = "rocky-linux"
		}
		prefix = "pkg:rpm/" + distro + "/"
	}
	if !strings.HasPrefix(purl, prefix) {
		return "", false, errors.New("feed: OSV package URL does not identify configured vendor")
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(purl, prefix), "@")
	name, err := url.PathUnescape(name)
	if err != nil || name != affected.Package.Name || strings.ContainsAny(name, ":/") {
		return "", false, errors.New("feed: unsupported OSV package identity or module")
	}
	qualifiers, err := url.ParseQuery(query)
	if err != nil {
		return "", false, errors.New("feed: invalid OSV package qualifiers")
	}
	for key, values := range qualifiers {
		if len(values) != 1 {
			return "", false, errors.New("feed: ambiguous OSV package qualifiers")
		}
		switch key {
		case "arch", "distro", "epoch":
		default:
			return "", false, errors.New("feed: unsupported OSV package qualifier")
		}
	}
	if distro := qualifiers.Get("distro"); distro != "" {
		want := config.GetDistro() + "-" + config.GetRelease()
		switch config.GetDistro() {
		case "ubuntu":
			_, codename, err := ubuntuRelease(config.GetRelease())
			if err != nil {
				return "", false, err
			}
			want = codename
		case "rocky", "almalinux":
			major, _, _ := strings.Cut(config.GetRelease(), ".")
			vendor := config.GetDistro()
			if vendor == "rocky" {
				vendor = "rocky-linux"
			}
			want = vendor + "-" + major
		}
		if distro != want {
			return "", false, errors.New("feed: conflicting OSV product qualifier")
		}
	}
	arch := qualifiers.Get("arch")
	switch arch {
	case "", "source", "src", "nosrc", "all", "noarch", "amd64", "x86_64", "i386", "i686", "arm64", "aarch64", "armhf", "ppc64el", "ppc64le", "s390x", "riscv64":
	default:
		return "", false, errors.New("feed: unsupported OSV architecture")
	}
	source := arch == "source" || arch == "src" || arch == "nosrc"
	if managerFor(config.GetDistro()) == "dpkg" && !source {
		return "", false, errors.New("feed: dpkg OSV source mapping unavailable")
	}
	if source {
		arch = ""
	}
	return arch, source, nil
}

func timestamp(value string) (*timestamppb.Timestamp, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			stamp := timestamppb.New(parsed)
			if err := stamp.CheckValid(); err != nil {
				return nil, fmt.Errorf("feed: timestamp: %w", err)
			}
			return stamp, nil
		}
	}
	return nil, errors.New("feed: missing or invalid publication timestamp")
}

func validCVE(value string) bool {
	if !strings.HasPrefix(value, "CVE-") || len(value) < 13 || value[8] != '-' {
		return false
	}
	for i := 4; i < len(value); i++ {
		if i != 8 && !digit(value[i]) {
			return false
		}
	}
	return true
}
