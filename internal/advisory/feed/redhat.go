package feed

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"buf.build/go/protovalidate"
	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const redHatRecordBytes = 32 << 20

var errRedHatNotApplicable = errors.New("feed: Red Hat document has no configured host RHEL applicability")

type redHatProduct struct {
	product     suseProduct
	arch        string
	unsupported bool
}

type redHatRPM struct {
	name, version, arch, module, stream string
	source                              bool
}

// parseRedHat shares the CSAF 2.0 wire representation with SUSE, but not its
// vendor policy. Product CPEs, not internal Errata Tool ID suffixes, establish
// servicing applicability: MAIN.EUS is a mainstream variant, not an EUS CPE.
func parseRedHat(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	if err := redHatConfig(config); err != nil {
		return nil, err
	}
	if len(raw) > redHatRecordBytes || !utf8.Valid(raw) {
		return nil, errors.New("feed: Red Hat CSAF record exceeds limit or is not UTF-8")
	}
	var notice suseCSAF
	if err := json.Unmarshal(raw, &notice); err != nil {
		return nil, fmt.Errorf("feed: decode Red Hat CSAF: %w", err)
	}
	d := &notice.Document
	if d.Version != "2.0" || (d.Category != "csaf_security_advisory" && d.Category != "csaf_vex") || d.Tracking.Status != "final" || d.Publisher.Category != "vendor" || d.Publisher.Namespace != "https://www.redhat.com" {
		return nil, errors.New("feed: unsupported Red Hat CSAF document or publisher")
	}
	published, err := timestamp(d.Tracking.Published)
	if err != nil {
		return nil, err
	}
	if len(notice.Tree.Branches) != 1 || notice.Tree.Branches[0].Category != "vendor" {
		return nil, errors.New("feed: Red Hat requires one explicit vendor root")
	}
	products := make(map[string]redHatProduct)
	count := 0
	if err := redHatProducts(notice.Tree.Branches, "", false, 0, products, &count); err != nil {
		return nil, err
	}
	potential := false
	for _, p := range products {
		if applies, _ := redHatPlatform(config, p.product, "under_investigation"); applies {
			potential = true
			break
		}
	}
	if !potential {
		return nil, errRedHatNotApplicable
	}
	if len(notice.Tree.FullProducts) != 0 || len(notice.Tree.Groups) != 0 {
		return nil, errors.New("feed: unsupported Red Hat standalone products or groups")
	}
	relations := make(map[string]suseRelationship, len(notice.Tree.Relationships))
	for _, relation := range notice.Tree.Relationships {
		_, duplicate := relations[relation.Product.ID]
		_, collision := products[relation.Product.ID]
		if relation.Product.ID == "" || duplicate || collision {
			return nil, errors.New("feed: unsupported or duplicate Red Hat relationship")
		}
		relations[relation.Product.ID] = relation
	}
	doc := &advisoryv1.FeedDocument{}
	for _, vulnerability := range notice.Vulnerabilities {
		if !validCVE(vulnerability.CVE) {
			return nil, errors.New("feed: Red Hat vulnerability lacks valid CVE")
		}
		// Iterate fixed status first, deterministically. Reconciliation below removes
		// bare affected statements only when an exact product/package fix exists.
		for _, status := range []string{"fixed", "known_affected", "known_not_affected", "under_investigation"} {
			for _, id := range vulnerability.Status[status] {
				relation, exists := relations[id]
				if !exists {
					return nil, errors.New("feed: unresolved Red Hat vulnerability relationship")
				}
				platform, module, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
				if err != nil {
					return nil, err
				}
				applies, uncertain := redHatPlatform(config, platform, status)
				if !applies {
					continue
				}
				if relation.Category != "default_component_of" || products[platform.ID].unsupported {
					return nil, errors.New("feed: unsupported relevant Red Hat product relationship")
				}
				component, exists := products[relation.Component]
				if !exists {
					return nil, errors.New("feed: unresolved Red Hat RPM component")
				}
				if component.unsupported {
					return nil, errors.New("feed: unsupported relevant Red Hat component constraint")
				}
				// OCI, Maven, JBoss, UBI and other layered content never become
				// host RPM evidence merely because their display name includes RHEL.
				if !strings.HasPrefix(component.product.Helper.PURL, "pkg:rpm/redhat/") {
					continue
				}
				pkg, err := redHatPackage(component)
				if err != nil {
					return nil, err
				}
				if module != "" {
					name, stream, err := redHatModule(module)
					if err != nil || (pkg.module != "" && (pkg.module != name || pkg.stream != stream)) {
						return nil, errors.New("feed: conflicting Red Hat module relationship")
					}
					pkg.module, pkg.stream = name, stream
				}
				if pkg.arch != "" && pkg.arch != "noarch" && !pkg.source && pkg.arch != canonicalArch(config.GetArchitecture()) {
					continue
				}
				record := &advisoryv1.Advisory{Id: d.Tracking.ID, Cves: []string{vulnerability.CVE}, PackageName: pkg.name, SourcePackage: pkg.source, Architecture: pkg.arch, Severity: d.Severity.Text, PublishedAt: published, SourceUrl: config.GetUrl(), PlatformRelease: config.GetRelease(), PlatformStream: config.GetPlatformStream(), ModuleName: pkg.module, ModuleStream: pkg.stream}
				if pkg.source {
					record.Architecture = ""
				}
				switch status {
				case "fixed":
					if pkg.version == "" {
						return nil, errors.New("feed: Red Hat fixed RPM lacks exact EVR")
					}
					record.FixedVersion = pkg.version
				case "known_affected":
					if pkg.version != "" {
						record.IntroducedVersion, record.LastAffectedVersion = pkg.version, pkg.version
					}
				case "known_not_affected":
					record.NotAffected = !uncertain
					if pkg.version != "" {
						record.IntroducedVersion, record.LastAffectedVersion = pkg.version, pkg.version
					}
				}
				record.AssessmentUnknown = uncertain || status == "under_investigation"
				if err := addRecord(doc, record, "rpm", validator); err != nil {
					return nil, err
				}
			}
		}
		for status, ids := range vulnerability.Status {
			if status == "fixed" || status == "known_affected" || status == "known_not_affected" || status == "under_investigation" {
				continue
			}
			for _, id := range ids {
				relation, ok := relations[id]
				if !ok {
					return nil, errors.New("feed: unresolved Red Hat status product")
				}
				platform, _, err := redHatPlatformProduct(relation.Platform, products, relations, 0)
				if err != nil {
					return nil, err
				}
				if applies, _ := redHatPlatform(config, platform, "under_investigation"); applies {
					return nil, fmt.Errorf("feed: unsupported relevant Red Hat status %q", status)
				}
			}
		}
	}
	if len(doc.Advisories) == 0 {
		return nil, errRedHatNotApplicable
	}
	redHatReconcile(doc)
	return doc, nil // Neither an individual advisory nor legacy VEX proves coverage.
}

func redHatConfig(config *advisoryv1.FeedSource) error {
	if config == nil || config.GetDistro() != "rhel" {
		return errors.New("feed: Red Hat CSAF requires native RHEL, not a compatible distribution")
	}
	parts := strings.Split(config.GetRelease(), ".")
	if len(parts) > 2 || !suseDigits(parts[0]) || (len(parts) == 2 && !suseDigits(parts[1])) {
		return errors.New("feed: invalid Red Hat release")
	}
	switch config.GetPlatformStream() {
	case "standard":
	case "eus", "e4s":
		if len(parts) != 2 {
			return errors.New("feed: extended Red Hat streams require exact major.minor")
		}
	default:
		return errors.New("feed: explicit Red Hat standard/eus/e4s stream required")
	}
	switch canonicalArch(config.GetArchitecture()) {
	case "x86_64", "aarch64", "ppc64le", "s390x", "i686":
		return nil
	default:
		return errors.New("feed: explicit supported Red Hat architecture required")
	}
}

func redHatProducts(branches []suseBranch, arch string, unsupported bool, depth int, products map[string]redHatProduct, count *int) error {
	if depth > 12 {
		return errors.New("feed: Red Hat product tree depth limit")
	}
	for _, branch := range branches {
		*count++
		if *count > maxEntries {
			return errors.New("feed: Red Hat product tree entry limit")
		}
		nextArch := arch
		nextUnsupported := unsupported
		switch branch.Category {
		case "vendor":
			if depth != 0 || branch.Name != "Red Hat" {
				return errors.New("feed: unsupported Red Hat product vendor")
			}
		case "product_family", "product_name", "product_version":
		case "architecture":
			if arch != "" {
				return errors.New("feed: nested Red Hat architecture")
			}
			nextArch = canonicalArch(branch.Name)
		default:
			nextUnsupported = true
		}
		if branch.Product != nil {
			p := *branch.Product
			// CSAF display labels are not identifiers. Red Hat uses "::module"
			// in branch names and "(module)" in the corresponding product name.
			if p.ID == "" || p.Name == "" {
				return errors.New("feed: invalid Red Hat product")
			}
			if previous, duplicate := products[p.ID]; duplicate {
				// Some vendor VEX documents reuse component IDs for different
				// module builds in unrelated releases. Preserve the ambiguity:
				// a relevant relationship must reject it, but an off-scope
				// product must not poison another release's host assessment.
				previous.unsupported = true
				products[p.ID] = previous
			} else {
				products[p.ID] = redHatProduct{product: p, arch: nextArch, unsupported: nextUnsupported}
			}
		}
		if err := redHatProducts(branch.Branches, nextArch, nextUnsupported, depth+1, products, count); err != nil {
			return err
		}
	}
	return nil
}

// Legacy module relationships may insert a module between RPM and product.
// Follow only declared edges, with a depth bound also rejecting cycles.
func redHatPlatformProduct(id string, products map[string]redHatProduct, relations map[string]suseRelationship, depth int) (suseProduct, string, error) {
	if depth > 8 {
		return suseProduct{}, "", errors.New("feed: cyclic Red Hat module relationship")
	}
	if p, ok := products[id]; ok {
		return p.product, "", nil
	}
	r, ok := relations[id]
	if !ok {
		return suseProduct{}, "", errors.New("feed: unresolved Red Hat platform")
	}
	p, module, err := redHatPlatformProduct(r.Platform, products, relations, depth+1)
	if err != nil {
		return p, "", err
	}
	component, ok := products[r.Component]
	if !ok || module != "" {
		return p, "", errors.New("feed: unsupported nested Red Hat module")
	}
	if r.Category != "default_component_of" || component.unsupported {
		return p, "", errors.New("feed: unsupported Red Hat module relationship constraint")
	}
	return p, component.product.ID, nil
}

func redHatPlatform(config *advisoryv1.FeedSource, product suseProduct, status string) (bool, bool) {
	cpe := strings.Split(product.Helper.CPE, ":")
	if len(cpe) < 5 || len(cpe) > 7 || (cpe[1] != "/o" && cpe[1] != "/a") || cpe[0] != "cpe" || cpe[2] != "redhat" {
		return false, false
	}
	if len(cpe) > 5 && cpe[5] != "" {
		return false, false
	}
	if len(cpe) == 7 && cpe[6] != "baseos" && cpe[6] != "appstream" && cpe[6] != "crb" && cpe[6] != "server" && cpe[6] != "workstation" && cpe[6] != "computenode" && cpe[6] != "client" {
		return false, false
	}
	release, stream := cpe[4], ""
	switch cpe[3] {
	case "enterprise_linux":
		stream = "standard"
	case "rhel_eus", "enterprise_linux_eus":
		stream = "eus"
	case "rhel_e4s", "enterprise_linux_e4s":
		stream = "e4s"
	default:
		return false, false
	}
	major, _, _ := strings.Cut(config.GetRelease(), ".")
	if release != config.GetRelease() && (stream != "standard" || strings.Contains(release, ".") || release != major) {
		return false, false
	}
	if stream == config.GetPlatformStream() {
		return true, false
	}
	// The legacy major-wide unfixed CPE is not proof of an EUS/E4S package
	// being vulnerable forever. Retain uncertainty until exact stream fixes
	// are reconciled; never transplant a mainstream fixed EVR into xUS.
	return stream == "standard" && status != "fixed", true
}

func redHatModule(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if (len(parts) != 2 && len(parts) != 4) || parts[0] == "" || parts[1] == "" || strings.ContainsAny(value, " /?&#\t\r\n") || (len(parts) == 4 && (parts[2] == "" || parts[3] == "")) {
		return "", "", errors.New("feed: invalid Red Hat module NS or NSVC")
	}
	return parts[0], parts[1], nil
}

func redHatPackage(component redHatProduct) (redHatRPM, error) {
	var pkg redHatRPM
	raw := strings.TrimPrefix(component.product.Helper.PURL, "pkg:rpm/redhat/")
	if strings.Contains(raw, "#") {
		return pkg, errors.New("feed: Red Hat RPM fragment unsupported")
	}
	identity, query, _ := strings.Cut(raw, "?")
	name, version, versioned := strings.Cut(identity, "@")
	q, err := url.ParseQuery(query)
	if err != nil || name == "" || strings.ContainsAny(name, "%/@ :\t\n\r") {
		return pkg, errors.New("feed: invalid Red Hat RPM purl")
	}
	for key, values := range q {
		if len(values) != 1 || (key != "arch" && key != "epoch" && key != "rpmmod" && key != "repository_id") {
			return pkg, errors.New("feed: unsupported Red Hat RPM qualifier")
		}
	}
	pkg.name, pkg.arch = name, canonicalArch(q.Get("arch"))
	pkg.source = pkg.arch == "src" || pkg.arch == "nosrc"
	if component.arch != "" && component.arch != pkg.arch {
		return pkg, errors.New("feed: conflicting Red Hat RPM architecture")
	}
	if value := q.Get("rpmmod"); value != "" {
		pkg.module, pkg.stream, err = redHatModule(value)
		if err != nil {
			return pkg, err
		}
	}
	if versioned {
		vr, err := url.PathUnescape(version)
		epoch := q.Get("epoch")
		if epoch == "" {
			epoch = "0"
		}
		if err != nil || !suseDigits(epoch) || !strings.Contains(vr, "-") || pkg.arch == "" {
			return pkg, errors.New("feed: invalid Red Hat RPM EVR")
		}
		pkg.version = epoch + ":" + vr
		nevra := name + "-" + pkg.version + "." + q.Get("arch")
		expected := nevra
		if pkg.module != "" {
			expected += " (" + pkg.module + ":" + pkg.stream + ")"
		}
		if component.product.Name != expected {
			return pkg, errors.New("feed: Red Hat RPM NEVRA disagrees with purl")
		}
	} else if q.Has("epoch") {
		return pkg, errors.New("feed: unversioned Red Hat RPM has epoch")
	}
	return pkg, nil
}

// Reconcile the same CVE/package/module and selected product before publishing.
// Keep the earliest fixed EVR, not later rebuilds which would falsely label an
// already backported build vulnerable. Binary and source evidence stay separate.
func redHatReconcile(doc *advisoryv1.FeedDocument) {
	type key struct {
		cve, name, module, stream, release, platform string
		source                                       bool
	}
	identity := func(r *advisoryv1.Advisory) key {
		return key{r.Cves[0], r.PackageName, r.ModuleName, r.ModuleStream, r.PlatformRelease, r.PlatformStream, r.SourcePackage}
	}
	fixes := make(map[key]map[string]*advisoryv1.Advisory)
	for _, r := range doc.Advisories {
		if r.FixedVersion == "" || r.AssessmentUnknown {
			continue
		}
		k := identity(r)
		if fixes[k] == nil {
			fixes[k] = make(map[string]*advisoryv1.Advisory)
		}
		prior := fixes[k][r.Architecture]
		if prior == nil {
			fixes[k][r.Architecture] = r
		} else if cmp, err := Compare("rpm", r.FixedVersion, prior.FixedVersion); err == nil && cmp < 0 {
			fixes[k][r.Architecture] = r
		}
	}
	kept := doc.Advisories[:0]
	for _, r := range doc.Advisories {
		matches := fixes[identity(r)]
		if r.FixedVersion != "" && !r.AssessmentUnknown {
			if matches[r.Architecture] != r {
				continue
			}
		} else if r.IntroducedVersion == "" && r.LastAffectedVersion == "" && !r.NotAffected && len(matches) != 0 {
			if r.Architecture == "" || matches[r.Architecture] != nil || matches["noarch"] != nil {
				continue
			}
		}
		kept = append(kept, r)
	}
	clear(doc.Advisories[len(kept):])
	doc.Advisories = kept
}

// parseRedHatArchive consumes an already authenticated weekly snapshot. Nothing
// is extracted to disk; only matching normalized records survive each entry.
func parseRedHatArchive(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	if err := redHatConfig(config); err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(redHatContextReader{ctx: ctx, reader: input}, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxExpandedBytes))
	if err != nil {
		return nil, fmt.Errorf("feed: open Red Hat archive: %w", err)
	}
	defer decoder.Close()
	limited := &io.LimitedReader{R: decoder, N: 16<<30 + 1}
	archive := tar.NewReader(limited)
	doc := &advisoryv1.FeedDocument{}
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("feed: read Red Hat archive: %w", err)
		}
		if entries >= maxEntries || limited.N <= 0 {
			return nil, errors.New("feed: Red Hat archive expansion or entry limit")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") || header.Size < 0 || header.Size > redHatRecordBytes || strings.HasPrefix(header.Name, "/") || strings.Contains(header.Name, "\\") || strings.Contains(header.Name, "../") {
			return nil, errors.New("feed: unsupported Red Hat archive entry")
		}
		raw := make([]byte, int(header.Size))
		if _, err := io.ReadFull(archive, raw); err != nil {
			return nil, fmt.Errorf("feed: read Red Hat archive JSON: %w", err)
		}
		parsed, err := parseRedHat(config, raw, validator)
		if errors.Is(err, errRedHatNotApplicable) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("feed: Red Hat archive entry %s: %w", path.Base(header.Name), err)
		}
		if len(doc.Advisories)+len(parsed.Advisories) > maxAdvisories {
			return nil, errors.New("feed: Red Hat archive advisory limit")
		}
		doc.Advisories = append(doc.Advisories, parsed.Advisories...)
	}
	// Consume the zstd trailer as well: tar EOF alone does not authenticate
	// the compressed frame checksum or bound trailing decompressed padding.
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return nil, fmt.Errorf("feed: finish Red Hat compressed archive: %w", err)
	}
	if limited.N <= 0 {
		return nil, errors.New("feed: Red Hat archive expansion limit")
	}
	redHatReconcile(doc)
	return doc, nil
}

type redHatContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r redHatContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
