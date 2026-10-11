package feed

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

// These external CSAF 2.0 wire types are shared by the SUSE and Red Hat parsers;
// vendor applicability policies stay separate. Product relationships, not a
// binary's upstream CPE or a display-name substring, bind packages to platforms.
type suseProduct struct {
	ID     string `json:"product_id"`
	Name   string `json:"name"`
	Helper struct {
		CPE  string `json:"cpe"`
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type suseBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *suseProduct `json:"product"`
	Branches []suseBranch `json:"branches"`
}

type suseRelationship struct {
	Category  string      `json:"category"`
	Product   suseProduct `json:"full_product_name"`
	Component string      `json:"product_reference"`
	Platform  string      `json:"relates_to_product_reference"`
}

type suseCSAF struct {
	Document struct {
		Category  string `json:"category"`
		Version   string `json:"csaf_version"`
		Title     string `json:"title"`
		Publisher struct {
			Category  string `json:"category"`
			Namespace string `json:"namespace"`
		} `json:"publisher"`
		Severity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Tracking struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			Published string `json:"initial_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	Tree struct {
		Branches      []suseBranch       `json:"branches"`
		Relationships []suseRelationship `json:"relationships"`
		FullProducts  []json.RawMessage  `json:"full_product_names"`
		Groups        []json.RawMessage  `json:"product_groups"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE          string              `json:"cve"`
		Status       map[string][]string `json:"product_status"`
		Remediations []struct {
			Category string   `json:"category"`
			Products []string `json:"product_ids"`
			Groups   []string `json:"group_ids"`
		} `json:"remediations"`
	} `json:"vulnerabilities"`
}

func parseSUSE(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	cpe, err := susePlatform(config)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRecordBytes || !utf8.Valid(raw) {
		return nil, errors.New("feed: SUSE CSAF record exceeds limit or is not UTF-8")
	}
	var notice suseCSAF
	if err := json.Unmarshal(raw, &notice); err != nil {
		return nil, fmt.Errorf("feed: decode SUSE CSAF: %w", err)
	}
	d := &notice.Document
	if d.Version != "2.0" || d.Category != "csaf_security_advisory" || d.Tracking.Status != "final" || d.Publisher.Category != "vendor" || d.Publisher.Namespace != "https://www.suse.com/" || (!strings.HasPrefix(d.Tracking.ID, "SUSE-SU-") && !strings.HasPrefix(d.Tracking.ID, "openSUSE-SU-")) {
		return nil, errors.New("feed: unsupported SUSE CSAF document or publisher")
	}
	// GA-media notices enumerate accumulated fixes in a shipped package, not
	// the first fixed EVR. Treating that EVR as a vulnerability boundary would
	// mislabel earlier already-fixed builds as affected.
	if strings.Contains(strings.ToLower(d.Title), "on ga media") {
		return nil, errors.New("feed: SUSE GA-media notice does not establish a fixed-version boundary")
	}
	published, err := timestamp(d.Tracking.Published)
	if err != nil {
		return nil, err
	}
	if len(notice.Tree.FullProducts) != 0 || len(notice.Tree.Groups) != 0 || len(notice.Tree.Relationships) == 0 || len(notice.Vulnerabilities) == 0 {
		return nil, errors.New("feed: unsupported SUSE product groups or absent applicability")
	}
	if len(notice.Tree.Branches) != 1 || notice.Tree.Branches[0].Category != "vendor" {
		return nil, errors.New("feed: SUSE product tree requires one explicit vendor root")
	}
	products := make(map[string]suseProduct)
	arches := make(map[string]string)
	count := 0
	if err := suseProducts(notice.Tree.Branches, "", 0, products, arches, &count); err != nil {
		return nil, err
	}
	relations := make(map[string]suseRelationship, len(notice.Tree.Relationships))
	for _, relation := range notice.Tree.Relationships {
		_, componentOK := products[relation.Component]
		platform, platformOK := products[relation.Platform]
		_, duplicate := relations[relation.Product.ID]
		_, collides := products[relation.Product.ID]
		if relation.Category != "default_component_of" || relation.Product.ID == "" || !componentOK || !platformOK || platform.Helper.CPE == "" || arches[relation.Component] == "" || arches[relation.Platform] != "" || duplicate || collides {
			return nil, errors.New("feed: unsupported or unresolved SUSE product relationship")
		}
		relations[relation.Product.ID] = relation
	}
	cves := make(map[string][]string)
	for _, vulnerability := range notice.Vulnerabilities {
		if !validCVE(vulnerability.CVE) || len(vulnerability.Status) == 0 {
			return nil, errors.New("feed: SUSE vulnerability lacks CVE or product status")
		}
		fixes := make(map[string]bool)
		for _, remediation := range vulnerability.Remediations {
			if len(remediation.Groups) != 0 {
				return nil, errors.New("feed: SUSE remediation groups unsupported")
			}
			for _, id := range remediation.Products {
				if _, ok := relations[id]; !ok {
					return nil, errors.New("feed: unresolved SUSE remediation product")
				}
				if remediation.Category == "vendor_fix" {
					fixes[id] = true
				}
			}
		}
		for status, ids := range vulnerability.Status {
			if status != "recommended" && status != "fixed" && status != "first_fixed" {
				return nil, errors.New("feed: unsupported SUSE vulnerability status constraint")
			}
			for _, id := range ids {
				if _, ok := relations[id]; !ok || !fixes[id] {
					return nil, errors.New("feed: SUSE fixed product lacks explicit vendor remediation")
				}
				if !slices.Contains(cves[id], vulnerability.CVE) {
					cves[id] = append(cves[id], vulnerability.CVE)
				}
			}
		}
	}
	doc := &advisoryv1.FeedDocument{}
	// Preserve vendor relationship order for deterministic normalized records.
	for _, relation := range notice.Tree.Relationships {
		if products[relation.Platform].Helper.CPE != cpe || len(cves[relation.Product.ID]) == 0 {
			continue
		}
		pkg := products[relation.Component]
		arch := arches[pkg.ID]
		if arch == "src" || arch == "nosrc" || (arch != "noarch" && arch != canonicalArch(config.GetArchitecture())) {
			continue
		}
		name, evr, err := suseRPM(pkg, arch)
		if err != nil {
			return nil, err
		}
		slices.Sort(cves[relation.Product.ID])
		record := &advisoryv1.Advisory{Id: d.Tracking.ID, Cves: cves[relation.Product.ID], PackageName: name, Architecture: arch, FixedVersion: evr, Severity: d.Severity.Text, PublishedAt: published, SourceUrl: config.GetUrl()}
		if err := addRecord(doc, record, "rpm", validator); err != nil {
			return nil, err
		}
	}
	if len(doc.Advisories) == 0 {
		return nil, errors.New("feed: SUSE advisory does not establish configured product/release/architecture applicability")
	}
	// A single advisory is never evidence of complete product coverage.
	return doc, nil
}

func susePlatform(config *advisoryv1.FeedSource) (string, error) {
	switch canonicalArch(config.GetArchitecture()) {
	case "x86_64", "aarch64", "ppc64le", "s390x", "i586", "i686", "riscv64":
	default:
		return "", errors.New("feed: unsupported or missing SUSE architecture")
	}
	product, err := vendorProduct(config, platform.FeedSUSECSAF)
	if err != nil {
		return "", err
	}
	// Only the base product CPE, not SAP, Desktop, LTSS, modules or extensions.
	// SLES names its service pack explicitly in the configured major.SP release.
	cpe, servicePack := strings.CutSuffix(product.Advisory.Ecosystem, "spN")
	if !servicePack {
		return cpe, nil
	}
	_, sp, ok := strings.Cut(config.GetRelease(), ".")
	if !ok || !suseDigits(sp) {
		return "", errors.New("feed: SLES requires explicit major.service-pack release")
	}
	return cpe + "sp" + sp, nil
}

func suseDigits(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for i := range len(value) {
		if !digit(value[i]) {
			return false
		}
	}
	return true
}

func suseProducts(branches []suseBranch, arch string, depth int, products map[string]suseProduct, arches map[string]string, count *int) error {
	if depth > 8 {
		return errors.New("feed: SUSE product tree depth limit")
	}
	for _, branch := range branches {
		*count++
		if *count > maxEntries {
			return errors.New("feed: SUSE product tree entry limit")
		}
		nextArch := arch
		switch branch.Category {
		case "vendor":
			if depth != 0 || branch.Name != "SUSE" {
				return errors.New("feed: unsupported SUSE product vendor")
			}
		case "product_family":
		case "architecture":
			if arch != "" {
				return errors.New("feed: nested SUSE architecture constraint")
			}
			nextArch = branch.Name
		case "product_name", "product_version":
			if branch.Product == nil || len(branch.Branches) != 0 || (branch.Category == "product_version") != (arch != "") {
				return errors.New("feed: unsupported SUSE product leaf")
			}
		default:
			return errors.New("feed: unsupported SUSE product applicability criterion")
		}
		if branch.Product != nil {
			product := *branch.Product
			if product.ID == "" || product.Name != branch.Name {
				return errors.New("feed: invalid SUSE product identity")
			}
			if _, exists := products[product.ID]; exists {
				return errors.New("feed: duplicate SUSE product identity")
			}
			products[product.ID], arches[product.ID] = product, nextArch
		}
		if err := suseProducts(branch.Branches, nextArch, depth+1, products, arches, count); err != nil {
			return err
		}
	}
	return nil
}

func suseRPM(product suseProduct, arch string) (string, string, error) {
	purl, ok := strings.CutPrefix(product.Helper.PURL, "pkg:rpm/suse/")
	if !ok || strings.Contains(purl, "#") {
		return "", "", errors.New("feed: unsupported SUSE RPM package URL")
	}
	identity, query, ok := strings.Cut(purl, "?")
	name, version, versionOK := strings.Cut(identity, "@")
	qualifiers, err := url.ParseQuery(query)
	if !ok || !versionOK || err != nil || name == "" || strings.ContainsAny(name, "%/@") || qualifiers.Get(purlArch) != arch {
		return "", "", errors.New("feed: invalid SUSE RPM package identity")
	}
	for key, values := range qualifiers {
		if len(values) != 1 || (key != purlArch && key != "upstream" && key != "epoch") {
			return "", "", errors.New("feed: unsupported SUSE RPM qualifier")
		}
	}
	evr, ok := strings.CutPrefix(product.Name, name+"-")
	if !ok || !strings.HasSuffix(evr, "."+arch) {
		return "", "", errors.New("feed: SUSE package name disagrees with package URL")
	}
	evr = strings.TrimSuffix(evr, "."+arch)
	epoch, vr, ok := strings.Cut(evr, ":")
	decodedVersion, err := url.PathUnescape(version)
	if !ok || !suseDigits(epoch) || err != nil || vr != decodedVersion || (qualifiers.Has("epoch") && qualifiers.Get("epoch") != epoch) || !strings.Contains(vr, "-") {
		return "", "", errors.New("feed: SUSE RPM EVR disagrees with package URL")
	}
	return name, evr, nil
}
