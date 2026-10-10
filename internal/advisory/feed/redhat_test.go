package feed

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func redHatSource(release, stream string) *advisoryv1.FeedSource {
	return &advisoryv1.FeedSource{Id: "redhat", Distro: "rhel", Release: release, PlatformStream: stream, Architecture: "x86_64", Url: "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_6783.json", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, MaxAgeSeconds: 604800}
}

func redHatValidator(t *testing.T) protovalidate.Validator {
	t.Helper()
	v, err := protovalidate.New(protovalidate.WithMessages(&advisoryv1.FeedSource{}, &advisoryv1.Advisory{}))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func redHatFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/redhat-" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func redHatRecord(t *testing.T, doc *advisoryv1.FeedDocument, name, cve, module string, source bool) *advisoryv1.Advisory {
	t.Helper()
	for _, record := range doc.Advisories {
		if record.PackageName == name && record.SourcePackage == source && record.ModuleStream == module && len(record.Cves) == 1 && record.Cves[0] == cve {
			return record
		}
	}
	t.Fatalf("missing normalized %s / %s / module %s / source %t", name, cve, module, source)
	return nil
}

func TestRedHatGenuineBackportAndMAINVariant(t *testing.T) {
	raw := redHatFixture(t, "rhsa-2024_6783")
	v := redHatValidator(t)
	// MAIN.EUS is a mainstream product variant. Its normative CPE covers
	// RHEL 9 standard, including later minor releases, not EUS by suffix.
	for _, release := range []string{"9", "9.4", "9.8"} {
		t.Run(release, func(t *testing.T) {
			doc, err := parseRedHat(redHatSource(release, "standard"), raw, v)
			if err != nil {
				t.Fatal(err)
			}
			r := redHatRecord(t, doc, "openssl-libs", "CVE-2024-6119", "", false)
			if r.FixedVersion != "1:3.0.7-28.el9_4" || r.Architecture != "x86_64" || r.PlatformRelease != release || r.PlatformStream != "standard" || doc.CompleteSnapshot {
				t.Fatalf("incorrect backport/product binding: %v", r)
			}
			for _, test := range []struct {
				installed string
				affected  bool
			}{
				{"1:3.0.7-27.el9_4", true},
				{"1:3.0.7-28.el9_4", false},
				{"1:3.0.7-29.el9_4", false},
			} {
				cmp, err := Compare("rpm", test.installed, r.FixedVersion)
				if err != nil || (cmp < 0) != test.affected {
					t.Fatalf("backport comparison %s: %d, %v", test.installed, cmp, err)
				}
			}
		})
	}
	for _, config := range []*advisoryv1.FeedSource{redHatSource("8.4", "standard"), redHatSource("9.4", "eus"), redHatSource("9.4", "e4s")} {
		if _, err := parseRedHat(config, raw, v); !errors.Is(err, errRedHatNotApplicable) {
			t.Fatalf("mismatched product %s/%s accepted: %v", config.Release, config.PlatformStream, err)
		}
	}
	for _, distro := range []string{"rocky", "almalinux", "fedora", "sles"} {
		config := redHatSource("9.4", "standard")
		config.Distro = distro
		if _, err := parseRedHat(config, raw, v); err == nil {
			t.Fatalf("compatible distro %s inherited RHEL authority", distro)
		}
	}
}

func TestRedHatGenuineExtendedStreamsAndModules(t *testing.T) {
	v := redHatValidator(t)
	for _, test := range []struct {
		fixture, release, stream, name, cve, fixed, module string
	}{
		{"rhsa-2024_7846", "8.6", "e4s", "openssl-libs", "CVE-2024-5535", "1:1.1.1k-14.el8_6", ""},
		{"rhsa-2024_1880", "8.8", "eus", "nodejs", "CVE-2023-46809", "1:18.19.1-1.module+el8.8.0+21592+14a8b93e", "18"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			raw := redHatFixture(t, test.fixture)
			doc, err := parseRedHat(redHatSource(test.release, test.stream), raw, v)
			if err != nil {
				t.Fatal(err)
			}
			r := redHatRecord(t, doc, test.name, test.cve, test.module, false)
			if r.FixedVersion != test.fixed || r.PlatformStream != test.stream || r.PlatformRelease != test.release || (test.module != "" && r.ModuleName != "nodejs") {
				t.Fatalf("lost native stream/module metadata: %v", r)
			}
			for _, config := range []*advisoryv1.FeedSource{redHatSource("8.7", test.stream), redHatSource(test.release, "standard"), redHatSource("9.8", test.stream)} {
				if _, err := parseRedHat(config, raw, v); !errors.Is(err, errRedHatNotApplicable) {
					t.Fatalf("wrong minor/stream/major accepted: %v, %v", config, err)
				}
			}
		})
	}
}

func TestRedHatGenuineVEXFixedAndNotAffected(t *testing.T) {
	v := redHatValidator(t)
	doc, err := parseRedHat(redHatSource("9.4", "standard"), redHatFixture(t, "cve-2024-6119"), v)
	if err != nil {
		t.Fatal(err)
	}
	fixed := redHatRecord(t, doc, "openssl-libs", "CVE-2024-6119", "", false)
	if fixed.FixedVersion != "1:3.0.7-28.el9_4" || fixed.AssessmentUnknown || fixed.NotAffected {
		t.Fatalf("VEX fix lost: %v", fixed)
	}
	notAffected := redHatRecord(t, doc, "compat-openssl11", "CVE-2024-6119", "", false)
	if !notAffected.NotAffected || notAffected.AssessmentUnknown || notAffected.FixedVersion != "" {
		t.Fatalf("VEX not-affected became vulnerable: %v", notAffected)
	}
	for _, r := range doc.Advisories {
		if strings.Contains(r.PackageName, "container") || strings.Contains(r.PackageName, "openshift") || strings.Contains(r.PackageName, "ubi") || strings.Contains(r.PackageName, "jboss") {
			t.Fatalf("non-host content leaked into RHEL assessment: %v", r)
		}
	}
	doc, err = parseRedHat(redHatSource("8.8", "eus"), redHatFixture(t, "cve-2024-21892"), v)
	if err != nil {
		t.Fatal(err)
	}
	node := redHatRecord(t, doc, "nodejs", "CVE-2024-21892", "18", false)
	if node.FixedVersion != "1:18.19.1-1.module+el8.8.0+21592+14a8b93e" || node.ModuleName != "nodejs" {
		t.Fatalf("VEX module fix lost: %v", node)
	}
	// The same package in another stream must not inherit the nodejs:18 fix.
	for _, r := range doc.Advisories {
		if r.ModuleStream == "16" && r.FixedVersion == node.FixedVersion {
			t.Fatalf("fix crossed module stream: %v", r)
		}
	}
}

func TestRedHatVEXBareStatusReconciledWithBackport(t *testing.T) {
	v := redHatValidator(t)
	var notice suseCSAF
	if err := json.Unmarshal(redHatFixture(t, "cve-2024-6119"), &notice); err != nil {
		t.Fatal(err)
	}
	// Derived mutations model legacy VEX documents retaining a bare affected
	// product alongside exact fixed RPMs. Original vendor fixtures stay intact.
	id := "red_hat_enterprise_linux_9:openssl-libs"
	var relation suseRelationship
	relation.Category = "default_component_of"
	relation.Component, relation.Platform = "openssl-libs", "red_hat_enterprise_linux_9"
	relation.Product.ID = id
	found := false
	for _, existing := range notice.Tree.Relationships {
		found = found || existing.Product.ID == id
	}
	if !found {
		notice.Tree.Relationships = append(notice.Tree.Relationships, relation)
	}
	for _, status := range []string{"known_affected", "under_investigation"} {
		t.Run(status, func(t *testing.T) {
			notice.Vulnerabilities[0].Status[status] = append(notice.Vulnerabilities[0].Status[status], id)
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := parseRedHat(redHatSource("9.8", "standard"), raw, v)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range doc.Advisories {
				if r.PackageName == "openssl-libs" && !r.SourcePackage && (r.FixedVersion == "" || r.AssessmentUnknown) {
					t.Fatalf("bare status overrides backported fix: %v", r)
				}
			}
			// The standard fix is not transferable to an EUS stream. Keep its
			// broad status explicitly uncertain, rather than unbounded affected.
			doc, err = parseRedHat(redHatSource("9.2", "eus"), raw, v)
			if err != nil {
				t.Fatal(err)
			}
			r := redHatRecord(t, doc, "openssl-libs", "CVE-2024-6119", "", false)
			if !r.AssessmentUnknown || r.FixedVersion != "" {
				t.Fatalf("ambiguous mainstream status misapplied to EUS: %v", r)
			}
		})
	}
}

func TestRedHatRejectsAmbiguousRPMAndPlatformEvidence(t *testing.T) {
	v := redHatValidator(t)
	raw := redHatFixture(t, "rhsa-2024_6783")
	for _, test := range []struct {
		name string
		edit func(*suseCSAF)
	}{
		{"publisher", func(n *suseCSAF) { n.Document.Publisher.Namespace = "https://example.com" }},
		{"relationship", func(n *suseCSAF) { n.Tree.Relationships[0].Category = "installed_on" }},
		{"status", func(n *suseCSAF) {
			n.Vulnerabilities[0].Status["first_affected"] = []string{n.Tree.Relationships[0].Product.ID}
		}},
		{"duplicate", func(n *suseCSAF) { n.Tree.Branches = append(n.Tree.Branches, n.Tree.Branches[0]) }},
		{"duplicate-relevant-products", func(n *suseCSAF) {
			root := &n.Tree.Branches[0]
			root.Branches = append(root.Branches, root.Branches...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(raw, &notice); err != nil {
				t.Fatal(err)
			}
			test.edit(&notice)
			changed, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseRedHat(redHatSource("9.4", "standard"), changed, v); err == nil {
				t.Fatal("ambiguous authority accepted")
			}
		})
	}
	var pkg suseProduct
	pkg.Name = "openssl-1:3.0.7-28.el9_4.x86_64"
	pkg.Helper.PURL = "pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&epoch=1"
	for _, purl := range []string{
		"pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=aarch64&epoch=1",
		"pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&epoch=2",
		"pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&arch=aarch64&epoch=1",
		"pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&epoch=1&rpmmod=nodejs:20",
	} {
		pkg.Helper.PURL = purl
		if _, err := redHatPackage(redHatProduct{product: pkg, arch: "x86_64"}); err == nil {
			t.Fatalf("conflicting native identity accepted: %s", purl)
		}
	}
	for _, cpe := range []string{"cpe:/a:redhat:jboss_enterprise_application_platform:9", "cpe:/a:redhat:universal_base_image:9", "cpe:/o:redhat:enterprise_linux:10.0", "cpe:/o:redhat:rhel_eus:9.2::baseos"} {
		var platform suseProduct
		platform.Helper.CPE = cpe
		if applies, _ := redHatPlatform(redHatSource("9.4", "standard"), platform, "fixed"); applies {
			t.Fatalf("foreign CPE applies: %s", cpe)
		}
	}
}

func TestRedHatArchiveBoundsAndPartialCoverage(t *testing.T) {
	v := redHatValidator(t)
	encode := func(name string, kind byte, raw []byte) []byte {
		t.Helper()
		var packed bytes.Buffer
		tarWriter := tar.NewWriter(&packed)
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Mode: 0600, Size: int64(len(raw))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := tarWriter.Close(); err != nil {
			t.Fatal(err)
		}
		compressor, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}
		compressed := compressor.EncodeAll(packed.Bytes(), nil)
		if err := compressor.Close(); err != nil {
			t.Fatal(err)
		}
		return compressed
	}
	raw := redHatFixture(t, "rhsa-2024_6783")
	archive := encode("2024/rhsa-2024_6783.json", tar.TypeReg, raw)
	doc, err := parseRedHatArchive(context.Background(), redHatSource("9.4", "standard"), bytes.NewReader(archive), v)
	if err != nil || len(doc.GetAdvisories()) == 0 || doc.GetCompleteSnapshot() {
		t.Fatalf("archive normalization: %v / %v", doc, err)
	}
	for _, name := range []string{"../outside.json", "/absolute.json", "2024/notice.exe"} {
		if _, err := parseRedHatArchive(context.Background(), redHatSource("9.4", "standard"), bytes.NewReader(encode(name, tar.TypeReg, raw)), v); err == nil {
			t.Fatalf("unsafe archive member accepted: %s", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseRedHatArchive(ctx, redHatSource("9.4", "standard"), bytes.NewReader(archive), v); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled archive ingestion: %v", err)
	}
	if _, err := parseRedHatArchive(context.Background(), redHatSource("9.4", "standard"), bytes.NewReader(archive[:len(archive)/2]), v); err == nil {
		t.Fatal("truncated compressed snapshot accepted")
	}
	if _, err := parseRedHatArchive(context.Background(), redHatSource("9.4", "standard"), bytes.NewReader(encode("link.json", tar.TypeSymlink, nil)), v); err == nil {
		t.Fatal("archive symlink accepted")
	}
}

func TestRedHatFixturePins(t *testing.T) {
	for name, pin := range map[string]string{
		"rhsa-2024_6783": "a1b1b6751e159378b0ccf5a96c3e4ccee2d36e36dfd5de156e479a72274cbe92",
		"cve-2024-6119":  "a488c851437a9eb0616c3103787e1372e9cac1f3f7ea79ab2cadc7336c8f91be",
		"rhsa-2024_7846": "2aa634dc4055d4966b63f5389bfbd46f0c554ba6abff9e994e4da660c14b8388",
		"rhsa-2024_1880": "10fc03ff1284b4de59d03761b1d573c6028184b9ce1f7882554937c05be844bf",
		"cve-2024-21892": "01061605d2ea43fe8c982e1e0a5092ee59edcc84ef52cad1c1de594f22dc43a8",
	} {
		digest := sha256.Sum256(redHatFixture(t, name))
		if hex.EncodeToString(digest[:]) != pin {
			t.Fatalf("genuine vendor fixture changed: %s", name)
		}
	}
}

func TestRedHatDeclaredModuleRelationship(t *testing.T) {
	var notice suseCSAF
	if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_1880"), &notice); err != nil {
		t.Fatal(err)
	}
	var module suseProduct
	module.ID = "nodejs:18:8080020240322102042:63b34585"
	module.Name = module.ID
	notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: module.Name, Product: &module})
	var relation suseRelationship
	relation.Category = "default_component_of"
	relation.Component = module.ID
	relation.Platform = notice.Tree.Relationships[0].Platform
	relation.Product.ID = "declared-nodejs-module-product"
	for i := range notice.Tree.Relationships {
		notice.Tree.Relationships[i].Platform = relation.Product.ID
	}
	notice.Tree.Relationships = append(notice.Tree.Relationships, relation)
	v := redHatValidator(t)
	raw, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseRedHat(redHatSource("8.8", "eus"), raw, v)
	if err != nil {
		t.Fatal(err)
	}
	record := redHatRecord(t, doc, "nodejs", "CVE-2023-46809", "18", false)
	if record.ModuleName != "nodejs" {
		t.Fatalf("module relationship lost: %v", record)
	}
	module.ID, module.Name = "nodejs:20:8080020240322102042:63b34585", "nodejs:20:8080020240322102042:63b34585"
	notice.Tree.Branches[0].Branches[len(notice.Tree.Branches[0].Branches)-1].Name = module.Name
	notice.Tree.Relationships[len(notice.Tree.Relationships)-1].Component = module.ID
	raw, err = json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRedHat(redHatSource("8.8", "eus"), raw, v); err == nil {
		t.Fatal("module relationship conflicts with native RPM module but was accepted")
	}
}

func TestRedHatOffScopeProductsDoNotPoisonHostCorpus(t *testing.T) {
	var notice suseCSAF
	if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_6783"), &notice); err != nil {
		t.Fatal(err)
	}
	var foreign suseProduct
	foreign.ID, foreign.Name = "layered-jboss", "Red Hat JBoss"
	foreign.Helper.CPE = "cpe:/a:redhat:jboss_enterprise_application_platform:9"
	notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_name", Name: foreign.Name, Product: &foreign})
	var relation suseRelationship
	relation.Category = "installed_on"
	relation.Component = notice.Tree.Relationships[0].Component
	relation.Platform = foreign.ID
	relation.Product.ID = "jboss-component"
	notice.Tree.Relationships = append(notice.Tree.Relationships, relation)
	notice.Vulnerabilities[0].Status["first_affected"] = []string{relation.Product.ID}
	notice.Vulnerabilities[0].Status["known_affected"] = []string{relation.Product.ID}
	raw, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseRedHat(redHatSource("9.4", "standard"), raw, redHatValidator(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Advisories {
		if r.FixedVersion == "" {
			t.Fatalf("off-scope unfixed product became host evidence: %v", r)
		}
		if !r.SourcePackage && r.Architecture != "x86_64" && r.Architecture != "noarch" {
			t.Fatalf("host record crossed architecture: %v", r)
		}
	}
}
