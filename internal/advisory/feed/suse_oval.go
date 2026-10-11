package feed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

type ovalTest struct {
	object, state, check string
	valid                bool
}
type ovalState struct {
	evr, operation, architectures string
	valid                         bool
}
type ovalIndex struct {
	tests   map[string]ovalTest
	objects map[string]string
	states  map[string]ovalState
}

func (x *ovalIndex) add(section string, n ovalNode) error {
	id := n.attr("id")
	if id == "" || len(id) > 256 {
		return errors.New("feed: OVAL native identity missing or oversized")
	}
	switch section {
	case "tests":
		if _, ok := x.tests[id]; ok || len(x.tests) >= ovalIndexLimit {
			return errors.New("feed: duplicate or excessive OVAL tests")
		}
		if len(n.child("object").attr("object_ref")) > 256 || len(n.child("state").attr("state_ref")) > 256 || len(n.attr("check")) > 32 {
			return errors.New("feed: oversized OVAL test reference")
		}
		x.tests[id] = ovalTest{object: n.child("object").attr("object_ref"), state: n.child("state").attr("state_ref"), check: n.attr("check"), valid: n.name.Space == ovalLinuxNS && n.name.Local == "rpminfo_test" && n.attributes("id", "version", "comment", "check") && len(n.children) == 2 && n.children[0].name.Space == ovalLinuxNS && n.children[0].name.Local == "object" && n.children[0].attributes("object_ref") && len(n.children[0].children) == 0 && n.children[1].name.Space == ovalLinuxNS && n.children[1].name.Local == "state" && n.children[1].attributes("state_ref") && len(n.children[1].children) == 0}
	case "objects":
		if _, ok := x.objects[id]; ok || len(x.objects) >= ovalIndexLimit {
			return errors.New("feed: duplicate or excessive OVAL objects")
		}
		name := n.child("name")
		if len(name.text) > 512 {
			return errors.New("feed: oversized OVAL package name")
		}
		value := ""
		if n.name.Space == ovalLinuxNS && n.name.Local == "rpminfo_object" && n.attributes("id", "version", "comment") && len(n.children) == 1 && name.name.Space == ovalLinuxNS && name.attributes() && len(name.children) == 0 {
			value = name.text
		}
		x.objects[id] = value
	case "states":
		if _, ok := x.states[id]; ok || len(x.states) >= ovalIndexLimit {
			return errors.New("feed: duplicate or excessive OVAL states")
		}
		evr, arch := n.child("evr"), n.child("arch")
		if len(evr.text) > 2048 || len(arch.text) > 4096 || len(evr.attr("operation")) > 32 {
			return errors.New("feed: oversized OVAL state")
		}
		valid := n.name.Space == ovalLinuxNS && n.name.Local == "rpminfo_state" && n.attributes("id", "version", "comment") && evr.name.Space == ovalLinuxNS && evr.attributes("datatype", "operation") && evr.attr("datatype") == "evr_string" && len(evr.children) == 0
		if arch.name.Local != "" {
			valid = valid && len(n.children) == 2 && arch.name.Space == ovalLinuxNS && arch.attributes("datatype", "operation") && arch.attr("datatype") == "string" && arch.attr("operation") == "pattern match" && len(arch.children) == 0
		} else {
			valid = valid && len(n.children) == 1
		}
		x.states[id] = ovalState{evr: evr.text, operation: evr.attr("operation"), architectures: arch.text, valid: valid}
	default:
		return errors.New("feed: unsupported OVAL index section")
	}
	return nil
}

func (x *ovalIndex) resolve(n ovalNode) (string, ovalTest, ovalState, error) {
	t := x.tests[n.attr("test_ref")]
	s := x.states[t.state]
	name := x.objects[t.object]
	if n.name.Space != ovalNS || n.name.Local != "criterion" || !n.attributes("test_ref", "comment") || len(n.children) != 0 || !t.valid || !s.valid || name == "" || (t.check != "at least one" && t.check != "all") {
		return "", t, s, errors.New("feed: unsupported or unresolved OVAL package criterion")
	}
	if _, err := Compare("rpm", s.evr, s.evr); err != nil {
		return "", t, s, err
	}
	return name, t, s, nil
}

func ovalArchitectures(pattern string) ([]string, error) {
	if pattern == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pattern, "(") || !strings.HasSuffix(pattern, ")") {
		return nil, errors.New("feed: unsupported OVAL architecture pattern")
	}
	arches := strings.Split(pattern[1:len(pattern)-1], "|")
	for i, arch := range arches {
		if arch == "" || strings.ContainsAny(arch, "^$.*+?()[]{}\\") || slices.Contains(arches[:i], arch) {
			return nil, errors.New("feed: unsupported OVAL architecture alternative")
		}
	}
	return arches, nil
}

func ovalSnapshot(n ovalNode) (*timestamppb.Timestamp, error) {
	stamp := n.child("timestamp")
	if n.child("schema_version").text != "5.5" || stamp.name.Space != ovalCommonNS {
		return nil, errors.New("feed: unsupported OVAL generator")
	}
	at, err := time.Parse(time.RFC3339, stamp.text)
	if err != nil {
		at, err = time.Parse("2006-01-02T15:04:05", stamp.text)
		if err != nil {
			return nil, fmt.Errorf("feed: invalid OVAL generation time: %w", err)
		}
		// SUSE omits the offset. Use the earliest possible UTC instant, not
		// a guessed local zone or fetch time, so freshness cannot be extended.
		at = at.Add(-14 * time.Hour)
	}
	return timestamppb.New(at), nil
}

func parseSUSEOVAL(ctx context.Context, config *advisoryv1.FeedSource, file *os.File, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
	product, err := vendorProduct(config, platform.FeedSUSEOVAL)
	if err != nil {
		return nil, err
	}
	if product.Advisory.OVALPlatform == "" || product.Advisory.OVALReleasePackage == "" || !slices.Contains(product.Architectures, canonicalArch(config.GetArchitecture())) {
		return nil, errors.New("feed: OVAL product or architecture unavailable")
	}
	x := ovalIndex{tests: make(map[string]ovalTest), objects: make(map[string]string), states: make(map[string]ovalState)}
	doc := &advisoryv1.FeedDocument{}
	if err := walkOVAL(ctx, file, false, func(section string, n ovalNode) error {
		switch section {
		case "generator":
			var err error
			doc.SnapshotAt, err = ovalSnapshot(n)
			return err
		default:
			return x.add(section, n)
		}
	}); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var claims uint64
	err = walkOVAL(ctx, file, true, func(section string, n ovalNode) error {
		if section != "definitions" {
			return nil
		}
		if seen[n.attr("id")] || len(seen) >= ovalIndexLimit {
			return errors.New("feed: duplicate or excessive OVAL definitions")
		}
		seen[n.attr("id")] = true
		if err := x.definition(config, product, n, validator, func(a *advisoryv1.Advisory) error {
			claims++
			if claims > totalClaimsLimit(config) {
				return errors.New("feed: total claims limit exceeded")
			}
			return emit(a)
		}); err != nil {
			return fmt.Errorf("feed: OVAL definition %s: %w", n.attr("id"), err)
		}
		return markProgress(progress)
	})
	if err != nil {
		return nil, err
	}
	if claims == 0 || doc.SnapshotAt == nil {
		return nil, errors.New("feed: OVAL contains no applicable claims or generation time")
	}
	// A vulnerability export is not authority for arbitrary third-party or
	// historical rolling packages. Missing CVEs always remain partial coverage.
	return doc, nil
}

func (x *ovalIndex) definition(config *advisoryv1.FeedSource, product *platform.Release, n ovalNode, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) error {
	if n.name.Space != ovalNS || n.name.Local != "definition" || !n.attributes("id", "version", "class") || n.attr("id") == "" || n.attr("class") != "vulnerability" || len(n.children) != 2 {
		return errors.New("unsupported definition")
	}
	meta, criteria := n.child("metadata"), n.child("criteria")
	cve := meta.child("title").text
	affected, advisory := meta.child("affected"), meta.child("advisory")
	cpes := advisory.child("affected_cpe_list")
	if !validCVE(cve) || meta.name.Space != ovalNS || affected.name.Space != ovalNS || !affected.attributes("family") || affected.attr("family") != "unix" || len(affected.children) != 1 || affected.child("platform").name.Space != ovalNS || affected.child("platform").text != product.Advisory.OVALPlatform || advisory.name.Space != ovalNS || cpes.name.Space != ovalNS || len(cpes.children) != 1 || cpes.child("cpe").name.Space != ovalNS || cpes.child("cpe").text != product.Advisory.Ecosystem {
		return errors.New("foreign or ambiguous product metadata")
	}
	if criteria.name.Space != ovalNS || !criteria.attributes("operator", "comment") || criteria.attr("operator") != "AND" || len(criteria.children) != 2 {
		return errors.New("unsupported product conjunction")
	}
	prerequisite, test, state, err := x.resolve(criteria.children[0])
	if err != nil {
		return err
	}
	if prerequisite != product.Advisory.OVALReleasePackage || test.check != "at least one" || state.operation != "greater than or equal" || state.architectures != "" {
		return errors.New("unsupported installed-product prerequisite")
	}
	packages := criteria.children[1:]
	if packages[0].name.Local == "criteria" {
		group := packages[0]
		if group.name.Space != ovalNS || !group.attributes("operator", "comment") || group.attr("operator") != "OR" || len(group.children) == 0 {
			return errors.New("unsupported package disjunction")
		}
		packages = group.children
	}
	date, err := time.Parse("2006-01-02", advisory.child("issued").attr("date"))
	if err != nil {
		return errors.New("invalid vendor issue date")
	}
	for _, criterion := range packages {
		name, test, pkgState, err := x.resolve(criterion)
		if err != nil {
			return err
		}
		if pkgState.operation != "less than" {
			return errors.New("unsupported package version predicate")
		}
		arches, err := ovalArchitectures(pkgState.architectures)
		if err != nil {
			return err
		}
		// Preserve every architecture alternative for check=all. SQL must not
		// collapse the vendor's AND over installed instances into a per-row OR.
		if len(arches) == 0 {
			arches = []string{""}
		}
		for _, arch := range arches {
			if arch != "" && arch != "noarch" && arch != canonicalArch(config.GetArchitecture()) {
				continue
			}
			a := &advisoryv1.Advisory{Id: n.attr("id"), Cves: []string{cve}, PackageName: name, Architecture: arch, FixedVersion: pkgState.evr, Severity: normalizeSeverity(advisory.child("severity").text), PublishedAt: timestamppb.New(date), SourceUrl: config.GetUrl(), PrerequisitePackage: prerequisite, PrerequisiteMinVersion: state.evr, AllInstalledInstances: test.check == "all"}
			if test.check == "all" && pkgState.architectures != "" {
				a.InstanceArchitectures = arches
			}
			if err := validator.Validate(a); err != nil {
				return err
			}
			if err := emit(a); err != nil {
				return err
			}
		}
	}
	return nil
}
