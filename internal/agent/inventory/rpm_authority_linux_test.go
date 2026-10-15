// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool"
	"lindm/internal/rpmauthority"
)

func rpmEvidenceLines(t *testing.T, fixtureName string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("../../rpmauthority/testdata/" + fixtureName + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ ImmutableHeader, Signature []byte }
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	identity, err := rpmauthority.Parse(f.ImmutableHeader)
	if err != nil {
		t.Fatal(err)
	}
	epoch, version, _ := strings.Cut(identity.Version, ":")
	dash := strings.LastIndexByte(version, '-')
	census := strings.Join([]string{identity.Name, epoch, version[:dash], version[dash+1:], identity.Architecture, "(none)"}, "\t")
	return census + "\n", census + "\t" + hex.EncodeToString(f.ImmutableHeader) + "\t" + hex.EncodeToString(f.Signature) + "\n"
}

func TestRPMNativeHeaderLargerThanCensusLineRemainsCollectable(t *testing.T) {
	census, evidence := rpmEvidenceLines(t, "bash")
	if len(evidence) <= maxLineBytes {
		t.Fatal("fixture does not exceed the census line bound")
	}
	run := func(_ context.Context, b backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if strings.Contains(strings.Join(b.args, " "), "HEADERIMMUTABLE") {
			return consume(strings.NewReader(evidence))
		}
		return consume(strings.NewReader(census))
	}
	out := collectPackages(t.Context(), map[string]string{"ID": "rhel", "VERSION_ID": "9.8"}, fixtureStat(fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: []byte("native db")}}), run, aptSources{})
	if out.Status != success || len(out.Packages) != 1 || out.Packages[0].RpmAuthority.GetStatus() != success {
		t.Fatalf("large native header erased census: %v", out)
	}
	if signer, reason := rpmauthority.Verify(out.Packages[0]); signer != rpmauthority.Fingerprint || reason != "" {
		t.Fatalf("export changed signed bytes: %q %q", signer, reason)
	}
}

func TestRPMAuthorityFailureDoesNotEraseSuccessfulCensus(t *testing.T) {
	census, evidence := rpmEvidenceLines(t, "bash")
	for _, failed := range []inventoryv1.CollectionStatus{capacity, commandFailure, unavailable, invalid} {
		t.Run(failed.String(), func(t *testing.T) {
			run := func(_ context.Context, b backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				if strings.Contains(strings.Join(b.args, " "), "HEADERIMMUTABLE") {
					return failed
				}
				return consume(strings.NewReader(census))
			}
			out := collectPackages(t.Context(), map[string]string{"ID": "rhel", "VERSION_ID": "9.8"}, fixtureStat(fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: []byte("native db")}}), run, aptSources{})
			if out.Status != success || len(out.Packages) != 1 || out.Packages[0].RpmAuthority.GetStatus() != failed || len(out.Packages[0].RpmAuthority.ImmutableHeader) != 0 {
				t.Fatalf("authority failure replaced complete census: %v", out)
			}
		})
	}
	packages, status := parsePackages(t.Context(), strings.NewReader(census), "rpm", parseLimits{maxRecords, maxOutputBytes})
	if status != success {
		t.Fatal(status)
	}
	run := func(_ context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return consume(strings.NewReader(evidence))
	}
	attachRpmAuthority(t.Context(), packages, run, int64(len(evidence)-1))
	if len(packages) != 1 || packages[0].RpmAuthority.Status != capacity || len(packages[0].RpmAuthority.ImmutableHeader) != 0 {
		t.Fatalf("evidence budget did not degrade independently: %v", packages)
	}
}

func TestRPMAuthorityCannotOverflowPackageUpload(t *testing.T) {
	if maxRpmPackageWire != spool.MaxBatchEncoded {
		t.Fatal("collector and spool package framing ceilings diverged")
	}
	census, evidence := rpmEvidenceLines(t, "bash")
	fields := strings.Split(strings.TrimSuffix(evidence, "\n"), "\t")
	fields[6] = hex.EncodeToString(bytes.Repeat([]byte{1}, maxRpmPackageWire))
	packages, status := parsePackages(t.Context(), strings.NewReader(census), "rpm", parseLimits{maxRecords, maxOutputBytes})
	if status != success {
		t.Fatal(status)
	}
	run := func(_ context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return consume(strings.NewReader(strings.Join(fields, "\t") + "\n"))
	}
	attachRpmAuthority(t.Context(), packages, run, maxOutputBytes)
	if len(packages) != 1 || packages[0].RpmAuthority.Status != capacity || proto.Size(&inventoryv1.PackageBatch{Packages: packages}) > spool.MaxBatchEncoded {
		t.Fatalf("oversized authority made inventory unuploadable: %v", packages)
	}
}

func TestRPMAuthorityJoinDoesNotTransferAcrossNativeIdentityChanges(t *testing.T) {
	census, evidence := rpmEvidenceLines(t, "dbus")
	packages, status := parsePackages(t.Context(), strings.NewReader(census), "rpm", parseLimits{maxRecords, maxOutputBytes})
	if status != success {
		t.Fatal(status)
	}
	packages[0].Version = "0:99-1.el9"
	run := func(_ context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return consume(strings.NewReader(evidence))
	}
	attachRpmAuthority(t.Context(), packages, run, maxOutputBytes)
	if packages[0].RpmAuthority.Status != unavailable {
		t.Fatal("RPMDB race transferred a signature to another installed version")
	}
}

func TestRPMHeaderProbeDoesNotRunForOtherPlatforms(t *testing.T) {
	census, _ := rpmEvidenceLines(t, "dbus")
	for _, release := range [][2]string{{"rhel", "8.10"}, {"fedora", "44"}, {"rocky", "9.8"}, {"almalinux", "10.2"}, {"sles", "15.7"}} {
		t.Run(release[0]+release[1], func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, b backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				calls++
				if strings.Contains(strings.Join(b.args, " "), "HEADERIMMUTABLE") {
					t.Fatal("unsupported platform incurred Red Hat authority collection")
				}
				return consume(strings.NewReader(census))
			}
			out := collectPackages(t.Context(), map[string]string{"ID": release[0], "VERSION_ID": release[1]}, fixtureStat(fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: []byte("native db")}}), run, aptSources{})
			if out.Status != success || calls != 1 || len(out.Packages) != 1 || out.Packages[0].GetRpmAuthority().GetStatus() != unavailable {
				t.Fatalf("ordinary RPM census changed: calls=%d observation=%v", calls, out)
			}
		})
	}
}

func TestRPMRetainedActualNativeStdoutFraming(t *testing.T) {
	// Captured from rpm4.18.2 -qp --queryformat using the identical eight
	// expressions, without binary format modifiers; provenance is in NOTICE.
	raw, err := os.ReadFile("testdata/rpm-authority-dracut9.txt")
	if err != nil {
		t.Fatal(err)
	}
	evidence := string(raw)
	fields := strings.Split(strings.TrimSuffix(evidence, "\n"), "\t")
	if strings.Count(evidence, "\n") != 1 || len(fields) != 8 {
		t.Fatal("native binary stdout is not one eight-field record")
	}
	query := strings.Join(rpmAuthorityBackend.args, " ")
	if strings.Contains(query, ":base64") || strings.Contains(query, ":json") || !strings.Contains(query, "%{HEADERIMMUTABLE}\t%{RSAHEADER}\n") {
		t.Fatal("native query no longer uses portable unwrapped BIN formatting")
	}
	census := strings.Join(fields[:6], "\t") + "\n"
	run := func(_ context.Context, b backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if strings.Contains(strings.Join(b.args, " "), "HEADERIMMUTABLE") {
			return consume(strings.NewReader(evidence))
		}
		return consume(strings.NewReader(census))
	}
	out := collectPackages(t.Context(), map[string]string{"ID": "rhel", "VERSION_ID": "9.8"}, fixtureStat(fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: []byte("native db")}}), run, aptSources{})
	if out.Status != success || len(out.Packages) != 1 {
		t.Fatalf("native framing erased census: %v", out)
	}
	p := out.Packages[0]
	if p.Name != "dracut" || p.SourceName != "dracut" {
		t.Fatalf("native source identity was not retained: %v", p)
	}
	if signer, reason := rpmauthority.Verify(p); signer != rpmauthority.Fingerprint || reason != "" {
		t.Fatalf("native BIN export changed authenticated bytes: %q %q", signer, reason)
	}
}

func TestRPMBadOptionalRecordDoesNotEraseOtherAuthority(t *testing.T) {
	census, evidence := rpmEvidenceLines(t, "dbus")
	oversizedCensus := strings.Replace(census, "dbus\t", "oversized\t", 1)
	malformedCensus := strings.Replace(census, "dbus\t", "malformed\t", 1)
	optional := strings.TrimSuffix(oversizedCensus, "\n") + "\t" + strings.Repeat("00", maxRpmAuthorityRecordBytes) + "\t(none)\n" +
		strings.TrimSuffix(malformedCensus, "\n") + "\tzz\t00\n" + evidence
	run := func(_ context.Context, b backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if strings.Contains(strings.Join(b.args, " "), "HEADERIMMUTABLE") {
			return consume(strings.NewReader(optional))
		}
		return consume(strings.NewReader(oversizedCensus + malformedCensus + census))
	}
	out := collectPackages(t.Context(), map[string]string{"ID": "rhel", "VERSION_ID": "9.8"}, fixtureStat(fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: []byte("native db")}}), run, aptSources{})
	if out.Status != success || len(out.Packages) != 3 {
		t.Fatalf("bad optional proof erased census: %v", out)
	}
	for _, p := range out.Packages {
		want := success
		if p.Name == "oversized" {
			want = capacity
		}
		if p.Name == "malformed" {
			want = invalid
		}
		if p.RpmAuthority.GetStatus() != want {
			t.Fatalf("%s authority=%v want=%v", p.Name, p.RpmAuthority.GetStatus(), want)
		}
		if p.Name == "dbus" {
			if signer, reason := rpmauthority.Verify(p); signer != rpmauthority.Fingerprint || reason != "" {
				t.Fatalf("another package erased valid proof: %q %q", signer, reason)
			}
		}
	}
}

func TestRPMAuthorityNativeRecordCompletionAndBudgets(t *testing.T) {
	_, evidence := rpmEvidenceLines(t, "dbus")
	for _, tc := range []struct {
		name, input string
		records     int
		bytes       int64
		want        inventoryv1.CollectionStatus
	}{
		{"incomplete", strings.TrimSuffix(evidence, "\n"), 1, maxOutputBytes, invalid},
		{"record-cap", evidence, 0, maxOutputBytes, capacity},
		{"byte-cap", evidence, 1, int64(len(evidence) - 1), capacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, status := parseRpmAuthority(t.Context(), strings.NewReader(tc.input), parseLimits{tc.records, tc.bytes}); status != tc.want || p != nil {
				t.Fatalf("incomplete/unbounded proof accepted: %v %v", p, status)
			}
		})
	}
}
