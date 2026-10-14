// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

// Approved adoption of a package lindm did not install. dpkg and rpm keep no
// record of the repository a package came from, so the provider proves instead
// that the installed native records are those of the exact artifact that the
// approved source's authenticated metadata lists:
//
//   - APT: the InRelease of every approved suite is verified with the approved
//     key and APT checks each Packages index against it. The index must list the
//     installed name, architecture and version; that .deb is fetched and checked
//     against the index's SHA256. dpkg keeps no archive digest, so its control
//     fields, md5sums and conffile list must equal the installed dpkg records,
//     and dpkg --verify must find every installed non-conffile matching those
//     MD5 sums.
//   - DNF5: the authenticated (signed or release-pinned metalink) metadata must
//     list the exact NEVRA in an approved repository; that package, signed by
//     the approved key, must have the installed header's SHA256HEADER (which
//     binds its payload and file digests), and rpm --verify must find every
//     installed non-config file's size, digest and link target unchanged.
//
// Not proven: that this very artifact was the one unpacked (an identical
// rebuild is indistinguishable, and harmless); MD5 collision resistance;
// conffile contents (administrator configuration); maintainer-script side
// effects; or integrity against a root compromise that rewrote the package
// database. DNF4, zypper and pacman have no proof: their installed packages stay
// existing_package_unverified.

// errProvenanceUnproven is a definitive negative answer: the approved metadata
// does not list the installed package, or the installed records differ from
// the listed artifact. Preparation then records no proof rather than failing.
var errProvenanceUnproven = errors.New("packageprovider: installed provenance unproven")

func unproven(reason string) error {
	return fmt.Errorf("%w: %s", errProvenanceUnproven, reason)
}

func (p *Provider) canProveInstalledProvenance() bool {
	if p.rolling() {
		return false
	}
	switch p.ecosystem {
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		return true
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
		return p.manager == dnf.DNF5
	default:
		return false
	}
}

// needsInstalledProvenance reports whether acquiring this row must first prove
// the provenance of an installed package lindm did not install. Only presence is
// adopted: removing a package lindm did not install is never offered.
func (p *Provider) needsInstalledProvenance(desired *resourcev1.ResourceDesiredState, before *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) bool {
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		return false
	}
	o := before.GetNativePackage()
	return operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE &&
		desired.GetNativePackage().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT &&
		o.GetInstalled() && !o.GetRecord().GetProvenanceKnown() && p.canProveInstalledProvenance()
}

// applyInstalledProvenance records a proof's provenance on exactly the
// installation it proved: the same package, version and installed identity,
// from the desired approved repository. It reports whether it applied.
func applyInstalledProvenance(record *resourcev1.NativePackageRecord, proof *resourcev1.InstalledProvenanceProof, repository *resourcev1.ResourceRef) bool {
	if proof == nil || record == nil || record.GetProvenanceKnown() ||
		!proto.Equal(proof.GetPackage(), record.GetPackage()) || !proto.Equal(proof.GetVersion(), record.GetVersion()) ||
		!bytes.Equal(proof.GetNativeIdentitySha256(), record.GetNativeIdentitySha256()) || !proto.Equal(proof.GetSource(), repository) {
		return false
	}
	record.Source = proto.CloneOf(proof.GetSource())
	record.SignerSha256 = bytes.Clone(proof.GetSignerSha256())
	record.MetadataRevisionSha256 = bytes.Clone(proof.GetMetadataRevisionSha256())
	record.ProvenanceKnown = true
	return true
}

// provenFrom reports whether record carries exactly the provenance proof proved.
func provenFrom(record *resourcev1.NativePackageRecord, proof *resourcev1.InstalledProvenanceProof) bool {
	return record.GetProvenanceKnown() && proto.Equal(record.GetPackage(), proof.GetPackage()) && proto.Equal(record.GetVersion(), proof.GetVersion()) &&
		bytes.Equal(record.GetNativeIdentitySha256(), proof.GetNativeIdentitySha256()) && proto.Equal(record.GetSource(), proof.GetSource()) &&
		bytes.Equal(record.GetSignerSha256(), proof.GetSignerSha256()) && bytes.Equal(record.GetMetadataRevisionSha256(), proof.GetMetadataRevisionSha256())
}

// provenanceStep is PREPARE's afterRefresh step: when the request asks for it,
// it proves record's provenance into *proof. An unproven installation is a
// definitive answer, recorded as a manifest without proof; the provider then
// refuses it as existing_package_unverified.
func (p *Provider) provenanceStep(ctx context.Context, directory string, request *agentv1.NativePackageTransactionRequest, record *resourcev1.NativePackageRecord, proof **resourcev1.InstalledProvenanceProof) func() error {
	return func() error {
		if !request.GetProveInstalledProvenance() {
			return nil
		}
		if !p.canProveInstalledProvenance() || record == nil {
			return ErrConflict
		}
		proven, err := p.proveInstalledProvenance(ctx, directory, record, request.GetSource())
		if errors.Is(err, errProvenanceUnproven) {
			slog.Warn("installed package provenance unproven", "package", packageKey(record.GetPackage()), "reason", err.Error())
			return nil
		}
		*proof = proven
		return err
	}
}

// boundProof binds a proof to the signer and bound metadata revision of the
// source snapshot its manifest records.
func boundProof(proof *resourcev1.InstalledProvenanceProof, snapshot *resourcev1.RepositorySnapshot) *resourcev1.InstalledProvenanceProof {
	if proof != nil {
		proof.SignerSha256 = bytes.Clone(snapshot.GetSignerSha256()[0])
		proof.MetadataRevisionSha256 = bytes.Clone(snapshot.GetMetadataSha256())
	}
	return proof
}

// proveInstalledProvenance runs only in PREPARE, after the approved metadata
// refresh. record is the installed database row. The fetched artifact is
// evidence only: it never joins the transaction and is removed afterwards.
// The caller binds the signer and metadata revision of the bound snapshot.
func (p *Provider) proveInstalledProvenance(ctx context.Context, directory string, record *resourcev1.NativePackageRecord, source *agentv1.NativePackageSource) (_ *resourcev1.InstalledProvenanceProof, resultErr error) {
	identity, err := p.installedIdentity(ctx, record)
	if err != nil {
		return nil, err
	}
	scratch := filepath.Join(directory, "provenance")
	if err := os.RemoveAll(scratch); err != nil {
		return nil, err
	}
	if err := os.Mkdir(scratch, 0700); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(scratch)) }()
	var artifact *resourcev1.ArtifactRef
	var method resourcev1.InstalledProvenanceMethod
	switch {
	case !p.canProveInstalledProvenance():
		return nil, unproven("native backend cannot prove installed provenance")
	case p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		method = resourcev1.InstalledProvenanceMethod_INSTALLED_PROVENANCE_METHOD_DPKG_CONTROL
		artifact, err = p.proveDEB(ctx, directory, scratch, record)
	default:
		method = resourcev1.InstalledProvenanceMethod_INSTALLED_PROVENANCE_METHOD_RPM_HEADER
		artifact, err = p.proveRPM(ctx, directory, scratch, record, source)
	}
	if err != nil {
		return nil, err
	}
	again, err := p.installedIdentity(ctx, record)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(identity, again) {
		return nil, fmt.Errorf("%w: installed package changed during its provenance proof", ErrConflict)
	}
	return &resourcev1.InstalledProvenanceProof{Package: proto.CloneOf(record.GetPackage()), Version: proto.CloneOf(record.GetVersion()), Source: sourceRef(source), Artifact: artifact, Method: method, NativeIdentitySha256: identity}, nil
}

func (p *Provider) proveDEB(ctx context.Context, directory, scratch string, record *resourcev1.NativePackageRecord) (*resourcev1.ArtifactRef, error) {
	spec := nativeSpec(record.GetPackage(), ":") + "=" + record.GetVersion().GetDeb()
	shown, err := p.apt(ctx, directory, "/usr/bin/apt-cache", []string{"show", "--no-all-versions", spec})
	if err != nil {
		return nil, err
	}
	indexed, err := aptIndexedArtifact(shown.stdout, record)
	if err != nil {
		return nil, err
	}
	// apt-get download writes into its working directory: the private scratch.
	env := []string{"APT_CONFIG=" + filepath.Join(directory, "apt.conf")}
	uris, err := p.run(ctx, "/usr/bin/apt-get", append(aptOptions(directory), "--print-uris", "download", spec), scratch, env)
	if err != nil {
		return nil, err
	}
	declarations, declared, err := parseAPTDownloadDeclarations(uris.stdout)
	if err != nil {
		return nil, err
	}
	if len(declarations) != 1 {
		return nil, errors.New("packageprovider: approved archive declaration missing")
	}
	var file string
	for name, declaration := range declarations {
		if declaration.size != indexed.size || !bytes.Equal(declaration.sha256, indexed.sha256) {
			return nil, errors.New("packageprovider: approved archive declaration differs from its index")
		}
		file = name
	}
	if err := checkDownloadBudget(directory, declared, p.stagingMax); err != nil {
		return nil, err
	}
	if err := boundedDownload(ctx, directory, scratch, declarations, func(downloadContext context.Context) error {
		_, err := p.run(downloadContext, "/usr/bin/apt-get", append(aptOptions(directory), "download", spec), scratch, env)
		return err
	}); err != nil {
		return nil, err
	}
	path := filepath.Join(scratch, file)
	ref, err := artifactFor(path)
	if err != nil {
		return nil, err
	}
	if ref.GetSizeBytes() != indexed.size || !bytes.Equal(ref.GetSha256(), indexed.sha256) {
		return nil, errors.New("packageprovider: fetched archive differs from its authenticated index")
	}
	if err := p.debMatchesInstalled(ctx, dpkgRoot{}, path, record); err != nil {
		return nil, err
	}
	return ref, nil
}

// aptIndexedArtifact reads `apt-cache show --no-all-versions name:arch=version`.
// APT prints the index record when an approved suite lists the version and only
// the dpkg status record (no Filename or SHA256) when none does.
func aptIndexedArtifact(output []byte, record *resourcev1.NativePackageRecord) (downloadDeclaration, error) {
	fields := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimRight(string(output), "\n"), "\n") {
		if line == "" {
			return downloadDeclaration{}, errors.New("packageprovider: ambiguous APT version record")
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return downloadDeclaration{}, errors.New("packageprovider: malformed APT version record")
		}
		if _, duplicate := fields[key]; duplicate {
			return downloadDeclaration{}, errors.New("packageprovider: ambiguous APT version record")
		}
		fields[key] = strings.TrimSpace(value)
	}
	identity := record.GetPackage()
	if fields["Package"] != identity.GetNativeName() || fields["Version"] != record.GetVersion().GetDeb() || (fields["Architecture"] != "" && fields["Architecture"] != identity.GetArchitecture()) {
		return downloadDeclaration{}, errors.New("packageprovider: APT version record names another package")
	}
	if fields["Filename"] == "" || fields["SHA256"] == "" {
		return downloadDeclaration{}, unproven("installed version is not in the approved suites' signed indexes")
	}
	digest, err := hex.DecodeString(fields["SHA256"])
	if err != nil || len(digest) != 32 {
		return downloadDeclaration{}, errors.New("packageprovider: invalid indexed archive digest")
	}
	size, err := strconv.ParseUint(fields["Size"], 10, 64)
	if err != nil || size == 0 || size > 512<<20 {
		return downloadDeclaration{}, errors.New("packageprovider: invalid indexed archive size")
	}
	return downloadDeclaration{size: size, sha256: digest}, nil
}

// dpkgRoot names a dpkg database; the zero value is the device's own. Tests
// install real packages into a private root with dpkg itself.
type dpkgRoot struct{ admin, instdir string }

func (r dpkgRoot) query(args ...string) []string {
	if r.admin == "" {
		return args
	}
	return append([]string{"--admindir=" + r.admin}, args...)
}

func (r dpkgRoot) dpkg(args ...string) []string {
	if r.admin == "" {
		return args
	}
	return append([]string{"--root=" + r.instdir, "--admindir=" + r.admin}, args...)
}

// dpkgControlFormat renders the control fields the .deb carries, through the
// same dpkg field formatter for the archive (dpkg-deb) and the installed record
// (dpkg-query). Single-line fields cannot contain a newline and continuation
// lines start with a space, so the labelled lines are unambiguous.
const dpkgControlFormat = "Package:${Package}\nVersion:${Version}\nArchitecture:${Architecture}\nMulti-Arch:${Multi-Arch}\n" +
	"Essential:${Essential}\nProtected:${Protected}\nPriority:${Priority}\nSection:${Section}\nInstalled-Size:${Installed-Size}\n" +
	"Origin:${Origin}\nMaintainer:${Maintainer}\nOriginal-Maintainer:${Original-Maintainer}\nBugs:${Bugs}\nSource:${Source}\n" +
	"Homepage:${Homepage}\nBuilt-Using:${Built-Using}\nPre-Depends:${Pre-Depends}\nDepends:${Depends}\nRecommends:${Recommends}\n" +
	"Suggests:${Suggests}\nEnhances:${Enhances}\nBreaks:${Breaks}\nConflicts:${Conflicts}\nReplaces:${Replaces}\nProvides:${Provides}\n" +
	"Description:${Description}\n"

// debMatchesInstalled compares the authenticated archive with the installed
// dpkg records of record's package.
func (p *Provider) debMatchesInstalled(ctx context.Context, root dpkgRoot, archive string, record *resourcev1.NativePackageRecord) error {
	name := nativeSpec(record.GetPackage(), ":")
	query := func(args ...string) ([]byte, error) {
		result, err := p.run(ctx, "/usr/bin/dpkg-query", root.query(args...), "/", nil)
		if err != nil {
			return nil, err
		}
		if len(result.stderr) != 0 {
			return nil, unproven("dpkg-query warned about the installed package")
		}
		return result.stdout, nil
	}
	installed, err := query("--show", "--showformat="+dpkgControlFormat, name)
	if err != nil {
		return err
	}
	shipped, err := p.run(ctx, "/usr/bin/dpkg-deb", []string{"--show", "--showformat=" + dpkgControlFormat, archive}, "/", nil)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(installed, []byte("Package:"+record.GetPackage().GetNativeName()+"\nVersion:"+record.GetVersion().GetDeb()+"\nArchitecture:"+record.GetPackage().GetArchitecture()+"\n")) {
		return errors.New("packageprovider: installed dpkg record names another package")
	}
	if len(shipped.stderr) != 0 || !bytes.Equal(installed, shipped.stdout) {
		return unproven("installed control fields differ from the approved archive")
	}
	control, err := p.run(ctx, "/usr/bin/dpkg-deb", []string{"--ctrl-tarfile", archive}, "/", nil)
	if err != nil {
		return err
	}
	members, err := debControlMembers(control.stdout)
	if err != nil {
		return err
	}
	md5sums := members["md5sums"]
	if len(md5sums) == 0 {
		return unproven("approved archive ships no md5sums")
	}
	list, err := query("--control-list", name)
	if err != nil {
		return err
	}
	if !slices.Contains(strings.Split(strings.TrimSpace(string(list)), "\n"), "md5sums") {
		return unproven("installed package records no md5sums")
	}
	recorded, err := query("--control-show", name, "md5sums")
	if err != nil {
		return err
	}
	if !bytes.Equal(recorded, md5sums) {
		return unproven("installed md5sums differ from the approved archive")
	}
	status, err := query("--show", "--showformat=${Conffiles}", name)
	if err != nil {
		return err
	}
	if !slices.Equal(installedConffiles(status), shippedConffiles(members["conffiles"])) {
		return unproven("installed conffiles differ from the approved archive")
	}
	verified, err := p.run(ctx, "/usr/bin/dpkg", root.dpkg("--verify", name), "/", nil)
	if err != nil {
		return err
	}
	if len(verified.stderr) != 0 {
		return unproven("dpkg --verify warned about the installed package")
	}
	failures, err := nativeVerifyFailures(verified.stdout, false)
	if err != nil {
		return err
	}
	if len(failures) != 0 {
		return unproven("installed file " + strconv.Quote(failures[0]) + " differs from its recorded MD5 sum")
	}
	return nil
}

// debControlMembers reads the bounded control.tar of a .deb.
func debControlMembers(data []byte) (map[string][]byte, error) {
	members := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return members, nil
		}
		if err != nil {
			return nil, fmt.Errorf("packageprovider: approved archive control: %w", err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag != tar.TypeReg || (name != "control" && name != "md5sums" && name != "conffiles") {
			continue
		}
		if _, duplicate := members[name]; duplicate || header.Size > 16<<20 {
			return nil, errors.New("packageprovider: ambiguous approved archive control")
		}
		member, err := io.ReadAll(io.LimitReader(reader, header.Size))
		if err != nil {
			return nil, err
		}
		members[name] = member
	}
}

// shippedConffiles lists the conffiles a .deb installs; entries flagged
// remove-on-upgrade are removals, not installed files.
func shippedConffiles(data []byte) []string {
	var paths []string
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || slices.Contains(fields[:len(fields)-1], "remove-on-upgrade") {
			continue
		}
		paths = append(paths, fields[len(fields)-1])
	}
	slices.Sort(paths)
	return paths
}

// installedConffiles reads dpkg-query's ${Conffiles} (" path md5 [flags]");
// obsolete entries belong to an earlier version.
func installedConffiles(data []byte) []string {
	var paths []string
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || slices.Contains(fields[2:], "obsolete") || slices.Contains(fields[2:], "remove-on-upgrade") {
			continue
		}
		paths = append(paths, fields[0])
	}
	slices.Sort(paths)
	return paths
}

// nativeVerifyFailures parses dpkg --verify and rpm --verify output
// ("<flags> [<attribute>] <path>") and returns the paths whose content is not
// the package's own. Configuration files are the administrator's. dpkg only
// reports failed MD5 checks; for rpm a missing file or a size, digest or link
// target difference (or a digest it could not compute) counts, while mode,
// owner and time changes are metadata.
func nativeVerifyFailures(output []byte, rpm bool) ([]string, error) {
	var failures []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if line == "" {
			continue
		}
		flags, rest, ok := strings.Cut(line, " ")
		if !ok || (flags != "missing" && (len(flags) != 9 || strings.Trim(flags, "SM5DLUGTP.?") != "")) {
			return nil, errors.New("packageprovider: unrecognized native verify record")
		}
		rest = strings.TrimLeft(rest, " ")
		attribute := byte(' ')
		if !strings.HasPrefix(rest, "/") {
			if len(rest) < 3 || rest[1] != ' ' || rest[2] != '/' {
				return nil, errors.New("packageprovider: unrecognized native verify record")
			}
			attribute, rest = rest[0], rest[2:]
		}
		if attribute == 'c' {
			continue
		}
		if !rpm || flags == "missing" || strings.ContainsAny(flags, "S5L") || flags[2] == '?' {
			failures = append(failures, rest)
		}
	}
	return failures, nil
}

func (p *Provider) proveRPM(ctx context.Context, directory, scratch string, record *resourcev1.NativePackageRecord, source *agentv1.NativePackageSource) (*resourcev1.ArtifactRef, error) {
	identity := record.GetPackage()
	nevra := identity.GetNativeName() + "-" + nativeVersion(record.GetVersion()) + "." + identity.GetArchitecture()
	listed, err := p.dnf(ctx, directory, []string{"repoquery", "--available", "--queryformat=%{full_nevra}\t%{repoid}\t%{downloadsize}\t%{location}\n", nevra})
	if err != nil {
		return nil, err
	}
	file, size, err := dnfIndexedArtifact(listed.stdout, nevra, source.GetRepository().GetRpm())
	if err != nil {
		return nil, err
	}
	declarations := map[string]downloadDeclaration{file: {size: size}}
	if err := checkDownloadBudget(directory, size, p.stagingMax); err != nil {
		return nil, err
	}
	if err := boundedDownload(ctx, directory, scratch, declarations, func(downloadContext context.Context) error {
		_, err := p.dnf(downloadContext, directory, []string{"download", "--destdir=" + scratch, nevra})
		return err
	}); err != nil {
		return nil, err
	}
	path := filepath.Join(scratch, file)
	ref, err := artifactFor(path)
	if err != nil {
		return nil, err
	}
	if ref.GetSizeBytes() != size {
		return nil, errors.New("packageprovider: fetched RPM differs from its declared size")
	}
	signature, err := p.run(ctx, "/usr/bin/rpmkeys", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--checksig", "--verbose", path}, "/", nil)
	if checkRPMSignature(signature, err, source.GetRpmSigningKeyFingerprint()) != nil {
		return nil, unproven("approved key does not verify the repository package")
	}
	const format = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SHA256HEADER}\n"
	shipped, err := p.run(ctx, "/usr/bin/rpm", []string{"--query", "--package", "--queryformat", format, path}, "/", nil)
	if err != nil {
		return nil, err
	}
	spec := nativeSpec(identity, ".")
	installed, err := p.run(ctx, "/usr/bin/rpm", []string{"--query", "--queryformat", format, spec}, "/", nil)
	if err != nil {
		return nil, err
	}
	if err := rpmHeaderMatches(installed.stdout, shipped.stdout, record); err != nil {
		return nil, err
	}
	// rpm --verify exits nonzero for any reported difference, including
	// configuration files; its report, not its status, is the evidence.
	verified, err := p.run(ctx, "/usr/bin/rpm", []string{"--verify", "--nodeps", "--noscripts", spec}, "/", nil)
	if err != nil && len(verified.stdout) == 0 {
		return nil, err
	}
	failures, parseErr := nativeVerifyFailures(verified.stdout, true)
	if parseErr != nil {
		return nil, errors.Join(parseErr, err)
	}
	if len(failures) != 0 {
		return nil, unproven("installed file " + strconv.Quote(failures[0]) + " differs from its package header")
	}
	return ref, nil
}

// dnfIndexedArtifact reads repoquery over the approved repositories for one
// exact NEVRA. Several approved repositories may list the same package.
func dnfIndexedArtifact(output []byte, nevra string, rpm *resourcev1.RpmRepository) (string, uint64, error) {
	var file string
	var size uint64
	for line := range strings.SplitSeq(string(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || fields[0] != nevra || !dnfApprovedRepository(rpm, fields[1]) {
			return "", 0, errors.New("packageprovider: unexpected approved repository record")
		}
		n, err := strconv.ParseUint(fields[2], 10, 64)
		name := filepath.Base(fields[3])
		if err != nil || n == 0 || n > 512<<20 || !strings.HasSuffix(name, ".rpm") || name != strings.TrimSpace(name) {
			return "", 0, errors.New("packageprovider: invalid approved RPM declaration")
		}
		if file != "" && (file != name || size != n) {
			return "", 0, errors.New("packageprovider: approved repositories disagree on one NEVRA")
		}
		file, size = name, n
	}
	if file == "" {
		return "", 0, unproven("installed NEVRA is not in the approved repositories' metadata")
	}
	return file, size, nil
}

// rpmHeaderMatches compares single-row NAME/EPOCH/VERSION/RELEASE/ARCH and
// SHA256HEADER queries of the installed package and the approved artifact.
func rpmHeaderMatches(installed, shipped []byte, record *resourcev1.NativePackageRecord) error {
	row := strings.TrimSuffix(string(installed), "\n")
	fields := strings.Split(row, "\t")
	if len(fields) != 6 || strings.Contains(row, "\n") || fields[0] != record.GetPackage().GetNativeName() || fields[4] != record.GetPackage().GetArchitecture() {
		return errors.New("packageprovider: installed RPM header names another package")
	}
	version, err := rpmVersion(fields[1], fields[2], fields[3])
	if err != nil || !proto.Equal(version, record.GetVersion()) {
		return errors.New("packageprovider: installed RPM header names another version")
	}
	if digest, err := hex.DecodeString(fields[5]); err != nil || len(digest) != 32 {
		return unproven("installed RPM header has no SHA256HEADER")
	}
	if !bytes.Equal(installed, shipped) {
		return unproven("installed RPM header differs from the approved package")
	}
	return nil
}
