// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lindm/internal/custody"

	"github.com/ProtonMail/go-crypto/openpgp"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/config"
	"lindm/internal/agent/dnf"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/rhsm"
	"lindm/internal/platform"
)

type dnfRPM struct {
	NEVRA       string `json:"nevra"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	RepoID      string `json:"repo_id"`
	PackagePath string `json:"package_path,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
}
type dnfTransaction struct {
	Version      string            `json:"version"`
	RPMs         []dnfRPM          `json:"rpms"`
	Groups       []json.RawMessage `json:"groups,omitempty"`
	Environments []json.RawMessage `json:"environments,omitempty"`
}

func parseDNFTransaction(data []byte) (*dnfTransaction, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var transaction dnfTransaction
	if err := decoder.Decode(&transaction); err != nil {
		return nil, fmt.Errorf("packageprovider: DNF manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("packageprovider: trailing DNF transaction data")
	}
	if transaction.Version != "1.0" || len(transaction.Groups) != 0 || len(transaction.Environments) != 0 || len(transaction.RPMs) > 8192 {
		return nil, errors.New("packageprovider: unsupported DNF transaction shape")
	}
	return &transaction, nil
}

func (p *Provider) dnf(ctx context.Context, directory string, args []string) (nativeResult, error) {
	return p.run(ctx, p.managerPath, p.dnfArgs(directory, args), "/", nil)
}

func (p *Provider) dnfArgs(directory string, args []string) []string {
	fixed := []string{"--config=" + filepath.Join(directory, "dnf.conf"), "--setopt=reposdir=" + filepath.Join(directory, "repos"), "--setopt=cachedir=" + filepath.Join(directory, "cache"), "--setopt=logdir=" + filepath.Join(directory, "log"), "--setopt=system_cachedir=" + filepath.Join(directory, "cache"), "--setopt=plugins=false", "--setopt=install_weak_deps=false", "--setopt=clean_requirements_on_remove=false", "--setopt=keepcache=true", "--setopt=skip_if_unavailable=false", "--setopt=best=true", "--setopt=localpkg_gpgcheck=true", "--setopt=tsflags=", "--assumeyes"}
	return append(fixed, args...)
}
func (p *Provider) prepareDNF(ctx context.Context, directory string, source *agentv1.NativePackageSource) ([]byte, error) {
	rpm := source.GetRepository().GetRpm()
	if rpm == nil {
		return nil, ErrUnsupported
	}
	for _, name := range []string{"repos", "cache", "log", "rpmkeys"} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
			return nil, err
		}
	}
	main := "[main]\nplugins=False\ngpgcheck=True\nrepo_gpgcheck=True\nlocalpkg_gpgcheck=True\n"
	if !rpm.GetRequireMetadataSignature() {
		main = "[main]\nplugins=False\ngpgcheck=True\nrepo_gpgcheck=False\nlocalpkg_gpgcheck=True\n"
	}
	if err := atomicFile(filepath.Join(directory, "dnf.conf"), []byte(main), 0600); err != nil {
		return nil, err
	}
	key, err := custody.ReadRoot(source.GetSigningKeyFile(), 4<<20, false)
	if err != nil {
		return nil, err
	}
	keyDigest := sha256.Sum256(key)
	if !bytes.Equal(keyDigest[:], source.GetSigningKeySha256()) {
		return nil, errors.New("packageprovider: approved signing key bytes changed")
	}
	var fingerprint, importKey []byte
	if config.HasEntitledLocation(rpm) {
		importKey, fingerprint, err = rhsm.ReleaseKey(key, source.GetRpmSigningKeyFingerprint())
		if err != nil {
			return nil, err
		}
	} else {
		var entities openpgp.EntityList
		if bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN PGP")) {
			entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(key))
		} else {
			entities, err = openpgp.ReadKeyRing(bytes.NewReader(key))
		}
		if err != nil || len(entities) != 1 {
			return nil, errors.New("packageprovider: RPM source must bind one valid public signing key")
		}
		fingerprint = entities[0].PrimaryKey.Fingerprint
		if !strings.EqualFold(hex.EncodeToString(fingerprint), source.GetRpmSigningKeyFingerprint()) {
			return nil, errors.New("packageprovider: approved RPM signing fingerprint mismatch")
		}
		importKey = key
	}
	keyFile := filepath.Join(directory, "signing-key.asc")
	if err := atomicFile(keyFile, importKey, 0600); err != nil {
		return nil, err
	}
	var repositoryConfig string
	if config.HasEntitledLocation(rpm) {
		repositoryConfig, err = entitledRepositoryConfig(source, keyFile)
		if err != nil {
			return nil, err
		}
	} else {
		repositoryConfig = dnfRepositoryConfig(source, keyFile)
	}
	if err := atomicFile(filepath.Join(directory, "repos", "approved.repo"), []byte(repositoryConfig), 0600); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(fingerprint)
	if _, err := p.run(ctx, "/usr/bin/rpm", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--initdb"}, "/", nil); err != nil {
		return nil, err
	}
	if _, err := p.run(ctx, "/usr/bin/rpm", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--import", keyFile}, "/", nil); err != nil {
		return nil, err
	}
	return digest[:], nil
}

func entitledRepositoryConfig(source *agentv1.NativePackageSource, keyFile string) (string, error) {
	identity, err := inventory.HostRelease(context.Background())
	if err != nil {
		return "", err
	}
	release := platform.Identify(identity)
	if err := config.CheckEntitledSource(release, source); err != nil {
		return "", err
	}
	vendor, architecture, _ := config.EntitledVendor(release, source.GetRepository().GetRpm())
	repositoryConfig, err := rhsm.RepositoryConfig(vendor, architecture, keyFile, func(path string) ([]byte, error) {
		return custody.ReadRoot(path, 1<<20, false)
	})
	if err != nil {
		return "", admissiondetail.Wrap(fmt.Errorf("%w: %w", ErrUnsupported, err), "rhsm_registration_required")
	}
	return repositoryConfig, nil
}

// dnfRepositoryConfig writes one section per approved native repository, all
// verified with the source's single key. Package signatures are always
// required; repository metadata signatures are waived only when the source
// says so, which checkSource admits only for metalinks the release pins.
func dnfRepositoryConfig(source *agentv1.NativePackageSource, keyFile string) string {
	rpm := source.GetRepository().GetRpm()
	metadata := "0"
	if rpm.GetRequireMetadataSignature() {
		metadata = "1"
	}
	section := func(id string, urls *resourcev1.RepositoryURLs, metalink string) string {
		location := "metalink=" + metalink
		if urls != nil {
			location = "baseurl=" + strings.Join(urls.GetUrls(), " ")
		}
		return "[" + id + "]\nname=Lindm approved repository\n" + location + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=" + metadata + "\nsslverify=1\nskip_if_unavailable=0\ngpgkey=file://" + keyFile + "\n"
	}
	config := section(rpm.GetNativeId(), rpm.GetBaseUrls(), rpm.GetMetalink())
	for _, additional := range rpm.GetAdditionalRepositories() {
		config += "\n" + section(additional.GetNativeId(), additional.GetBaseUrls(), additional.GetMetalink())
	}
	return config
}

// dnfApprovedRepository reports whether a resolved or stored package came
// from one of the source's approved native repositories.
func dnfApprovedRepository(rpm *resourcev1.RpmRepository, repoID string) bool {
	ids := []string{rpm.GetNativeId()}
	for _, additional := range rpm.GetAdditionalRepositories() {
		ids = append(ids, additional.GetNativeId())
	}
	for _, id := range ids {
		if repoID == id || repoID == "@stored_transaction("+id+")" {
			return true
		}
	}
	return false
}

// dnfSpec asks DNF for the native target; for a bare name DNF selects its
// best architecture for this host, never a multilib sibling.
func dnfSpec(d *resourcev1.NativePackageDesired, target *resourcev1.PackageIdentity) string {
	if d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		return nativeSpec(&resourcev1.PackageIdentity{NativeName: target.GetNativeName() + "-" + nativeVersion(d.GetExact()), Architecture: target.GetArchitecture()}, ".")
	}
	return nativeSpec(target, ".")
}

// afterRefresh runs once the approved metadata is authenticated, before the
// solver and the source snapshot use it (the installed-provenance proof).
func (p *Provider) planDNF(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource, afterRefresh func() error) ([]*resourcev1.PackageTransactionEntry, *resourcev1.RepositorySnapshot, error) {
	signer, err := p.prepareDNF(ctx, directory, source)
	if err != nil {
		return nil, nil, err
	}
	command := "install"
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		command = "remove"
	}
	if p.manager == dnf.DNF5 {
		if _, err := p.dnf(ctx, directory, []string{"makecache", "--refresh"}); err != nil {
			return nil, nil, err
		}
	}
	if err := afterRefresh(); err != nil {
		return nil, nil, err
	}
	target, err := p.nativeTarget(db, d.GetPackage())
	if err != nil {
		return nil, nil, err
	}
	spec := dnfSpec(d, target)
	resolved := &dnfResolved{Version: 1}
	if !p.dnfSatisfied(d, db.records[packageKey(target)]) {
		if resolved, err = p.stageDNF(ctx, directory, command, d, spec); err != nil {
			return nil, nil, err
		}
	}
	data, err := custody.ReadRoot(filepath.Join(directory, "transaction", "transaction.json"), 4<<20, false)
	if errors.Is(err, os.ErrNotExist) {
		// DNF writes no bundle for an already satisfied request. Its database
		// observation, rather than a success exit or missing file alone, must
		// independently establish that there is genuinely nothing to do.
		if !nativeMatches(d, db.records[packageKey(target)]) {
			return nil, nil, errors.New("packageprovider: DNF omitted unsatisfied transaction")
		}
		data = []byte(`{"version":"1.0","rpms":[]}`)
		if err := os.MkdirAll(filepath.Join(directory, "transaction"), 0700); err != nil {
			return nil, nil, err
		}
		if err := atomicFile(filepath.Join(directory, "transaction", "transaction.json"), data, 0600); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	transaction, err := parseDNFTransaction(data)
	if err != nil {
		return nil, nil, err
	}
	if err := matchDNFDeclaration(resolved, transaction); err != nil {
		return nil, nil, err
	}
	metadata, err := snapshotDirectory(filepath.Join(directory, "cache"))
	if err != nil && p.manager == dnf.DNF5 {
		// Removal may not require repository metadata. Refresh the approved
		// repository explicitly rather than fabricating an empty source revision.
		if _, refreshErr := p.dnf(ctx, directory, []string{"makecache", "--refresh"}); refreshErr != nil {
			return nil, nil, errors.Join(err, refreshErr)
		}
		metadata, err = snapshotDirectory(filepath.Join(directory, "cache"))
	}
	if err != nil {
		return nil, nil, err
	}
	snapshot := &resourcev1.RepositorySnapshot{Repository: sourceRef(source), MetadataSha256: metadata, SignerSha256: [][]byte{signer}}
	entries, err := p.dnfEntries(ctx, directory, transaction, d, db, source, snapshot)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		if entry.GetArtifact() == nil {
			continue
		}
		found := false
		for _, declaration := range resolved.Entries {
			identity, version, err := parseNEVRA(declaration.NEVRA)
			if err != nil {
				return nil, nil, err
			}
			if proto.Equal(identity, entry.GetPackage()) && proto.Equal(version, entry.GetAfter()) {
				if declaration.DownloadSize != entry.GetArtifact().GetSizeBytes() {
					return nil, nil, errors.New("packageprovider: RPM exceeds exact declared size")
				}
				found = true
				break
			}
		}
		if !found {
			return nil, nil, errors.New("packageprovider: RPM omitted from predownload declaration")
		}
	}
	return entries, snapshot, nil
}

// dnfSatisfied reports a DNF5 request that the installed record already
// satisfies, which has no package transaction. libdnf5 still resolves one for
// a package installed outside DNF (an image build or rpm -i): a "Reason
// Change" to user-installed, which is DNF history, not a package effect, and
// never part of a lindm transaction.
func (p *Provider) dnfSatisfied(d *resourcev1.NativePackageDesired, installed *resourcev1.NativePackageRecord) bool {
	return p.manager == dnf.DNF5 && nativeMatches(d, installed)
}

// stageDNF resolves the exact download sizes, then has the native manager
// download and store the transaction within those declarations.
func (p *Provider) stageDNF(ctx context.Context, directory, command string, d *resourcev1.NativePackageDesired, spec string) (*dnfResolved, error) {
	resolved, declared, err := p.resolveDNFSizes(ctx, directory, command, d, spec)
	if err != nil {
		return nil, err
	}
	// --store may retain both native cache and transaction copies.
	if err := checkDownloadBudget(directory, 2*declared, p.stagingMax); err != nil {
		return nil, err
	}
	declarations := make(map[string]downloadDeclaration)
	for _, entry := range resolved.Entries {
		if entry.DownloadSize == 0 {
			continue
		}
		if entry.FileName == "" || filepath.Base(entry.FileName) != entry.FileName || !strings.HasSuffix(entry.FileName, ".rpm") {
			return nil, errors.New("packageprovider: invalid native RPM download filename")
		}
		if _, exists := declarations[entry.FileName]; exists {
			return nil, ErrConflict
		}
		declarations[entry.FileName] = downloadDeclaration{size: entry.DownloadSize}
	}
	if err := boundedDownload(ctx, directory, directory, declarations, func(downloadContext context.Context) error {
		if p.manager == dnf.DNF4 {
			_, err := p.dnf4(downloadContext, "stage", directory, p.versionlock, command, spec)
			return err
		}
		_, err := p.dnf(downloadContext, directory, []string{command, "--store=" + filepath.Join(directory, "transaction"), spec})
		return err
	}); err != nil {
		return nil, err
	}
	return resolved, nil
}

func parseNEVRA(nevra string) (*resourcev1.PackageIdentity, *resourcev1.NativeVersion, error) {
	dot := strings.LastIndexByte(nevra, '.')
	if dot < 0 {
		return nil, nil, errors.New("packageprovider: invalid NEVRA architecture")
	}
	arch, rest := nevra[dot+1:], nevra[:dot]
	dash := strings.LastIndexByte(rest, '-')
	if dash < 0 {
		return nil, nil, errors.New("packageprovider: invalid NEVRA release")
	}
	release, rest := rest[dash+1:], rest[:dash]
	dash = strings.LastIndexByte(rest, '-')
	if dash < 0 {
		return nil, nil, errors.New("packageprovider: invalid NEVRA version")
	}
	name, version := rest[:dash], rest[dash+1:]
	epoch := "0"
	if e, v, ok := strings.Cut(version, ":"); ok {
		epoch, version = e, v
	}
	native, err := rpmVersion(epoch, version, release)
	if err != nil {
		return nil, nil, err
	}
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: name, Architecture: arch}
	if err := validateMessage(identity); err != nil {
		return nil, nil, err
	}
	return identity, native, nil
}
func dnfPackagePath(directory, relative string) (string, error) {
	clean := filepath.Clean(relative)
	if filepath.IsAbs(clean) || !strings.HasPrefix(clean, "packages/") || strings.Contains(clean, "/../") || !strings.HasSuffix(clean, ".rpm") {
		return "", errors.New("packageprovider: unsafe DNF package path")
	}
	return filepath.Join(directory, "transaction", clean), nil
}

func (p *Provider) dnfEntries(ctx context.Context, directory string, transaction *dnfTransaction, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource, snapshot *resourcev1.RepositorySnapshot) ([]*resourcev1.PackageTransactionEntry, error) {
	entries := make([]*resourcev1.PackageTransactionEntry, 0, len(transaction.RPMs))
	replaced := make(map[string]*resourcev1.NativeVersion)
	seen := make(map[string]bool)
	for _, rpm := range transaction.RPMs {
		identity, version, err := parseNEVRA(rpm.NEVRA)
		if err != nil {
			return nil, err
		}
		key := packageKey(identity)
		before := db.records[key]
		if rpm.Action == "Replaced" {
			if before == nil || !proto.Equal(version, before.GetVersion()) || replaced[key] != nil {
				return nil, errors.New("packageprovider: unbound replaced RPM")
			}
			replaced[key] = version
			continue
		}
		if seen[key] {
			return nil, errors.New("packageprovider: duplicate DNF transaction package")
		}
		seen[key] = true
		entry := &resourcev1.PackageTransactionEntry{Package: identity, Before: before.GetVersion(), Source: d.GetRepository(), DirectRequest: p.requests(d.GetPackage(), identity)}
		switch rpm.Action {
		case "Remove":
			if !entry.DirectRequest || d.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT || before == nil || !proto.Equal(version, before.GetVersion()) {
				return nil, errors.New("packageprovider: hidden dependency removal refused")
			}
			entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED
			entry.OwnedInstallation = true
		case "Install", "Upgrade":
			if !dnfApprovedRepository(source.GetRepository().GetRpm(), rpm.RepoID) {
				return nil, errors.New("packageprovider: unapproved DNF package source")
			}
			if rpm.Reason != "User" && rpm.Reason != "Dependency" && rpm.Reason != "Weak Dependency" {
				return nil, errors.New("packageprovider: unapproved DNF install reason")
			}
			if err := checkNoDowngrade(before.GetVersion(), version); err != nil {
				return nil, err
			}
			path, err := dnfPackagePath(directory, rpm.PackagePath)
			if err != nil {
				return nil, err
			}
			result, err := p.run(ctx, "/usr/bin/rpm", []string{"--query", "--package", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", path}, "/", nil)
			if err != nil {
				return nil, err
			}
			parsed, err := parseDatabase(result.stdout, p.ecosystem)
			if err != nil {
				return nil, err
			}
			if !samePackageRecord(parsed.records[key], &resourcev1.NativePackageRecord{Package: identity, Version: version}) {
				return nil, errors.New("packageprovider: stored RPM identity mismatch")
			}
			result, err = p.run(ctx, "/usr/bin/rpmkeys", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--checksig", "--verbose", path}, "/", nil)
			if err := checkRPMSignature(result, err, source.GetRpmSigningKeyFingerprint()); err != nil {
				return nil, err
			}
			result, err = p.run(ctx, "/usr/bin/rpmkeys", []string{"--checksig", "--verbose", path}, "/", nil)
			if err := checkRPMSignature(result, err, source.GetRpmSigningKeyFingerprint()); err != nil {
				return nil, fmt.Errorf("packageprovider: package signing key must already be root-provisioned in system RPM trust: %w", err)
			}
			entry.Artifact, err = artifactFor(path)
			if err != nil {
				return nil, err
			}
			entry.After = version
			entry.SignerSha256 = snapshot.GetSignerSha256()[0]
			entry.MetadataRevisionSha256 = snapshot.GetMetadataSha256()
			entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_INSTALL
			if before != nil {
				entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE
			}
		default:
			return nil, fmt.Errorf("packageprovider: DNF action %q refused (no downgrade, reinstall, obsoletes, or reason changes)", rpm.Action)
		}
		entries = append(entries, entry)
	}
	for key := range replaced {
		found := false
		for _, entry := range entries {
			if packageKey(entry.GetPackage()) == key && entry.GetOperation() == resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("packageprovider: hidden obsoleting RPM removal refused")
		}
	}
	return entries, nil
}

// checkRPMSignature requires every reported digest and at least one signature
// from the pinned approved key. An independent, unapproved NOKEY co-signature
// supplies no authority; only that condition can explain rpmkeys exit status 1.
// Failed signatures, warnings, incomplete output and other execution errors
// remain refusals. No additional key is imported or approved.
func checkRPMSignature(result nativeResult, runErr error, fingerprint string) error {
	if len(result.stderr) != 0 || (len(fingerprint) != 40 && len(fingerprint) != 64) || !rpmSignerHex(fingerprint) {
		return errors.New("packageprovider: ambiguous RPM verification")
	}
	text := string(result.stdout)
	if !strings.HasSuffix(text, "\n") {
		return errors.New("packageprovider: incomplete RPM verification")
	}
	var digests uint8
	valid, unknown, header := false, false, false
	for line := range strings.SplitSeq(text[:len(text)-1], "\n") {
		for _, char := range line {
			if char < ' ' || char > '~' {
				return errors.New("packageprovider: malformed RPM verification")
			}
		}
		if !header {
			if !strings.HasSuffix(line, ".rpm:") || len(line) == len(".rpm:") {
				return errors.New("packageprovider: missing RPM verification header")
			}
			header = true
			continue
		}
		line, indented := strings.CutPrefix(line, "    ")
		separator := strings.LastIndex(line, ": ")
		if !indented || separator < 0 {
			return errors.New("packageprovider: unknown RPM verification")
		}
		entry, status := line[:separator], line[separator+2:]
		var digest uint8
		switch entry {
		case "Header SHA256 digest":
			digest = 1
		case "Header SHA512 digest":
			digest = 2
		case "Header SHA1 digest":
			digest = 4
		case "Payload SHA256 digest":
			digest = 8
		case "Payload SHA512 digest":
			digest = 16
		case "MD5 digest":
			digest = 32
		}
		if digest != 0 {
			if status != "OK" || digests&digest != 0 {
				return errors.New("packageprovider: unverified RPM digest")
			}
			digests |= digest
			continue
		}
		description, signer, signature := strings.Cut(entry, " Signature, ")
		if !signature {
			description, signer, signature = strings.Cut(entry, " signature, ")
		}
		description = strings.TrimPrefix(strings.TrimPrefix(description, "Header "), "OpenPGP ")
		version, algorithm, described := strings.Cut(description, " ")
		if !signature || !described || (version != "V3" && version != "V4" && version != "V6") {
			return errors.New("packageprovider: unknown RPM signature")
		}
		switch algorithm {
		case "RSA/SHA1", "RSA/SHA256", "RSA/SHA512", "DSA/SHA1", "DSA/SHA256",
			"ECDSA/SHA256", "ECDSA/SHA384", "ECDSA/SHA512", "EdDSA/SHA256", "EdDSA/SHA512",
			"ML-DSA-87+Ed448/SHA512":
		default:
			return errors.New("packageprovider: unknown RPM signature algorithm")
		}
		id, short := strings.CutPrefix(signer, "key ID ")
		if !short {
			var full bool
			id, full = strings.CutPrefix(signer, "key fingerprint: ")
			if !full || (len(id) != 40 && len(id) != 64) {
				return errors.New("packageprovider: ambiguous RPM signer")
			}
		} else if len(id) != 8 && len(id) != 16 {
			return errors.New("packageprovider: ambiguous RPM signer")
		}
		if !rpmSignerHex(id) {
			return errors.New("packageprovider: malformed RPM signer")
		}
		approved := strings.EqualFold(id, fingerprint)
		if short {
			approved = strings.EqualFold(id, fingerprint[len(fingerprint)-len(id):])
		}
		switch status {
		case "OK":
			valid = valid || approved
		case "NOKEY":
			if approved {
				return errors.New("packageprovider: approved RPM signature is unverified")
			}
			unknown = true
		default:
			return errors.New("packageprovider: untrusted RPM signature")
		}
	}
	if !valid || digests&3 == 0 || digests&24 == 0 {
		return errors.New("packageprovider: RPM lacks an approved signature or verified header/payload digest")
	}
	if runErr != nil && (!unknown || !rpmKeysUnknownSignatureExit(runErr)) {
		return runErr
	}
	return nil
}

func rpmSignerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return value != ""
}

// Every error leaf must be rpmkeys' ordinary unknown-signature exit. In
// particular, a joined deadline, output limit or descriptor error is not lost.
func rpmKeysUnknownSignatureExit(err error) bool {
	switch wrapped := err.(type) {
	case *nativeexec.ExitError:
		return wrapped.Program == "rpmkeys" && wrapped.Code == 1
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !rpmKeysUnknownSignatureExit(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return rpmKeysUnknownSignatureExit(wrapped.Unwrap())
	default:
		return false
	}
}
