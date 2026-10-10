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

	"github.com/ProtonMail/go-crypto/openpgp"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
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
	fixed := []string{"--config=" + filepath.Join(directory, "dnf.conf"), "--setopt=reposdir=" + filepath.Join(directory, "repos"), "--setopt=cachedir=" + filepath.Join(directory, "cache"), "--setopt=logdir=" + filepath.Join(directory, "log"), "--setopt=system_cachedir=" + filepath.Join(directory, "cache"), "--setopt=plugins=false", "--setopt=install_weak_deps=false", "--setopt=clean_requirements_on_remove=false", "--setopt=keepcache=true", "--setopt=skip_if_unavailable=false", "--setopt=best=true", "--setopt=localpkg_gpgcheck=true", "--setopt=tsflags=", "--assumeyes"}
	return p.run(ctx, p.managerPath, append(fixed, args...), "/", nil)
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
	if err := atomicFile(filepath.Join(directory, "dnf.conf"), []byte("[main]\nplugins=False\ngpgcheck=True\nrepo_gpgcheck=True\nlocalpkg_gpgcheck=True\n"), 0600); err != nil {
		return nil, err
	}
	location := "metalink=" + rpm.GetMetalink()
	if urls := rpm.GetBaseUrls(); urls != nil {
		location = "baseurl=" + strings.Join(urls.GetUrls(), " ")
	}
	config := "[" + rpm.GetNativeId() + "]\nname=Lindm approved repository\n" + location + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\ngpgkey=file://" + source.GetSigningKeyFile() + "\n"
	if err := atomicFile(filepath.Join(directory, "repos", "approved.repo"), []byte(config), 0600); err != nil {
		return nil, err
	}
	key, err := protectedFile(source.GetSigningKeyFile(), 4<<20)
	if err != nil {
		return nil, err
	}
	var entities openpgp.EntityList
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(key))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(key))
	}
	if err != nil || len(entities) != 1 {
		return nil, errors.New("packageprovider: RPM source must bind one valid public signing key")
	}
	fingerprint := entities[0].PrimaryKey.Fingerprint
	if !strings.EqualFold(hex.EncodeToString(fingerprint), source.GetRpmSigningKeyFingerprint()) {
		return nil, errors.New("packageprovider: approved RPM signing fingerprint mismatch")
	}
	digest := sha256.Sum256(fingerprint)
	if _, err := p.run(ctx, "/usr/bin/rpm", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--initdb"}, "/", nil); err != nil {
		return nil, err
	}
	if _, err := p.run(ctx, "/usr/bin/rpm", []string{"--dbpath", filepath.Join(directory, "rpmkeys"), "--import", source.GetSigningKeyFile()}, "/", nil); err != nil {
		return nil, err
	}
	return digest[:], nil
}
func dnfSpec(d *resourcev1.NativePackageDesired) string {
	if d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		return d.GetPackage().GetNativeName() + "-" + nativeVersion(d.GetExact()) + "." + d.GetPackage().GetArchitecture()
	}
	return d.GetPackage().GetNativeName() + "." + d.GetPackage().GetArchitecture()
}
func (p *Provider) planDNF(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource) ([]*resourcev1.PackageTransactionEntry, *resourcev1.RepositorySnapshot, error) {
	signer, err := p.prepareDNF(ctx, directory, source)
	if err != nil {
		return nil, nil, err
	}
	command := "install"
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		command = "remove"
	}
	if _, err := p.dnf(ctx, directory, []string{"makecache", "--refresh"}); err != nil {
		return nil, nil, err
	}
	resolved, declared, err := p.resolveDNFSizes(ctx, directory, command, d)
	if err != nil {
		return nil, nil, err
	}
	// --store may retain both native cache and transaction copies.
	if err := checkDownloadBudget(directory, 2*declared, p.stagingMax); err != nil {
		return nil, nil, err
	}
	declarations := make(map[string]downloadDeclaration)
	for _, entry := range resolved.Entries {
		if entry.DownloadSize == 0 {
			continue
		}
		if entry.FileName == "" || filepath.Base(entry.FileName) != entry.FileName || !strings.HasSuffix(entry.FileName, ".rpm") {
			return nil, nil, errors.New("packageprovider: invalid native RPM download filename")
		}
		if _, exists := declarations[entry.FileName]; exists {
			return nil, nil, ErrConflict
		}
		declarations[entry.FileName] = downloadDeclaration{size: entry.DownloadSize}
	}
	if err := boundedDownload(ctx, directory, declarations, func(downloadContext context.Context) error {
		_, err := p.dnf(downloadContext, directory, []string{command, "--store=" + filepath.Join(directory, "transaction"), dnfSpec(d)})
		return err
	}); err != nil {
		return nil, nil, err
	}
	data, err := protectedFile(filepath.Join(directory, "transaction", "transaction.json"), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		// DNF writes no bundle for an already satisfied request. Its database
		// observation, rather than a success exit or missing file alone, must
		// independently establish that there is genuinely nothing to do.
		if !nativeMatches(d, db.records[packageKey(d.GetPackage())]) {
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
	if err != nil {
		// Removal may not require repository metadata. Refresh the approved
		// repository explicitly rather than fabricating an empty source revision.
		if _, refreshErr := p.dnf(ctx, directory, []string{"makecache", "--refresh"}); refreshErr != nil {
			return nil, nil, errors.Join(err, refreshErr)
		}
		metadata, err = snapshotDirectory(filepath.Join(directory, "cache"))
		if err != nil {
			return nil, nil, err
		}
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
		entry := &resourcev1.PackageTransactionEntry{Package: identity, Before: before.GetVersion(), Source: d.GetRepository(), DirectRequest: key == packageKey(d.GetPackage())}
		switch rpm.Action {
		case "Remove":
			if !entry.DirectRequest || d.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT || before == nil || !proto.Equal(version, before.GetVersion()) {
				return nil, errors.New("packageprovider: hidden dependency removal refused")
			}
			entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED
			entry.OwnedInstallation = true
		case "Install", "Upgrade":
			if rpm.RepoID != source.GetRepository().GetRpm().GetNativeId() && rpm.RepoID != "@stored_transaction("+source.GetRepository().GetRpm().GetNativeId()+")" {
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
			if err != nil {
				return nil, err
			}
			if err := checkRPMSignature(result.stdout, source.GetRpmSigningKeyFingerprint()); err != nil {
				return nil, err
			}
			result, err = p.run(ctx, "/usr/bin/rpmkeys", []string{"--checksig", "--verbose", path}, "/", nil)
			if err != nil {
				return nil, errors.New("packageprovider: package signing key must already be root-provisioned in system RPM trust")
			}
			if err := checkRPMSignature(result.stdout, source.GetRpmSigningKeyFingerprint()); err != nil {
				return nil, err
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
func checkRPMSignature(output []byte, fingerprint string) error {
	valid := false
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.Contains(line, "NOT OK") || strings.Contains(line, "NOKEY") || strings.Contains(line, "NOTTRUSTED") {
			return errors.New("packageprovider: untrusted RPM signature")
		}
		if !strings.Contains(line, "Signature,") || !strings.HasSuffix(strings.TrimSpace(line), ": OK") {
			continue
		}
		_, suffix, ok := strings.Cut(line, "key ID ")
		if !ok {
			continue
		}
		id, _, ok := strings.Cut(suffix, ":")
		if !ok || len(id) < 8 || !strings.HasSuffix(strings.ToLower(fingerprint), strings.ToLower(id)) {
			return errors.New("packageprovider: wrong RPM signer")
		}
		valid = true
	}
	if !valid {
		return errors.New("packageprovider: RPM has no verified package signature")
	}
	return nil
}
