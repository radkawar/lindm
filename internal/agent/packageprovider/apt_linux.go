//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// The fixed native interface is apt-get(8) update/simulate/download-only,
// apt-cache(8) show and dpkg-deb(1) --show. Commit uses ordered dpkg(1) steps.
func (p *Provider) prepareAPT(ctx context.Context, directory string, source *agentv1.NativePackageSource) (*resourcev1.RepositorySnapshot, error) {
	for _, name := range []string{"lists", "lists/partial", "archives", "archives/partial", "empty"} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
			return nil, err
		}
	}
	apt := source.GetRepository().GetApt()
	if apt == nil {
		return nil, ErrUnsupported
	}
	keyring, err := protectedFile(source.GetSigningKeyFile(), 1<<20)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(bytes.TrimSpace(keyring), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		block, err := armor.Decode(bytes.NewReader(keyring))
		if err != nil || block.Type != "PGP PUBLIC KEY BLOCK" {
			return nil, errors.New("packageprovider: invalid approved APT signing key")
		}
		keyring, err = io.ReadAll(io.LimitReader(block.Body, (1<<20)+1))
		if err != nil || len(keyring) > 1<<20 {
			return nil, errors.New("packageprovider: invalid armored signing key")
		}
	}
	keyPath := filepath.Join(directory, "approved-key.gpg")
	if err := atomicFile(keyPath, keyring, 0600); err != nil {
		return nil, err
	}
	line := "deb [arch=" + strings.Join(apt.GetArchitectures(), ",") + " signed-by=" + keyPath + "] " + apt.GetUri() + " " + apt.GetSuite() + " " + strings.Join(apt.GetComponents(), " ") + "\n"
	if err := atomicFile(filepath.Join(directory, "sources.list"), []byte(line), 0600); err != nil {
		return nil, err
	}
	// APT_CONFIG is read before apt.conf.d and apt.conf, so neither host hooks
	// nor arbitrary local package-manager overrides enter this transaction.
	config := []byte("Dir::Etc::parts \"/dev/null\";\nDir::Etc::main \"/dev/null\";\nAPT::Sandbox::User \"root\";\n")
	if err := atomicFile(filepath.Join(directory, "apt.conf"), config, 0600); err != nil {
		return nil, err
	}
	result, err := p.apt(ctx, directory, "/usr/bin/apt-get", []string{"update", "--error-on=any"})
	if err != nil {
		return nil, err
	}
	if bytes.Contains(result.stderr, []byte("W:")) || bytes.Contains(result.stderr, []byte("E:")) {
		return nil, errors.New("packageprovider: incomplete APT metadata refresh")
	}
	entries, err := os.ReadDir(filepath.Join(directory, "lists"))
	if err != nil {
		return nil, err
	}
	var signers [][]byte
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_InRelease") {
			continue
		}
		result, err := p.run(ctx, "/usr/bin/gpgv", []string{"--status-fd=1", "--keyring", keyPath, filepath.Join(directory, "lists", entry.Name())}, "/", nil)
		if err != nil {
			return nil, err
		}
		fingerprints, err := validSigners(result.stdout)
		if err != nil {
			return nil, err
		}
		signers = append(signers, fingerprints...)
	}
	if len(signers) == 0 {
		return nil, errors.New("packageprovider: signed APT InRelease evidence unavailable")
	}
	metadata, err := snapshotDirectory(filepath.Join(directory, "lists"))
	if err != nil {
		return nil, err
	}
	return &resourcev1.RepositorySnapshot{Repository: sourceRef(source), MetadataSha256: metadata, SignerSha256: signers}, nil
}

func validSigners(status []byte) ([][]byte, error) {
	var signers [][]byte
	for line := range strings.SplitSeq(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "[GNUPG:]" {
			continue
		}
		switch f[1] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY":
			return nil, errors.New("packageprovider: untrusted repository signature")
		case "VALIDSIG":
			if len(f) < 11 {
				return nil, errors.New("packageprovider: incomplete signature status")
			}
			fingerprint, err := hex.DecodeString(f[2])
			if err != nil || len(fingerprint) < 20 {
				return nil, errors.New("packageprovider: invalid signer fingerprint")
			}
			digest := sha256.Sum256(fingerprint)
			if !slices.ContainsFunc(signers, func(other []byte) bool { return bytes.Equal(other, digest[:]) }) {
				signers = append(signers, digest[:])
			}
		}
	}
	if len(signers) == 0 {
		return nil, errors.New("packageprovider: signature did not identify its signer")
	}
	return signers, nil
}

func aptOptions(directory string) []string {
	return []string{
		"-o", "Dir::Etc::sourcelist=" + filepath.Join(directory, "sources.list"),
		"-o", "Dir::Etc::sourceparts=" + filepath.Join(directory, "empty"),
		"-o", "Dir::State::lists=" + filepath.Join(directory, "lists"),
		"-o", "Dir::Cache::archives=" + filepath.Join(directory, "archives"),
		"-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
		"-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false",
		"-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "Acquire::Check-Valid-Until=true",
		"-o", "Acquire::Retries=0", "-o", "Acquire::ForceHash=sha256",
		"-o", "DPkg::Lock::Timeout=0", "-o", "APT::Get::AutomaticRemove=false",
		"-o", "APT::Install-Recommends=false", "-o", "APT::Install-Suggests=false",
		"-o", "APT::Get::allow-Downgrades=false", "-o", "APT::Get::allow-Remove-Essential=false",
		"-o", "APT::Get::allow-Change-Held-Packages=false",
	}
}
func (p *Provider) apt(ctx context.Context, directory, tool string, args []string) (nativeResult, error) {
	return p.run(ctx, tool, append(aptOptions(directory), args...), "/", []string{"APT_CONFIG=" + filepath.Join(directory, "apt.conf")})
}
func aptSpec(d *resourcev1.NativePackageDesired) string {
	spec := d.GetPackage().GetNativeName() + ":" + d.GetPackage().GetArchitecture()
	if d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		spec += "=" + d.GetExact().GetDeb()
	}
	return spec
}
func aptTransactionArgs(d *resourcev1.NativePackageDesired) []string {
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return []string{"remove", aptSpec(d)}
	}
	return []string{"--no-remove", "install", aptSpec(d)}
}

type aptChange struct {
	name, architecture, version string
	remove                      bool
}

var aptInstall = regexp.MustCompile(`^Inst ([^ ]+)(?: \[[^\]]+\])? \(([^ ]+) .*\[([^\]]+)\]\)$`)
var aptRemove = regexp.MustCompile(`^Remv ([^ ]+) \[([^\]]+)\](?: .*)?$`)

func parseAPTSimulation(output []byte) ([]aptChange, error) {
	var changes []aptChange
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.HasPrefix(line, "Inst ") {
			m := aptInstall.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("packageprovider: unrecognized APT install record %q", line)
			}
			name, qualifier, _ := strings.Cut(m[1], ":")
			if qualifier != "" && qualifier != m[3] {
				return nil, errors.New("packageprovider: inconsistent APT architecture")
			}
			changes = append(changes, aptChange{name: name, architecture: m[3], version: m[2]})
		} else if strings.HasPrefix(line, "Remv ") {
			m := aptRemove.FindStringSubmatch(line)
			if m == nil {
				return nil, errors.New("packageprovider: unrecognized APT removal record")
			}
			name, arch, _ := strings.Cut(m[1], ":")
			changes = append(changes, aptChange{name: name, architecture: arch, version: m[2], remove: true})
		} else if strings.HasPrefix(line, "Purg ") || strings.HasPrefix(line, "E:") {
			return nil, errors.New("packageprovider: unsafe APT transaction")
		}
		if len(changes) > 4096 {
			return nil, errors.New("packageprovider: APT transaction capacity")
		}
	}
	return changes, nil
}

func (p *Provider) planAPT(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource) ([]*resourcev1.PackageTransactionEntry, *resourcev1.RepositorySnapshot, error) {
	snapshot, err := p.prepareAPT(ctx, directory, source)
	if err != nil {
		return nil, nil, err
	}
	result, err := p.apt(ctx, directory, "/usr/bin/apt-get", append([]string{"--simulate"}, aptTransactionArgs(d)...))
	if err != nil {
		return nil, nil, err
	}
	changes, err := parseAPTSimulation(result.stdout)
	if err != nil {
		return nil, nil, err
	}
	if _, err := parseAPTSteps(result.stdout); err != nil {
		return nil, nil, err
	}
	if err := atomicFile(filepath.Join(directory, "native-transaction.txt"), result.stdout, 0600); err != nil {
		return nil, nil, err
	}
	declarations := make(map[string]downloadDeclaration)
	if d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT && len(changes) > 0 {
		result, err := p.apt(ctx, directory, "/usr/bin/apt-get", append([]string{"--print-uris", "--download-only"}, aptTransactionArgs(d)...))
		if err != nil {
			return nil, nil, err
		}
		var declared uint64
		declarations, declared, err = parseAPTDownloadDeclarations(result.stdout)
		if err != nil {
			return nil, nil, err
		}
		if len(declarations) != len(changes) {
			return nil, nil, errors.New("packageprovider: incomplete APT download declarations")
		}
		if err := checkDownloadBudget(directory, declared, p.stagingMax); err != nil {
			return nil, nil, err
		}
		if err := boundedDownload(ctx, directory, declarations, func(downloadContext context.Context) error {
			_, err := p.apt(downloadContext, directory, "/usr/bin/apt-get", append([]string{"--assume-yes", "--download-only"}, aptTransactionArgs(d)...))
			return err
		}); err != nil {
			return nil, nil, err
		}
	}
	archives, err := os.ReadDir(filepath.Join(directory, "archives"))
	if err != nil {
		return nil, nil, err
	}
	type archive struct {
		path string
		ref  *resourcev1.ArtifactRef
	}
	files := make(map[string]archive)
	for _, file := range archives {
		if !strings.HasSuffix(file.Name(), ".deb") {
			continue
		}
		path := filepath.Join(directory, "archives", file.Name())
		result, err := p.run(ctx, "/usr/bin/dpkg-deb", []string{"--show", "--showformat=${Package}\t${Version}\t${Architecture}\n", path}, "/", nil)
		if err != nil {
			return nil, nil, err
		}
		f := strings.Split(strings.TrimSuffix(string(result.stdout), "\n"), "\t")
		if len(f) != 3 {
			return nil, nil, errors.New("packageprovider: invalid DEB archive identity")
		}
		ref, err := artifactFor(path)
		if err != nil {
			return nil, nil, err
		}
		declaration, ok := declarations[file.Name()]
		if !ok || declaration.size != ref.GetSizeBytes() || !bytes.Equal(declaration.sha256, ref.GetSha256()) {
			return nil, nil, errors.New("packageprovider: downloaded DEB exceeds or differs from authenticated declaration")
		}
		key := f[0] + "/" + f[2] + "/" + f[1]
		if _, duplicate := files[key]; duplicate {
			return nil, nil, errors.New("packageprovider: ambiguous DEB archive")
		}
		files[key] = archive{path, ref}
	}
	entries := make([]*resourcev1.PackageTransactionEntry, 0, len(changes))
	for _, change := range changes {
		if change.remove {
			if d.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT || change.name != d.GetPackage().GetNativeName() || (change.architecture != "" && change.architecture != d.GetPackage().GetArchitecture()) {
				return nil, nil, errors.New("packageprovider: hidden dependency removal refused")
			}
			before := db.records[packageKey(d.GetPackage())]
			if before == nil {
				return nil, nil, ErrConflict
			}
			entries = append(entries, &resourcev1.PackageTransactionEntry{Package: d.GetPackage(), Operation: resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED, Before: before.GetVersion(), Source: d.GetRepository(), DirectRequest: true, OwnedInstallation: true})
			continue
		}
		identity := &resourcev1.PackageIdentity{Ecosystem: p.ecosystem, NativeName: change.name, Architecture: change.architecture}
		before := db.records[packageKey(identity)]
		after := debVersion(change.version)
		if err := checkNoDowngrade(before.GetVersion(), after); err != nil {
			return nil, nil, err
		}
		file, ok := files[change.name+"/"+change.architecture+"/"+change.version]
		if !ok {
			return nil, nil, errors.New("packageprovider: missing planned dependency archive")
		}
		result, err := p.apt(ctx, directory, "/usr/bin/apt-cache", []string{"show", "--no-all-versions", change.name + ":" + change.architecture + "=" + change.version})
		if err != nil {
			return nil, nil, err
		}
		if err := matchAPTArchive(result.stdout, file.ref); err != nil {
			return nil, nil, err
		}
		archivePath := filepath.Join(directory, "archives", hex.EncodeToString(file.ref.GetSha256())+".deb")
		if err := os.Rename(file.path, archivePath); err != nil {
			return nil, nil, err
		}
		operation := resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_INSTALL
		if before != nil {
			operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE
		}
		entry := &resourcev1.PackageTransactionEntry{Package: identity, Operation: operation, Before: before.GetVersion(), After: after, Artifact: file.ref, Source: d.GetRepository(), DirectRequest: packageKey(identity) == packageKey(d.GetPackage()), SignerSha256: snapshot.GetSignerSha256()[0], MetadataRevisionSha256: snapshot.GetMetadataSha256()}
		entries = append(entries, entry)
	}
	if len(files) != countInbound(entries) {
		return nil, nil, errors.New("packageprovider: unmanifested DEB archive")
	}
	return entries, snapshot, nil
}

func matchAPTArchive(output []byte, ref *resourcev1.ArtifactRef) error {
	var digest string
	for line := range strings.SplitSeq(string(output), "\n") {
		if value, ok := strings.CutPrefix(line, "SHA256: "); ok {
			if digest != "" && digest != value {
				return errors.New("packageprovider: ambiguous APT artifact metadata")
			}
			digest = value
		}
	}
	if digest != hex.EncodeToString(ref.GetSha256()) {
		return errors.New("packageprovider: DEB archive does not match authenticated source metadata")
	}
	return nil
}
func countInbound(entries []*resourcev1.PackageTransactionEntry) int {
	n := 0
	for _, entry := range entries {
		if entry.GetAfter() != nil {
			n++
		}
	}
	return n
}
