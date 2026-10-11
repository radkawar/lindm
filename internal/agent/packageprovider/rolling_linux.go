//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/custody"
	"lindm/internal/platform"
)

func (p *Provider) rolling() bool {
	return p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM || platform.Of(p.config.Platform).Native().Packages.Backend == platform.BackendZypper
}

func (p *Provider) selectRolling() error {
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		p.managerPath = "/usr/bin/pacman"
		return nil
	}
	p.managerPath = "/usr/bin/zypper"
	var err error
	p.rpmdb, err = rpmDatabase()
	return err
}

func (p *Provider) prepareRollingKey(ctx context.Context, directory string, source *agentv1.NativePackageSource) ([]byte, error) {
	fingerprint := source.GetAlpmSigningKeyFingerprint()
	if source.GetRepository().GetRpm() != nil {
		fingerprint = source.GetRpmSigningKeyFingerprint()
	}
	keyring := filepath.Join(directory, "keyring")
	if err := os.Mkdir(keyring, 0700); err != nil {
		return nil, err
	}
	args := []string{"--batch", "--no-options", "--homedir", keyring, "--no-default-keyring", "--keyring", filepath.Join(keyring, "pubring.gpg"), "--no-auto-key-retrieve"}
	result, err := p.run(ctx, "/usr/bin/gpg", append(args, "--with-colons", "--import-options", "show-only", "--import", source.GetSigningKeyFile()), "/", nil)
	if err != nil {
		return nil, err
	}
	primary, actual := 0, ""
	wantPrimary := false
	for line := range strings.SplitSeq(string(result.stdout), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}
		switch fields[0] {
		case "pub":
			primary++
			wantPrimary = true
		case "fpr":
			if wantPrimary {
				actual, wantPrimary = fields[9], false
			}
		}
	}
	if primary != 1 || actual != fingerprint {
		return nil, errors.New("packageprovider: approved native signer mismatch")
	}
	if _, err := p.run(ctx, "/usr/bin/gpg", append(args, "--import", source.GetSigningKeyFile()), "/", nil); err != nil {
		return nil, err
	}
	trust := filepath.Join(directory, "ownertrust")
	if err := atomicFile(trust, []byte(fingerprint+":6:\n"), 0600); err != nil {
		return nil, err
	}
	if _, err := p.run(ctx, "/usr/bin/gpg", append(args, "--import-ownertrust", trust), "/", nil); err != nil {
		return nil, err
	}
	if err := atomicFile(filepath.Join(keyring, "gpg.conf"), []byte("no-auto-key-retrieve\nauto-key-locate clear\n"), 0600); err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(decoded)
	return digest[:], nil
}

func (p *Provider) verifyRollingSignature(ctx context.Context, directory, path, fingerprint string) error {
	keyring := filepath.Join(directory, "keyring")
	result, err := p.run(ctx, "/usr/bin/gpg", []string{"--batch", "--no-options", "--homedir", keyring, "--no-default-keyring", "--keyring", filepath.Join(keyring, "pubring.gpg"), "--no-auto-key-retrieve", "--status-fd=1", "--verify", path + ".sig", path}, "/", nil)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(result.stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 12 && fields[0] == "[GNUPG:]" && fields[1] == "VALIDSIG" && (fields[2] == fingerprint || fields[len(fields)-1] == fingerprint) {
			return nil
		}
	}
	return errors.New("packageprovider: detached signature lacks approved signer")
}

func (p *Provider) planRolling(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource) ([]*resourcev1.PackageTransactionEntry, *resourcev1.RepositorySnapshot, error) {
	for _, name := range []string{"cache", "archives", "run"} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
			return nil, nil, err
		}
	}
	signer, err := p.prepareRollingKey(ctx, directory, source)
	if err != nil {
		return nil, nil, err
	}
	var entries []*resourcev1.PackageTransactionEntry
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		entries, err = p.planALPM(ctx, directory, d, db, source)
	} else {
		entries, err = p.planZypper(ctx, directory, d, db, source)
	}
	if err != nil {
		return nil, nil, err
	}
	if !nativeMatches(d, db.records[packageKey(d.GetPackage())]) {
		direct := false
		for _, entry := range entries {
			direct = direct || entry.GetDirectRequest()
		}
		if !direct {
			return nil, nil, errors.New("packageprovider: native solver omitted unsatisfied target")
		}
	}
	metadata, err := snapshotDirectory(filepath.Join(directory, "cache"))
	if err != nil {
		return nil, nil, err
	}
	snapshot := &resourcev1.RepositorySnapshot{Repository: sourceRef(source), MetadataSha256: metadata, SignerSha256: [][]byte{signer}}
	for _, entry := range entries {
		if entry.GetAfter() != nil {
			entry.SignerSha256 = bytes.Clone(signer)
			entry.MetadataRevisionSha256 = bytes.Clone(metadata)
		}
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&resourcev1.PackageTransactionManifest{Entries: entries})
	if err != nil {
		return nil, nil, err
	}
	// An empty proto message is not a valid nonempty artifact. Keep its version
	// domain prefix even for a no-effect plan; decoding checks the exact prefix.
	encoded = append([]byte("lindm.rolling.transaction.v1\n"), encoded...)
	if err := atomicFile(p.nativeTransactionPath(directory), encoded, 0600); err != nil {
		return nil, nil, err
	}
	return entries, snapshot, nil
}

func rollingArtifactPath(directory string, entry *resourcev1.PackageTransactionEntry) string {
	extension := ".rpm"
	if entry.GetPackage().GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		extension = ".pkg.tar.zst"
	}
	return filepath.Join(directory, "archives", hex.EncodeToString(entry.GetArtifact().GetSha256())+extension)
}

func (p *Provider) checkRollingArtifacts(ctx context.Context, directory string, request *agentv1.NativePackageTransactionRequest, manifest *resourcev1.PackageTransactionManifest) error {
	encoded, err := custody.ReadRoot(p.nativeTransactionPath(directory), 256<<10, false)
	if err != nil {
		return err
	}
	encoded, ok := bytes.CutPrefix(encoded, []byte("lindm.rolling.transaction.v1\n"))
	if !ok {
		return ErrConflict
	}
	staged := new(resourcev1.PackageTransactionManifest)
	if err := proto.Unmarshal(encoded, staged); err != nil {
		return err
	}
	if len(staged.GetEntries()) != len(manifest.GetEntries()) {
		return ErrConflict
	}
	for i, entry := range staged.GetEntries() {
		other := proto.CloneOf(manifest.GetEntries()[i])
		other.MetadataRevisionSha256 = bytes.Clone(entry.GetMetadataRevisionSha256())
		if !proto.Equal(entry, other) {
			return ErrConflict
		}
		if entry.GetArtifact() != nil {
			path := rollingArtifactPath(directory, entry)
			if err := checkArtifact(path, entry.GetArtifact()); err != nil {
				return err
			}
			if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
				if err := p.verifyRollingSignature(ctx, directory, path, request.GetSource().GetAlpmSigningKeyFingerprint()); err != nil {
					return err
				}
			} else if err := p.verifyZypperRPM(ctx, directory, path, request.GetSource()); err != nil {
				return err
			}
		}
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		// The adapter performs actual native prepare, revalidation and commit
		// under one retained libalpm lock; a --print preview is not authority.
		return nil
	}
	return p.previewZypperCommit(ctx, directory, request.GetEffectiveDesired(), manifest.GetEntries())
}

func rollingEntry(record *resourcev1.NativePackageRecord, d *resourcev1.NativePackageDesired, db *database, remove bool) *resourcev1.PackageTransactionEntry {
	key := packageKey(record.GetPackage())
	entry := &resourcev1.PackageTransactionEntry{Package: record.GetPackage(), Before: db.records[key].GetVersion(), Source: d.GetRepository(), DirectRequest: key == packageKey(d.GetPackage())}
	if remove {
		entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED
		entry.OwnedInstallation = true
	} else {
		entry.After = record.GetVersion()
		entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_INSTALL
		if entry.Before != nil {
			entry.Operation = resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE
		}
	}
	return entry
}
