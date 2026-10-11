//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/custody"
)

const alpmPrintFormat = "%n\t%v\t%a\t%f\t%s\t%h\t%g\t%r\t%R\t%G"

type alpmSelection struct {
	record    *resourcev1.NativePackageRecord
	filename  string
	size      uint64
	digest    []byte
	signature []byte
	groups    []string
}

func parseALPMSelection(data []byte, repository string, remove bool) ([]alpmSelection, error) {
	var result []alpmSelection
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 10 || len(result) >= 8192 {
			return nil, errors.New("packageprovider: malformed ALPM solver output")
		}
		identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, NativeName: fields[0], Architecture: fields[2]}
		if err := validateMessage(identity); err != nil {
			return nil, err
		}
		version, err := alpmVersion(fields[1])
		if err != nil {
			return nil, err
		}
		key := packageKey(identity)
		if seen[key] {
			return nil, ErrConflict
		}
		seen[key] = true
		entry := alpmSelection{record: &resourcev1.NativePackageRecord{Package: identity, Version: version}, filename: fields[3], groups: strings.Fields(fields[9])}
		if !remove {
			if fields[7] != repository || fields[8] != "" || filepath.Base(entry.filename) != entry.filename || !strings.Contains(entry.filename, ".pkg.tar.") {
				return nil, errors.New("packageprovider: ALPM repository, replacement or filename mismatch")
			}
			entry.size, err = strconv.ParseUint(fields[4], 10, 64)
			if err != nil || entry.size == 0 || entry.size > 512<<20 {
				return nil, errors.New("packageprovider: invalid ALPM download declaration")
			}
			entry.digest, err = hex.DecodeString(fields[5])
			if err != nil || len(entry.digest) != 32 {
				return nil, errors.New("packageprovider: missing ALPM archive checksum")
			}
			entry.signature, err = base64.StdEncoding.DecodeString(fields[6])
			if err != nil || len(entry.signature) == 0 || len(entry.signature) > 16<<10 {
				return nil, errors.New("packageprovider: missing ALPM package signature")
			}
		}
		result = append(result, entry)
	}
	return result, nil
}

// A private local database gives libalpm its real installed dependency universe
// without allowing preparation to acquire/write the live database or refresh its
// sync repositories. Every copied byte is bounded and subsequently reobserved.
func copyALPMLocal(directory string) error {
	root := "/var/lib/pacman/local"
	var total int
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(directory, "cache", "local", relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !entry.Type().IsRegular() {
			return ErrConflict
		}
		data, err := custody.ReadRoot(path, 4<<20, false)
		if err != nil {
			return err
		}
		total += len(data)
		if total > maxOutput {
			return errors.New("packageprovider: ALPM local database staging capacity")
		}
		return atomicFile(target, data, 0600)
	})
}

func (p *Provider) alpmPolicy(ctx context.Context, directory string, d *resourcev1.NativePackageDesired) (string, [32]byte, error) {
	_, current, err := readPin(pacmanConfigPath)
	if err != nil {
		return "", [32]byte{}, err
	}
	without, _, err := removeOwnedPin(current, packageRef(d.GetPackage()))
	if err != nil {
		return "", [32]byte{}, err
	}
	inputs, err := alpmPolicyInputs(without)
	if err != nil {
		return "", [32]byte{}, err
	}
	path := filepath.Join(directory, "pacman-system.conf")
	if err := atomicFile(path, without, 0600); err != nil {
		return "", [32]byte{}, err
	}
	var policy strings.Builder
	for _, directive := range []string{"IgnorePkg", "IgnoreGroup", "HoldPkg"} {
		result, err := p.run(ctx, "/usr/bin/pacman-conf", []string{"--config", path, directive}, "/", nil)
		if err != nil || len(result.stderr) != 0 {
			return "", [32]byte{}, errors.Join(err, errors.New("packageprovider: native pacman configuration probe failed"))
		}
		values := strings.Fields(string(result.stdout))
		for _, value := range values {
			if strings.ContainsAny(value, "#=\x00") {
				return "", [32]byte{}, ErrConflict
			}
		}
		if len(values) != 0 {
			fmt.Fprintf(&policy, "%s = %s\n", directive, strings.Join(values, " "))
		}
	}
	reobserved, err := alpmPolicyInputs(without)
	if err != nil || inputs != reobserved || policy.Len() > maxPin-65 {
		return "", [32]byte{}, errors.Join(ErrConflict, err)
	}
	if err := checkALPMHolds(policy.String(), alpmSelection{record: &resourcev1.NativePackageRecord{Package: d.GetPackage()}}, d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT); err != nil {
		return "", [32]byte{}, err
	}
	return policy.String(), inputs, nil
}

func (p *Provider) alpmArgs(directory string, args ...string) []string {
	return append([]string{"--config", filepath.Join(directory, "pacman.conf"), "--dbpath", filepath.Join(directory, "cache"), "--cachedir", filepath.Join(directory, "downloads"), "--gpgdir", filepath.Join(directory, "keyring"), "--logfile", filepath.Join(directory, "pacman.log"), "--noconfirm", "--noprogressbar", "--color", "never"}, args...)
}

func (p *Provider) planALPM(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource) ([]*resourcev1.PackageTransactionEntry, error) {
	repo := source.GetRepository().GetAlpm()
	if repo == nil || repo.GetArchitecture() != d.GetPackage().GetArchitecture() && d.GetPackage().GetArchitecture() != "any" {
		return nil, ErrUnsupported
	}
	policy, inputs, err := p.alpmPolicy(ctx, directory, d)
	if err != nil {
		return nil, err
	}
	if err := atomicFile(filepath.Join(directory, "cache", "alpm-policy"), []byte(hex.EncodeToString(inputs[:])+"\n"+policy), 0600); err != nil {
		return nil, err
	}
	base := "[options]\nArchitecture = " + repo.GetArchitecture() + "\nSigLevel = PackageRequired DatabaseRequired TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n" + policy
	config := base + "[" + repo.GetNativeName() + "]\nServer = " + repo.GetSnapshotUri() + "\n"
	if err := atomicFile(filepath.Join(directory, "pacman.conf"), []byte(config), 0600); err != nil {
		return nil, err
	}
	if err := copyALPMLocal(directory); err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(directory, "downloads"), 0700); err != nil {
		return nil, err
	}
	if _, err := p.run(ctx, p.managerPath, p.alpmArgs(directory, "-Sy"), "/", nil); err != nil {
		return nil, err
	}
	if err := p.verifyRollingSignature(ctx, directory, filepath.Join(directory, "cache", "sync", repo.GetNativeName()+".db"), source.GetAlpmSigningKeyFingerprint()); err != nil {
		return nil, err
	}
	if nativeMatches(d, db.records[packageKey(d.GetPackage())]) {
		return nil, nil
	}
	remove := d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT
	operation, target := "-S", repo.GetNativeName()+"/"+d.GetPackage().GetNativeName()
	if remove {
		operation, target = "-R", d.GetPackage().GetNativeName()
	} else if d.GetExact() != nil {
		target += "=" + nativeVersion(d.GetExact())
	}
	result, err := p.run(ctx, p.managerPath, p.alpmArgs(directory, operation, "--print-format", alpmPrintFormat, "--", target), "/", nil)
	if err != nil {
		return nil, err
	}
	selected, err := parseALPMSelection(result.stdout, repo.GetNativeName(), remove)
	if err != nil {
		return nil, err
	}
	var total uint64
	declarations := make(map[string]downloadDeclaration, len(selected))
	entries := make([]*resourcev1.PackageTransactionEntry, 0, len(selected))
	for _, selection := range selected {
		if err := checkALPMHolds(policy, selection, remove); err != nil {
			return nil, err
		}
		total += selection.size
		if !remove {
			if _, duplicate := declarations[selection.filename]; duplicate {
				return nil, ErrConflict
			}
			declarations[selection.filename] = downloadDeclaration{size: selection.size, sha256: selection.digest}
		}
		entries = append(entries, rollingEntry(selection.record, d, db, remove))
	}
	if err := validateEntries(entries, d, db); err != nil {
		return nil, err
	}
	if remove {
		return entries, nil
	}
	if err := checkDownloadBudget(directory, total, p.stagingMax); err != nil {
		return nil, err
	}
	if err := boundedDownload(ctx, directory, declarations, func(ctx context.Context) error {
		_, err := p.run(ctx, p.managerPath, p.alpmArgs(directory, "-Sw", "--", target), "/", nil)
		return err
	}); err != nil {
		return nil, err
	}
	for i, selection := range selected {
		path := filepath.Join(directory, "downloads", selection.filename)
		artifact, err := artifactFor(path)
		if err != nil {
			return nil, err
		}
		if artifact.GetSizeBytes() != selection.size || !bytes.Equal(artifact.GetSha256(), selection.digest) {
			return nil, errors.New("packageprovider: downloaded ALPM archive differs from authenticated metadata")
		}
		entries[i].Artifact = artifact
		destination := rollingArtifactPath(directory, entries[i])
		if err := os.Rename(path, destination); err != nil {
			return nil, err
		}
		if err := atomicFile(destination+".sig", selection.signature, 0600); err != nil {
			return nil, err
		}
		if err := p.verifyRollingSignature(ctx, directory, destination, source.GetAlpmSigningKeyFingerprint()); err != nil {
			return nil, err
		}
	}
	return entries, nil
}
