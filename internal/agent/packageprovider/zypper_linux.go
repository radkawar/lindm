// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

type zypperSolvable struct {
	Kind         string `xml:"type,attr"`
	Name         string `xml:"name,attr"`
	Edition      string `xml:"edition,attr"`
	Architecture string `xml:"arch,attr"`
	Repository   string `xml:"repository,attr"`
}
type zypperGroup struct {
	XMLName  xml.Name
	Packages []zypperSolvable `xml:"solvable"`
}
type zypperSummary struct {
	Count    uint64        `xml:"packages-to-change,attr"`
	Download uint64        `xml:"download-size,attr"`
	Groups   []zypperGroup `xml:",any"`
}

func (p *Provider) parseZypperSummary(data []byte, d *resourcev1.NativePackageDesired, db *database, repository string) ([]*resourcev1.PackageTransactionEntry, uint64, error) {
	var document struct {
		XMLName   xml.Name        `xml:"stream"`
		Summaries []zypperSummary `xml:"install-summary"`
		Messages  []struct {
			Type string `xml:"type,attr"`
		} `xml:"message"`
	}
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, 0, err
	}
	for _, message := range document.Messages {
		if message.Type == "error" || message.Type == "warning" {
			return nil, 0, errors.New("packageprovider: zypper solver warned")
		}
	}
	if len(document.Summaries) != 1 {
		return nil, 0, errors.New("packageprovider: missing or repeated zypper transaction summary")
	}
	summary := document.Summaries[0]
	if summary.Count > 8192 || summary.Download > 512<<20 {
		return nil, 0, errors.New("packageprovider: zypper transaction capacity")
	}
	entries := make([]*resourcev1.PackageTransactionEntry, 0, summary.Count)
	for _, group := range summary.Groups {
		if group.XMLName.Local == "_unsupported" {
			// Summary::dumpAsXmlTo repeats packages here to describe vendor
			// support level; it is not a transaction effect group.
			continue
		}
		remove := group.XMLName.Local == "to-remove"
		if !remove && group.XMLName.Local != "to-install" && group.XMLName.Local != "to-upgrade" {
			return nil, 0, errors.New("packageprovider: zypper downgrade, replacement, reinstall or unknown transaction refused")
		}
		for _, item := range group.Packages {
			if item.Kind != "package" || (!remove && repository != "" && item.Repository != repository) {
				return nil, 0, errors.New("packageprovider: zypper package source mismatch")
			}
			identity, version, err := parseNEVRA(item.Name + "-" + item.Edition + "." + item.Architecture)
			if err != nil {
				return nil, 0, err
			}
			record := &resourcev1.NativePackageRecord{Package: identity, Version: version}
			if remove && !samePackageRecord(record, db.records[packageKey(identity)]) {
				return nil, 0, ErrConflict
			}
			entries = append(entries, p.rollingEntry(record, d, db, remove))
		}
	}
	if uint64(len(entries)) != summary.Count {
		return nil, 0, ErrConflict
	}
	if err := p.validateEntries(entries, d, db); err != nil {
		return nil, 0, err
	}
	return entries, summary.Download, nil
}

func zypperArgs(directory string, args ...string) []string {
	return append([]string{"--non-interactive", "--xmlout", "--no-refresh", "--reposd-dir", filepath.Join(directory, "repos"), "--cache-dir", filepath.Join(directory, "cache")}, args...)
}
func zypperEnv(directory string, preparation bool) []string {
	env := []string{"ZYPP_CONF=" + filepath.Join(directory, "zypp.conf"), "ZYPP_LOGFILE=" + filepath.Join(directory, "zypp.log"), "ZYPP_LOCK_TIMEOUT=0"}
	if preparation {
		env = append(env, "ZYPP_LOCKFILE_ROOT="+directory)
	}
	return env
}
func zypperTarget(d *resourcev1.NativePackageDesired, target *resourcev1.PackageIdentity) string {
	spec := nativeSpec(target, ".")
	if d.GetExact() != nil && d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		spec += "=" + nativeVersion(d.GetExact())
	}
	return spec
}

// zypperDryRun solves the desired change against the staged repository only.
func zypperDryRun(d *resourcev1.NativePackageDesired, target *resourcev1.PackageIdentity) []string {
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return []string{"remove", "--dry-run", "--", zypperTarget(d, target)}
	}
	return []string{"install", "--no-recommends", "--no-allow-vendor-change", "--dry-run", "--", zypperTarget(d, target)}
}

// zyppGPGCheckMarker reports libzypp's raw-cache record of the repository
// signature mode: a symlink named .repo_gpgcheck targeting ./true or ./false.
func zyppGPGCheckMarker(path string) bool {
	if filepath.Base(path) != ".repo_gpgcheck" {
		return false
	}
	target, err := os.Readlink(path)
	return err == nil && (target == "./true" || target == "./false")
}

// consumeZyppGPGCheckMarker requires native zypper's own record that it
// enforced the repository signature, then removes that symlink so the cache
// commit hashes and syncs regular files only. Later --no-refresh solves read
// the retained metadata without it (observed with zypper 1.14.101).
func consumeZyppGPGCheckMarker(raw string) error {
	marker := filepath.Join(raw, ".repo_gpgcheck")
	target, err := os.Readlink(marker)
	if err != nil || target != "./true" {
		return errors.Join(errors.New("packageprovider: zypper did not record enforced repository signature checking"), err)
	}
	return os.Remove(marker)
}

func (p *Provider) verifyZypperRPM(ctx context.Context, directory, path string, source *agentv1.NativePackageSource) error {
	for _, keydb := range []string{filepath.Join(directory, "rpmkeys"), ""} {
		args := []string{"--checksig", "--verbose", path}
		if keydb != "" {
			args = append([]string{"--dbpath", keydb}, args...)
		}
		result, err := p.run(ctx, "/usr/bin/rpmkeys", args, "/", nil)
		if err := checkRPMSignature(result, err, source.GetRpmSigningKeyFingerprint()); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) planZypper(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, db *database, source *agentv1.NativePackageSource) ([]*resourcev1.PackageTransactionEntry, error) {
	// The existing RPM preparation binds one key by full fingerprint, creates
	// an isolated verification database and writes the sole approved repository.
	// The zypper adapter models exactly one signed-metadata repository.
	if rpm := source.GetRepository().GetRpm(); len(rpm.GetAdditionalRepositories()) != 0 || !rpm.GetRequireMetadataSignature() {
		return nil, fmt.Errorf("%w: zypper sources need one repository with signed metadata", ErrUnsupported)
	}
	if _, err := p.prepareDNF(ctx, directory, source); err != nil {
		return nil, err
	}
	repo := source.GetRepository().GetRpm()
	_, current, err := readPin(zypperLocksPath)
	if err != nil {
		return nil, err
	}
	// The signed transaction supplies the exact target. Its private candidate
	// drops only this resource's lock, otherwise a != new-version lock also
	// freezes the old installed version and makes an authorized upgrade fail.
	unlocked := proto.CloneOf(d)
	unlocked.Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	locks, err := renderRollingPin(packageRef(d.GetPackage()), unlocked, current, false)
	if err != nil {
		return nil, err
	}
	if err := atomicFile(filepath.Join(directory, "locks"), locks, 0600); err != nil {
		return nil, err
	}
	config := "[main]\nconfigdir=" + directory + "\nreposdir=" + filepath.Join(directory, "repos") + "\ncachedir=" + filepath.Join(directory, "cache") + "\nlocksfile.path=" + filepath.Join(directory, "locks") + "\nlocksfile.apply=true\nhistory.logfile=" + filepath.Join(directory, "history") + "\ngpgcheck=true\nrepo_gpgcheck=true\npkg_gpgcheck=true\nsolver.onlyRequires=true\nsolver.cleandepsOnRemove=false\nsolver.allowVendorChange=false\ndownload.use_deltarpm=false\n"
	if err := atomicFile(filepath.Join(directory, "zypp.conf"), []byte(config), 0600); err != nil {
		return nil, err
	}
	// Zypper must use an already provisioned trusted key. There is deliberately
	// no auto-import, unsigned-repository acceptance or signature bypass.
	if _, err := p.run(ctx, p.managerPath, zypperArgs(directory, "refresh", "--force"), "/", zypperEnv(directory, true)); err != nil {
		return nil, err
	}
	raw := filepath.Join(directory, "cache", "raw", repo.GetNativeId())
	if err := consumeZyppGPGCheckMarker(raw); err != nil {
		return nil, err
	}
	repomd := filepath.Join(raw, "repodata", "repomd.xml")
	if err := os.Rename(repomd+".asc", repomd+".sig"); err != nil {
		return nil, err
	}
	if err := p.verifyRollingSignature(ctx, directory, repomd, source.GetRpmSigningKeyFingerprint()); err != nil {
		return nil, err
	}
	target, err := p.nativeTarget(db, d.GetPackage())
	if err != nil {
		return nil, err
	}
	if nativeMatches(d, db.records[packageKey(target)]) {
		return nil, nil
	}
	result, err := p.run(ctx, p.managerPath, zypperArgs(directory, zypperDryRun(d, target)...), "/", zypperEnv(directory, true))
	if err != nil {
		return nil, err
	}
	entries, declared, err := p.parseZypperSummary(result.stdout, d, db, repo.GetNativeId())
	if err != nil {
		return nil, err
	}
	if err := checkDownloadBudget(directory, declared, p.stagingMax); err != nil {
		return nil, err
	}
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return entries, nil
	}
	// The staging unit's root filesystem is read-only (ProtectSystem=strict),
	// and zypper refuses even "install --download-only" there with exit 5
	// ("target filesystem is mounted as read-only"; observed on Tumbleweed).
	// "zypper download" fetches exactly the solved NEVRAs into the private
	// cache without touching the target.
	download := []string{"download", "--"}
	for _, entry := range entries {
		if entry.GetAfter() != nil {
			download = append(download, entry.GetPackage().GetNativeName()+"."+entry.GetPackage().GetArchitecture()+"="+nativeVersion(entry.GetAfter()))
		}
	}
	if _, err := p.run(ctx, p.managerPath, zypperArgs(directory, download...), "/", zypperEnv(directory, true)); err != nil {
		return nil, err
	}
	var total uint64
	found := make(map[string]bool)
	err = filepath.WalkDir(filepath.Join(directory, "cache", "packages"), func(path string, file fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if file.IsDir() {
			return nil
		}
		if !strings.HasSuffix(file.Name(), ".rpm") {
			return nil
		}
		if err := p.verifyZypperRPM(ctx, directory, path, source); err != nil {
			return err
		}
		result, err := p.run(ctx, "/usr/bin/rpm", []string{"-qp", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", path}, "/", nil)
		if err != nil || len(result.stderr) != 0 {
			return errors.Join(err, errors.New("packageprovider: staged RPM identity probe failed"))
		}
		packages, err := parseDatabase(result.stdout, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
		if err != nil || len(packages.records) != 1 {
			return errors.Join(err, ErrConflict)
		}
		for key, record := range packages.records {
			for _, entry := range entries {
				if packageKey(entry.GetPackage()) != key || !proto.Equal(entry.GetAfter(), record.GetVersion()) {
					continue
				}
				if found[key] {
					return ErrConflict
				}
				found[key] = true
				entry.Artifact, err = artifactFor(path)
				if err != nil {
					return err
				}
				total += entry.GetArtifact().GetSizeBytes()
				if total > declared {
					return errors.New("packageprovider: zypper archive bytes exceed native declaration")
				}
				return os.Rename(path, rollingArtifactPath(directory, entry))
			}
		}
		return errors.New("packageprovider: zypper downloaded unmanifested package")
	})
	if err != nil {
		return nil, err
	}
	if total != declared || len(found) != countInbound(entries) {
		return nil, fmt.Errorf("packageprovider: incomplete zypper download closure: bytes %d/%d", total, declared)
	}
	return entries, nil
}

func sameRollingSelection(a, b []*resourcev1.PackageTransactionEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for _, entry := range a {
		found := false
		for _, other := range b {
			if proto.Equal(entry.GetPackage(), other.GetPackage()) && proto.Equal(entry.GetBefore(), other.GetBefore()) && proto.Equal(entry.GetAfter(), other.GetAfter()) && entry.GetOperation() == other.GetOperation() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// zypperCommitRepos names an always-empty private repository directory. A
// commit must see only the staged RPM files and the installed system, yet
// --disable-repositories also disables zypper's command-line RPM repository
// (exit 104: "_tmpRPMcache_:<name>=<evr>" not found), so commits replace the
// staging repository directory with this empty one instead.
const zypperCommitRepos = "commit-repos"

func zypperCommitArgs(directory string, d *resourcev1.NativePackageDesired, target *resourcev1.PackageIdentity, entries []*resourcev1.PackageTransactionEntry, preview bool) []string {
	var paths []string
	for _, entry := range entries {
		if entry.GetArtifact() != nil {
			paths = append(paths, rollingArtifactPath(directory, entry))
		}
	}
	args := []string{"install", "--no-recommends", "--no-allow-vendor-change"}
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		args, paths = []string{"remove"}, []string{zypperTarget(d, target)}
	}
	if preview {
		args = append(args, "--dry-run")
	}
	args = append(args, "--")
	return append([]string{"--non-interactive", "--xmlout", "--no-refresh", "--reposd-dir", filepath.Join(directory, zypperCommitRepos), "--cache-dir", filepath.Join(directory, "cache")}, append(args, paths...)...)
}

// emptyZypperCommitRepos creates or admits the private commit repository
// directory only as a real, empty directory.
func emptyZypperCommitRepos(directory string) error {
	path := filepath.Join(directory, zypperCommitRepos)
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("packageprovider: zypper commit repository directory %s is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("packageprovider: zypper commit repository directory %s is not empty", path)
	}
	return nil
}

func (p *Provider) previewZypperCommit(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, entries []*resourcev1.PackageTransactionEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if err := emptyZypperCommitRepos(directory); err != nil {
		return err
	}
	db, err := p.database(ctx)
	if err != nil {
		return err
	}
	target, err := p.nativeTarget(db, d.GetPackage())
	if err != nil {
		return err
	}
	result, err := p.run(ctx, p.managerPath, zypperCommitArgs(directory, d, target, entries, true), "/", zypperEnv(directory, false))
	if err != nil {
		return err
	}
	selected, _, err := p.parseZypperSummary(result.stdout, d, db, "")
	if err != nil {
		return err
	}
	if !sameRollingSelection(selected, entries) {
		return ErrConflict
	}
	return nil
}

func (p *Provider) commitZypper(ctx context.Context, directory string, d *resourcev1.NativePackageDesired, target *resourcev1.PackageIdentity, entries []*resourcev1.PackageTransactionEntry) error {
	if err := emptyZypperCommitRepos(directory); err != nil {
		return err
	}
	_, err := commitNative(ctx, p.managerPath, zypperCommitArgs(directory, d, target, entries, false), "/", zypperEnv(directory, false))
	return err
}
