// SPDX-License-Identifier: Apache-2.0

// Package offlinebundle builds, verifies and imports signed air-gap bundles.
//
// A bundle is a directory with a fixed layout: release/ (a verified release
// export with per-artifact SBOM/provenance statements), repositories/ (signed
// APT and RPM repositories, plus pacman where the release carries Arch packages,
// built from those packages), updates/ (offline-signed
// TUF root chain, targets metadata, targets and paused channel proposals) and
// advisories/ (authenticated vendor feed snapshots). bundle.json is a strict
// protobuf OfflineBundleManifest naming every file's SHA-256 and size;
// bundle.json.dsse is its DSSE signature by a dedicated, independently pinned
// Ed25519 bundle-signing key.
//
// Import never trusts a bundle in place: it authenticates the manifest, copies
// every file into private server-owned staging while hashing it, re-verifies
// release attestations with the pinned release key, verifies TUF metadata from
// the deployment's authenticated release root, and admits the sequence through
// the PostgreSQL replay ledger before any publication. It does not install
// packages, change host trust, contact a network, or extend TUF/advisory expiry.
package offlinebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	bundlev1 "lindm/gen/lindm/bundle/v1"
)

const (
	// ManifestName and EnvelopeName are the only unlisted files in a bundle.
	ManifestName = "bundle.json"
	EnvelopeName = "bundle.json.dsse"
	releaseDir   = "release"
	reposDir     = "repositories"
	updatesDir   = "updates"
	advisoryDir  = "advisories"
	// maxClockSkew tolerates station/site clock difference for creation time
	// only; expiry is never extended.
	maxClockSkew = 5 * time.Minute
	maxEntries   = 70000
)

var (
	// ErrExpired means the signed validity window has ended.
	ErrExpired = errors.New("offline_bundle_expired")
	// ErrNotYetValid means the bundle claims creation in the future.
	ErrNotYetValid = errors.New("offline_bundle_not_yet_valid")
	// ErrReplayed means an equal or newer sequence was already admitted.
	ErrReplayed = errors.New("offline_bundle_replayed")
	// ErrEquivocation means a different manifest reuses an admitted sequence.
	ErrEquivocation = errors.New("offline_bundle_equivocation")
	// ErrCorrupt means the tree differs from the signed manifest.
	ErrCorrupt = errors.New("offline_bundle_corrupt")
)

// Bundle is an authenticated manifest bound to one directory. Its files are
// trusted only after VerifyFiles or Stage has hashed them.
type Bundle struct {
	Directory      string
	Manifest       *bundlev1.OfflineBundleManifest
	ManifestSHA256 [sha256.Size]byte
	files          map[string]*bundlev1.BundleFile
}

// Open authenticates bundle.json with the pinned key, validates the manifest
// and requires the directory tree to contain exactly the listed regular files
// with their signed sizes. Content digests are checked by VerifyFiles/Stage.
func Open(ctx context.Context, directory string, verifier *Verifier, now time.Time) (_ *Bundle, err error) {
	if verifier == nil {
		return nil, errors.New("offlinebundle: pinned verifier required")
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("offlinebundle: bundle must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	envelope, err := readRootFile(root, EnvelopeName, 2*maxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("read bundle signature: %w", err)
	}
	payload, err := verifier.open(envelope)
	if err != nil {
		return nil, err
	}
	document, err := readRootFile(root, ManifestName, maxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}
	if string(document) != string(payload) {
		return nil, errors.New("offlinebundle: manifest differs from its signed payload")
	}
	manifest := new(bundlev1.OfflineBundleManifest)
	if err := protojson.Unmarshal(payload, manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	if err := protovalidate.Validate(manifest); err != nil {
		return nil, fmt.Errorf("validate bundle manifest: %w", err)
	}
	if manifest.GetSigningKeyId() != verifier.id {
		return nil, errors.New("offlinebundle: manifest names a different signing key")
	}
	if manifest.GetCreatedAt().AsTime().After(now.Add(maxClockSkew)) {
		return nil, ErrNotYetValid
	}
	if !now.Before(manifest.GetExpiresAt().AsTime()) {
		return nil, ErrExpired
	}
	b := &Bundle{Directory: directory, Manifest: manifest, ManifestSHA256: sha256.Sum256(payload), files: make(map[string]*bundlev1.BundleFile, len(manifest.GetFiles()))}
	for _, file := range manifest.GetFiles() {
		if b.files[file.GetPath()] != nil {
			return nil, fmt.Errorf("%w: duplicate path %s", ErrCorrupt, file.GetPath())
		}
		b.files[file.GetPath()] = file
	}
	if err := b.checkLayout(); err != nil {
		return nil, err
	}
	seen := 0
	if err := walkTree(ctx, root, ".", func(name string, entry fs.DirEntry) error {
		if name == ManifestName || name == EnvelopeName {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file or directory", ErrCorrupt, name)
		}
		listed := b.files[name]
		if listed == nil {
			return fmt.Errorf("%w: unlisted file %s", ErrCorrupt, name)
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != listed.GetSize() {
			return fmt.Errorf("%w: size or type of %s differs", ErrCorrupt, name)
		}
		seen++
		return nil
	}); err != nil {
		return nil, err
	}
	if seen != len(b.files) {
		return nil, fmt.Errorf("%w: %d listed files are missing", ErrCorrupt, len(b.files)-seen)
	}
	return b, nil
}

// checkLayout binds the manifest's typed claims to listed files.
func (b *Bundle) checkLayout() error {
	required := []string{releaseDir + "/release.json", releaseDir + "/release.json.dsse", fmt.Sprintf("%s/metadata/%d.targets.json", updatesDir, b.Manifest.GetUpdates().GetTargetsVersion())}
	if b.Manifest.GetUpdates().GetRootVersion() < b.Manifest.GetUpdates().GetFirstRootVersion() {
		return fmt.Errorf("%w: TUF root chain is inverted", ErrCorrupt)
	}
	for version := b.Manifest.GetUpdates().GetFirstRootVersion(); version <= b.Manifest.GetUpdates().GetRootVersion(); version++ {
		required = append(required, fmt.Sprintf("%s/metadata/%d.root.json", updatesDir, version))
	}
	for _, ring := range b.Manifest.GetUpdates().GetChannels() {
		required = append(required, updatesDir+"/channels/"+ring+".json")
	}
	repositories := map[string]bool{}
	for _, repository := range b.Manifest.GetRepositories() {
		directory := repositoryPath(repository)
		if repositories[directory] {
			return fmt.Errorf("%w: duplicate repository %s", ErrCorrupt, directory)
		}
		repositories[directory] = true
		switch repository.GetFormat() {
		case "deb":
			required = append(required, directory+"/dists/stable/InRelease")
		case "arch":
			required = append(required, directory+"/lindm.db", directory+"/lindm.db.sig")
		default:
			required = append(required, directory+"/repodata/repomd.xml", directory+"/repodata/repomd.xml.asc")
		}
	}
	feeds := map[string]bool{}
	for _, snapshot := range b.Manifest.GetAdvisories() {
		id := snapshot.GetSource().GetId()
		if feeds[id] || id != path.Base(id) || strings.HasPrefix(id, ".") {
			return fmt.Errorf("%w: invalid or duplicate advisory feed %q", ErrCorrupt, id)
		}
		feeds[id] = true
		required = append(required, advisoryDir+"/"+id)
	}
	for _, name := range required {
		if b.files[name] == nil {
			return fmt.Errorf("%w: manifest omits required %s", ErrCorrupt, name)
		}
	}
	return nil
}

func repositoryPath(repository *bundlev1.NativeRepository) string {
	kind := "apt"
	if format := repository.GetFormat(); format == "rpm" || format == "arch" {
		kind = format
	}
	return reposDir + "/" + repository.GetArchitecture() + "/" + kind
}

// VerifyFiles hashes every listed file in place. Use Stage before acting on a
// bundle: an in-place check cannot prevent later modification.
func (b *Bundle) VerifyFiles(ctx context.Context) (err error) {
	root, err := os.OpenRoot(b.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	digest := sha256.New()
	for _, file := range b.Manifest.GetFiles() {
		if err := copyVerified(ctx, root, file, io.Discard, digest); err != nil {
			return err
		}
	}
	return nil
}

// Stage copies every listed file into a new private directory while hashing it
// and returns a Bundle bound to the copy. Only staged bytes are imported.
func (b *Bundle) Stage(ctx context.Context, destination string) (_ *Bundle, err error) {
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(destination))
		}
	}()
	source, err := os.OpenRoot(b.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	digest := sha256.New()
	directories := map[string]bool{}
	for _, file := range b.Manifest.GetFiles() {
		target := filepath.Join(destination, filepath.FromSlash(file.GetPath()))
		parent := filepath.Dir(target)
		if !directories[parent] {
			if err := os.MkdirAll(parent, 0700); err != nil {
				return nil, err
			}
			directories[parent] = true
		}
		if err := stageFile(ctx, source, file, target, digest); err != nil {
			return nil, err
		}
	}
	for directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return nil, err
		}
	}
	staged := &Bundle{Directory: destination, Manifest: b.Manifest, ManifestSHA256: b.ManifestSHA256, files: b.files}
	return staged, syncDirectory(destination)
}

func stageFile(ctx context.Context, source *os.Root, file *bundlev1.BundleFile, target string, digest hash.Hash) (err error) {
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	if err := copyVerified(ctx, source, file, output, digest); err != nil {
		return err
	}
	return output.Sync()
}

func copyVerified(ctx context.Context, root *os.Root, file *bundlev1.BundleFile, output io.Writer, digest hash.Hash) (err error) {
	input, err := root.Open(file.GetPath())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not regular", ErrCorrupt, file.GetPath())
	}
	digest.Reset()
	n, err := io.Copy(io.MultiWriter(output, digest), io.LimitReader(contextReader{ctx, input}, file.GetSize()+1))
	if err != nil {
		return err
	}
	if n != file.GetSize() || hex.EncodeToString(digest.Sum(nil)) != file.GetSha256() {
		return fmt.Errorf("%w: digest of %s differs from the signed manifest", ErrCorrupt, file.GetPath())
	}
	return nil
}

// Path resolves a manifest-relative path inside the bundle directory.
func (b *Bundle) Path(name string) string {
	return filepath.Join(b.Directory, filepath.FromSlash(name))
}

func walkTree(ctx context.Context, root *os.Root, name string, visit func(string, fs.DirEntry) error) error {
	count := 0
	var walk func(string) error
	walk = func(directory string) (err error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := root.Open(directory)
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(-1)
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		for _, entry := range entries {
			count++
			if count > maxEntries {
				return fmt.Errorf("%w: entry bound exceeded", ErrCorrupt)
			}
			child := entry.Name()
			if directory != "." {
				child = directory + "/" + entry.Name()
			}
			if entry.IsDir() {
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			if err := visit(child, entry); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(name)
}

func readRootFile(root *os.Root, name string, limit int64) (data []byte, err error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("offlinebundle: bounded regular file required")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return readLimited(f, limit)
}

func syncDirectory(directory string) (err error) {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
