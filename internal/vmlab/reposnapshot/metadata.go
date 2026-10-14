// SPDX-License-Identifier: Apache-2.0

package reposnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
	"lindm/internal/platform"
)

type checksum struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}
type location struct {
	Href string `xml:"href,attr"`
}
type metadataFile struct {
	Type     string   `xml:"type,attr"`
	Checksum checksum `xml:"checksum"`
	Location location `xml:"location"`
	Size     uint64   `xml:"size"`
}
type rpmPackage struct {
	Name     string   `xml:"name"`
	Arch     string   `xml:"arch"`
	Checksum checksum `xml:"checksum"`
	Location location `xml:"location"`
	Size     struct {
		Package uint64 `xml:"package,attr"`
	} `xml:"size"`
}
type repomd struct {
	Revision string         `xml:"revision"`
	Data     []metadataFile `xml:"data"`
	Tags     []string       `xml:"tags>content"`
	Distro   string         `xml:"tags>distro"`
	Repo     string         `xml:"tags>repo"`
}

func checksumHash(kind string) (hash.Hash, error) {
	switch kind {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported signed digest %q", kind)
	}
}

func verifySignature(ctx context.Context, key, signature, data *os.File, signer string) (err error) {
	if err := verifyKeyDescriptor(ctx, key, signer); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "lindm-repository-signature-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	decoded, stderr := nativeexec.NewBuffer(int(maxTrustBytes)), nativeexec.NewBuffer(64<<10)
	err = labexec.Run(ctx, labexec.Command{Path: "gpg", Args: []string{"--no-options", "--batch", "--homedir", dir, "--dearmor", "--output", "-", "/proc/self/fd/3"}, Files: []*os.File{key}, Stdout: decoded, Stderr: stderr, Timeout: 30 * time.Second})
	if err != nil || decoded.Truncated() || stderr.Truncated() || decoded.Len() == 0 {
		return errors.Join(err, errors.New("decode bounded pinned repository key"))
	}
	digest := sha256.Sum256(decoded.Bytes())
	keyring, err := newSealedFile(bytes.NewReader(decoded.Bytes()), uint64(decoded.Len()), hex.EncodeToString(digest[:]))
	if err != nil {
		return err
	}
	defer func() { _ = keyring.Close() }()
	out, stderr := nativeexec.NewBuffer(64<<10), nativeexec.NewBuffer(64<<10)
	err = labexec.Run(ctx, labexec.Command{Path: "gpgv", Args: []string{"--homedir", dir, "--keyring", "/proc/self/fd/3", "--status-fd", "1", "/proc/self/fd/4", "/proc/self/fd/5"}, Files: []*os.File{keyring, signature, data}, Stdout: out, Stderr: stderr, Timeout: 30 * time.Second})
	if err != nil || out.Truncated() || stderr.Truncated() {
		return errors.Join(err, errors.New("verify bounded sealed repomd signature"))
	}
	valid := false
	for _, line := range strings.Split(out.String(), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "[GNUPG:]" {
			continue
		}
		switch f[1] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "KEYEXPIRED", "SIGEXPIRED", "NO_PUBKEY", "FAILURE", "ERROR", "NODATA":
			return errors.New("repository signature rejected")
		case "VALIDSIG":
			if valid || len(f) < 11 || (f[2] != signer && (len(f) < 12 || f[11] != signer)) || (f[9] != "8" && f[9] != "9" && f[9] != "10") {
				return errors.New("repository signature pin/hash mismatch")
			}
			valid = true
		}
	}
	if !valid {
		return errors.New("no valid repository signature")
	}
	return nil
}

func readMetadata(ctx context.Context, rootPath string, m *labv1.RepositorySnapshotManifest) (*repomd, error) {
	root, err := openSnapshotRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return readMetadataFrom(ctx, root, m)
}

func readMetadataFrom(ctx context.Context, root *os.File, m *labv1.RepositorySnapshotManifest) (*repomd, error) {
	recipe, ok := platform.RepositorySnapshotRecipes[m.Distribution]
	if !ok {
		return nil, errors.New("repository snapshot backend is not maintained for distribution")
	}
	if recipe.Signer != m.SignerFingerprint {
		return nil, errors.New("repository signer is not registry pinned")
	}
	source, ok := recipe.Sources[m.Architecture]
	if !ok {
		return nil, errors.New("unsupported repository architecture")
	}
	if strings.Contains(source, "%s") {
		source = fmt.Sprintf(source, strings.ReplaceAll(m.SnapshotDate, "-", ""))
	}
	if m.SourceRootUrl != source {
		return nil, errors.New("repository source differs from registry")
	}
	if _, err := time.Parse("2006-01-02", m.SnapshotDate); err != nil {
		return nil, err
	}
	var snapshots [3]*os.File
	defer func() {
		for _, f := range snapshots {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for i, name := range []string{"repodata/repomd.xml.key", "repodata/repomd.xml.asc", "repodata/repomd.xml"} {
		item, err := retainedFile(m, name)
		if err != nil {
			return nil, err
		}
		if i == 2 && item.Sha256 != m.RepomdSha256 {
			return nil, errors.New("repomd pin differs from manifest")
		}
		snapshots[i], err = sealRetained(root, item, maxTrustBytes)
		if err != nil {
			return nil, err
		}
	}
	if err := verifySignature(ctx, snapshots[0], snapshots[1], snapshots[2], m.SignerFingerprint); err != nil {
		return nil, err
	}
	if _, err := snapshots[2].Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var md repomd
	if err := xml.NewDecoder(snapshots[2]).Decode(&md); err != nil {
		return nil, err
	}
	if len(md.Data) == 0 || len(md.Data) > 128 {
		return nil, errors.New("repomd metadata count bound")
	}
	date := strings.ReplaceAll(m.SnapshotDate, "-", "")
	if !strings.HasSuffix(md.Repo, "/"+date) || !strings.HasSuffix(md.Distro, " "+date) {
		return nil, errors.New("signed repository snapshot date drift")
	}
	seen := make(map[string]bool, len(md.Data))
	for _, d := range md.Data {
		if !safePath(d.Location.Href) || !strings.HasPrefix(d.Location.Href, "repodata/") || d.Size == 0 || d.Size > HardMaxBytes || seen[d.Location.Href] {
			return nil, errors.New("invalid or duplicated signed metadata path/size")
		}
		seen[d.Location.Href] = true
	}
	return &md, nil
}

func primaryPackages(rootPath string, m *labv1.RepositorySnapshotManifest, md *repomd, visit func(rpmPackage) error) error {
	root, err := openSnapshotRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return primaryPackagesFrom(root, m, md, visit)
}

func primaryPackagesFrom(root *os.File, m *labv1.RepositorySnapshotManifest, md *repomd, visit func(rpmPackage) error) error {
	var primary *metadataFile
	for i := range md.Data {
		if md.Data[i].Type == "primary" {
			if primary != nil {
				return errors.New("duplicate primary metadata")
			}
			primary = &md.Data[i]
		}
	}
	if primary == nil || !strings.HasSuffix(primary.Location.Href, ".zst") {
		return errors.New("native capture requires signed zstd primary metadata")
	}
	item, err := retainedFile(m, primary.Location.Href)
	if err != nil {
		return err
	}
	if item.SizeBytes != primary.Size {
		return errors.New("primary signed size differs from manifest")
	}
	file, err := sealRetained(root, item, maxPrimaryBytes)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	signedHash, err := checksumHash(primary.Checksum.Type)
	if err != nil {
		return err
	}
	if _, err := io.Copy(signedHash, file); err != nil {
		return err
	}
	if hex.EncodeToString(signedHash.Sum(nil)) != primary.Checksum.Value {
		return errors.New("sealed primary differs from signed checksum")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	z, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(512<<20))
	if err != nil {
		return err
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: 1 << 30}
	decoder := xml.NewDecoder(limited)
	count := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}
		count++
		if count > 500000 {
			return errors.New("primary package count bound")
		}
		var p rpmPackage
		if err := decoder.DecodeElement(&p, &start); err != nil {
			return err
		}
		if err := visit(p); err != nil {
			return err
		}
	}
	if limited.N == 0 {
		return errors.New("primary expansion exceeds bound")
	}
	return nil
}

func validateRepository(ctx context.Context, rootPath string, m *labv1.RepositorySnapshotManifest) error {
	root, err := openSnapshotRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return validateRepositoryFrom(ctx, root, m)
}

func validateRepositoryFrom(ctx context.Context, root *os.File, m *labv1.RepositorySnapshotManifest) error {
	md, err := readMetadataFrom(ctx, root, m)
	if err != nil {
		return err
	}
	retained := make(map[string]*labv1.RepositorySnapshotFile, len(m.Files))
	checked := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		retained[f.Path] = f
	}
	for _, name := range []string{"repodata/repomd.xml", "repodata/repomd.xml.asc", "repodata/repomd.xml.key"} {
		checked[name] = true
	}
	keys, err := repositoryKeys(md)
	if err != nil {
		return err
	}
	for name, pin := range keys {
		item := retained[name]
		if item == nil {
			return errors.New("missing authenticated RPM trust key")
		}
		if err := verifyRPMKeyFrom(ctx, root, item, pin); err != nil {
			return err
		}
		checked[name] = true
	}
	for _, required := range []string{"evidence/solver.txt", "evidence/signatures.txt"} {
		if retained[required] == nil {
			return fmt.Errorf("missing closure evidence %s", required)
		}
	}
	for _, d := range md.Data {
		item := retained[d.Location.Href]
		if item == nil {
			return fmt.Errorf("missing signed metadata %s", d.Location.Href)
		}
		if d.Type != "primary" {
			if err := checkRetained(root, item, &d.Checksum, d.Size); err != nil {
				return err
			}
		}
		checked[d.Location.Href] = true
	}
	matched := map[string]bool{}
	if err := primaryPackagesFrom(root, m, md, func(p rpmPackage) error {
		item := retained[p.Location.Href]
		if item == nil {
			return nil
		}
		if matched[p.Location.Href] {
			return errors.New("duplicate retained RPM in primary")
		}
		if p.Arch != m.Architecture && p.Arch != "noarch" {
			return errors.New("foreign architecture in closure")
		}
		if err := checkRetained(root, item, &p.Checksum, p.Size.Package); err != nil {
			return err
		}
		matched[p.Location.Href] = true
		checked[p.Location.Href] = true
		return nil
	}); err != nil {
		return err
	}
	for _, item := range m.Files {
		if strings.HasSuffix(item.Path, ".rpm") && !matched[item.Path] {
			return errors.New("RPM absent from authenticated primary")
		}
		if !checked[item.Path] {
			if err := checkRetained(root, item, nil, item.SizeBytes); err != nil {
				return err
			}
		}
	}
	return nil
}
