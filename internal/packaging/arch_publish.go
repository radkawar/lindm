//go:build linux

package packaging

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// ArchRequest publishes signed packages, each with an adjacent .sig. One
// version of each product is allowed in a repository, as pacman's sync DB is
// indexed by product name. OutputDir must be an existing private directory.
type ArchRequest struct {
	OutputDir       string
	Packages        []string
	Signer          SigningKey
	SourceDateEpoch int64
}

// ArchRepository is a pacman sync database generated directly in repo-add's
// tar/desc format. It never modifies a host keyring or pacman configuration.
type ArchRepository struct {
	Root               string        `json:"root"`
	Name               string        `json:"name"`
	Database           string        `json:"database"`
	DatabaseSignature  string        `json:"database_signature"`
	PublicKey          string        `json:"public_key"`
	PublicKeyArmor     string        `json:"public_key_armor"`
	Fingerprint        string        `json:"fingerprint"`
	Custody            Custody       `json:"custody"`
	PackagesVerified   bool          `json:"packages_verified"`
	RepoMetadataSigned bool          `json:"repo_metadata_signed"`
	Tools              []ToolVersion `json:"tools"`
}

// ArchRepoConfig requires trusted signatures on both packages and the database.
// The caller must import and locally trust Fingerprint in the guest's isolated
// pacman keyring first. This function does not establish that trust itself.
func ArchRepoConfig(repoRoot string) (string, error) {
	root, err := cleanAbsolute(repoRoot)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(root, "\r\n#$") {
		return "", ErrUnsafePath
	}
	return "[lindm]\nSigLevel = PackageRequired DatabaseRequired TrustedOnly\nServer = file://" + root + "\n", nil
}

// PublishArch snapshots and verifies package signatures before reading their
// metadata, then signs and verifies the deterministic sync database. Unsigned,
// tampered and differently signed input never enters a published repository.
func PublishArch(ctx context.Context, req ArchRequest) (result *ArchRepository, err error) {
	if len(req.Packages) == 0 || len(req.Packages) > 8 {
		return nil, fmt.Errorf("%w: Arch publication requires one to eight packages", ErrArtifact)
	}
	out, err := openPrivate(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	epoch, err := epochOf(req.SourceDateEpoch)
	if err != nil {
		return nil, err
	}
	work, cleanup, err := privateWork(req.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, cleanup())
		if err != nil {
			result = nil
		}
	}()
	key, guard, err := validateSigner(ctx, work, req.Signer)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, guard.close(ctx, work))
		if err != nil {
			result = nil
		}
	}()
	repo := filepath.Join(work, "arch")
	if err := mkdir(repo, epoch); err != nil {
		return nil, err
	}
	public, armor, err := exportPublicKeys(ctx, work, key, repo)
	if err != nil {
		return nil, err
	}
	var descriptions []archMember
	seen := make(map[string]bool)
	var architecture string
	for _, input := range req.Packages {
		name := filepath.Base(input)
		if !strings.HasSuffix(name, ".pkg.tar.zst") {
			return nil, fmt.Errorf("%w: expected .pkg.tar.zst", ErrArtifact)
		}
		dest := filepath.Join(repo, name)
		if err := archCopyInput(input, dest, maxBinaryBytes+(8<<20), epoch); err != nil {
			return nil, err
		}
		if err := archCopyInput(input+".sig", dest+".sig", 64<<10, epoch); err != nil {
			return nil, err
		}
		if err := verifyArchSignature(ctx, work, dest, public); err != nil {
			return nil, err
		}
		info, err := readArchInfo(dest)
		if err != nil {
			return nil, err
		}
		product, version, arch := info["pkgname"][0], info["pkgver"][0], info["arch"][0]
		if seen[product] || (architecture != "" && architecture != arch) {
			return nil, fmt.Errorf("%w: duplicate products or mixed Arch architectures", ErrArtifact)
		}
		seen[product], architecture = true, arch
		if name != product+"-"+version+"-"+arch+".pkg.tar.zst" {
			return nil, fmt.Errorf("%w: package filename differs from .PKGINFO", ErrArtifact)
		}
		sum, size, err := hashFile(dest)
		if err != nil {
			return nil, err
		}
		sig, err := os.ReadFile(dest + ".sig")
		if err != nil {
			return nil, err
		}
		var desc strings.Builder
		for _, field := range []struct {
			key    string
			values []string
		}{
			{"FILENAME", []string{name}}, {"NAME", []string{product}}, {"BASE", info["pkgbase"]}, {"VERSION", []string{version}},
			{"DESC", info["pkgdesc"]}, {"CSIZE", []string{strconv.FormatInt(size, 10)}}, {"ISIZE", info["size"]},
			{"SHA256SUM", []string{sum}}, {"PGPSIG", []string{base64.StdEncoding.EncodeToString(sig)}}, {"URL", info["url"]},
			{"LICENSE", info["license"]}, {"ARCH", []string{arch}}, {"BUILDDATE", info["builddate"]}, {"PACKAGER", info["packager"]},
			{"DEPENDS", info["depend"]}, {"OPTDEPENDS", info["optdepend"]}, {"PROVIDES", info["provides"]}, {"CONFLICTS", info["conflict"]}, {"REPLACES", info["replaces"]},
		} {
			if len(field.values) > 0 {
				fmt.Fprintf(&desc, "%%%s%%\n%s\n\n", field.key, strings.Join(field.values, "\n"))
			}
		}
		descriptions = append(descriptions, archMemoryMember(product+"-"+version+"/desc", []byte(desc.String())))
	}
	sort.Slice(descriptions, func(i, j int) bool { return descriptions[i].name < descriptions[j].name })
	database := filepath.Join(repo, "lindm.db")
	if err := writeArchDatabase(database, descriptions, epoch); err != nil {
		return nil, err
	}
	if err := signArchFile(ctx, work, database, key, epoch); err != nil {
		return nil, err
	}
	if err := verifyArchSignature(ctx, work, database, public); err != nil {
		return nil, err
	}
	if err := guard.close(ctx, work); err != nil {
		return nil, err
	}
	final := filepath.Join(req.OutputDir, "arch")
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: Arch output already exists or is inaccessible", ErrArtifact)
	}
	if err := os.Rename(repo, final); err != nil {
		return nil, err
	}
	if err := syncDir(req.OutputDir); err != nil {
		return nil, err
	}
	return &ArchRepository{Root: final, Name: "lindm", Database: filepath.Join(final, filepath.Base(database)), DatabaseSignature: filepath.Join(final, filepath.Base(database)+".sig"), PublicKey: filepath.Join(final, filepath.Base(public)), PublicKeyArmor: filepath.Join(final, filepath.Base(armor)), Fingerprint: key.Fingerprint, Custody: key.Custody, PackagesVerified: true, RepoMetadataSigned: true, Tools: []ToolVersion{archBuildToolVersion(), toolVersion(ctx, work, "gpg", "--version"), toolVersion(ctx, work, "gpgv", "--version")}}, nil
}

func archCopyInput(src, dst string, limit, epoch int64) error {
	// Reuse the checked, nonblocking, no-symlink bounded snapshot used by
	// rejection fixtures; a FIFO or parent symlink must never reach GPG.
	if err := rejectionCopyPath(src, dst, limit); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o644); err != nil {
		return err
	}
	stamp := time.Unix(epoch, 0)
	return os.Chtimes(dst, stamp, stamp)
}

func writeArchDatabase(path string, members []archMember, epoch int64) (err error) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: m.mode, Size: m.size, ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return errors.Join(err, tw.Close(), gz.Close())
		}
		if _, err := tw.Write(m.data); err != nil {
			return errors.Join(err, tw.Close(), gz.Close())
		}
	}
	return errors.Join(tw.Close(), gz.Close(), out.Chmod(0o644), out.Sync())
}

// readArchInfo accepts only the bounded archive profile emitted by this package.
// All archive bytes are streamed; only .PKGINFO is retained in memory.
func readArchInfo(filename string) (map[string][]string, error) {
	file, err := openRegular(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	zr, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	limited := &io.LimitedReader{R: zr, N: maxBinaryBytes + (16 << 20)}
	tr := tar.NewReader(limited)
	seen := make(map[string]bool)
	var info map[string][]string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: Arch archive: %w", ErrArtifact, err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\x00\r\n") || seen[name] || len(seen) >= 4096 || h.Uid != 0 || h.Gid != 0 || (h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg) {
			return nil, fmt.Errorf("%w: unsafe Arch archive member", ErrArtifact)
		}
		seen[name] = true
		if name == ".PKGINFO" {
			if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 64<<10 {
				return nil, fmt.Errorf("%w: invalid .PKGINFO size", ErrArtifact)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			info, err = parseArchInfo(data)
			if err != nil {
				return nil, err
			}
		}
	}
	// Consume the frame footer/checksum as tar may stop before zstd does.
	if _, err := io.Copy(io.Discard, limited); err != nil || limited.N <= 0 {
		return nil, fmt.Errorf("%w: Arch decompression bound/checksum: %v", ErrArtifact, err)
	}
	for _, required := range []string{".PKGINFO", ".MTREE", ".BUILDINFO", ".INSTALL", BinaryPath[1:]} {
		if !seen[required] {
			return nil, fmt.Errorf("%w: missing Arch member %s", ErrArtifact, required)
		}
	}
	return info, nil
}

func parseArchInfo(data []byte) (map[string][]string, error) {
	fields := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok || key == "" || value == "" || strings.ContainsAny(value, "\r\x00") {
			return nil, fmt.Errorf("%w: malformed .PKGINFO", ErrArtifact)
		}
		fields[key] = append(fields[key], value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, key := range []string{"pkgname", "pkgbase", "pkgver", "pkgdesc", "arch", "size", "builddate", "packager"} {
		if len(fields[key]) != 1 {
			return nil, fmt.Errorf("%w: missing/duplicate .PKGINFO %s", ErrArtifact, key)
		}
	}
	pkgtype := 0
	for _, value := range fields["xdata"] {
		if value == "pkgtype=pkg" {
			pkgtype++
		} else if strings.HasPrefix(value, "pkgtype=") {
			return nil, fmt.Errorf("%w: unsupported Arch package type", ErrArtifact)
		}
	}
	if pkgtype != 1 {
		return nil, fmt.Errorf("%w: missing/duplicate Arch package type", ErrArtifact)
	}
	version, ok := strings.CutSuffix(fields["pkgver"][0], "-"+archRelease)
	if _, err := parseVersion(version); err != nil || !ok || fields["pkgname"][0] != PackageName || fields["pkgbase"][0] != PackageName {
		return nil, fmt.Errorf("%w: unsupported Arch product/version", ErrArtifact)
	}
	if arch := fields["arch"][0]; arch != "x86_64" && arch != "aarch64" {
		return nil, ErrArchitecture
	}
	for _, key := range []string{"size", "builddate"} {
		if value, err := strconv.ParseInt(fields[key][0], 10, 64); err != nil || value < 0 {
			return nil, fmt.Errorf("%w: invalid .PKGINFO %s", ErrArtifact, key)
		}
	}
	return fields, nil
}
