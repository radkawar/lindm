//go:build linux

package packaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// RejectionRequest requires the first positive build and its signed APT archive.
// OutputDir must be empty, private 0700, and have trusted ancestry. Only a
// purpose-marked development package signer is accepted; production is rejected.
type RejectionRequest struct {
	DEB       Artifact
	RPM       Artifact
	APT       *APTRepository
	Signer    SigningKey
	OutputDir string
}

// RejectionCase is deliberately unsuitable for installation. Artifact digests
// describe the actual variant, not the positive build. Signed and repository
// verification flags are false: producing a negative case is not verification.
type RejectionCase struct {
	Name     string         `json:"name"`
	Artifact Artifact       `json:"artifact"`
	APT      *APTRepository `json:"apt,omitempty"`
}

// RejectionFixtures contains unsigned, tampered and wrong-signer cases for both
// package managers. WrongSignerFingerprint is public evidence, never guest trust.
type RejectionFixtures struct {
	Cases                  []RejectionCase `json:"cases"`
	WrongSignerFingerprint string          `json:"wrong_signer_fingerprint"`
}

// BuildRejectionFixtures makes real native authentication failures without
// changing positive artifacts or host trust. All secret material stays in a
// private work directory, whose agents and contents are removed on every return.
// Guest rejection and absence of installation side effects must be proved by
// the caller; this producer makes no claim that a manager rejected a fixture.
func BuildRejectionFixtures(ctx context.Context, req RejectionRequest) (result *RejectionFixtures, err error) {
	if req.Signer.Custody != CustodyDevelopment || req.APT == nil || req.APT.Custody != CustodyDevelopment {
		return nil, fmt.Errorf("%w: rejection fixtures require development custody", ErrSigner)
	}
	out, err := openPrivate(req.OutputDir)
	if err != nil {
		return nil, err
	}
	entries, readErr := out.Readdirnames(1)
	closeErr := out.Close()
	if closeErr != nil || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(entries) != 0 {
		return nil, fmt.Errorf("%w: rejection output must be empty", ErrUnsafePath)
	}
	if within(req.DEB.Path, req.OutputDir) || within(req.RPM.Path, req.OutputDir) || within(req.APT.Root, req.OutputDir) || within(req.OutputDir, req.APT.Root) || within(req.OutputDir, req.Signer.Home) {
		return nil, fmt.Errorf("%w: rejection output overlaps positive inputs", ErrUnsafePath)
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
	defer func() { err = errors.Join(err, guard.close(ctx, work)) }()
	if req.APT.Fingerprint != key.Fingerprint || req.RPM.SignerFingerprint != key.Fingerprint || !req.RPM.Signed || !req.APT.InReleaseVerified || !req.APT.PackagesHashVerified {
		return nil, fmt.Errorf("%w: positive inputs must have the development signer", ErrSigner)
	}
	if req.DEB.Format != FormatDEB || req.RPM.Format != FormatRPM || req.DEB.Version != req.RPM.Version || req.DEB.Architecture != req.RPM.Architecture {
		return nil, fmt.Errorf("%w: positive artifacts must be one matching DEB/RPM build", ErrArtifact)
	}
	positive := filepath.Join(work, "positive")
	if err := os.Mkdir(positive, 0o700); err != nil {
		return nil, err
	}
	deb, err := rejectionSnapshotArtifact(ctx, work, positive, req.DEB)
	if err != nil {
		return nil, err
	}
	rpm, err := rejectionSnapshotArtifact(ctx, work, positive, req.RPM)
	if err != nil {
		return nil, err
	}
	publicDir := filepath.Join(work, "original-public")
	if err := os.Mkdir(publicDir, 0o700); err != nil {
		return nil, err
	}
	public, armor, err := exportPublicKeys(ctx, work, key, publicDir)
	if err != nil {
		return nil, err
	}
	if err := rejectionVerifyRPM(ctx, work, rpm.Path, armor); err != nil {
		return nil, err
	}
	repo, err := rejectionSnapshotAPT(ctx, work, req.APT, deb, public, armor)
	if err != nil {
		return nil, err
	}
	if err := verifyDEB(ctx, work, deb.Path, deb.Version, deb.Architecture, deb.PayloadSHA256, nil); err != nil {
		return nil, err
	}
	if err := rejectionVerifyPayloadClaim(ctx, work, rpm); err != nil {
		return nil, err
	}
	wrong, wrongGuard, err := generateDevelopmentSigner(ctx, work)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, wrongGuard.close(ctx, work)) }()
	if wrong.Fingerprint == key.Fingerprint {
		return nil, fmt.Errorf("%w: wrong signer matches trusted signer", ErrSigner)
	}
	gpg, err := lookupTool("gpg")
	if err != nil {
		return nil, err
	}
	result = &RejectionFixtures{WrongSignerFingerprint: wrong.Fingerprint}
	// Publish only completed public trees; the private signer is never moved.
	staged := filepath.Join(work, "fixtures")
	if err := os.Mkdir(staged, 0o700); err != nil {
		return nil, err
	}
	for _, kind := range []string{"unsigned", "tampered", "wrong-signer"} {
		base := filepath.Join(staged, kind)
		if err := os.Mkdir(base, 0o700); err != nil {
			return nil, err
		}
		variantRepo, err := rejectionCopyAPT(repo, filepath.Join(base, "apt"))
		if err != nil {
			return nil, err
		}
		variantDEB := deb
		variantDEB.Path = filepath.Join(variantRepo.Root, "pool", "main", "l", PackageName, filepath.Base(deb.Path))
		variantRPM := rpm
		if err := os.Mkdir(filepath.Join(base, "rpm"), 0o755); err != nil {
			return nil, err
		}
		variantRPM.Path = filepath.Join(base, "rpm", filepath.Base(rpm.Path))
		if err := rejectionCopyPath(rpm.Path, variantRPM.Path, maxBinaryBytes); err != nil {
			return nil, err
		}
		switch kind {
		case "unsigned", "wrong-signer":
			if err := os.Remove(variantRepo.InRelease); err != nil {
				return nil, err
			}
			if err := os.Remove(variantRepo.Release + ".gpg"); err != nil {
				return nil, err
			}
			if _, _, err := runTool(ctx, work, toolCmd{Name: "rpmsign", Args: []string{"--delsign", variantRPM.Path}}); err != nil {
				return nil, err
			}
			if kind == "wrong-signer" {
				for _, signature := range []struct{ option, path string }{{"--clearsign", variantRepo.InRelease}, {"--detach-sign", variantRepo.Release + ".gpg"}} {
					if _, _, err := runTool(ctx, work, toolCmd{
						Name:     "gpg",
						Args:     []string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", wrong.PassphraseFile, "--homedir", wrong.Home, "--local-user", wrong.Fingerprint + "!", "--armor", signature.option, "--output", signature.path, variantRepo.Release},
						ExtraEnv: gpgEnv(wrong.Home),
					}); err != nil {
						return nil, err
					}
					if err := os.Chmod(signature.path, 0o644); err != nil {
						return nil, err
					}
				}
				if err := signRPM(ctx, work, variantRPM.Path, *wrong, wrong.PassphraseFile, gpg); err != nil {
					return nil, err
				}
				variantRPM.SignerFingerprint = wrong.Fingerprint
				variantRepo.Fingerprint = wrong.Fingerprint
			} else {
				variantRPM.SignerFingerprint = ""
				variantRepo.Fingerprint = ""
				variantRepo.InRelease = ""
			}
		case "tampered":
			if err := rejectionFlipByte(variantDEB.Path, deb.Size/2); err != nil {
				return nil, err
			}
			payloadOffset, err := rejectionRPMPayload(variantRPM.Path)
			if err != nil {
				return nil, err
			}
			if err := rejectionFlipByte(variantRPM.Path, payloadOffset+(rpm.Size-payloadOffset)/2); err != nil {
				return nil, err
			}
			variantDEB.PayloadSHA256 = ""
			variantRPM.PayloadSHA256 = ""
		}
		variantDEB.Signed = false
		variantRPM.Signed = false
		for _, artifact := range []*Artifact{&variantDEB, &variantRPM} {
			artifact.SHA256, artifact.Size, err = hashFile(artifact.Path)
			if err != nil {
				return nil, err
			}
		}
		result.Cases = append(result.Cases, RejectionCase{Name: kind, Artifact: variantDEB, APT: variantRepo}, RejectionCase{Name: kind, Artifact: variantRPM})
	}
	if err := errors.Join(wrongGuard.close(ctx, work), guard.close(ctx, work)); err != nil {
		return nil, err
	}
	final := filepath.Join(req.OutputDir, "fixtures")
	if err := os.Rename(staged, final); err != nil {
		return nil, err
	}
	for i := range result.Cases {
		c := &result.Cases[i]
		c.Artifact.Path = final + strings.TrimPrefix(c.Artifact.Path, staged)
		if c.APT != nil {
			rejectionRebaseAPT(c.APT, final+strings.TrimPrefix(c.APT.Root, staged))
		}
	}
	return result, nil
}

func rejectionSnapshotArtifact(ctx context.Context, work, dir string, artifact Artifact) (Artifact, error) {
	if _, err := parseVersion(artifact.Version); err != nil {
		return Artifact{}, err
	}
	if artifact.Architecture.Debian != "amd64" && artifact.Architecture.Debian != "arm64" {
		return Artifact{}, ErrArchitecture
	}
	wantArch := Architecture{ELF: "EM_X86_64", GOARCH: "amd64", Debian: "amd64", RPM: "x86_64"}
	if artifact.Architecture.Debian == "arm64" {
		wantArch = Architecture{ELF: "EM_AARCH64", GOARCH: "arm64", Debian: "arm64", RPM: "aarch64"}
	}
	if artifact.Architecture != wantArch {
		return Artifact{}, ErrArchitecture
	}
	name := fmt.Sprintf("%s_%s_%s.deb", PackageName, artifact.Version, artifact.Architecture.Debian)
	if artifact.Format == FormatRPM {
		name = fmt.Sprintf("%s-%s-%s.%s.rpm", PackageName, artifact.Version, RPMRelease, artifact.Architecture.RPM)
	}
	if filepath.Base(artifact.Path) != name {
		return Artifact{}, fmt.Errorf("%w: positive artifact basename is not canonical", ErrArtifact)
	}
	parent, err := openPrivate(filepath.Dir(artifact.Path))
	if err != nil {
		return Artifact{}, err
	}
	defer func() { _ = parent.Close() }()
	file, err := openRegular(artifact.Path)
	if err != nil {
		return Artifact{}, err
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(file, maxBinaryBytes+1))
	if err != nil {
		return Artifact{}, err
	}
	if size != artifact.Size || size > maxBinaryBytes || hex.EncodeToString(h.Sum(nil)) != artifact.SHA256 {
		return Artifact{}, fmt.Errorf("%w: positive manifest digest/size differs from opened bytes", ErrArtifact)
	}
	artifact.Path = filepath.Join(dir, name)
	if err := rejectionCopyFile(file, artifact.Path, maxBinaryBytes); err != nil {
		return Artifact{}, err
	}
	copied, copiedSize, err := hashFile(artifact.Path)
	if err != nil || copied != artifact.SHA256 || copiedSize != artifact.Size {
		return Artifact{}, fmt.Errorf("%w: positive artifact changed while copying: %v", ErrArtifact, err)
	}
	cmd := toolCmd{Name: "dpkg-deb", Args: []string{"--show", "--showformat", "${Package}\n${Version}\n${Architecture}\n", artifact.Path}}
	want := fmt.Sprintf("%s\n%s\n%s\n", PackageName, artifact.Version, artifact.Architecture.Debian)
	if artifact.Format == FormatRPM {
		cmd = toolCmd{Name: "rpm", Args: []string{"--query", "--package", "--queryformat", "%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", artifact.Path}}
		want = fmt.Sprintf("%s\n%s\n%s\n%s\n", PackageName, artifact.Version, RPMRelease, artifact.Architecture.RPM)
	}
	identity, _, err := runTool(ctx, work, cmd)
	if err != nil {
		return Artifact{}, err
	}
	if string(identity) != want {
		return Artifact{}, fmt.Errorf("%w: native package identity differs from manifest", ErrArtifact)
	}
	return artifact, nil
}

func rejectionVerifyRPM(ctx context.Context, work, path, armor string) error {
	db := filepath.Join(work, "positive-rpmdb")
	if err := os.Mkdir(db, 0o700); err != nil {
		return err
	}
	if _, _, err := runTool(ctx, work, toolCmd{Name: "rpmkeys", Args: []string{"--dbpath", db, "--import", armor}}); err != nil {
		return err
	}
	out, _, err := runTool(ctx, work, toolCmd{Name: "rpm", Args: []string{"--dbpath", db, "-K", path}})
	if err != nil {
		return err
	}
	text := string(out)
	if !strings.Contains(text, "signatures OK") || strings.Contains(text, "NOT OK") || strings.Contains(text, "NOKEY") || strings.Contains(text, "BAD") {
		return fmt.Errorf("%w: positive RPM signature was not verified", ErrArtifact)
	}
	return nil
}

func rejectionSnapshotAPT(ctx context.Context, work string, input *APTRepository, deb Artifact, public, armor string) (*APTRepository, error) {
	if input.Distribution != APTDistribution || input.Component != APTComponent {
		return nil, fmt.Errorf("%w: unexpected positive APT distribution", ErrArtifact)
	}
	parent, err := openPrivate(filepath.Dir(input.Root))
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	root := filepath.Join(work, "positive-apt")
	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, err
	}
	dist := filepath.Join("dists", APTDistribution)
	packages := filepath.Join(dist, APTComponent, "binary-"+deb.Architecture.Debian, "Packages")
	for _, rel := range []string{filepath.Join(dist, "Release"), filepath.Join(dist, "InRelease"), filepath.Join(dist, "Release.gpg"), packages, packages + ".gz"} {
		if err := rejectionCopyPath(filepath.Join(input.Root, rel), filepath.Join(root, rel), toolOutputLimit); err != nil {
			return nil, err
		}
	}
	for _, path := range []string{public, armor} {
		if err := rejectionCopyPath(path, filepath.Join(root, filepath.Base(path)), toolOutputLimit); err != nil {
			return nil, err
		}
	}
	index, err := os.ReadFile(filepath.Join(root, packages))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	found := false
	for _, block := range strings.Split(string(index), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok {
				fields[k] = v
			}
		}
		rel := fields["Filename"]
		canonical := filepath.Join("pool", "main", "l", PackageName, filepath.Base(rel))
		if rel != canonical || fields["Package"] != PackageName || !strings.HasSuffix(rel, ".deb") || seen[rel] || len(seen) >= 8 {
			return nil, fmt.Errorf("%w: positive Packages filename/count rejected", ErrArtifact)
		}
		seen[rel] = true
		if err := rejectionCopyPath(filepath.Join(input.Root, rel), filepath.Join(root, rel), maxBinaryBytes); err != nil {
			return nil, err
		}
		if filepath.Base(rel) == filepath.Base(deb.Path) {
			found = fields["SHA256"] == deb.SHA256 && fields["Size"] == strconv.FormatInt(deb.Size, 10) && fields["Version"] == deb.Version && fields["Architecture"] == deb.Architecture.Debian
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: positive repository does not contain the requested DEB", ErrArtifact)
	}
	if err := verifyPackageIndex(root, filepath.Join(root, packages)); err != nil {
		return nil, err
	}
	release := filepath.Join(root, dist, "Release")
	if err := verifyReleaseHashes(filepath.Dir(release), release); err != nil {
		return nil, err
	}
	verified, _, err := runTool(ctx, work, toolCmd{Name: "gpgv", Args: []string{"--keyring", public, "--output", "-", filepath.Join(root, dist, "InRelease")}})
	if err != nil {
		return nil, err
	}
	releaseBytes, err := os.ReadFile(release)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(releaseBytes, verified) && !bytes.Equal(releaseBytes, bytes.TrimSuffix(verified, []byte("\n"))) {
		return nil, fmt.Errorf("%w: signed Release does not match repository metadata", ErrArtifact)
	}
	if _, _, err := runTool(ctx, work, toolCmd{Name: "gpgv", Args: []string{"--keyring", public, release + ".gpg", release}}); err != nil {
		return nil, err
	}
	return &APTRepository{Root: root, Distribution: APTDistribution, Component: APTComponent, InRelease: filepath.Join(root, dist, "InRelease"), Release: release, Packages: filepath.Join(root, packages), PublicKey: filepath.Join(root, filepath.Base(public)), PublicKeyArmor: filepath.Join(root, filepath.Base(armor)), Fingerprint: input.Fingerprint, Custody: CustodyDevelopment}, nil
}

func rejectionCopyAPT(source *APTRepository, destination string) (*APTRepository, error) {
	count := 0
	err := filepath.WalkDir(source.Root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 64 || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: rejection repository exceeds public tree bounds", ErrArtifact)
		}
		rel, err := filepath.Rel(source.Root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0o755)
		}
		return rejectionCopyPath(path, target, maxBinaryBytes)
	})
	if err != nil {
		return nil, err
	}
	result := *source
	rejectionRebaseAPT(&result, destination)
	return &result, nil
}

func rejectionRebaseAPT(repo *APTRepository, root string) {
	for _, path := range []*string{&repo.InRelease, &repo.Release, &repo.Packages, &repo.PublicKey, &repo.PublicKeyArmor} {
		if *path != "" {
			*path = root + strings.TrimPrefix(*path, repo.Root)
		}
	}
	repo.Root = root
	repo.InReleaseVerified = false
	repo.PackagesHashVerified = false
	repo.Tools = nil
}

func rejectionCopyPath(source, destination string, limit int64) error {
	if _, err := cleanAbsolute(source); err != nil {
		return err
	}
	// Reject symlinks in every component, not only the final public filename.
	fd, err := unix.Openat2(unix.AT_FDCWD, source, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), source)
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Size <= 0 || stat.Size > limit {
		return fmt.Errorf("%w: rejection source file boundary rejected", ErrUnsafePath)
	}
	return rejectionCopyFile(file, destination, limit)
}

func rejectionCopyFile(source *os.File, destination string, limit int64) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(file, io.LimitReader(source, limit+1))
	if n > limit {
		copyErr = fmt.Errorf("%w: rejection source exceeds copy bound", ErrArtifact)
	}
	return errors.Join(copyErr, file.Sync(), file.Close())
}

// RPM v3/v4 headers have a 16-byte prefix and 16-byte index entries. The
// signature header follows the 96-byte lead and is padded to eight bytes; the
// main header follows it. Mutating after that header preserves the signature
// and package identity and corrupts an actual compressed payload byte.
func rejectionRPMPayload(path string) (int64, error) {
	file, err := openRegular(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return 0, err
	}
	if magic != [4]byte{0xed, 0xab, 0xee, 0xdb} {
		return 0, fmt.Errorf("%w: RPM lead magic rejected", ErrArtifact)
	}
	offset := int64(96)
	for i := range 2 {
		var header [16]byte
		if _, err := file.ReadAt(header[:], offset); err != nil {
			return 0, err
		}
		if !bytes.Equal(header[:4], []byte{0x8e, 0xad, 0xe8, 1}) {
			return 0, fmt.Errorf("%w: RPM header magic rejected", ErrArtifact)
		}
		offset += 16 + 16*int64(binary.BigEndian.Uint32(header[8:12])) + int64(binary.BigEndian.Uint32(header[12:16]))
		if i == 0 {
			offset = (offset + 7) &^ 7
		}
		if offset >= info.Size() {
			return 0, fmt.Errorf("%w: RPM payload bounds rejected", ErrArtifact)
		}
	}
	return offset, nil
}

func rejectionFlipByte(path string, offset int64) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	var value [1]byte
	if _, err := file.ReadAt(value[:], offset); err != nil {
		return err
	}
	value[0] ^= 1
	if _, err := file.WriteAt(value[:], offset); err != nil {
		return err
	}
	return file.Sync()
}

// The verified RPM header binds each installed file's digest; rpm -K above
// also checks the archive's payload digest. No archive extraction is needed.
func rejectionVerifyPayloadClaim(ctx context.Context, work string, artifact Artifact) error {
	out, _, err := runTool(ctx, work, toolCmd{
		Name: "rpm",
		Args: []string{"--query", "--package", "--queryformat", "%{FILEDIGESTALGO}\\n[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", artifact.Path},
	})
	if err != nil {
		return err
	}
	algorithm, files, ok := strings.Cut(string(out), "\n")
	if !ok || algorithm != "8" {
		return fmt.Errorf("%w: positive RPM must use SHA256 file digests", ErrArtifact)
	}
	found := false
	for _, line := range strings.Split(files, "\n") {
		name, digest, ok := strings.Cut(line, "\t")
		if ok && name == BinaryPath {
			if found || len(digest) != sha256.Size*2 || digest != artifact.PayloadSHA256 {
				return fmt.Errorf("%w: positive RPM binary digest differs from manifest", ErrArtifact)
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: positive RPM binary digest missing", ErrArtifact)
	}
	return nil
}
