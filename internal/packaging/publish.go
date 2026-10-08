//go:build linux

package packaging

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// APTSources returns a deb822 source that pins Signed-By. It rejects the
// system trusted.gpg directories.
func APTSources(repoRoot, keyPath string) (string, error) {
	root, err := cleanAbsolute(repoRoot)
	if err != nil {
		return "", err
	}
	key, err := cleanAbsolute(keyPath)
	if err != nil {
		return "", err
	}
	if isTrustedGPG(key) {
		return "", fmt.Errorf("%w: Signed-By must not use trusted.gpg", ErrUnsafePath)
	}
	return fmt.Sprintf("Types: deb\nURIs: file://%s\nSuites: %s\nComponents: %s\nSigned-By: %s\n", root, APTDistribution, APTComponent, key), nil
}

func isTrustedGPG(path string) bool {
	if path == "/etc/apt/trusted.gpg" || within(path, "/etc/apt/trusted.gpg.d") {
		return true
	}
	return filepath.Base(path) == "trusted.gpg"
}

// RPMRepoConfig returns a repository file with package signature checks forced
// on. repo_gpgcheck is 1 only when metadataSigned is true.
func RPMRepoConfig(repoRoot, keyPath string, metadataSigned bool) (string, error) {
	root, err := cleanAbsolute(repoRoot)
	if err != nil {
		return "", err
	}
	key, err := cleanAbsolute(keyPath)
	if err != nil {
		return "", err
	}
	repoGPG := 0
	if metadataSigned {
		repoGPG = 1
	}
	return fmt.Sprintf("[lindm]\nname=Lindm\nbaseurl=file://%s\nenabled=1\ngpgcheck=1\nlocalpkg_gpgcheck=1\nrepo_gpgcheck=%d\ngpgkey=file://%s\n", root, repoGPG, key), nil
}

// PublishAPT writes an isolated signed APT repository. It does not install a key
// into the host trust store.
func PublishAPT(ctx context.Context, req APTRequest) (result *APTRepository, err error) {
	if len(req.DEBs) == 0 || len(req.DEBs) > 8 {
		return nil, fmt.Errorf("%w: APT publication requires one to eight debs", ErrArtifact)
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
	defer func() { _ = cleanup() }()
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
	pass, err := passphraseFile(work, key)
	if err != nil {
		return nil, err
	}
	repo := filepath.Join(work, "apt")
	pool := filepath.Join(repo, "pool", "main", "l", PackageName)
	dist := filepath.Join(repo, "dists", APTDistribution, "main", "binary-amd64")
	if err := mkdir(pool, epoch); err != nil {
		return nil, err
	}
	if err := mkdir(dist, epoch); err != nil {
		return nil, err
	}
	var arch string
	for _, deb := range req.DEBs {
		file, err := openRegular(deb)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		name := info.Name()
		if !strings.HasPrefix(name, PackageName+"_") || !strings.HasSuffix(name, ".deb") {
			_ = file.Close()
			return nil, fmt.Errorf("%w: unexpected deb name", ErrArtifact)
		}
		shown, _, err := runTool(ctx, work, toolCmd{
			Name: "dpkg-deb",
			Args: []string{"--show", "--showformat", "${Package}\t${Architecture}\n", file.Name()},
		})
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		fields := strings.Split(strings.TrimSpace(string(shown)), "\t")
		if len(fields) != 2 || fields[0] != PackageName {
			_ = file.Close()
			return nil, fmt.Errorf("%w: deb is not %s", ErrArtifact, PackageName)
		}
		if arch == "" {
			arch = fields[1]
		} else if arch != fields[1] {
			_ = file.Close()
			return nil, fmt.Errorf("%w: mixed deb architectures", ErrArtifact)
		}
		if err := copyFile(filepath.Join(pool, name), file, 0o644, epoch); err != nil {
			_ = file.Close()
			return nil, err
		}
		_ = file.Close()
	}
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("%w: unsupported deb architecture", ErrArchitecture)
	}
	binaryDir := filepath.Join(repo, "dists", APTDistribution, "main", "binary-"+arch)
	if arch != "amd64" {
		if err := os.RemoveAll(dist); err != nil {
			return nil, err
		}
		if err := mkdir(binaryDir, epoch); err != nil {
			return nil, err
		}
	} else {
		binaryDir = dist
	}
	packagesPath := filepath.Join(binaryDir, "Packages")
	packages, err := os.OpenFile(packagesPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	_, _, err = runTool(ctx, work, toolCmd{
		Name:   "apt-ftparchive",
		Args:   []string{"--sha256", "packages", "pool"},
		Dir:    repo,
		Stdout: packages,
	})
	closeErr := packages.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			err = closeErr
		}
		return nil, err
	}
	if err := verifyPackageIndex(repo, packagesPath); err != nil {
		return nil, err
	}
	gz, err := os.OpenFile(packagesPath+".gz", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	_, _, err = runTool(ctx, work, toolCmd{Name: "gzip", Args: []string{"-n", "-c", packagesPath}, Stdout: gz})
	closeErr = gz.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			err = closeErr
		}
		return nil, err
	}
	origin := "lindm"
	if key.Custody == CustodyDevelopment {
		origin = "lindm-development"
	}
	conf := fmt.Sprintf("APT::FTPArchive::Release::Origin \"%s\";\nAPT::FTPArchive::Release::Label \"lindm\";\nAPT::FTPArchive::Release::Suite \"%s\";\nAPT::FTPArchive::Release::Codename \"%s\";\nAPT::FTPArchive::Release::Architectures \"%s\";\nAPT::FTPArchive::Release::Components \"%s\";\n", origin, APTDistribution, APTDistribution, arch, APTComponent)
	confPath := filepath.Join(work, "apt-release.conf")
	if err := writeFile(confPath, []byte(conf), 0o644, epoch); err != nil {
		return nil, err
	}
	releasePath := filepath.Join(repo, "dists", APTDistribution, "Release")
	// Keep the output outside the tree apt-ftparchive hashes.
	releaseTemp := filepath.Join(work, "Release")
	release, err := os.OpenFile(releaseTemp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	_, _, err = runTool(ctx, work, toolCmd{
		Name:   "apt-ftparchive",
		Args:   []string{"-c", confPath, "--sha256", "release", filepath.Join(repo, "dists", APTDistribution)},
		Stdout: release,
	})
	closeErr = release.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			err = closeErr
		}
		return nil, err
	}
	if err := os.Rename(releaseTemp, releasePath); err != nil {
		return nil, err
	}
	if err := verifyReleaseHashes(filepath.Join(repo, "dists", APTDistribution), releasePath); err != nil {
		return nil, err
	}
	inRelease := filepath.Join(repo, "dists", APTDistribution, "InRelease")
	detached := filepath.Join(repo, "dists", APTDistribution, "Release.gpg")
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", pass, "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--clearsign", "--output", inRelease, releasePath},
		ExtraEnv: gpgEnv(key.Home),
	}); err != nil {
		return nil, err
	}
	if err := os.Chmod(inRelease, 0o644); err != nil {
		return nil, err
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", pass, "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--detach-sign", "--armor", "--output", detached, releasePath},
		ExtraEnv: gpgEnv(key.Home),
	}); err != nil {
		return nil, err
	}
	if err := os.Chmod(detached, 0o644); err != nil {
		return nil, err
	}
	binaryKey, armorKey, err := exportPublicKeys(ctx, work, key, repo)
	if err != nil {
		return nil, err
	}
	verified := filepath.Join(work, "inrelease-verified")
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "gpgv",
		Args: []string{"--keyring", binaryKey, "--output", verified, inRelease},
	}); err != nil {
		return nil, fmt.Errorf("%w: InRelease verification failed", ErrArtifact)
	}
	releaseBytes, err := os.ReadFile(releasePath)
	if err != nil {
		return nil, err
	}
	verifiedBytes, err := os.ReadFile(verified)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(releaseBytes, verifiedBytes) && !bytes.Equal(releaseBytes, bytes.TrimSuffix(verifiedBytes, []byte("\n"))) {
		return nil, fmt.Errorf("%w: verified InRelease payload does not match Release", ErrArtifact)
	}
	if err := guard.close(ctx, work); err != nil {
		return nil, err
	}
	final := filepath.Join(req.OutputDir, "apt")
	if _, err := os.Lstat(final); err == nil {
		return nil, fmt.Errorf("%w: APT output already exists", ErrArtifact)
	}
	if err := os.Rename(repo, final); err != nil {
		return nil, err
	}
	return &APTRepository{
		Root:                 final,
		Distribution:         APTDistribution,
		Component:            APTComponent,
		InRelease:            filepath.Join(final, "dists", APTDistribution, "InRelease"),
		Release:              filepath.Join(final, "dists", APTDistribution, "Release"),
		Packages:             filepath.Join(final, "dists", APTDistribution, "main", "binary-"+arch, "Packages"),
		PublicKey:            filepath.Join(final, filepath.Base(binaryKey)),
		PublicKeyArmor:       filepath.Join(final, filepath.Base(armorKey)),
		Fingerprint:          key.Fingerprint,
		Custody:              key.Custody,
		InReleaseVerified:    true,
		PackagesHashVerified: true,
		Tools:                []ToolVersion{toolVersion(ctx, work, "apt-ftparchive", "--help"), toolVersion(ctx, work, "gpg", "--version"), toolVersion(ctx, work, "gpgv", "--version")},
	}, nil
}

func verifyPackageIndex(repo, packagesPath string) error {
	data, err := os.ReadFile(packagesPath)
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("SHA256: ")) {
		return fmt.Errorf("%w: Packages index has no SHA256 records", ErrArtifact)
	}
	blocks := strings.Split(string(data), "\n\n")
	checked := 0
	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ": ")
			if ok {
				fields[key] = value
			}
		}
		if fields["Package"] != PackageName || fields["Filename"] == "" || fields["SHA256"] == "" {
			return fmt.Errorf("%w: Packages record is incomplete", ErrArtifact)
		}
		path := filepath.Join(repo, fields["Filename"])
		if filepath.Clean(path) != path || !within(path, repo) {
			return fmt.Errorf("%w: Packages filename escapes the repository", ErrArtifact)
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		if sum != fields["SHA256"] {
			return fmt.Errorf("%w: Packages SHA256 does not match the deb", ErrArtifact)
		}
		if fields["Size"] != "" && fields["Size"] != fmt.Sprint(size) {
			return fmt.Errorf("%w: Packages size does not match the deb", ErrArtifact)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("%w: Packages index is empty", ErrArtifact)
	}
	return nil
}

func verifyReleaseHashes(root, releasePath string) error {
	file, err := os.Open(releasePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	inSHA := false
	checked := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "SHA256:" {
			inSHA = true
			continue
		}
		if !inSHA {
			continue
		}
		if line == "" || !strings.HasPrefix(line, " ") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("%w: malformed Release hash line", ErrArtifact)
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return err
		}
		path := filepath.Join(root, fields[2])
		if !within(path, root) {
			return fmt.Errorf("%w: Release hash path escapes the distribution", ErrArtifact)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(data)) != size {
			return fmt.Errorf("%w: Release size mismatch for %s", ErrArtifact, fields[2])
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != fields[0] {
			return fmt.Errorf("%w: Release SHA256 mismatch for %s", ErrArtifact, fields[2])
		}
		checked++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if checked == 0 {
		return fmt.Errorf("%w: Release has no SHA256 records", ErrArtifact)
	}
	return nil
}

// PublishRPM writes repodata with createrepo_c. If that tool is missing, it
// returns ErrRepositoryTool and writes nothing.
func PublishRPM(ctx context.Context, req RPMRequest) (result *RPMRepository, err error) {
	if _, err := lookupTool("createrepo_c"); err != nil {
		return nil, ErrRepositoryTool
	}
	if len(req.RPMs) == 0 || len(req.RPMs) > 8 {
		return nil, fmt.Errorf("%w: RPM publication requires one to eight rpms", ErrArtifact)
	}
	out, err := openPrivate(req.OutputDir)
	if err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	work, cleanup, err := privateWork(req.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
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
	pass, err := passphraseFile(work, key)
	if err != nil {
		return nil, err
	}
	repo := filepath.Join(work, "rpm")
	if err := os.Mkdir(repo, 0o755); err != nil {
		return nil, err
	}
	for _, rpm := range req.RPMs {
		file, err := openRegular(rpm)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if !strings.HasPrefix(info.Name(), PackageName+"-") || !strings.HasSuffix(info.Name(), ".rpm") {
			_ = file.Close()
			return nil, fmt.Errorf("%w: unexpected rpm name", ErrArtifact)
		}
		if err := copyFile(filepath.Join(repo, info.Name()), file, 0o644, DefaultSourceDateEpoch); err != nil {
			_ = file.Close()
			return nil, err
		}
		_ = file.Close()
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "createrepo_c",
		Args: []string{"--checksum", "sha256", "--general-compress-type", "gz", repo},
	}); err != nil {
		return nil, err
	}
	repomd := filepath.Join(repo, "repodata", "repomd.xml")
	if _, err := os.Stat(repomd); err != nil {
		return nil, fmt.Errorf("%w: createrepo_c did not write repomd.xml", ErrArtifact)
	}
	signature := repomd + ".asc"
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", pass, "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--detach-sign", "--armor", "--output", signature, repomd},
		ExtraEnv: gpgEnv(key.Home),
	}); err != nil {
		return nil, err
	}
	if err := os.Chmod(signature, 0o644); err != nil {
		return nil, err
	}
	binaryKey, armorKey, err := exportPublicKeys(ctx, work, key, repo)
	if err != nil {
		return nil, err
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "gpgv",
		Args: []string{"--keyring", binaryKey, signature, repomd},
	}); err != nil {
		return nil, fmt.Errorf("%w: repomd signature verification failed", ErrArtifact)
	}
	if err := guard.close(ctx, work); err != nil {
		return nil, err
	}
	final := filepath.Join(req.OutputDir, "rpm")
	if _, err := os.Lstat(final); err == nil {
		return nil, fmt.Errorf("%w: RPM repository output already exists", ErrArtifact)
	}
	if err := os.Rename(repo, final); err != nil {
		return nil, err
	}
	return &RPMRepository{
		Root:               final,
		Repomd:             filepath.Join(final, "repodata", "repomd.xml"),
		PublicKey:          filepath.Join(final, filepath.Base(binaryKey)),
		PublicKeyArmor:     filepath.Join(final, filepath.Base(armorKey)),
		Fingerprint:        key.Fingerprint,
		Custody:            key.Custody,
		GPGCheck:           true,
		LocalPkgGPGCheck:   true,
		RepoMetadataSigned: true,
		Tools:              []ToolVersion{toolVersion(ctx, work, "createrepo_c", "--version")},
	}, nil
}
