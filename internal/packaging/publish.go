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
	"slices"
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
	architectures, err := stageDEBs(ctx, work, repo, req.DEBs, epoch)
	if err != nil {
		return nil, err
	}
	indexes := make(map[string]string, len(architectures))
	for _, arch := range architectures {
		binaryDir := filepath.Join(repo, "dists", APTDistribution, "main", "binary-"+arch)
		if err := mkdir(binaryDir, epoch); err != nil {
			return nil, err
		}
		index := filepath.Join(binaryDir, "Packages")
		if err := writeAPTPackages(ctx, work, repo, index, arch); err != nil {
			return nil, err
		}
		indexes[arch] = filepath.Join(req.OutputDir, "apt", "dists", APTDistribution, "main", "binary-"+arch, "Packages")
	}
	releasePath, err := writeAPTRelease(ctx, work, repo, key, strings.Join(architectures, " "), epoch)
	if err != nil {
		return nil, err
	}
	inRelease, err := signAPTRelease(ctx, work, key, pass, releasePath)
	if err != nil {
		return nil, err
	}
	binaryKey, armorKey, err := exportPublicKeys(ctx, work, key, repo)
	if err != nil {
		return nil, err
	}
	if err := verifyInRelease(ctx, work, binaryKey, inRelease, releasePath); err != nil {
		return nil, err
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
		Packages:             indexes,
		PublicKey:            filepath.Join(final, filepath.Base(binaryKey)),
		PublicKeyArmor:       filepath.Join(final, filepath.Base(armorKey)),
		Fingerprint:          key.Fingerprint,
		Custody:              key.Custody,
		InReleaseVerified:    true,
		PackagesHashVerified: true,
		Tools:                []ToolVersion{toolVersion(ctx, work, "apt-ftparchive", "--help"), toolVersion(ctx, work, "gpg", "--version"), toolVersion(ctx, work, "gpgv", "--version")},
	}, nil
}

// stageDEBs copies supported products into the pool and returns their sorted
// native architectures. Each architecture receives its own signed index.
func stageDEBs(ctx context.Context, work, repo string, debs []string, epoch int64) ([]string, error) {
	var architectures []string
	for _, deb := range debs {
		arch, err := stageDEB(ctx, work, repo, deb, epoch)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(architectures, arch) {
			architectures = append(architectures, arch)
		}
	}
	slices.Sort(architectures)
	return architectures, nil
}

// stageDEB checks the product and architecture, then copies the archive into
// pool/main/l/<package>. It returns the deb's architecture.
func stageDEB(ctx context.Context, work, repo, deb string, epoch int64) (string, error) {
	file, err := openBoundedRegular(deb, maxPackageBytes)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	name := info.Name()
	shown, _, err := runTool(ctx, work, toolCmd{
		Name: "dpkg-deb",
		Args: []string{"--show", "--showformat", "${Package}\t${Architecture}\n", file.Name()},
	})
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(string(shown)), "\t")
	if len(fields) != 2 || !supportedProduct(fields[0]) || !strings.HasPrefix(name, fields[0]+"_") || !strings.HasSuffix(name, ".deb") {
		return "", fmt.Errorf("%w: unexpected deb product or filename", ErrArtifact)
	}
	if fields[1] != "amd64" && fields[1] != "arm64" {
		return "", fmt.Errorf("%w: unsupported deb architecture", ErrArchitecture)
	}
	if !strings.HasSuffix(name, "_"+fields[1]+".deb") {
		return "", fmt.Errorf("%w: deb filename architecture differs from package identity", ErrArtifact)
	}
	pool := filepath.Join(repo, "pool", "main", "l", fields[0])
	if err := mkdir(pool, epoch); err != nil {
		return "", err
	}
	if err := copyFile(filepath.Join(pool, name), file, 0o644, epoch); err != nil {
		return "", err
	}
	return fields[1], nil
}

// writeAPTPackages generates and verifies one architecture's SHA-256 Packages
// index, then writes its reproducible gzip copy.
func writeAPTPackages(ctx context.Context, work, repo, packagesPath, arch string) error {
	if err := runToolToFile(ctx, work, packagesPath, toolCmd{
		Name: "apt-ftparchive",
		Args: []string{"--sha256", "--arch", arch, "packages", "pool"},
		Dir:  repo,
	}); err != nil {
		return err
	}
	if err := verifyPackageIndex(repo, packagesPath); err != nil {
		return err
	}
	return runToolToFile(ctx, work, packagesPath+".gz", toolCmd{Name: "gzip", Args: []string{"-n", "-c", packagesPath}})
}

// writeAPTRelease generates the distribution Release file and verifies the index
// hashes it lists. It returns the Release path.
func writeAPTRelease(ctx context.Context, work, repo string, key SigningKey, arch string, epoch int64) (string, error) {
	origin := "lindm"
	if key.Custody == CustodyDevelopment {
		origin = "lindm-development"
	}
	conf := fmt.Sprintf("APT::FTPArchive::Release::Origin \"%s\";\nAPT::FTPArchive::Release::Label \"lindm\";\nAPT::FTPArchive::Release::Suite \"%s\";\nAPT::FTPArchive::Release::Codename \"%s\";\nAPT::FTPArchive::Release::Architectures \"%s\";\nAPT::FTPArchive::Release::Components \"%s\";\n", origin, APTDistribution, APTDistribution, arch, APTComponent)
	confPath := filepath.Join(work, "apt-release.conf")
	if err := writeFile(confPath, []byte(conf), 0o644, epoch); err != nil {
		return "", err
	}
	distDir := filepath.Join(repo, "dists", APTDistribution)
	releasePath := filepath.Join(distDir, "Release")
	// Keep the output outside the tree apt-ftparchive hashes.
	releaseTemp := filepath.Join(work, "Release")
	if err := runToolToFile(ctx, work, releaseTemp, toolCmd{
		Name: "apt-ftparchive",
		Args: []string{"-c", confPath, "--sha256", "release", distDir},
	}); err != nil {
		return "", err
	}
	if err := os.Rename(releaseTemp, releasePath); err != nil {
		return "", err
	}
	if err := verifyReleaseHashes(distDir, releasePath); err != nil {
		return "", err
	}
	return releasePath, nil
}

// signAPTRelease writes the clearsigned InRelease and the detached Release.gpg
// beside releasePath. It returns the InRelease path.
func signAPTRelease(ctx context.Context, work string, key SigningKey, pass, releasePath string) (string, error) {
	distDir := filepath.Dir(releasePath)
	inRelease := filepath.Join(distDir, "InRelease")
	detached := filepath.Join(distDir, "Release.gpg")
	for _, mode := range [][]string{{"--clearsign", "--output", inRelease}, {"--detach-sign", "--armor", "--output", detached}} {
		args := append([]string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", pass, "--homedir", key.Home, "--local-user", key.Fingerprint + "!"}, mode...)
		if _, _, err := runTool(ctx, work, toolCmd{
			Name:     "gpg",
			Args:     append(args, releasePath),
			ExtraEnv: gpgEnv(key.Home),
		}); err != nil {
			return "", err
		}
		if err := os.Chmod(mode[len(mode)-1], 0o644); err != nil {
			return "", err
		}
	}
	return inRelease, nil
}

// verifyInRelease checks InRelease with gpgv against only the exported key and
// requires its signed payload to be the Release file.
func verifyInRelease(ctx context.Context, work, binaryKey, inRelease, releasePath string) error {
	verified := filepath.Join(work, "inrelease-verified")
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "gpgv",
		Args: []string{"--keyring", binaryKey, "--output", verified, inRelease},
	}); err != nil {
		return fmt.Errorf("%w: InRelease verification failed", ErrArtifact)
	}
	releaseBytes, err := os.ReadFile(releasePath)
	if err != nil {
		return err
	}
	verifiedBytes, err := os.ReadFile(verified)
	if err != nil {
		return err
	}
	if !bytes.Equal(releaseBytes, verifiedBytes) && !bytes.Equal(releaseBytes, bytes.TrimSuffix(verifiedBytes, []byte("\n"))) {
		return fmt.Errorf("%w: verified InRelease payload does not match Release", ErrArtifact)
	}
	return nil
}

// runToolToFile runs cmd with stdout captured in a new 0644 file at path. A tool
// failure takes precedence over the close error.
func runToolToFile(ctx context.Context, work, path string, cmd toolCmd) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	cmd.Stdout = out
	_, _, err = runTool(ctx, work, cmd)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
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
		if !supportedProduct(fields["Package"]) || fields["Filename"] == "" || fields["SHA256"] == "" {
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
		file, err := openBoundedRegular(rpm, maxPackageBytes)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if (!strings.HasPrefix(info.Name(), PackageName+"-") && !strings.HasPrefix(info.Name(), ServerPackageName+"-") && !strings.HasPrefix(info.Name(), CLIPackageName+"-")) || !strings.HasSuffix(info.Name(), ".rpm") {
			_ = file.Close()
			return nil, fmt.Errorf("%w: unexpected rpm name", ErrArtifact)
		}
		copied := filepath.Join(repo, info.Name())
		if err := copyFile(copied, file, 0o644, DefaultSourceDateEpoch); err != nil {
			_ = file.Close()
			return nil, err
		}
		_ = file.Close()
		identity, _, err := runTool(ctx, work, toolCmd{Name: "rpm", Args: []string{"--query", "--package", "--queryformat", "%{NAME}", copied}})
		if err != nil {
			return nil, err
		}
		if !supportedProduct(string(identity)) {
			return nil, fmt.Errorf("%w: unsupported RPM product", ErrArtifact)
		}
		if err := verifyRPMSignature(ctx, work, copied, key); err != nil {
			return nil, err
		}
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
