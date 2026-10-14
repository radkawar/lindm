// SPDX-License-Identifier: Apache-2.0

package serverdeps

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

// UbuntuArchiveFingerprint is Ubuntu's archive signing key, not lindm release custody.
const UbuntuArchiveFingerprint = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

func signedRelease(ctx context.Context, root *os.File, m *serverdepsv1.Manifest, r *serverdepsv1.Repository) (_ []byte, err error) {
	if r.SignerFingerprint != UbuntuArchiveFingerprint || r.Authentication != "apt-inrelease" {
		return nil, errors.New("APT requires pinned Ubuntu archive authentication")
	}
	keyEntry, err := retainedFile(m, r.SigningKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := sealRetained(root, keyEntry, maxTrustBytes)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, key.Close()) }()
	entry, err := retainedFile(m, r.MetadataPath)
	if err != nil {
		return nil, err
	}
	metadata, err := sealRetained(root, entry, maxTrustBytes)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, metadata.Close()) }()
	verified, err := nativeCommand(ctx, nil, []*os.File{key, metadata}, "gpgv", "--status-fd=1", "--keyring", "/proc/self/fd/3", "/proc/self/fd/4")
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(verified, []byte("[GNUPG:] VALIDSIG "+UbuntuArchiveFingerprint+" ")) {
		return nil, errors.New("APT InRelease signer does not match pinned vendor key")
	}
	if _, err := metadata.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(metadata, int64(maxTrustBytes)+1))
	if err != nil {
		return nil, err
	}
	_, body, ok := strings.Cut(string(data), "\n\n")
	if !ok {
		return nil, errors.New("invalid InRelease armor")
	}
	body, _, ok = strings.Cut(body, "-----BEGIN PGP SIGNATURE-----")
	if !ok {
		return nil, errors.New("invalid InRelease signature armor")
	}
	return []byte(strings.ReplaceAll(body, "\n- ", "\n")), nil
}

type aptDigest struct {
	hash     string
	size     uint64
	metadata string
	identity string
}

func releaseDigests(data []byte, prefix string) (map[string]aptDigest, error) {
	result := map[string]aptDigest{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inSHA := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "SHA256:" {
			inSHA = true
			continue
		}
		if !inSHA {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inSHA = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !validDigest(fields[0]) || !aptIndexPath(fields[2]) {
			return nil, errors.New("malformed signed APT digest")
		}
		size, err := strconv.ParseUint(fields[1], 10, 64)
		// Release also lists unused, potentially huge Contents indexes and empty
		// installer indexes. Bounds apply to files we retain, not a full mirror.
		if err != nil {
			return nil, errors.New("invalid signed APT index size")
		}
		result[path.Join(prefix, fields[2])] = aptDigest{hash: fields[0], size: size}
	}
	return result, scanner.Err()
}

// Signed Release declarations include paths outside the retained closure (for
// example HiDPI icon names). They are canonical relative vendor paths, not I/O
// authority; retained files still pass the tighter shared safePath boundary.
func aptIndexPath(name string) bool {
	return name != "" && name != "." && name != ".." && !path.IsAbs(name) &&
		path.Clean(name) == name && !strings.HasPrefix(name, "../") &&
		!strings.ContainsRune(name, 0)
}

func packageDigests(input io.Reader, prefix, metadata string) (map[string]aptDigest, error) {
	result := map[string]aptDigest{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	fields := map[string]string{}
	add := func() error {
		if len(fields) == 0 {
			return nil
		}
		size, err := strconv.ParseUint(fields["Size"], 10, 64)
		if err != nil || size == 0 || size > HardMaxBytes || !validDigest(fields["SHA256"]) || !safePath(fields["Filename"]) {
			return errors.New("malformed authenticated APT package record")
		}
		result[path.Join(prefix, fields["Filename"])] = aptDigest{hash: fields["SHA256"], size: size, metadata: metadata, identity: fields["Package"] + "=" + fields["Version"] + ":" + fields["Architecture"]}
		fields = map[string]string{}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := add(); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			return nil, errors.New("malformed APT package index")
		}
		fields[key] = value
	}
	if err := add(); err != nil {
		return nil, err
	}
	return result, scanner.Err()
}

// APTProvenance authenticates original InRelease and Packages.gz, without generating indexes.
// It returns exact vendor package checksums for capture and load validation.
func APTProvenance(ctx context.Context, root *os.File, m *serverdepsv1.Manifest) (map[string]aptDigest, error) {
	packages := map[string]aptDigest{}
	for _, r := range m.Repositories {
		if err := aptRepositoryTarget(r); err != nil {
			return nil, err
		}
		data, err := signedRelease(ctx, root, m, r)
		if err != nil {
			return nil, err
		}
		if err := aptReleaseTarget(data, r.Id, time.Now()); err != nil {
			return nil, err
		}
		indexes, err := releaseDigests(data, path.Dir(r.MetadataPath))
		if err != nil {
			return nil, err
		}
		prefix, _, ok := strings.Cut(r.MetadataPath, "/dists/")
		if !ok {
			return nil, errors.New("APT metadata is outside dists")
		}
		found := false
		for _, entry := range m.Files {
			if !strings.HasPrefix(entry.Path, path.Dir(r.MetadataPath)+"/") || !strings.HasSuffix(entry.Path, "/Packages.gz") {
				continue
			}
			signed, ok := indexes[entry.Path]
			if !ok || signed.hash != entry.Sha256 || signed.size != entry.SizeBytes || entry.VendorSha256 != signed.hash || entry.VendorMetadataPath != r.MetadataPath || entry.SignerFingerprint != UbuntuArchiveFingerprint {
				return nil, errors.New("APT index differs from signed Release")
			}
			f, err := sealRetained(root, entry, maxPrimaryBytes)
			if err != nil {
				return nil, err
			}
			reader, decodeErr := gzip.NewReader(f)
			if decodeErr != nil {
				return nil, errors.Join(decodeErr, f.Close())
			}
			bounded := &io.LimitedReader{R: reader, N: int64(maxPrimaryBytes) + 1}
			values, parseErr := packageDigests(bounded, prefix, entry.Path)
			closeErr := errors.Join(reader.Close(), f.Close())
			if err := errors.Join(parseErr, closeErr); err != nil {
				return nil, err
			}
			if bounded.N == 0 {
				return nil, errors.New("APT decoded index exceeds bound")
			}
			for name, value := range values {
				packages[name+"#"+value.hash] = value
			}
			found = true
		}
		if !found {
			return nil, errors.New("APT signed repository has no retained package index")
		}
	}
	return packages, nil
}

func aptRepositoryTarget(r *serverdepsv1.Repository) error {
	prefix, origin := "archive", "https://archive.ubuntu.com/ubuntu/"
	switch r.Id {
	case "noble", "noble-updates":
	case "noble-security":
		prefix, origin = "security", "https://security.ubuntu.com/ubuntu/"
	default:
		return errors.New("unsupported Ubuntu server repository suite")
	}
	if r.SourceUrl != origin || r.MetadataPath != prefix+"/dists/"+r.Id+"/InRelease" {
		return errors.New("serverdeps: Ubuntu metadata provenance does not match pinned vendor source")
	}
	return nil
}

func aptReleaseTarget(data []byte, suite string, now time.Time) error {
	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") {
			continue
		}
		if key, value, ok := strings.Cut(line, ": "); ok {
			fields[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if fields["Origin"] != "Ubuntu" || fields["Codename"] != "noble" || fields["Suite"] != suite || !slices.Contains(strings.Fields(fields["Architectures"]), "amd64") {
		return errors.New("signed APT metadata belongs to another target")
	}
	date, err := time.Parse(time.RFC1123, fields["Date"])
	if err != nil || date.After(now.Add(10*time.Second)) {
		return errors.New("signed APT metadata date is invalid or ahead of local clock")
	}
	if until := fields["Valid-Until"]; until != "" {
		expiry, err := time.Parse(time.RFC1123, until)
		if err != nil || !now.Before(expiry) {
			return errors.New("signed APT metadata is expired")
		}
	}
	return nil
}

func ValidateAPT(ctx context.Context, root *os.File, m *serverdepsv1.Manifest) error {
	packages, err := APTProvenance(ctx, root, m)
	if err != nil {
		return err
	}
	for _, entry := range m.Files {
		if entry.Kind != serverdepsv1.FileKind_FILE_KIND_PACKAGE {
			continue
		}
		signed, ok := packages[entry.Path+"#"+entry.Sha256]
		if !ok || signed.size != entry.SizeBytes || entry.VendorSha256 != signed.hash || entry.VendorMetadataPath != signed.metadata || entry.PackageIdentity != signed.identity || entry.SignerFingerprint != UbuntuArchiveFingerprint {
			return fmt.Errorf("APT package lacks exact vendor provenance: %s", entry.Path)
		}
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// APTScript isolates source lists, indexes and archive cache from ambient APT configuration.
// Call inside an egress-denied namespace. Native APT retains signature and expiry checks.
func APTScript(repository, state string, m *serverdepsv1.Manifest, downloadOnly, emptyStatus bool) (string, error) {
	if !strings.HasPrefix(repository, "/") || !strings.HasPrefix(state, "/") || !safePath(strings.TrimPrefix(repository, "/")) || !safePath(strings.TrimPrefix(state, "/")) {
		return "", errors.New("APT paths must be safe absolute paths")
	}
	var sources strings.Builder
	for _, r := range m.Repositories {
		prefix, rest, ok := strings.Cut(r.MetadataPath, "/dists/")
		suite, _, valid := strings.Cut(rest, "/")
		if !ok || !valid || !safePath(prefix) || !safePath(suite) {
			return "", errors.New("APT source shape is invalid")
		}
		fmt.Fprintf(&sources, "deb [signed-by=%s] file:%s/%s %s main\n", repository+"/"+r.SigningKeyPath, repository, prefix, suite)
	}
	config := "Dir::Etc::parts \"" + state + "/config-parts\";\nDir::Etc::main \"" + state + "/empty-main.conf\";\nDir::Etc::sourcelist \"" + state + "/sources.list\";\nDir::Etc::sourceparts \"" + state + "/source-parts\";\nDir::State::lists \"" + state + "/lists\";\nDir::Cache::archives \"" + state + "/archives\";\nAcquire::Languages \"none\";\nAcquire::PDiffs \"false\";\nAcquire::By-Hash \"false\";\nAcquire::CompressionTypes::Order { \"gz\"; };\n"
	// Respect operator-owned configuration during native package upgrades.
	config += "DPkg::Options { \"--force-confdef\"; \"--force-confold\"; };\n"
	if emptyStatus {
		config += "Dir::State::status \"" + state + "/status\";\n"
	}
	script := "set -eu\numask 022\nexport DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1\nmkdir -p " + shellQuote(state+"/lists/partial") + " " + shellQuote(state+"/archives/partial") + " " + shellQuote(state+"/config-parts") + " " + shellQuote(state+"/source-parts") + "\n: > " + shellQuote(state+"/empty-main.conf") + "\nprintf '%s' " + shellQuote(sources.String()) + " > " + shellQuote(state+"/sources.list") + "\nprintf '%s' " + shellQuote(config) + " > " + shellQuote(state+"/apt.conf") + "\n: > " + shellQuote(state+"/status") + "\nexport APT_CONFIG=" + shellQuote(state+"/apt.conf") + "\napt-get update\napt-get -y --no-install-recommends "
	if downloadOnly {
		script += "--download-only "
	}
	script += "install --"
	for _, input := range m.RequestedPackages {
		script += " " + shellQuote(input)
	}
	return script + "\n", nil
}

func InstallAPT(ctx context.Context, repository string, m *serverdepsv1.Manifest) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("APT installation requires root")
	}
	state, err := os.MkdirTemp("", "lindm-serverdeps-apt-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(state)) }()
	// Root-only immutable cache files are not readable by _apt. A private copy is
	// made world-readable but remains root-owned and unmodifiable by that sandbox.
	if err := os.Chmod(state, 0755); err != nil {
		return err
	}
	root, err := openSnapshotRoot(repository)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	copyRoot := state + "/repository"
	for _, item := range m.Files {
		if err := os.MkdirAll(path.Dir(copyRoot+"/"+item.Path), 0755); err != nil {
			return err
		}
		input, err := OpenRetained(root, item)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(copyRoot+"/"+item.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
		if err != nil {
			return errors.Join(err, input.Close())
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(output, hash), input, int64(item.SizeBytes))
		if err := errors.Join(copyErr, input.Close(), output.Close()); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.Sha256 {
			return errors.New("APT staged package changed while copying")
		}
	}
	script, err := APTScript(copyRoot, state+"/native", m, false, false)
	if err != nil {
		return err
	}
	_, err = nativeCommand(ctx, strings.NewReader(script), nil, "unshare", "--net", "--", "sh", "-s")
	return err
}
