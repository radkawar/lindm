// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/custody"
)

// APT origin evidence bounds. A desktop with Ubuntu, vendor and a few
// third-party sources has tens of Release files and a few hundred MiB of
// uncompressed Packages indexes; exceeding a bound is a failed observation,
// never a partial origin set.
const (
	maxAptListEntries   = 8192
	maxAptReleases      = 256
	maxAptIndexes       = 2048
	maxAptReleaseBytes  = 16 << 20
	maxAptIndexBytes    = 1 << 30
	maxAptKeyringFiles  = 128
	maxAptKeyringBytes  = 4 << 20
	maxAptListings      = 16
	maxAptFieldBytes    = 256
	aptIndexLineBytes   = 64 << 10
	aptVerified         = inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED
	aptUnsigned         = inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_UNSIGNED
	aptUnverified       = inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_UNVERIFIED
	aptReleaseSuffix    = "_Release"
	aptInReleaseSuffix  = "_InRelease"
	aptReleaseSigSuffix = "_Release.gpg"
)

// aptSources names the native APT state read for origin evidence. Lists are
// the indexes APT itself resolves installed versions against; keyrings only
// supply public key material, so a verified signer is a cryptographic fact
// about the Release, independent of which file held the key.
type aptSources struct {
	lists    string
	keyrings []aptKeyring
	now      func() time.Time
	// openDir opens a directory whose whole ancestry is trusted; protected
	// accepts an opened entry. Native reads use the custody root walk; tests
	// substitute unprivileged fixtures.
	openDir   func(path string) (*os.File, error)
	protected func(*unix.Stat_t) bool
}

// aptKeyring is one trust location: a directory of *.gpg/*.asc keyrings, or
// only the named file in it.
type aptKeyring struct{ dir, only string }

// nativeApt reads APT's own trust locations through custody: every directory
// and file must be root-protected, and no symlink is followed (Ubuntu's
// trusted.gpg.d links are skipped; their targets are read from
// /usr/share/keyrings). Retired-key files (*-removed-keys.gpg) are never loaded.
var nativeApt = aptSources{
	lists: "/var/lib/apt/lists",
	keyrings: []aptKeyring{
		{dir: "/etc/apt", only: "trusted.gpg"}, {dir: "/etc/apt/trusted.gpg.d"},
		{dir: "/etc/apt/keyrings"}, {dir: "/usr/share/keyrings"},
	},
	now: time.Now,
	openDir: func(path string) (*os.File, error) {
		dir, stat, err := custody.OpenRoot(path, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errors.Join(custody.ErrUnsafe, dir.Close())
		}
		return dir, nil
	},
	protected: custody.RootProtected,
}

// aptRelease is the signed metadata of one Release file in the lists directory.
type aptRelease struct {
	prefix  string
	listing *inventoryv1.AptListing
	sums    map[string]string
}

// attachAptOrigins sets every package's origin. Failure to read the lists
// fails every package's origin with the same status; it never publishes a
// partial listing set that could make a version look singly sourced.
func attachAptOrigins(ctx context.Context, packages []*inventoryv1.Package, sources aptSources, budget int64) {
	listings, status := collectAptListings(ctx, packages, sources)
	used := int64(0)
	for _, pkg := range packages {
		used += int64(proto.Size(pkg)) + 6
	}
	for i, pkg := range packages {
		if status != success {
			pkg.Origin = &inventoryv1.PackageOrigin{Status: status}
			continue
		}
		origin := &inventoryv1.PackageOrigin{Status: success, Listings: listings[i]}
		if len(origin.Listings) > maxAptListings {
			origin = &inventoryv1.PackageOrigin{Status: capacity}
		}
		pkg.Origin = origin
		used += int64(proto.Size(origin)) + 6
	}
	if used > budget {
		for _, pkg := range packages {
			pkg.Origin = &inventoryv1.PackageOrigin{Status: capacity}
		}
	}
}

func collectAptListings(ctx context.Context, packages []*inventoryv1.Package, sources aptSources) ([][]*inventoryv1.AptListing, inventoryv1.CollectionStatus) {
	dir, err := sources.openDir(sources.lists)
	if err != nil {
		return nil, statusFor(err)
	}
	defer func() { _ = dir.Close() }()
	before, err := dir.Stat()
	if err != nil {
		return nil, statusFor(err)
	}
	entries, err := dir.ReadDir(maxAptListEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, statusFor(err)
	}
	if len(entries) > maxAptListEntries {
		return nil, capacity
	}
	releaseNames, signatures, indexes, status := classifyAptLists(entries)
	if status != success {
		return nil, status
	}
	keyring := loadAptKeyring(ctx, sources)
	config := &packet.Config{Time: sources.now}
	releases := make([]aptRelease, 0, len(releaseNames))
	for prefix, name := range releaseNames {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		data, status := sources.readAt(dir, name, maxAptReleaseBytes)
		if status != success {
			return nil, status
		}
		var detached []byte
		if strings.HasSuffix(name, aptReleaseSuffix) && signatures[prefix] {
			detached, status = sources.readAt(dir, prefix+aptReleaseSigSuffix, maxAptReleaseBytes)
			if status != success {
				return nil, status
			}
		}
		releases = append(releases, verifyAptRelease(prefix, data, detached, strings.HasSuffix(name, aptInReleaseSuffix), keyring, config))
	}
	// Longest prefix first, so a nested suite directory binds to its own Release.
	slices.SortFunc(releases, func(a, b aptRelease) int {
		if len(a.prefix) != len(b.prefix) {
			return len(b.prefix) - len(a.prefix)
		}
		return strings.Compare(a.prefix, b.prefix)
	})
	installed := make(map[string][]int, len(packages))
	for i, pkg := range packages {
		key := pkg.GetName() + "\x00" + pkg.GetVersion() + "\x00" + pkg.GetArchitecture()
		installed[key] = append(installed[key], i)
	}
	found := make([][]*inventoryv1.AptListing, len(packages))
	budget := int64(maxAptIndexBytes)
	slices.Sort(indexes)
	for _, name := range indexes {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		listing := &inventoryv1.AptListing{Signature: aptUnsigned}
		var sums map[string]string
		relative := ""
		for _, release := range releases {
			if strings.HasPrefix(name, release.prefix+"_") {
				listing = proto.CloneOf(release.listing)
				sums = release.sums
				relative = name[len(release.prefix)+1:]
				break
			}
		}
		matches, digest, used, status := scanAptIndex(ctx, sources, dir, name, budget, installed)
		if status != success {
			return nil, status
		}
		budget -= used
		if listing.GetSignature() == aptVerified {
			// The index is only as trustworthy as its SHA256 entry in the
			// signed Release; APT's on-disk name maps "/" to "_".
			path, err := url.PathUnescape(strings.ReplaceAll(relative, "_", "/"))
			if err != nil || sums[path] == "" || sums[path] != digest {
				listing.Signature, listing.Signer = aptUnverified, ""
			}
		}
		for _, i := range matches {
			if !slices.ContainsFunc(found[i], func(l *inventoryv1.AptListing) bool { return proto.Equal(l, listing) }) {
				found[i] = append(found[i], listing)
			}
		}
	}
	after, err := dir.Stat()
	if err != nil {
		return nil, statusFor(err)
	}
	// A concurrent apt update replaces lists; a mixed view is not evidence.
	if !before.ModTime().Equal(after.ModTime()) {
		return nil, invalid
	}
	for i := range found {
		slices.SortFunc(found[i], compareListing)
	}
	return found, success
}

// classifyAptLists maps each Release prefix to the file APT verified,
// records detached signatures and returns the Packages indexes.
func classifyAptLists(entries []fs.DirEntry) (releaseNames map[string]string, signatures map[string]bool, indexes []string, status inventoryv1.CollectionStatus) {
	inRelease := map[string]bool{}
	detachedRelease := map[string]bool{}
	signatures = map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() {
			continue
		}
		switch {
		case strings.HasSuffix(name, aptInReleaseSuffix):
			inRelease[strings.TrimSuffix(name, aptInReleaseSuffix)] = true
		case strings.HasSuffix(name, aptReleaseSigSuffix):
			signatures[strings.TrimSuffix(name, aptReleaseSigSuffix)] = true
		case strings.HasSuffix(name, aptReleaseSuffix):
			detachedRelease[strings.TrimSuffix(name, aptReleaseSuffix)] = true
		case strings.HasSuffix(name, "_Packages") || strings.HasSuffix(name, "_Packages.gz"):
			indexes = append(indexes, name)
		case strings.HasSuffix(name, "_Packages.xz") || strings.HasSuffix(name, "_Packages.lz4") || strings.HasSuffix(name, "_Packages.zst") || strings.HasSuffix(name, "_Packages.bz2"):
			// An index this reader cannot decode would silently drop listings.
			return nil, nil, nil, unavailable
		}
	}
	// APT keeps the InRelease it verified; a stale detached Release next to
	// it is not a second source.
	releaseNames = map[string]string{}
	for prefix := range detachedRelease {
		releaseNames[prefix] = prefix + aptReleaseSuffix
	}
	for prefix := range inRelease {
		releaseNames[prefix] = prefix + aptInReleaseSuffix
	}
	if len(releaseNames) > maxAptReleases || len(indexes) > maxAptIndexes {
		return nil, nil, nil, capacity
	}
	return releaseNames, signatures, indexes, success
}

func compareListing(a, b *inventoryv1.AptListing) int {
	for _, pair := range [][2]string{{a.GetOrigin(), b.GetOrigin()}, {a.GetSuite(), b.GetSuite()}, {a.GetCodename(), b.GetCodename()}, {a.GetLabel(), b.GetLabel()}, {a.GetSigner(), b.GetSigner()}} {
		if c := strings.Compare(pair[0], pair[1]); c != 0 {
			return c
		}
	}
	return int(a.GetSignature()) - int(b.GetSignature())
}

// verifyAptRelease parses only signed content. A clearsigned InRelease that
// does not decode, or a Release that fails to parse, contributes listings with
// no claimed origin; its indexes are never dropped.
func verifyAptRelease(prefix string, data, detached []byte, clearsigned bool, keyring openpgp.EntityList, config *packet.Config) aptRelease {
	invalidRelease := aptRelease{prefix: prefix, listing: &inventoryv1.AptListing{Signature: aptUnverified}}
	signed := data
	var signer *openpgp.Entity
	var verifyErr error
	switch {
	case clearsigned:
		block, rest := clearsign.Decode(data)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return invalidRelease
		}
		signed = block.Plaintext
		signer, verifyErr = block.VerifySignature(keyring, config)
	case detached != nil:
		if bytes.HasPrefix(bytes.TrimSpace(detached), []byte("-----BEGIN PGP SIGNATURE-----")) {
			signer, verifyErr = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(detached), config)
		} else {
			signer, verifyErr = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(detached), config)
		}
	}
	fields, sums, ok := parseAptRelease(signed)
	if !ok {
		return invalidRelease
	}
	listing := &inventoryv1.AptListing{Origin: fields["Origin"], Label: fields["Label"], Suite: fields["Suite"], Codename: fields["Codename"]}
	switch {
	case !clearsigned && detached == nil:
		listing.Signature = aptUnsigned
	case verifyErr != nil || signer == nil || signer.PrimaryKey == nil:
		listing.Signature = aptUnverified
	default:
		listing.Signature = aptVerified
		listing.Signer = strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint))
	}
	return aptRelease{prefix: prefix, listing: listing, sums: sums}
}

// parseAptRelease reads the deb822 Release paragraph: the four identity
// fields and the SHA256 index table.
func parseAptRelease(data []byte) (map[string]string, map[string]string, bool) {
	if !utf8.Valid(data) {
		return nil, nil, false
	}
	fields := map[string]string{}
	sums := map[string]string{}
	inSums := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !inSums {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 || len(parts[0]) != 2*sha256.Size {
				return nil, nil, false
			}
			if _, err := strconv.ParseUint(parts[1], 10, 63); err != nil {
				return nil, nil, false
			}
			sums[parts[2]] = strings.ToLower(parts[0])
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, nil, false
		}
		inSums = name == "SHA256"
		switch name {
		case "Origin", "Label", "Suite", "Codename":
			value = strings.TrimSpace(value)
			if _, duplicate := fields[name]; duplicate || len(value) > maxAptFieldBytes || strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return nil, nil, false
			}
			fields[name] = value
		}
	}
	return fields, sums, true
}

// scanAptIndex streams one Packages index, hashing the bytes as stored, and
// returns the installed packages whose exact identity it lists.
func scanAptIndex(ctx context.Context, sources aptSources, dir *os.File, name string, budget int64, installed map[string][]int) (_ []int, digest string, used int64, status inventoryv1.CollectionStatus) {
	file, status := sources.openAt(dir, name)
	if status != success {
		return nil, "", 0, status
	}
	defer func() {
		if err := file.Close(); err != nil && status == success {
			status = statusFor(err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, "", 0, statusFor(err)
	}
	if info.Size() > budget {
		return nil, "", 0, capacity
	}
	limited := &io.LimitedReader{R: file, N: budget + 1}
	hash := sha256.New()
	stored := io.TeeReader(limited, hash)
	input := stored
	if strings.HasSuffix(name, ".gz") {
		decompressed, err := gzip.NewReader(stored)
		if err != nil {
			return nil, "", 0, invalid
		}
		defer func() { _ = decompressed.Close() }()
		input = &io.LimitedReader{R: decompressed, N: budget + 1}
	}
	matches, status := parseAptIndex(ctx, input, installed)
	if status != success {
		return nil, "", 0, status
	}
	if _, err := io.Copy(io.Discard, stored); err != nil {
		return nil, "", 0, statusFor(err)
	}
	used = budget + 1 - limited.N
	if limited.N == 0 {
		return nil, "", used, capacity
	}
	after, err := file.Stat()
	if err != nil {
		return nil, "", used, statusFor(err)
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, "", used, invalid
	}
	return matches, hex.EncodeToString(hash.Sum(nil)), used, success
}

func parseAptIndex(ctx context.Context, input io.Reader, installed map[string][]int) ([]int, inventoryv1.CollectionStatus) {
	reader := bufio.NewReaderSize(input, aptIndexLineBytes)
	var matches []int
	var name, version, arch string
	stanzas := 0
	flush := func() {
		if name != "" {
			matches = append(matches, installed[name+"\x00"+version+"\x00"+arch]...)
		}
		name, version, arch = "", "", ""
	}
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Long dependency or description lines are irrelevant; identity
			// fields never exceed the buffer.
			if bytes.HasPrefix(line, []byte("Package:")) || bytes.HasPrefix(line, []byte("Version:")) || bytes.HasPrefix(line, []byte("Architecture:")) {
				return nil, invalid
			}
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, statusFor(err)
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, invalid
		}
		text := strings.TrimRight(string(line), "\r\n")
		switch {
		case text == "":
			flush()
			stanzas++
			if stanzas%4096 == 0 && ctx.Err() != nil {
				return nil, statusFor(ctx.Err())
			}
		case strings.HasPrefix(text, "Package:"):
			name = strings.TrimSpace(text[len("Package:"):])
		case strings.HasPrefix(text, "Version:"):
			version = strings.TrimSpace(text[len("Version:"):])
		case strings.HasPrefix(text, "Architecture:"):
			arch = strings.TrimSpace(text[len("Architecture:"):])
		}
		if errors.Is(err, io.EOF) {
			flush()
			return matches, success
		}
	}
}

// loadAptKeyring collects public keys from APT's trust locations. Unreadable
// or malformed keyrings contribute no keys: their releases stay UNVERIFIED,
// which can only reduce, never extend, verified origin.
func loadAptKeyring(ctx context.Context, sources aptSources) openpgp.EntityList {
	var keyring openpgp.EntityList
	files := 0
	for _, location := range sources.keyrings {
		dir, err := sources.openDir(location.dir)
		if err != nil {
			continue
		}
		entries, err := dir.ReadDir(maxAptKeyringFiles + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			entries = nil
		}
		for _, entry := range entries {
			name := entry.Name()
			if files >= maxAptKeyringFiles || ctx.Err() != nil {
				break
			}
			if location.only != "" && name != location.only {
				continue
			}
			if !entry.Type().IsRegular() || strings.Contains(name, "-removed-keys") || (location.only == "" && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".asc")) {
				continue
			}
			files++
			data, status := sources.readAt(dir, name, maxAptKeyringBytes)
			if status != success {
				continue
			}
			var entities openpgp.EntityList
			if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PGP")) {
				entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
			} else {
				entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
			}
			if err == nil {
				keyring = append(keyring, entities...)
			}
		}
		_ = dir.Close()
	}
	return keyring
}

// openAt opens a regular, protected entry of an already-open directory
// without following a symlink.
func (s aptSources) openAt(dir *os.File, name string) (*os.File, inventoryv1.CollectionStatus) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, statusFor(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, statusFor(errors.Join(err, unix.Close(fd)))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || !s.protected(&stat) {
		return nil, statusFor(errors.Join(custody.ErrUnsafe, unix.Close(fd)))
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), success
}

func (s aptSources) readAt(dir *os.File, name string, limit int64) (_ []byte, status inventoryv1.CollectionStatus) {
	file, status := s.openAt(dir, name)
	if status != success {
		return nil, status
	}
	defer func() {
		if err := file.Close(); err != nil && status == success {
			status = statusFor(err)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, statusFor(err)
	}
	if int64(len(data)) > limit {
		return nil, capacity
	}
	return data, success
}
