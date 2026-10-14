// SPDX-License-Identifier: Apache-2.0

//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"buf.build/go/protovalidate"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"golang.org/x/sys/unix"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
	"lindm/internal/packaging"
)

const nativeMetadataLimit = 16 << 20
const nativePackageLimit = 1 << 30
const nativePublicKey = "lindm-package-signing.asc"

var nativeComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)

// A snapshot admits only public files reached through authenticated native
// metadata. Installed bundles are immutable release artifacts; custom
// publications must be identical on every replica. A restart captures the
// matching publication after an upgrade.
type nativeRepository struct {
	ctx           context.Context
	directory     string
	files         map[string]nativeFile
	architectures []string
	fingerprint   string
	versions      map[string][]string
	err           error
}

type nativeFile struct {
	info   os.FileInfo
	digest string
}

type nativeRepositories struct {
	apt, rpm, arch *nativeRepository
}

func loadNativeRepositories(ctx context.Context, resources *config.Resources) *nativeRepositories {
	pins := resources.Proto.GetReleaseRepository().GetNativeRepositories()
	if pins == nil {
		return loadBundledNativeRepositories(ctx)
	}
	return &nativeRepositories{
		apt:  loadNativeRepository(ctx, resources.ReleaseRepositoryDirectory, "apt", pins.GetAptSigningKeyFingerprint()),
		rpm:  loadNativeRepository(ctx, resources.ReleaseRepositoryDirectory, "rpm", pins.GetRpmSigningKeyFingerprint()),
		arch: loadNativeRepository(ctx, resources.ReleaseRepositoryDirectory, string(packaging.FormatArch), pins.GetArchSigningKeyFingerprint()),
	}
}

func loadNativeRepository(ctx context.Context, directory, family, fingerprint string) *nativeRepository {
	r := &nativeRepository{ctx: ctx, directory: filepath.Join(directory, "repo", family), files: make(map[string]nativeFile), fingerprint: fingerprint, versions: make(map[string][]string)}
	if directory == "" || fingerprint == "" {
		r.err = errors.New("native repository directory and signer pin are required")
		return r
	}
	key, err := r.read(nativePublicKey)
	if err != nil {
		r.err = err
		return r
	}
	keys, err := nativeSigningKeys(key, fingerprint)
	if err == nil {
		switch family {
		case "apt":
			err = r.readAPT(keys)
		case "rpm":
			err = r.readRPM(keys)
		case string(packaging.FormatArch):
			err = r.readArch(keys)
		}
	}
	if err == nil && len(r.architectures) == 0 {
		err = errors.New("signed repository contains no supported lindm-agent architecture")
	}
	r.err = err
	return r
}

func (r *nativeRepository) addVersion(arch, version string) error {
	if err := protovalidate.Validate(&adminv1.EnrollmentAgentPackage{Architecture: arch, Version: version}); err != nil {
		return err
	}
	if version == "" || version == "-" {
		return errors.New("native agent version is missing from signed metadata")
	}
	if !slices.Contains(r.versions[arch], version) {
		r.versions[arch] = append(r.versions[arch], version)
		slices.Sort(r.versions[arch])
	}
	return nil
}

func nativeSigningKeys(encoded []byte, fingerprint string) (openpgp.EntityList, error) {
	encoded = bytes.TrimSpace(encoded)
	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"
	if !bytes.HasPrefix(encoded, []byte(begin)) || !bytes.HasSuffix(encoded, []byte(end)) || bytes.Count(encoded, []byte("-----BEGIN PGP")) != 1 || bytes.Count(encoded, []byte("-----END PGP")) != 1 {
		return nil, errors.New("native repository requires exactly one public key armor block")
	}
	block, err := armor.Decode(bytes.NewReader(encoded))
	if err != nil || block.Type != openpgp.PublicKeyType {
		return nil, errors.New("native repository requires a public OpenPGP export")
	}
	// Inspect every packet: parsers may otherwise retain or ignore secret subkeys.
	packets := packet.NewReader(block.Body)
	for {
		p, err := packets.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if _, secret := p.(*packet.PrivateKey); secret {
			return nil, errors.New("native repository contains private key material")
		}
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 || strings.ToUpper(hex.EncodeToString(keys[0].PrimaryKey.Fingerprint)) != fingerprint || keys[0].PrivateKey != nil {
		return nil, errors.New("native repository signer does not match configured fingerprint")
	}
	return keys, nil
}

func verifyNativeSignature(keys openpgp.EntityList, data, signature []byte, armored bool) error {
	proof, err := nativeSignature(signature, armored)
	if err != nil {
		return err
	}
	now := time.Now()
	cfg := &packet.Config{Time: func() time.Time { return now }}
	sig, signer, err := openpgp.VerifyDetachedSignature(keys, bytes.NewReader(data), bytes.NewReader(proof), cfg)
	if err != nil {
		return err
	}
	if sig.IssuerKeyId == nil || sig.CreationTime.After(now) {
		return errors.New("native repository signature time or issuer is invalid")
	}
	if _, ok := signer.SigningKeyById(now, *sig.IssuerKeyId, cfg); !ok {
		return errors.New("native repository signer is expired or revoked")
	}
	return nil
}

func nativeSignature(signature []byte, armored bool) ([]byte, error) {
	if len(signature) == 0 || len(signature) > 64<<10 {
		return nil, errors.New("native signature exceeds bound")
	}
	if armored {
		signature = bytes.TrimSpace(signature)
		if !bytes.HasPrefix(signature, []byte("-----BEGIN PGP SIGNATURE-----")) || !bytes.HasSuffix(signature, []byte("-----END PGP SIGNATURE-----")) || bytes.Count(signature, []byte("-----BEGIN PGP")) != 1 || bytes.Count(signature, []byte("-----END PGP")) != 1 {
			return nil, errors.New("native repository requires exactly one signature armor block")
		}
		block, err := armor.Decode(bytes.NewReader(signature))
		if err != nil {
			return nil, err
		}
		signature, err = io.ReadAll(io.LimitReader(block.Body, (64<<10)+1))
		if err != nil {
			return nil, err
		}
	}
	reader := bytes.NewReader(signature)
	p, err := packet.Read(reader)
	if err != nil {
		return nil, err
	}
	if _, ok := p.(*packet.Signature); !ok || reader.Len() != 0 {
		return nil, errors.New("native repository requires exactly one detached signature packet")
	}
	return signature, nil
}

func nativePath(name string) bool {
	if len(name) == 0 || len(name) > 1024 {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if !nativeComponent.MatchString(component) {
			return false
		}
	}
	return true
}

func (r *nativeRepository) open(name string) (*os.File, error) {
	if !nativePath(name) {
		return nil, errors.New("invalid native artifact path")
	}
	path, err := filepath.Abs(filepath.Join(r.directory, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	// RestrictSUIDSGID returns ENOSYS for openat2. Pin each directory instead;
	// O_NOFOLLOW on only the leaf would not preserve RESOLVE_NO_SYMLINKS.
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for remaining := path[1:]; remaining != ""; {
		component, rest, _ := strings.Cut(remaining, "/")
		flags := unix.O_PATH | unix.O_DIRECTORY
		if rest == "" {
			flags = unix.O_RDONLY
		}
		next, openErr := unix.Openat(fd, component, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		closeErr := unix.Close(fd)
		if err := errors.Join(openErr, closeErr); err != nil {
			if next >= 0 {
				err = errors.Join(err, unix.Close(next))
			}
			return nil, fmt.Errorf("open native artifact: %w", err)
		}
		fd, remaining = next, rest
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > nativePackageLimit {
		_ = f.Close()
		return nil, errors.New("native artifact must be a bounded nonempty regular file")
	}
	return f, nil
}

func (r *nativeRepository) read(name string) (data []byte, err error) {
	if len(r.files) >= 256 {
		return nil, errors.New("too many native repository files")
	}
	f, err := r.open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > nativeMetadataLimit {
		return nil, errors.New("native metadata exceeds bound")
	}
	data, err = io.ReadAll(io.LimitReader(nativeContextReader{r.ctx, f}, nativeMetadataLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > nativeMetadataLimit {
		return nil, errors.New("native metadata exceeds bound")
	}
	digest := sha256.Sum256(data)
	r.files[name] = nativeFile{info: info, digest: hex.EncodeToString(digest[:])}
	return data, nil
}

func (r *nativeRepository) admitPackage(name, checksum string, size int64) (err error) {
	if len(r.files) >= 256 || len(checksum) != 64 || size <= 0 || size > nativePackageLimit {
		return errors.New("invalid native package metadata")
	}
	f, err := r.open(name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return errors.New("native package size mismatch")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(nativeContextReader{r.ctx, f}, nativePackageLimit+1)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != checksum {
		return errors.New("native package checksum mismatch")
	}
	r.files[name] = nativeFile{info: info, digest: checksum}
	return nil
}

func (r *nativeRepository) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := req.URL.Path
	entry, ok := r.files[name]
	if r.err != nil || !ok || req.URL.RawPath != "" || req.URL.RawQuery != "" || !nativePath(name) {
		http.NotFound(w, req)
		return
	}
	f, err := r.open(name)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !nativeFileUnchanged(entry.info, info) {
		http.Error(w, "repository publication changed; restart required", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+entry.digest+`"`)
	// Stable metadata names must revalidate across coordinated publications.
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	http.ServeContent(w, req, name, info.ModTime(), f)
}

func nativeFileUnchanged(before, after os.FileInfo) bool {
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	first, firstOK := before.Sys().(*syscall.Stat_t)
	second, secondOK := after.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && first.Ctim == second.Ctim
}

func (r *nativeRepository) readAPT(keys openpgp.EntityList) error {
	base := "dists/" + packaging.APTDistribution + "/"
	inRelease, err := r.read(base + "InRelease")
	if err != nil {
		return err
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil || !bytes.HasPrefix(bytes.TrimSpace(inRelease), []byte("-----BEGIN PGP SIGNED MESSAGE-----")) || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid native InRelease")
	}
	proof, err := io.ReadAll(io.LimitReader(block.ArmoredSignature.Body, nativeMetadataLimit+1))
	if err != nil {
		return err
	}
	if err := verifyNativeSignature(keys, block.Bytes, proof, false); err != nil {
		return err
	}
	release, err := r.read(base + "Release")
	if err != nil {
		return err
	}
	signature, err := r.read(base + "Release.gpg")
	if err != nil {
		return err
	}
	if err := verifyNativeSignature(keys, release, signature, true); err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(block.Plaintext), bytes.TrimSpace(release)) {
		return errors.New("native Release and InRelease differ")
	}
	checksums := make(map[string]string)
	inSHA256 := false
	for _, line := range strings.Split(string(release), "\n") {
		if line == "SHA256:" {
			inSHA256 = true
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inSHA256 = false
		}
		if !inSHA256 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return errors.New("invalid native Release checksum")
		}
		checksums[fields[2]] = fields[0]
	}
	for _, arch := range []string{"amd64", "arm64"} {
		name := packaging.APTComponent + "/binary-" + arch + "/Packages"
		expected, ok := checksums[name]
		if !ok {
			continue
		}
		data, err := r.read(base + name)
		if err != nil {
			return err
		}
		if r.files[base+name].digest != expected {
			return errors.New("native Packages checksum mismatch")
		}
		found := false
		for _, paragraph := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
			fields := make(map[string]string)
			for _, line := range strings.Split(paragraph, "\n") {
				key, value, ok := strings.Cut(line, ": ")
				if ok {
					fields[key] = value
				}
			}
			if fields["Package"] != packaging.PackageName {
				continue
			}
			if fields["Architecture"] != arch || !strings.HasPrefix(fields["Filename"], "pool/") || !strings.HasSuffix(fields["Filename"], ".deb") {
				return errors.New("invalid native agent package identity")
			}
			size, err := strconv.ParseInt(fields["Size"], 10, 64)
			if err != nil {
				return err
			}
			if err := r.admitPackage(fields["Filename"], fields["SHA256"], size); err != nil {
				return err
			}
			if err := r.addVersion(arch, fields["Version"]); err != nil {
				return err
			}
			found = true
		}
		if found {
			r.architectures = append(r.architectures, arch)
		}
		if expected, ok := checksums[name+".gz"]; ok {
			if _, err := r.read(base + name + ".gz"); err != nil {
				return err
			}
			if r.files[base+name+".gz"].digest != expected {
				return errors.New("native compressed Packages checksum mismatch")
			}
		}
	}
	return nil
}

type nativeRepoMD struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Checksum struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
	} `xml:"data"`
}

type nativeRPMPrimary struct {
	Packages []struct {
		Name    string `xml:"name"`
		Arch    string `xml:"arch"`
		Version struct {
			Epoch   string `xml:"epoch,attr"`
			Version string `xml:"ver,attr"`
			Release string `xml:"rel,attr"`
		} `xml:"version"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Checksum struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
		Size struct {
			Package int64 `xml:"package,attr"`
		} `xml:"size"`
	} `xml:"package"`
}

func (r *nativeRepository) readRPM(keys openpgp.EntityList) error {
	data, err := r.read("repodata/repomd.xml")
	if err != nil {
		return err
	}
	sig, err := r.read("repodata/repomd.xml.asc")
	if err != nil {
		return err
	}
	if err := verifyNativeSignature(keys, data, sig, true); err != nil {
		return err
	}
	var metadata nativeRepoMD
	if err := xml.Unmarshal(data, &metadata); err != nil {
		return err
	}
	for _, item := range metadata.Data {
		name := item.Location.Href
		if !strings.HasPrefix(name, "repodata/") || path.Ext(name) != ".gz" || item.Checksum.Type != "sha256" {
			return errors.New("unsupported native RPM metadata")
		}
		encoded, err := r.read(name)
		if err != nil {
			return err
		}
		if r.files[name].digest != item.Checksum.Value {
			return errors.New("native RPM metadata checksum mismatch")
		}
		if item.Type != "primary" {
			continue
		}
		gz, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		decoded, err := io.ReadAll(io.LimitReader(gz, nativeMetadataLimit+1))
		err = errors.Join(err, gz.Close())
		if err != nil {
			return err
		}
		if len(decoded) > nativeMetadataLimit {
			return errors.New("native RPM primary exceeds bound")
		}
		var primary nativeRPMPrimary
		if err := xml.Unmarshal(decoded, &primary); err != nil {
			return err
		}
		for _, pkg := range primary.Packages {
			if pkg.Name != packaging.PackageName {
				continue
			}
			arch := nativeArchitecture(pkg.Arch)
			if arch == "" {
				continue
			}
			if pkg.Checksum.Type != "sha256" || !strings.HasPrefix(pkg.Location.Href, packaging.PackageName+"-") || !strings.HasSuffix(pkg.Location.Href, ".rpm") {
				return errors.New("invalid native RPM agent identity")
			}
			if err := r.admitPackage(pkg.Location.Href, pkg.Checksum.Value, pkg.Size.Package); err != nil {
				return err
			}
			version := pkg.Version.Version + "-" + pkg.Version.Release
			if pkg.Version.Epoch != "" && pkg.Version.Epoch != "0" {
				version = pkg.Version.Epoch + ":" + version
			}
			if err := r.addVersion(arch, version); err != nil {
				return err
			}
			if !containsArchitecture(r.architectures, arch) {
				r.architectures = append(r.architectures, arch)
			}
		}
	}
	return nil
}

func containsArchitecture(architectures []string, arch string) bool {
	for _, value := range architectures {
		if value == arch {
			return true
		}
	}
	return false
}

func nativeArchitecture(arch string) string {
	switch arch {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return ""
	}
}

func (r *nativeRepository) readArch(keys openpgp.EntityList) error {
	data, err := r.read("lindm.db")
	if err != nil {
		return err
	}
	signature, err := r.read("lindm.db.sig")
	if err != nil {
		return err
	}
	if err := verifyNativeSignature(keys, data, signature, false); err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(io.LimitReader(gz, nativeMetadataLimit+1))
	for count := 0; ; count++ {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= 8 || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 64<<10 || !nativePath(header.Name) || !strings.HasSuffix(header.Name, "/desc") {
			return errors.New("invalid native Arch sync database entry")
		}
		data, err := io.ReadAll(io.LimitReader(tr, (64<<10)+1))
		if err != nil {
			return err
		}
		fields := make(map[string]string)
		for _, section := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
			key, value, ok := strings.Cut(section, "\n")
			if ok {
				fields[key] = value
			}
		}
		if fields["%NAME%"] != packaging.PackageName {
			continue
		}
		arch := nativeArchitecture(fields["%ARCH%"])
		if arch == "" {
			continue
		}
		name := fields["%FILENAME%"]
		if !strings.HasPrefix(name, packaging.PackageName+"-") || !strings.HasSuffix(name, ".pkg.tar.zst") || strings.Contains(name, "/") {
			return errors.New("invalid native Arch agent identity")
		}
		size, err := strconv.ParseInt(fields["%CSIZE%"], 10, 64)
		if err != nil {
			return err
		}
		if err := r.admitPackage(name, fields["%SHA256SUM%"], size); err != nil {
			return err
		}
		if err := r.addVersion(arch, fields["%VERSION%"]); err != nil {
			return err
		}
		signature, err := r.read(name + ".sig")
		if err != nil {
			return err
		}
		embedded, err := base64.StdEncoding.DecodeString(fields["%PGPSIG%"])
		if err != nil || !bytes.Equal(signature, embedded) {
			return errors.New("native Arch package signature differs from signed database")
		}
		if _, err := nativeSignature(signature, false); err != nil {
			return err
		}
		// Package bytes are streamed through native OpenPGP verification.
		file, err := r.open(name)
		if err != nil {
			return err
		}
		_, _, verifyErr := openpgp.VerifyDetachedSignature(keys, nativeContextReader{r.ctx, file}, bytes.NewReader(signature), nil)
		if err := errors.Join(verifyErr, file.Close()); err != nil {
			return err
		}
		if !containsArchitecture(r.architectures, arch) {
			r.architectures = append(r.architectures, arch)
		}
	}
}

type nativeContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r nativeContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
