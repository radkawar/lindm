//go:build linux

package packaging

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"lindm/internal/platform"
)

const archRelease = "1"

// Pacman sources .INSTALL and calls these fixed functions. The lifecycle asset
// owns the account, protected state and service transitions on every platform.
const archInstall = `post_install() {
  /bin/sh /usr/libexec/lindm/lifecycle configure
}
pre_upgrade() {
  /bin/sh /usr/libexec/lindm/lifecycle upgrade-stop
}
post_upgrade() {
  post_install
}
pre_remove() {
  /bin/sh /usr/libexec/lindm/lifecycle remove
}
post_remove() {
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
  fi
}
`

type archMember struct {
	name   string
	mode   int64
	size   int64
	dir    bool
	path   string
	data   []byte
	digest string
}

func buildArch(ctx context.Context, work, payload, version string, arch Architecture, epoch int64, key SigningKey, payloadSHA string, staged []stagedFile, p product) (Artifact, error) {
	arch.Arch = arch.RPM
	if arch.Arch != "x86_64" && arch.Arch != "aarch64" {
		return Artifact{}, ErrArchitecture
	}
	members, err := archPayloadMembers(payload)
	if err != nil {
		return Artifact{}, err
	}
	var size int64
	for _, m := range members {
		size += m.size
	}
	pkgver := version + "-" + archRelease
	var info strings.Builder
	fmt.Fprintf(&info, "pkgname = %s\npkgbase = %s\nxdata = pkgtype=pkg\npkgver = %s\npkgdesc = %s\nbuilddate = %d\npackager = Lindm Packaging <packaging@lindm.invalid>\nsize = %d\narch = %s\nlicense = UNLICENSED\ndepend = systemd\ndepend = glibc\ndepend = coreutils\ndepend = sh\n", p.name, p.name, pkgver, p.summary, epoch, size, arch.Arch)
	if p.name == PackageName {
		for _, dependency := range platform.BackendPacman.ResourceDependencies() {
			fmt.Fprintf(&info, "depend = %s\n", dependency)
		}
	}
	for _, optional := range p.archOptdepends {
		fmt.Fprintf(&info, "optdepend = %s\n", optional)
	}
	for _, file := range staged {
		if file.Conf {
			fmt.Fprintf(&info, "backup = %s\n", file.Rel)
		}
	}
	// This is a Go assembler, not a makepkg invocation. Keep its deterministic
	// recipe in the archive and hash that exact input, without inventing an
	// installed-package inventory or claiming a clean Arch build environment.
	recipe := fmt.Sprintf("# lindm native archive recipe: payload is staged before assembly\npkgname=%s\npkgver=%s\npkgrel=%s\narch=('%s')\n# prebuilt static Go payload sha256: %s\npackage() {\n  cp -a \"$srcdir/payload/.\" \"$pkgdir/\"\n}\n", p.name, version, archRelease, arch.Arch, payloadSHA)
	buildinfo := fmt.Sprintf("format = 2\npkgname = %s\npkgbase = %s\npkgver = %s\npkgarch = %s\npkgbuild_sha256sum = %x\npackager = Lindm Packaging <packaging@lindm.invalid>\nbuilddate = %d\nbuilddir = /build/lindm\nstartdir = /build/lindm\nbuildtool = go\nbuildtoolver = %s-1-any\n", p.name, p.name, pkgver, arch.Arch, sha256.Sum256([]byte(recipe)), epoch, strings.TrimPrefix(runtime.Version(), "go"))
	install := strings.ReplaceAll(archInstall, lifecyclePath, p.lifecycle)
	if p.name == ServerPackageName {
		// Server upgrades never stop/start services or run migrations.
		install = `post_install() {
  /bin/sh /usr/libexec/lindmd/lifecycle configure
}
post_upgrade() {
  post_install
}
pre_remove() {
  /bin/sh /usr/libexec/lindmd/lifecycle remove
}
post_remove() {
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
  fi
}
`
	}
	for _, item := range []struct{ name, data string }{{".PKGINFO", info.String()}, {".BUILDINFO", buildinfo}, {".INSTALL", install}, {".PKGBUILD", recipe}} {
		members = append(members, archMemoryMember(item.name, []byte(item.data)))
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	mtree, err := archMtree(members, epoch)
	if err != nil {
		return Artifact{}, err
	}
	members = append([]archMember{archMemoryMember(".MTREE", mtree)}, members...)
	path := filepath.Join(work, fmt.Sprintf("%s-%s-%s.pkg.tar.zst", p.name, pkgver, arch.Arch))
	if err := writeArchArchive(ctx, path, members, epoch); err != nil {
		return Artifact{}, err
	}
	if err := signArchFile(ctx, work, path, key, epoch); err != nil {
		return Artifact{}, err
	}
	publicDir, err := os.MkdirTemp(work, "arch-public-")
	if err != nil {
		return Artifact{}, err
	}
	public, _, err := exportPublicKeys(ctx, work, key, publicDir)
	if err != nil {
		return Artifact{}, err
	}
	if err := verifyArchSignature(ctx, work, path, public); err != nil {
		return Artifact{}, err
	}
	sum, archiveSize, err := hashFile(path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Product: p.name, Format: FormatArch, Path: path, SignaturePath: path + ".sig", SHA256: sum, UnsignedSHA256: sum, Size: archiveSize, Architecture: arch, Version: version, PayloadSHA256: payloadSHA, Signed: true, SignerFingerprint: key.Fingerprint}, nil
}

func archMemoryMember(name string, data []byte) archMember {
	return archMember{name: name, mode: 0o644, size: int64(len(data)), data: data, digest: fmt.Sprintf("%x", sha256.Sum256(data))}
}

func archPayloadMembers(root string) ([]archMember, error) {
	var members []archMember
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%w: unsupported Arch payload member", ErrArtifact)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		m := archMember{name: filepath.ToSlash(rel), mode: int64(info.Mode().Perm()), dir: info.IsDir(), path: path}
		if !m.dir {
			m.digest, m.size, err = hashFile(path)
			if err != nil {
				return err
			}
		}
		members = append(members, m)
		return nil
	})
	return members, err
}

func archMtree(members []archMember, epoch int64) ([]byte, error) {
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	if _, err := io.WriteString(gz, "#mtree\n/set uid=0 gid=0\n"); err != nil {
		return nil, err
	}
	for _, m := range members {
		kind := "file"
		if m.dir {
			kind = "dir"
		}
		// Fixed product paths contain no whitespace or mtree metacharacters.
		if strings.ContainsAny(m.name, "\\ \t\r\n#=") {
			return nil, fmt.Errorf("%w: unsafe mtree member", ErrArtifact)
		}
		line := fmt.Sprintf("./%s type=%s mode=%o time=%d.0", m.name, kind, m.mode, epoch)
		if !m.dir {
			line += fmt.Sprintf(" size=%d sha256digest=%s", m.size, m.digest)
		}
		if _, err := io.WriteString(gz, line+"\n"); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func writeArchArchive(ctx context.Context, path string, members []archMember, epoch int64) (err error) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	zw, err := zstd.NewWriter(out, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)
	for _, m := range members {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, tw.Close(), zw.Close())
		}
		h := &tar.Header{Name: m.name, Mode: m.mode, Size: m.size, ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if m.dir {
			h.Typeflag = tar.TypeDir
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return errors.Join(err, tw.Close(), zw.Close())
		}
		if m.dir {
			continue
		}
		var copyErr error
		if m.path == "" {
			_, copyErr = tw.Write(m.data)
		} else {
			file, openErr := os.Open(m.path)
			if openErr != nil {
				return errors.Join(openErr, tw.Close(), zw.Close())
			}
			_, copyErr = io.Copy(tw, file)
			copyErr = errors.Join(copyErr, file.Close())
		}
		if copyErr != nil {
			return errors.Join(copyErr, tw.Close(), zw.Close())
		}
	}
	return errors.Join(tw.Close(), zw.Close(), out.Chmod(0o644), out.Sync())
}

func signArchFile(ctx context.Context, work, path string, key SigningKey, epoch int64) error {
	pass, err := passphraseFile(work, key)
	if err != nil {
		return err
	}
	signingEpoch, err := rpmSigningEpoch(ctx, work, key, epoch)
	if err != nil {
		return err
	}
	if _, _, err := runTool(ctx, work, toolCmd{Name: "gpg", Args: []string{"--no-options", "--batch", "--no-tty", "--faked-system-time", fmt.Sprintf("%d!", signingEpoch), "--pinentry-mode", "loopback", "--passphrase-file", pass, "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--no-armor", "--detach-sign", "--output", path + ".sig", path}, ExtraEnv: gpgEnv(key.Home)}); err != nil {
		return err
	}
	return os.Chmod(path+".sig", 0o644)
}

func verifyArchSignature(ctx context.Context, work, path, public string) error {
	if _, _, err := runTool(ctx, work, toolCmd{Name: "gpgv", Args: []string{"--homedir", work, "--keyring", public, path + ".sig", path}}); err != nil {
		return fmt.Errorf("%w: Arch detached signature: %w", ErrArtifact, err)
	}
	return nil
}

// archBuildToolVersion identifies the in-process archive implementation. It is
// not evidence that makepkg or repo-add were invoked.
func archBuildToolVersion() ToolVersion {
	return ToolVersion{Name: "lindm-packaging", Version: "arch-format-1 " + runtime.Version()}
}
