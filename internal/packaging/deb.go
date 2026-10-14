// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func buildDEB(ctx context.Context, work, payload, version string, arch Architecture, epoch int64, staged []stagedFile, payloadSHA string, p product) (Artifact, error) {
	root := filepath.Join(work, "deb")
	if err := os.Mkdir(root, 0o755); err != nil {
		return Artifact{}, err
	}
	if err := copyTree(payload, root, epoch); err != nil {
		return Artifact{}, err
	}
	control := filepath.Join(root, "DEBIAN")
	if err := os.Mkdir(control, 0o755); err != nil {
		return Artifact{}, err
	}
	size, err := installedSize(payload)
	if err != nil {
		return Artifact{}, err
	}
	dependencies := ""
	if len(p.units) != 0 {
		dependencies = "Depends: systemd\n"
	}
	if len(p.debRecommends) != 0 {
		dependencies += "Recommends: " + strings.Join(p.debRecommends, ", ") + "\n"
	}
	text := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Lindm Packaging <packaging@lindm.invalid>\nSection: admin\nPriority: optional\n%sInstalled-Size: %d\nDescription: %s\n %s\n", p.name, version, arch.Debian, dependencies, size, p.summary, strings.ReplaceAll(p.description, "\n", "\n "))
	if err := writeFile(filepath.Join(control, "control"), []byte(text), 0o644, epoch); err != nil {
		return Artifact{}, err
	}
	if p.lifecycleAsset != "" {
		script, err := asset(p.lifecycleAsset)
		if err != nil {
			return Artifact{}, err
		}
		for _, name := range []string{"postinst", "prerm", "postrm"} {
			if err := writeFile(filepath.Join(control, name), script, 0o755, epoch); err != nil {
				return Artifact{}, err
			}
		}
	}
	if p.name == ServerPackageName {
		gate, err := asset("server-preinstall.sh")
		if err != nil {
			return Artifact{}, err
		}
		gate = []byte(strings.ReplaceAll(string(gate), "@LINDM_VERSION@", version))
		if err := writeFile(filepath.Join(control, "preinst"), gate, 0o755, epoch); err != nil {
			return Artifact{}, err
		}
	}
	var conffiles strings.Builder
	for _, file := range staged {
		if file.Conf {
			fmt.Fprintf(&conffiles, "/%s\n", file.Rel)
		}
	}
	if conffiles.Len() != 0 {
		if err := writeFile(filepath.Join(control, "conffiles"), []byte(conffiles.String()), 0o644, epoch); err != nil {
			return Artifact{}, err
		}
	}
	if err := stampDirectories(root, epoch); err != nil {
		return Artifact{}, err
	}
	out := filepath.Join(work, fmt.Sprintf("%s_%s_%s.deb", p.name, version, arch.Debian))
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:     "dpkg-deb",
		Args:     []string{"--root-owner-group", "--uniform-compression", "-Zgzip", "-z9", "--build", root, out},
		ExtraEnv: []string{"SOURCE_DATE_EPOCH=" + fmt.Sprint(epoch)},
	}); err != nil {
		return Artifact{}, err
	}
	if err := verifyDEB(ctx, work, out, version, arch, payloadSHA, staged, p); err != nil {
		return Artifact{}, err
	}
	sum, sizeBytes, err := hashFile(out)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Product:        p.name,
		Format:         FormatDEB,
		Path:           out,
		SHA256:         sum,
		UnsignedSHA256: sum,
		Size:           sizeBytes,
		Architecture:   arch,
		Version:        version,
		PayloadSHA256:  payloadSHA,
		Signed:         false,
	}, nil
}

func verifyDEB(ctx context.Context, work, deb, version string, arch Architecture, payloadSHA string, staged []stagedFile, p product) error {
	stdout, _, err := runTool(ctx, work, toolCmd{
		Name: "dpkg-deb",
		Args: []string{"--show", "--showformat", "${Package}\t${Version}\t${Architecture}\n", deb},
	})
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s\t%s\t%s\n", p.name, version, arch.Debian)
	if string(stdout) != want {
		return fmt.Errorf("%w: deb control fields do not match the request", ErrArtifact)
	}
	tarPath := filepath.Join(work, "deb.tar")
	stream, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	_, _, runErr := runTool(ctx, work, toolCmd{
		Name:   "dpkg-deb",
		Args:   []string{"--fsys-tarfile", deb},
		Stdout: stream,
	})
	closeErr := stream.Close()
	if err := errors.Join(runErr, closeErr); err != nil {
		return err
	}
	file, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	reader := tar.NewReader(file)
	found := map[string]bool{}
	expected := make(map[string]stagedFile, len(staged))
	for _, item := range staged {
		expected[item.Rel] = item
	}
	var payload string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(header.Name, "./")
		name = strings.TrimPrefix(name, "/")
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return fmt.Errorf("%w: deb contains a link", ErrArtifact)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return fmt.Errorf("%w: deb contains an unexpected member", ErrArtifact)
		}
		if strings.Contains(name, "..") {
			return fmt.Errorf("%w: deb member escapes the archive", ErrArtifact)
		}
		if header.Uid != 0 || header.Gid != 0 {
			return fmt.Errorf("%w: deb member is not root-owned", ErrArtifact)
		}
		if item, ok := expected[name]; ok {
			if header.Typeflag != tar.TypeReg || header.Mode != int64(item.Mode.Perm()) {
				return fmt.Errorf("%w: deb member mode differs from layout", ErrArtifact)
			}
			if item.SHA256 != "" {
				hash := sha256.New()
				if _, err := io.Copy(hash, reader); err != nil {
					return err
				}
				if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
					return fmt.Errorf("%w: deb repository member digest differs", ErrArtifact)
				}
			}
		}
		found[name] = true
		if name == p.binary[1:] {
			hash := sha256.New()
			if _, err := io.Copy(hash, reader); err != nil {
				return err
			}
			payload = hex.EncodeToString(hash.Sum(nil))
		}
	}
	if payload != payloadSHA {
		return fmt.Errorf("%w: packaged binary digest does not match the input", ErrArtifact)
	}
	for _, item := range staged {
		if !found[item.Rel] {
			return fmt.Errorf("%w: deb is missing %s", ErrArtifact, item.Rel)
		}
	}
	return nil
}

func copyTree(src, dst string, epoch int64) error {
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to copy a symlink", ErrArtifact)
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return mkdir(target, epoch)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: staged payload is not a regular file", ErrArtifact)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		copyErr := copyFile(target, in, info.Mode().Perm(), epoch)
		return errors.Join(copyErr, in.Close())
	})
	if err != nil {
		return err
	}
	return stampDirectories(dst, epoch)
}
