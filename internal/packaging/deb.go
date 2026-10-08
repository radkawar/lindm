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

	"lindm/internal/agent/config"
)

func buildDEB(ctx context.Context, work, payload, version string, arch Architecture, epoch int64, staged []stagedFile, payloadSHA string) (Artifact, error) {
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
	text := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Lindm Packaging <packaging@lindm.invalid>\nSection: admin\nPriority: optional\nDepends: systemd\nInstalled-Size: %d\nDescription: Lindm protected agent\n Versioned agent binary with a root executor and an unprivileged\n network service. Remove and purge retain identity and spool state.\n This package does not grant a root shell.\n", PackageName, version, arch.Debian, size)
	if err := writeFile(filepath.Join(control, "control"), []byte(text), 0o644, epoch); err != nil {
		return Artifact{}, err
	}
	script, err := asset("lifecycle.sh")
	if err != nil {
		return Artifact{}, err
	}
	for _, name := range []string{"postinst", "prerm", "postrm"} {
		if err := writeFile(filepath.Join(control, name), script, 0o755, epoch); err != nil {
			return Artifact{}, err
		}
	}
	conffiles := config.ExecutorConfigPath + "\n" + config.NetworkConfigPath + "\n"
	if err := writeFile(filepath.Join(control, "conffiles"), []byte(conffiles), 0o644, epoch); err != nil {
		return Artifact{}, err
	}
	out := filepath.Join(work, fmt.Sprintf("%s_%s_%s.deb", PackageName, version, arch.Debian))
	if _, _, err := runTool(ctx, work, toolCmd{
		Name:     "dpkg-deb",
		Args:     []string{"--root-owner-group", "--uniform-compression", "-Zgzip", "-z9", "--build", root, out},
		ExtraEnv: []string{"SOURCE_DATE_EPOCH=" + fmt.Sprint(epoch)},
	}); err != nil {
		return Artifact{}, err
	}
	if err := verifyDEB(ctx, work, out, version, arch, payloadSHA, staged); err != nil {
		return Artifact{}, err
	}
	sum, sizeBytes, err := hashFile(out)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Format:        FormatDEB,
		Path:          out,
		SHA256:        sum,
		Size:          sizeBytes,
		Architecture:  arch,
		Version:       version,
		PayloadSHA256: payloadSHA,
		Signed:        false,
	}, nil
}

func verifyDEB(ctx context.Context, work, deb, version string, arch Architecture, payloadSHA string, staged []stagedFile) error {
	stdout, _, err := runTool(ctx, work, toolCmd{
		Name: "dpkg-deb",
		Args: []string{"--show", "--showformat", "${Package}\t${Version}\t${Architecture}\n", deb},
	})
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s\t%s\t%s\n", PackageName, version, arch.Debian)
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
		found[name] = true
		if name == BinaryPath[1:] {
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
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
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
}
