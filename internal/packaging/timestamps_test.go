// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFutureEpochNormalizesAllNativeDirectories(t *testing.T) {
	requireNativeTools(t, "dpkg-deb")
	const epoch int64 = 2200000000
	for _, product := range []product{agentProduct(), serverProduct(), cliProduct()} {
		t.Run(product.name, func(t *testing.T) {
			work := t.TempDir()
			if err := os.Mkdir(filepath.Join(work, "tmp"), 0700); err != nil {
				t.Fatal(err)
			}
			binaryPath := filepath.Join(work, "input")
			if err := os.WriteFile(binaryPath, []byte("native timestamp regression payload"), 0755); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Open(binaryPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := binary.Close(); err != nil {
					t.Error(err)
				}
			}()
			payload, staged, digest, err := stagePayload(work, binary, epoch, product)
			if err != nil {
				t.Fatal(err)
			}
			// RPM cp -a preserves this tree. Check every explicit and implicit directory,
			// not just files or the root, before either native assembler sees it.
			if err := filepath.Walk(payload, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.ModTime().Unix() != epoch {
					t.Errorf("staged timestamp %s = %d, want %d", path, info.ModTime().Unix(), epoch)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			artifact, err := buildDEB(t.Context(), work, payload, "0.2.0", Architecture{Debian: "amd64"}, epoch, staged, digest, product)
			if err != nil {
				t.Fatal(err)
			}
			for _, section := range []string{"--ctrl-tarfile", "--fsys-tarfile"} {
				data, _, err := runTool(t.Context(), work, toolCmd{Name: "dpkg-deb", Args: []string{section, artifact.Path}})
				if err != nil {
					t.Fatal(err)
				}
				reader := tar.NewReader(bytes.NewReader(data))
				count := 0
				for {
					header, err := reader.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					count++
					if header.ModTime.Unix() != epoch {
						t.Errorf("native %s member %s timestamp = %d, want %d", section, header.Name, header.ModTime.Unix(), epoch)
					}
				}
				if count == 0 {
					t.Fatal("empty native archive section")
				}
			}
			// Deliberately change source directory timestamps; compare the full
			// native archives, not just file bytes or extracted executables.
			secondWork := t.TempDir()
			if err := os.Mkdir(filepath.Join(secondWork, "tmp"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := filepath.Walk(payload, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					stamp := time.Unix(123456789+int64(len(path)), 0)
					return os.Chtimes(path, stamp, stamp)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			second, err := buildDEB(t.Context(), secondWork, payload, "0.2.0", Architecture{Debian: "amd64"}, epoch, staged, digest, product)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.UnsignedSHA256 != second.UnsignedSHA256 || artifact.SHA256 != second.SHA256 {
				t.Fatal("source directory times changed complete native archive bytes")
			}
		})
	}
}
