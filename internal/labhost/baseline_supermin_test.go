// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const superminTestRelease = "6.17.0-1008-nvidia"

func superminTestRoots(t *testing.T) (work, modules string) {
	t.Helper()
	work, modules = t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(modules, superminTestRelease), 0755); err != nil {
		t.Fatal(err)
	}
	return work, modules
}

func stageSuperminTestKernel(t *testing.T, work, release string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(work, superminDirectory)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(dir, "vmlinuz-"+release)
	if err := os.WriteFile(kernel, []byte("kernel"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kernel, mode); err != nil {
		t.Fatal(err)
	}
	return kernel
}

// host-exec exports the explicit libguestfs pair only for the running kernel's
// private staged copy; an operator override always wins.
func TestSuperminEnvironmentExportsOnlyStagedRunningKernel(t *testing.T) {
	export := func(work, modules string) (string, string, error) {
		t.Setenv("SUPERMIN_KERNEL", "")
		t.Setenv("SUPERMIN_MODULES", "")
		err := exportSuperminEnvironment(work, superminTestRelease, modules)
		return os.Getenv("SUPERMIN_KERNEL"), os.Getenv("SUPERMIN_MODULES"), err
	}
	work, modules := superminTestRoots(t)
	if kernel, moduleDir, err := export(work, modules); err != nil || kernel != "" || moduleDir != "" {
		t.Fatalf("unstaged host exported %q %q: %v", kernel, moduleDir, err)
	}
	stageSuperminTestKernel(t, work, "6.11.0-1014-nvidia", 0600)
	if kernel, _, err := export(work, modules); err != nil || kernel != "" {
		t.Fatalf("selected a stale kernel %q: %v", kernel, err)
	}
	staged := stageSuperminTestKernel(t, work, superminTestRelease, 0600)
	kernel, moduleDir, err := export(work, modules)
	if err != nil || kernel != staged || moduleDir != filepath.Join(modules, superminTestRelease) {
		t.Fatalf("exported %q %q: %v", kernel, moduleDir, err)
	}
	t.Setenv("SUPERMIN_KERNEL", "/operator/vmlinuz")
	t.Setenv("SUPERMIN_MODULES", "/operator/modules")
	if err := exportSuperminEnvironment(work, superminTestRelease, modules); err != nil || os.Getenv("SUPERMIN_KERNEL") != "/operator/vmlinuz" || os.Getenv("SUPERMIN_MODULES") != "/operator/modules" {
		t.Fatalf("replaced operator override: %v", err)
	}
	if err := os.Chmod(staged, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := export(work, modules); err == nil {
		t.Fatal("exported a non-private staged kernel")
	}
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/boot/vmlinuz", staged); err != nil {
		t.Fatal(err)
	}
	if _, _, err := export(work, modules); err == nil {
		t.Fatal("exported a symlinked kernel")
	}
	missing, _ := superminTestRoots(t)
	stageSuperminTestKernel(t, missing, superminTestRelease, 0600)
	if _, _, err := export(missing, t.TempDir()); err == nil {
		t.Fatal("exported a kernel without its module directory")
	}
	for _, release := range []string{"", ".", "..", "a/b"} {
		if _, err := superminEnvironment(work, release, modules); err == nil {
			t.Fatalf("accepted kernel release %q", release)
		}
	}
}

// The staging transaction runs against fake package tools: it must publish only
// a payload whose bytes match dpkg's digest of the installed /boot file.
func TestBaselineSuperminScriptPublishesOnlyDpkgMatchingPayload(t *testing.T) {
	payload := []byte("signed kernel image bytes")
	md5sum := md5.Sum(payload)
	for _, tc := range []struct {
		name, status, recorded string
		ok                     bool
	}{
		{"matching", "installed", hex.EncodeToString(md5sum[:]), true},
		{"differs", "installed", strings.Repeat("0", 32), false},
		{"not installed", "config-files", hex.EncodeToString(md5sum[:]), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, modules := superminTestRoots(t)
			if err := os.Chmod(work, 0700); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			if err := writer.WriteHeader(&tar.Header{Name: "./boot/vmlinuz-" + superminTestRelease, Mode: 0600, Size: int64(len(payload))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			tarball := filepath.Join(t.TempDir(), "data.tar")
			if err := os.WriteFile(tarball, archive.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"uname":      "echo " + superminTestRelease + "\n",
				"dpkg-query": "if [[ $1 == --control-show ]]; then printf '%s  boot/vmlinuz-" + superminTestRelease + "\\n0123  boot/System.map\\n' " + tc.recorded + "; else printf '" + tc.status + " 6.17.0-1008.8\\n'; fi\n",
				"apt-get":    "[[ ${*: -1} == linux-image-" + superminTestRelease + "=6.17.0-1008.8 ]] && : > linux-image_6.17.0-1008.8_arm64.deb\n",
				"dpkg-deb":   "cat " + baselineQuote(tarball) + "\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-s")
			cmd.Stdin = strings.NewReader("set -euo pipefail\nexport PATH=" + baselineQuote(bin+":/usr/bin:/bin") + "\n" + baselineSuperminScript(work, modules))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			published := filepath.Join(work, superminDirectory, "vmlinuz-"+superminTestRelease)
			data, readErr := os.ReadFile(published)
			if !tc.ok {
				if runErr == nil || readErr == nil {
					t.Fatalf("published an unverified kernel: %v, %s", runErr, stderr.String())
				}
				return
			}
			if runErr != nil {
				t.Fatalf("staging failed: %v: %s", runErr, stderr.String())
			}
			info, err := os.Lstat(published)
			if err != nil || !bytes.Equal(data, payload) || info.Mode().Perm() != 0600 {
				t.Fatalf("published %q mode %v: %v", data, info, err)
			}
			kernel, err := parseBaselineSupermin(stdout.Bytes())
			digest := sha256.Sum256(payload)
			if err != nil || kernel.Path != published || kernel.SHA256 != hex.EncodeToString(digest[:]) || kernel.Version != "6.17.0-1008.8" || kernel.ModulesPath != filepath.Join(modules, superminTestRelease) {
				t.Fatalf("receipt %+v: %v", kernel, err)
			}
			entries, err := os.ReadDir(filepath.Join(work, superminDirectory))
			if err != nil || len(entries) != 1 {
				t.Fatalf("staging residue left behind: %v, %v", entries, err)
			}
		})
	}
}
