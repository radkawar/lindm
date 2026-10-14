// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A valid release signature cannot authorize a changed TUF bootstrap root,
// unsigned dependency snapshot, unexpected path or missing bootstrap executable.
func TestInstallerSupplementalAuthentication(t *testing.T) {
	for _, mutation := range []string{"none", "connected", "ubuntu_only", "rhel_only", "root_tamper", "snapshot_tamper", "native_key_tamper", "native_fingerprint_tamper", "wrong_pin", "missing_asset", "omitted_executable", "unexpected_path", "duplicate_path", "signature_tamper", "orphan_snapshot", "orphan_digest", "unsigned_addon", "unsigned_addon_pair"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			pin := sha256.Sum256(der)
			keyPath := filepath.Join(dir, "trusted.pub")
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			var payload strings.Builder
			names := []string{"install.sh", "lindm-install", "release-root.json", "release.json", "agent-repository/package-signing.asc", "native-package.fingerprint"}
			switch mutation {
			case "connected", "unsigned_addon", "unsigned_addon_pair":
			case "ubuntu_only":
				names = append(names, "ubuntu24.04.snapshot", "ubuntu24.04.snapshot.digest")
			case "rhel_only":
				names = append(names, "rhel9.snapshot", "rhel9.snapshot.digest")
			default:
				names = append(names, "ubuntu24.04.snapshot", "ubuntu24.04.snapshot.digest", "rhel9.snapshot", "rhel9.snapshot.digest")
			}
			for _, name := range names {
				data := []byte("distinct authenticated asset " + name)
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
				if (mutation == "omitted_executable" && name == "lindm-install") ||
					(mutation == "orphan_snapshot" && name == "rhel9.snapshot.digest") ||
					(mutation == "orphan_digest" && name == "rhel9.snapshot") {
					continue
				}
				sum := sha256.Sum256(data)
				fmt.Fprintf(&payload, "%x  %s\n", sum, name)
			}
			if mutation == "unexpected_path" {
				payload.WriteString(strings.Repeat("0", 64) + "  ../escape\n")
			}
			if mutation == "duplicate_path" {
				payload.WriteString(strings.Repeat("0", 64) + "  install.sh\n")
			}
			data := []byte(payload.String())
			sig := ed25519.Sign(key, data)
			if mutation == "signature_tamper" {
				sig[0] ^= 1
			}
			if err := os.WriteFile(filepath.Join(dir, "installer.sha256"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "installer.sha256.sig"), sig, 0600); err != nil {
				t.Fatal(err)
			}
			if mutation == "root_tamper" {
				if err := os.WriteFile(filepath.Join(dir, "release-root.json"), []byte("replacement authority"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "snapshot_tamper" {
				if err := os.WriteFile(filepath.Join(dir, "rhel9.snapshot"), []byte("replacement packages"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "native_key_tamper" {
				if err := os.WriteFile(filepath.Join(dir, "agent-repository", "package-signing.asc"), []byte("additional attacker armor"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "native_fingerprint_tamper" {
				if err := os.WriteFile(filepath.Join(dir, "native-package.fingerprint"), []byte(strings.Repeat("A", 40)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "missing_asset" {
				if err := os.Remove(filepath.Join(dir, "lindm-install")); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "unsigned_addon" || mutation == "unsigned_addon_pair" {
				if err := os.WriteFile(filepath.Join(dir, "rhel9.snapshot"), []byte("not authorized by this release"), 0600); err != nil {
					t.Fatal(err)
				}
				if mutation == "unsigned_addon_pair" {
					if err := os.WriteFile(filepath.Join(dir, "rhel9.snapshot.digest"), []byte(strings.Repeat("0", 64)+"\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			expected := hex.EncodeToString(pin[:])
			if mutation == "wrong_pin" {
				expected = strings.Repeat("0", 64)
			}
			err = VerifyInstaller(t.Context(), dir, keyPath, expected)
			valid := mutation == "none" || mutation == "connected" || mutation == "ubuntu_only" || mutation == "rhel_only"
			if (err == nil) != valid {
				t.Fatalf("mutation %s verification error=%v", mutation, err)
			}
		})
	}
}

func TestInstallerSnapshotsAreOptionalButRequestedInputsFailClosed(t *testing.T) {
	t.Run("connected_production", func(t *testing.T) {
		var sums strings.Builder
		if err := exportInstallerSnapshots(t.Context(), t.TempDir(), "production", &InstallerInputs{}, &sums); err != nil {
			t.Fatal(err)
		}
		if sums.Len() != 0 {
			t.Fatal("connected export unexpectedly included offline assets")
		}
	})
	for _, inputs := range []InstallerInputs{
		{UbuntuSnapshot: strings.Repeat("0", 64)},
		{RHELSnapshot: strings.Repeat("0", 64)},
		{SnapshotCache: t.TempDir(), UbuntuSnapshot: strings.Repeat("0", 64)},
		{SnapshotCache: t.TempDir(), RHELSnapshot: strings.Repeat("0", 64)},
	} {
		var sums strings.Builder
		if err := exportInstallerSnapshots(t.Context(), t.TempDir(), "production", &inputs, &sums); err == nil {
			t.Fatal("requested offline add-on accepted missing cache or authenticated snapshot")
		}
	}
}

func TestInstallerSnapshotPreservesPublicModesUnderPrivateUmask(t *testing.T) {
	script, err := os.ReadFile("../../deploy/server/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	var copyCommand string
	for _, line := range strings.Split(string(script), "\n") {
		if strings.HasPrefix(line, "cp -R ") {
			if copyCommand != "" {
				t.Fatal("installer snapshot has multiple recursive copies")
			}
			copyCommand = line
		}
	}
	if copyCommand == "" || !strings.Contains(copyCommand, "--no-dereference") || !strings.Contains(copyCommand, "--no-preserve=ownership") {
		t.Fatal("installer snapshot lost its no-follow or ownership boundary")
	}
	directory := t.TempDir()
	source, work := filepath.Join(directory, "source"), filepath.Join(directory, "work")
	repository := filepath.Join(source, "agent-repository")
	for _, name := range []string{repository, filepath.Join(work, "bundle")} {
		if err := os.MkdirAll(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(repository, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]os.FileMode{"agent-repository/release.json": 0644, "lindm-install": 0755}
	for name, mode := range files {
		path := filepath.Join(source, name)
		if err := os.WriteFile(path, []byte("public fixture\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(t.Context(), "sh", "-eu", "-c", "umask 077; "+copyCommand+"\nchmod -R go-w -- \"$work/bundle\"")
	command.Env = append(os.Environ(), "bundle="+source, "work="+work)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native installer snapshot: %v: %s", err, output)
	}
	files["agent-repository"] = 0755
	for name, mode := range files {
		info, err := os.Stat(filepath.Join(work, "bundle", name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private snapshot changed authenticated public mode: %s: %v", name, err)
		}
	}
	info, err := os.Stat(work)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("snapshot lost private ancestry: %v", err)
	}
}
