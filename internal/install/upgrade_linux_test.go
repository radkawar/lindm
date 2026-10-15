// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"lindm/internal/platform"
)

func TestRollbackAfterFailedUpgradeUsesNativeInstalledVersion(t *testing.T) {
	state := installState{Version: "1.0.0"}
	if err := checkUpgradeVersion(&state, "1.1.0", "1.0.0", true); err != nil {
		t.Fatalf("last-ready A must remain an admissible rollback from native-installed failed B: %v", err)
	}
	if state.Version != "1.0.0" {
		t.Fatal("admission changed the last-ready release")
	}
}

func TestUpgradeVersionAdmissionDoesNotTrustLastReadyOrAttempt(t *testing.T) {
	state := installState{Version: "1.0.0", AttemptedVersion: "1.2.0", InstalledVersion: "1.1.0"}
	for _, tc := range []struct {
		name      string
		installed string
		target    string
		rollback  bool
		allowed   bool
	}{
		{"newer than native", "1.1.0", "1.2.0", false, true},
		{"failed target is not native proof", "1.0.0", "1.0.0", true, false},
		{"native changed after checkpoint", "1.2.0", "1.1.0", true, true},
		{"downgrade requires explicit flag", "1.1.0", "1.0.0", false, false},
		{"rollback cannot upgrade", "1.1.0", "1.2.0", true, false},
		{"same native release", "1.1.0", "1.1.0", false, false},
		{"invalid native version", "unknown", "1.0.0", true, false},
		{"ambiguous native version", "1.1.01.2.0", "1.0.0", true, false},
		{"invalid target", "1.1.0", "unknown", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUpgradeVersion(&state, tc.installed, tc.target, tc.rollback)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t, error=%v", tc.allowed, err)
			}
		})
	}
}

// Re-execution confines native command fixtures and the protected journal to a
// private chroot. It never touches the host package database or service manager.
func TestUpgradeFailureCheckpointsNativePackageBeforeMigrations(t *testing.T) {
	if os.Getenv("LINDM_UPGRADE_CHECKPOINT_FIXTURE") == "1" {
		release, ok := platform.Lookup(os.Getenv("LINDM_UPGRADE_CHECKPOINT_PLATFORM"))
		if !ok {
			t.Fatal("missing fixture platform")
		}
		state := installState{Version: "1.0.0", AttemptedVersion: "1.1.0", InstalledVersion: "1.0.0"}
		if err := writeInstallationState(&state); err != nil {
			t.Fatal(err)
		}
		err := activateUpgrade(t.Context(), &Options{}, &state, "/authenticated-package", release, "/previous-binary", false)
		if err == nil {
			t.Fatal("expected the injected native hook or migration failure")
		}
		if os.Getenv("LINDM_UPGRADE_CHECKPOINT_FAILURE") == "migration" {
			if !strings.Contains(err.Error(), "migration failed;") {
				t.Fatalf("failed before the expected migration gate: %v", err)
			}
		} else if !strings.Contains(err.Error(), "failed (output withheld;") {
			t.Fatalf("failed before the expected native hook gate: %v", err)
		}
		data, err := protected("/etc/lindm/install-state.json", true)
		if err != nil {
			t.Fatal(err)
		}
		var saved installState
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		expectedInstalled := "1.1.0"
		if os.Getenv("LINDM_UPGRADE_CHECKPOINT_FAILURE") == "preinstall" {
			expectedInstalled = "1.0.0"
		}
		if saved.Version != "1.0.0" || saved.AttemptedVersion != "1.1.0" || saved.InstalledVersion != expectedInstalled {
			t.Fatalf("failed upgrade lost separate last-ready/authenticated/native versions: %+v", saved)
		}
		installed, err := nativeInstalledVersion(t.Context(), release)
		if err != nil {
			t.Fatal(err)
		}
		admissionErr := checkUpgradeVersion(&saved, installed, "1.0.0", true)
		if (admissionErr == nil) != (expectedInstalled == "1.1.0") {
			t.Fatalf("rollback admission did not match actual native replacement: %v", admissionErr)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("isolated native package checkpoint regression requires root")
	}
	for _, key := range []string{"ubuntu-24.04", "rhel-9"} {
		for _, failure := range []string{"preinstall", "native hook", "migration"} {
			t.Run(key+"/"+failure, func(t *testing.T) {
				root, err := os.MkdirTemp("/var/lib", "lindm-upgrade-checkpoint-test-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.RemoveAll(root); err != nil {
						t.Error(err)
					}
				})
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				for source, destination := range map[string]string{binary: "/install.test", "/bin/sh": "/bin/sh"} {
					upgradeFixtureExecutable(t, root, source, destination)
				}
				if err := os.MkdirAll(filepath.Join(root, "etc/lindm"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "native-version"), []byte("1.0.0\n"), 0600); err != nil {
					t.Fatal(err)
				}
				packageExit := 0
				if failure == "native hook" {
					packageExit = 23
				}
				packageScript := fmt.Sprintf("printf '1.1.0\\n' > /native-version\nexit %d\n", packageExit)
				if failure == "preinstall" {
					packageScript = "exit 23\n"
				}
				for name, script := range map[string]string{
					"dpkg":       packageScript,
					"rpm":        "case \"$1\" in --query) read -r version < /native-version; printf '%s' \"$version\";; *)\n" + packageScript + ";; esac\n",
					"dpkg-query": "read -r version < /native-version\nprintf '%s' \"$version\"\n",
					"systemctl":  "exit 24\n",
				} {
					path := filepath.Join(root, "usr/bin", name)
					if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+script), 0755); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.CommandContext(t.Context(), "/install.test", "-test.run=^TestUpgradeFailureCheckpointsNativePackageBeforeMigrations$", "-test.timeout=30s")
				cmd.Dir = "/"
				cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
				cmd.Env = append(os.Environ(), "LINDM_UPGRADE_CHECKPOINT_FIXTURE=1", "LINDM_UPGRADE_CHECKPOINT_PLATFORM="+key, "LINDM_UPGRADE_CHECKPOINT_FAILURE="+failure)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("isolated checkpoint regression: %v\n%s", err, output)
				}
			})
		}
	}
}

func upgradeFixtureExecutable(t *testing.T, root, source, destination string) {
	t.Helper()
	copyExecutable := func(source, destination string) {
		t.Helper()
		actual, err := filepath.EvalSymlinks(source)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, destination)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := copyFileNew(actual, path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	copyExecutable(source, destination)
	output, err := exec.CommandContext(t.Context(), "ldd", source).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "not a dynamic executable") || strings.Contains(string(output), "statically linked") {
			return
		}
		t.Fatalf("discover fixture executable libraries: %v", err)
	}
	for _, field := range strings.Fields(string(output)) {
		if strings.HasPrefix(field, "/") {
			copyExecutable(field, field)
		}
	}
}

func TestRPMUpgradePreflightParentsRemainTraversableUnderPrivateUmask(t *testing.T) {
	cpio, err := exec.LookPath("cpio")
	if err != nil {
		t.Skip("native CPIO extraction regression requires cpio")
	}
	source := t.TempDir()
	payload := filepath.Join(source, "usr/bin/lindmd")
	if err := os.MkdirAll(filepath.Dir(payload), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(payload, 0755); err != nil {
		t.Fatal(err)
	}
	create := exec.CommandContext(t.Context(), cpio, "--create", "--format=newc")
	create.Dir = source
	create.Stdin = strings.NewReader("usr/bin/lindmd\n")
	archive, err := create.Output()
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "public-payload.cpio")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	// The real CPIO extractor receives the exact production command and an
	// archive with no parent entries; only the RPM-to-CPIO converter is a fixture.
	if err := os.WriteFile(filepath.Join(tools, "rpm2cpio"), []byte("#!/bin/sh\nexec /bin/cat \"$1\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, script string
		mode         os.FileMode
	}{
		{"private-inherited-mask-without-policy", strings.Replace(rpmUpgradeExtractCommand, "umask 022; ", "", 1), 0700},
		{"public-payload-child-policy", rpmUpgradeExtractCommand, 0755},
	} {
		t.Run(test.name, func(t *testing.T) {
			stage := t.TempDir()
			if err := os.Chmod(stage, 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "umask 077; "+test.script, "extract", archivePath, stage)
			cmd.Env = []string{"PATH=" + tools + ":" + filepath.Dir(cpio) + ":/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
			if err := cmd.Run(); err != nil {
				t.Fatal(err)
			}
			for _, parent := range []string{"usr", "usr/bin"} {
				info, err := os.Stat(filepath.Join(stage, parent))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != test.mode {
					t.Fatalf("implicit package parent %s: mode %04o, want %04o", parent, info.Mode().Perm(), test.mode)
				}
			}
			info, err := os.Stat(filepath.Join(stage, "usr/bin/lindmd"))
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("public preflight executable permissions changed: %v", err)
			}
		})
	}
}

func TestUpgradeExecutableUsesOnlyTheInstalledNativeSELinuxContext(t *testing.T) {
	const binary = "/var/lib/lindm-upgrade-fixture/usr/bin/lindmd"
	for _, test := range []struct {
		name, distro, version, state, failAt string
		label, wantError                     bool
	}{
		{"ubuntu", "ubuntu", "24.04", "", "", false, false},
		{"rhel-enforcing", "rhel", "9.8", "Enforcing\n", "", true, false},
		{"rhel-permissive", "rhel", "9.8", "Permissive\n", "", false, false},
		{"rhel-disabled", "rhel", "9.8", "Disabled\n", "", false, false},
		{"rhel-unknown", "rhel", "9.8", "unexpected", "", false, true},
		{"rhel-detection-fails", "rhel", "9.8", "", "getenforce", false, true},
		{"rhel-relabel-fails", "rhel", "9.8", "Enforcing", "chcon", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
				calls = append(calls, name)
				if len(input) != 0 {
					t.Fatal("public executable preparation received secret input")
				}
				if name == "getenforce" {
					if len(args) != 0 {
						t.Fatal("unexpected SELinux detector arguments")
					}
					if test.failAt == name {
						return nil, errors.New("fixture detection failure")
					}
					return []byte(test.state), nil
				}
				if name != "chcon" || strings.Join(args, "\x00") != "--reference=/usr/bin/lindmd\x00--\x00"+binary {
					t.Fatal("preparation changed policy or relabelled anything other than the verified executable")
				}
				if test.failAt == name {
					return nil, errors.New("fixture relabel failure")
				}
				return nil, nil
			}
			err := prepareUpgradeExecutable(t.Context(), binary, platform.ForManifest(test.distro, test.version), run)
			if (err != nil) != test.wantError {
				t.Fatalf("preparation error=%v, want error=%t", err, test.wantError)
			}
			wantCalls := ""
			if test.distro == "rhel" {
				wantCalls = "getenforce"
			}
			if test.label {
				wantCalls += ",chcon"
			}
			if strings.Join(calls, ",") != wantCalls {
				t.Fatalf("commands=%v, want %s", calls, wantCalls)
			}
		})
	}
}
