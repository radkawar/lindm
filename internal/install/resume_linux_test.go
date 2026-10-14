// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFreshInstallationJournalsBeforeNativeMutation(t *testing.T) {
	source, err := os.ReadFile("install_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "beginInstallation(*o, version)") || !strings.Contains(text, "validateInstallationResume(&state, o, manifest.GetVersion())") || !strings.Contains(text, "continueInstallation(ctx, &o, release, packagePath, &state, nil)") {
		t.Fatal("fresh installation has no authenticated in-progress journal and resume dispatch")
	}
}

func TestInstallationFileRetryPreservesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	uid, gid := os.Getuid(), os.Getgid()
	if err := installationFile(path, []byte("original"), uid, gid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installationFile(path, []byte("original"), uid, gid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installationFile(path, []byte("replacement"), uid, gid, 0600); err == nil {
		t.Fatal("rekeyed existing credential")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("credential changed: %q %v", data, err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := installationFile(link, []byte("original"), uid, gid, 0600); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestInstallationStateReplacementSurvivesAbandonedTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "install-state.json")
	if err := os.WriteFile(filepath.Join(dir, ".install-state-abandoned"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{"Pending":{"Version":"0.1.0"}}`, `{"Version":"0.1.0"}`} {
		if err := replaceInstallationState(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatalf("state %q: %v", got, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unprotected state: %v %v", info, err)
		}
	}
}

func TestInterruptedInstallationResumeAdmission(t *testing.T) {
	for _, stage := range []struct{ identity, provisioned bool }{{false, false}, {true, false}, {true, true}} {
		state := &installState{Pending: &installationProgress{Version: "0.1.0", Binding: "authenticated-bundle-and-inputs", Deployment: "stable-deployment", IdentityReady: stage.identity, Provisioned: stage.provisioned}}
		if err := admitInstallationResume(state, state.Pending.Binding, "0.1.0", false); err != nil {
			t.Fatal(err)
		}
		for _, attempt := range []struct {
			binding, version string
			rollback         bool
		}{
			{"different-bundle-or-inputs", "0.1.0", false},
			{state.Pending.Binding, "0.2.0", false},
			{state.Pending.Binding, "0.1.0", true},
		} {
			if err := admitInstallationResume(state, attempt.binding, attempt.version, attempt.rollback); err == nil {
				t.Fatal("unfinished install admitted different bundle, inputs or rollback")
			}
		}
		if state.Pending.Deployment != "stable-deployment" || state.Pending.IdentityReady != stage.identity || state.Pending.Provisioned != stage.provisioned {
			t.Fatal("resume admission changed bootstrap identity or checkpoint")
		}
	}
	if err := admitInstallationResume(&installState{Version: "0.1.0"}, "binding", "0.1.0", false); err == nil {
		t.Fatal("completed installation treated as pending bootstrap")
	}
}

func TestInstallationDatabasePasswordRetryPreservesCredential(t *testing.T) {
	path := filepath.Join(rootDatabaseFixture(t), "database-url")
	first, err := installationDatabasePassword(path, "lindm_runtime", "5433", "/etc/lindm/database-ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	second, err := installationDatabasePassword(path, "lindm_runtime", "5433", "/etc/lindm/database-ca.crt")
	if err != nil || first != second {
		t.Fatalf("retry did not retain database credential: %v", err)
	}
	if _, err := installationDatabasePassword(path, "lindm_migrator", "5433", "/etc/lindm/database-ca.crt"); err == nil {
		t.Fatal("accepted a credential for another role")
	}
}

func TestInterruptedInstallationJournalRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installation journal ownership requires root")
	}
	if root := os.Getenv("LINDM_INSTALL_RESUME_TEST_ROOT"); root != "" {
		if err := syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/etc/lindm/migrate", "/etc/lindm/offline", "/bundle", "/usr/bin", "/var/lib/lindmd-operations"} {
			if err := os.MkdirAll(path, 0755); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"release.json", "installer.sha256", "release.pub", "backup.pub"} {
			if err := os.WriteFile(filepath.Join("/bundle", name), []byte("authenticated fixture "+name), 0600); err != nil {
				t.Fatal(err)
			}
		}
		o := Options{Bundle: "/bundle", ReleaseKey: "/bundle/release.pub", ReleaseKeyID: "trusted-key", BackupRecipient: "/bundle/backup.pub", Origin: "https://console.example", DeviceOrigin: "https://device.example", AdminPort: 18444, DevicePort: 18445}
		state, err := beginInstallation(o, "0.1.0")
		if err != nil {
			t.Fatal(err)
		}
		deployment := state.Pending.Deployment
		// A package installed before provisioning must already have a durable
		// journal, even though there is no last-ready version yet.
		if err := os.WriteFile("/usr/bin/lindmd", []byte("authenticated package installed"), 0755); err != nil {
			t.Fatal(err)
		}
		data, err := protected("/etc/lindm/install-state.json", true)
		if err != nil {
			t.Fatal(err)
		}
		var resumed installState
		if err := json.Unmarshal(data, &resumed); err != nil {
			t.Fatal(err)
		}
		if err := validateInstallationResume(&resumed, o, "0.1.0"); err != nil {
			t.Fatal(err)
		}
		if resumed.Pending.Deployment != deployment || resumed.Version != "" {
			t.Fatal("lost pending identity or fabricated ready version")
		}
		if err := newFile("/etc/lindm/device-ca.key", []byte("unpublished incomplete identity"), 0, 0, 0600); err != nil {
			t.Fatal(err)
		}
		if err := resetUnpublishedIdentity(&resumed); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat("/etc/lindm/device-ca.key"); !os.IsNotExist(err) {
			t.Fatal("incomplete unpublished identity was not reclaimed")
		}
		// Once identity generation commits, a later database/readiness failure
		// must retain keys, custody and existing configuration on retry.
		resumed.Pending.IdentityReady = true
		if err := writeInstallationState(&resumed); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/etc/lindm/device-ca.key", "/etc/lindm/database-url", "/etc/lindm/server.json", "/var/lib/lindmd-operations/recovery-custody.age"} {
			if err := installationFile(path, []byte("committed identity"), 0, 0, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := validateInstallationResume(&resumed, o, "0.1.0"); err != nil {
			t.Fatal(err)
		}
		if err := resetUnpublishedIdentity(&resumed); err == nil {
			t.Fatal("committed installation could be rekeyed")
		}
		for _, path := range []string{"/etc/lindm/device-ca.key", "/etc/lindm/database-url", "/etc/lindm/server.json", "/var/lib/lindmd-operations/recovery-custody.age"} {
			if err := installationFile(path, []byte("committed identity"), 0, 0, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile("/bundle/release.json", []byte("another authenticated release"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateInstallationResume(&resumed, o, "0.1.0"); err == nil {
			t.Fatal("different authenticated bundle took over pending install")
		}
		return
	}
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestInterruptedInstallationJournalRecovery$")
	cmd.Env = append(os.Environ(), "LINDM_INSTALL_RESUME_TEST_ROOT="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated installation recovery: %v\n%s", err, output)
	}
}

func TestUnpublishedIdentityCleanupRejectsLinkedParent(t *testing.T) {
	root := rootDatabaseFixture(t)
	target := filepath.Join(root, "unrelated.key")
	if err := newFile(target, []byte("unrelated retained key"), 0, 0, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := removeUnpublishedIdentityFile(filepath.Join(link, "unrelated.key")); err == nil {
		t.Fatal("cleanup traversed a linked parent")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("cleanup removed an unrelated key")
	}
}
