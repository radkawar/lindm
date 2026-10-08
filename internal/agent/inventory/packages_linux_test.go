//go:build linux

package inventory

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestDPKGInstalledEvidence(t *testing.T) {
	input := "rc \tremoved\t1.0-1\tamd64\n" +
		"ii \tzlib1g\t1:1.3.dfsg-2ubuntu1\tamd64\n" +
		"hi \tlibc6\t2.39-0ubuntu8.6\ti386\n" +
		"ii \tlibc6\t2.39-0ubuntu8.6\tamd64\n" +
		"un \tnever-installed\t\t\n"
	rows, status := parsePackages(context.Background(), strings.NewReader(input), "dpkg", parseLimits{maxRecords, maxOutputBytes})
	if status != success || len(rows) != 3 {
		t.Fatalf("status=%s rows=%v", status, rows)
	}
	if rows[0].Name != "libc6" || rows[0].Architecture != "amd64" || rows[1].Architecture != "i386" || rows[2].Version != "1:1.3.dfsg-2ubuntu1" || rows[2].Manager != "dpkg" {
		t.Fatalf("lost installed package identity or ordering: %v", rows)
	}
}

func TestRPMEpochAndMultipleVersions(t *testing.T) {
	input := "kernel-core\t0\t6.9.3\t200.fc40\tx86_64\n" +
		"kernel-core\t0\t6.9.2\t200.fc40\tx86_64\n" +
		"vim-enhanced\t2\t9.1\t1.el9\tx86_64\n"
	rows, status := parsePackages(context.Background(), strings.NewReader(input), "rpm", parseLimits{maxRecords, maxOutputBytes})
	if status != success || len(rows) != 3 {
		t.Fatalf("status=%s rows=%v", status, rows)
	}
	if rows[0].Version != "0:6.9.2-200.fc40" || rows[1].Version != "0:6.9.3-200.fc40" || rows[2].Version != "2:9.1-1.el9" || rows[2].Manager != "rpm" {
		t.Fatalf("lost RPM epoch/release/multiversion identity: %v", rows)
	}
}

func TestRPMImportedSigningKeyPreservesCompleteInventory(t *testing.T) {
	// Native RPM 4.x output after importing the pinned Ubuntu cloud-image key
	// into an isolated RPM database. Signing-key headers have no ARCH tag.
	input := "gpg-pubkey\t0\t7db87c81\t4ab02935\t(none)\n" +
		"kernel-core\t0\t6.9.3\t200.fc40\tx86_64\n"
	rows, status := parsePackages(t.Context(), strings.NewReader(input), "rpm", parseLimits{maxRecords, maxOutputBytes})
	if status != success || len(rows) != 2 {
		t.Fatalf("native signing-key metadata invalidated complete inventory: status=%s rows=%v", status, rows)
	}
	if rows[0].Name != "gpg-pubkey" || rows[0].Version != "0:7db87c81-4ab02935" || rows[0].Architecture != "" || rows[0].Manager != "rpm" ||
		rows[1].Name != "kernel-core" || rows[1].Architecture != "x86_64" {
		t.Fatalf("native package identity changed: %v", rows)
	}
}

func TestInvalidPackageOutputNeverPublishesPartialRows(t *testing.T) {
	for _, tc := range []struct {
		name, manager, valid, bad string
	}{
		{"truncated", "dpkg", "ii \tgood\t1\tamd64\n", "ii \tbad\t1\tamd64"},
		{"columns", "dpkg", "ii \tgood\t1\tamd64\n", "ii \tbad\t1\n"},
		{"status", "dpkg", "ii \tgood\t1\tamd64\n", "xx \tbad\t1\tamd64\n"},
		{"reinst-required", "dpkg", "ii \tgood\t1\tamd64\n", "iiR\tbad\t1\tamd64\n"},
		{"invalid-residual", "dpkg", "ii \tgood\t1\tamd64\n", "rc \tbad name\t1\tamd64\n"},
		{"nul", "dpkg", "ii \tgood\t1\tamd64\n", "ii \tbad\t1\x00\tamd64\n"},
		{"invalid-utf8", "dpkg", "ii \tgood\t1\tamd64\n", "ii \tbad\t\xff\tamd64\n"},
		{"rpm-epoch", "rpm", "good\t0\t1\t1\tx86_64\n", "bad\t(none)\t1\t1\tx86_64\n"},
		{"rpm-release", "rpm", "good\t0\t1\t1\tx86_64\n", "bad\t0\t1\t\tx86_64\n"},
		{"rpm-empty-architecture", "rpm", "good\t0\t1\t1\tx86_64\n", "bad\t0\t1\t1\t\n"},
		{"rpm-malformed-architecture", "rpm", "good\t0\t1\t1\tx86_64\n", "bad\t0\t1\t1\t(broken)\n"},
		{"dpkg-absent-architecture", "dpkg", "ii \tgood\t1\tamd64\n", "ii \tbad\t1\t(none)\n"},
		{"blank", "rpm", "good\t0\t1\t1\tx86_64\n", "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, status := parsePackages(context.Background(), strings.NewReader(tc.valid+tc.bad), tc.manager, parseLimits{maxRecords, maxOutputBytes})
			if status != invalid || len(rows) != 0 {
				t.Fatalf("status=%s rows=%v", status, rows)
			}
		})
	}
}

func TestPackageCapacityAndCancellation(t *testing.T) {
	line := "ii \tgood\t1\tamd64\n"
	for _, tc := range []struct {
		name, input string
		limits      parseLimits
	}{
		{"records", strings.Repeat(line, 3), parseLimits{2, maxOutputBytes}},
		{"bytes", strings.Repeat(line, 3), parseLimits{maxRecords, int64(len(line) * 2)}},
		{"line", strings.Repeat("x", maxLineBytes+1) + "\n", parseLimits{maxRecords, maxOutputBytes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, status := parsePackages(context.Background(), strings.NewReader(tc.input), "dpkg", tc.limits)
			if status != capacity || len(rows) != 0 {
				t.Fatalf("status=%s rows=%v", status, rows)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rows, status := parsePackages(ctx, strings.NewReader(line), "dpkg", parseLimits{maxRecords, maxOutputBytes})
	if status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || len(rows) != 0 {
		t.Fatalf("canceled status=%s rows=%v", status, rows)
	}
	rows, status = parsePackages(context.Background(), strings.NewReader(""), "dpkg", parseLimits{maxRecords, maxOutputBytes})
	if status != success || len(rows) != 0 {
		t.Fatalf("empty complete snapshot status=%s rows=%v", status, rows)
	}
}

func fixtureStat(files fstest.MapFS) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) { return files.Stat(strings.TrimPrefix(path, "/")) }
}

func TestBackendRequiresVendorVersionAndDatabase(t *testing.T) {
	files := fstest.MapFS{
		"var/lib/dpkg/status":               {Data: []byte("native db")},
		"usr/lib/sysimage/rpm/rpmdb.sqlite": {Data: []byte("native db")},
	}
	for _, id := range []string{"ubuntu", "debian", "fedora", "rhel", "rocky", "almalinux", "centos", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"} {
		t.Run(id, func(t *testing.T) {
			selected, status := selectBackend(map[string]string{"ID": id, "VERSION_ID": "42"}, fixtureStat(files))
			if status != success || selected.name == "" {
				t.Fatalf("backend=%v status=%s", selected, status)
			}
		})
	}
	for _, release := range []map[string]string{
		{"ID": "arch", "ID_LIKE": "debian", "VERSION_ID": "42"},
		{"ID": "nixos", "VERSION_ID": "42"},
		{"ID": "unknown", "ID_LIKE": "rhel", "VERSION_ID": "42"},
		{"ID": "ubuntu"},
		{"ID": "fedora", "VERSION_ID": "42", "VARIANT_ID": "silverblue"},
		{"ID": "fedora", "VERSION_ID": "42", "VARIANT_ID": "coreos"},
		{"ID": "fedora", "VERSION_ID": "42", "VARIANT_ID": "future-atomic"},
		{"ID": "opensuse-microos", "VERSION_ID": "42"},
	} {
		if _, status := selectBackend(release, fixtureStat(files)); status != unavailable {
			t.Fatalf("release=%v status=%s", release, status)
		}
	}
	if _, status := selectBackend(map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"}, fixtureStat(fstest.MapFS{})); status != unavailable {
		t.Fatalf("missing DB status=%s", status)
	}
	files["run/ostree-booted"] = &fstest.MapFile{}
	if _, status := selectBackend(map[string]string{"ID": "fedora", "VERSION_ID": "42"}, fixtureStat(files)); status != unavailable {
		t.Fatalf("immutable host status=%s", status)
	}
}

func TestFailedCommandDiscardsParsedRows(t *testing.T) {
	stat := fixtureStat(fstest.MapFS{"var/lib/dpkg/status": {Data: []byte("db")}})
	run := func(ctx context.Context, _ backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if status := consume(strings.NewReader("ii \tgood\t1\tamd64\n")); status != success {
			t.Fatalf("parse status=%s", status)
		}
		return commandFailure
	}
	result := collectPackages(context.Background(), map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"}, stat, run)
	if result.Status != commandFailure || len(result.Packages) != 0 {
		t.Fatalf("partial collection leaked: %v", result)
	}
	if err := protovalidate.Validate(result); err != nil {
		t.Fatalf("invalid failure evidence: %v", err)
	}
}

func TestNativeSubprocess(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want inventoryv1.CollectionStatus
	}{
		{"complete", success},
		{"failure", commandFailure},
		{"warning", commandFailure},
		{"truncated", invalid},
		{"stderr-capacity", capacity},
		{"wait", inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			deadline := 5 * time.Second
			if tc.mode == "wait" {
				deadline = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInventorySubprocessHelper$")
			cmd.Env = []string{"LINDM_INVENTORY_HELPER=" + tc.mode, "LANG=C", "LC_ALL=C"}
			cmd.Dir = "/"
			cmd.WaitDelay = time.Second
			status := runCommand(ctx, cmd, func(reader io.Reader) inventoryv1.CollectionStatus {
				_, status := parsePackages(ctx, reader, "dpkg", parseLimits{maxRecords, maxOutputBytes})
				return status
			})
			if status != tc.want {
				t.Fatalf("status=%s want=%s", status, tc.want)
			}
		})
	}
}

func TestInventorySubprocessHelper(t *testing.T) {
	mode := os.Getenv("LINDM_INVENTORY_HELPER")
	if mode == "" {
		return
	}
	var output, diagnostic string
	exit := 0
	switch mode {
	case "complete", "failure", "warning":
		output = "ii \tgood\t1\tamd64\n"
		if mode == "failure" {
			exit = 7
		}
		if mode == "warning" {
			diagnostic = "database record ignored\n"
		}
	case "truncated":
		output = "ii \tgood\t1\tamd64"
	case "stderr-capacity":
		diagnostic = strings.Repeat("x", 65<<10)
	case "wait":
		time.Sleep(30 * time.Second)
	default:
		os.Exit(8)
	}
	if _, err := io.WriteString(os.Stdout, output); err != nil {
		os.Exit(9)
	}
	if _, err := io.WriteString(os.Stderr, diagnostic); err != nil {
		os.Exit(9)
	}
	os.Exit(exit)
}

func TestBackendPermissionAndNonregularEvidence(t *testing.T) {
	release := map[string]string{"ID": "debian", "VERSION_ID": "12"}
	denied := func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if _, status := selectBackend(release, denied); status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("database permission status=%s", status)
	}
	directory := fixtureStat(fstest.MapFS{"var/lib/dpkg/status": {Mode: fs.ModeDir | 0755}})
	if _, status := selectBackend(release, directory); status != invalid {
		t.Fatalf("nonregular database status=%s", status)
	}
}

func TestCanceledCollectionDoesNotRunNativeTool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stat := func(string) (fs.FileInfo, error) {
		t.Fatal("canceled collection probed the database")
		return nil, fs.ErrNotExist
	}
	run := func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		t.Fatal("canceled collection ran a native tool")
		return success
	}
	result := collectPackages(ctx, map[string]string{"ID": "ubuntu", "VERSION_ID": "24.04"}, stat, run)
	if result.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || len(result.Packages) != 0 {
		t.Fatalf("canceled collection=%v", result)
	}
	if err := protovalidate.Validate(result); err != nil {
		t.Fatalf("invalid cancellation evidence: %v", err)
	}
}
