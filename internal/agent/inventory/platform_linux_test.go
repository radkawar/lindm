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
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestPlatformCanonicalEvidence(t *testing.T) {
	// Constructed canonical helper output, not a claim of installed RHEL or
	// live subscription qualification. IDs are evidence; URLs never belong here.
	data := []byte(`{"cpe":{"status":2},"releaseverLock":{"status":1,"value":"9.4"},"repositories":{"status":1,"ids":["rhel-9-for-x86_64-appstream-eus-rpms","rhel-9-for-x86_64-baseos-eus-rpms"],"backend":"dnf4"}}`)
	got := parsePlatform(data)
	if got.ReleaseverLock.Status != success || got.ReleaseverLock.Value != "9.4" || got.Repositories.Status != success || len(got.Repositories.Ids) != 2 || got.Repositories.Backend != "dnf4" {
		t.Fatalf("lost explicit platform evidence: %v", got)
	}
	for _, data := range []string{
		`{}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":["repo"],"backend":"dnf4","baseurl":"https://secret:credential@example.test"}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":3,"ids":["partial"],"backend":"dnf4"}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":["duplicate","duplicate"],"backend":"dnf4"}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":[],"backend":""}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":1},"repositories":{"status":2}}`,
	} {
		got := parsePlatform([]byte(data))
		if got.Repositories.Status != invalid || len(got.Repositories.Ids) != 0 || got.ReleaseverLock.Status != invalid {
			t.Fatalf("malformed/partial platform accepted: %v", got)
		}
	}
	zero := parsePlatform([]byte(`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":[],"backend":"dnf4"}}`))
	if zero.Repositories.Status != success || len(zero.Repositories.Ids) != 0 || zero.ReleaseverLock.Status != unavailable {
		t.Fatalf("explicit empty native repository list: %v", zero)
	}
}

func TestPlatformBoundsAndHistoricalAbsence(t *testing.T) {
	for _, count := range []int{256, 257} {
		repositories := &inventoryv1.RepositoryObservation{Status: success, Backend: "dnf4"}
		for i := range count {
			repositories.Ids = append(repositories.Ids, strings.Repeat("a", i+1))
		}
		data, err := protojson.Marshal(&inventoryv1.PlatformDetails{Cpe: observed("", fs.ErrNotExist), ReleaseverLock: observed("", fs.ErrNotExist), Repositories: repositories})
		if err != nil {
			t.Fatal(err)
		}
		got := parsePlatform(data)
		if (count == 256 && got.Repositories.Status != success) || (count == 257 && got.Repositories.Status != invalid) {
			t.Fatalf("repository bounds %d: %v", count, got.Repositories.Status)
		}
	}
	pkg := &inventoryv1.Package{Name: "legacy", Version: "1", Manager: "rpm"}
	if err := protovalidate.Validate(pkg); err != nil {
		t.Fatalf("historical module absence rejected: %v", err)
	}
	details := collectDetails(t.Context(), fixtureDetails(t.TempDir()))
	details.Platform = nil
	if err := protovalidate.Validate(details); err != nil {
		t.Fatalf("historical platform absence rejected: %v", err)
	}
}

func TestPlatformFailureDoesNotEraseNativeCPE(t *testing.T) {
	sources := fixtureDetails(t.TempDir())
	sources.readFile = func(path string) ([]byte, error) {
		if path == "/etc/os-release" {
			return []byte("ID=rhel\nVERSION_ID=9.4\nCPE_NAME=\"cpe:/o:redhat:enterprise_linux:9::baseos\"\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	sources.run = func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	}
	got := collectPlatform(t.Context(), sources)
	if got.Cpe.Value != "cpe:/o:redhat:enterprise_linux:9::baseos" || got.Repositories.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED || got.ReleaseverLock.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED {
		t.Fatalf("independent product evidence lost: %v", got)
	}
	if got.ReleaseverLock.Value != "" {
		t.Fatal("OS version was inferred as explicit release lock")
	}
}

func TestDNFConfigReaderNativeFileBounds(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		if os.IsNotExist(err) {
			t.Skip("optional native Python configuration provider is absent")
		}
		t.Fatal(err)
	}
	// Exercise the actual helper's file reader against owned real files. This
	// neither mocks DNF nor claims native repository/backend qualification.
	const script = `
import os, sys, tempfile
scope = {"__name__": "inventory_config_reader_test"}
exec(compile(sys.stdin.read(), "<embedded-dnf-probe>", "exec"), scope)
Reader, Failure = scope["ConfigReader"], scope["EvidenceFailure"]
def rejects(operation, status):
    try:
        operation()
    except Failure as error:
        assert error.status == status
    else:
        raise AssertionError("unbounded or invalid config accepted")
with tempfile.TemporaryDirectory(prefix="lindm-config-reader-") as root:
    config = os.path.join(root, "native.repo")
    with open(config, "wb") as target:
        target.write(b"[fixture]\nenabled=1\n")
    assert Reader().read(config) == b"[fixture]\nenabled=1\n"
    rejects(lambda: Reader().read(config, 4), 6)
    rejects(lambda: Reader().read("relative.repo"), 5)
    fifo = os.path.join(root, "unexpected-fifo")
    os.mkfifo(fifo)
    rejects(lambda: Reader().read(fifo), 5)
    os.unlink(fifo)
    for index in range(256):
        with open(os.path.join(root, str(index)), "wb") as target:
            target.write(b"x")
    rejects(lambda: Reader().directory(root), 6)
`
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", script)
	cmd.Stdin = strings.NewReader(dnfConfigProbe)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "HOME=/", "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	status := runCommand(ctx, cmd, func(reader io.Reader) inventoryv1.CollectionStatus {
		data, err := io.ReadAll(io.LimitReader(reader, 1025))
		if err != nil || len(data) != 0 {
			return invalid
		}
		return success
	})
	if status != success {
		t.Fatalf("native config file-bound assertions: %s", status)
	}
}
