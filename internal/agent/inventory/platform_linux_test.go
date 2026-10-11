//go:build linux

package inventory

import (
	"context"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/nativeexec"
)

func TestPlatformCanonicalEvidence(t *testing.T) {
	// Constructed canonical helper output, not a claim of installed RHEL or
	// live subscription qualification. Historical ID-only evidence stays valid.
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
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":["repo"],"backend":"dnf5","configurations":[{"id":"other"}]}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":1,"ids":["a","b"],"backend":"dnf5","configurations":[{"id":"a"},{"id":"a"}]}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"repositories":{"status":7,"configurations":[{"id":"partial"}]}}`,
		`{"cpe":{"status":2},"releaseverLock":{"status":2},"releasever":{"status":2,"value":"44"},"repositories":{"status":2}}`,
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
	modern := parsePlatform([]byte(`{"cpe":{"status":2},"releaseverLock":{"status":2},"releasever":{"status":1,"value":"44"},"repositories":{"status":1,"ids":["updates"],"backend":"dnf5","configurations":[{"id":"updates","metalink":"https://mirrors.example.test/metalink","gpgcheck":true,"gpgKeys":["file:///etc/pki/rpm-gpg/vendor"],"urlsRedacted":true}]}}`))
	if modern.GetReleasever().GetValue() != "44" || modern.GetReleaseverLock().GetStatus() != unavailable || len(modern.GetRepositories().GetConfigurations()) != 1 || !modern.GetRepositories().GetConfigurations()[0].GetGpgcheck() {
		t.Fatalf("effective version/configuration lost or guessed as lock: %v", modern)
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
	sources.stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
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
repository = scope["repository"]
repo = repository("updates", ["https://user:secret@example.test/repo?token=secret#secret"],
                  "https://mirrors.example.test/metalink?repo=updates&arch=x86_64",
                  "", True, ["file:///etc/pki/rpm-gpg/vendor"])
assert repo["baseUrls"] == ["https://example.test/repo"]
assert repo["metalink"] == "https://mirrors.example.test/metalink"
assert repo["urlsRedacted"] and repo["gpgcheck"]
assert repo["gpgKeys"] == ["file:///etc/pki/rpm-gpg/vendor"]
assert not repository("base", [], "", "", False, [])["urlsRedacted"]
rejects(lambda: repository("bad id", [], "", "", True, []), 5)
rejects(lambda: repository("repo", ["https://example.test"] * 33, "", "", True, []), 6)
rejects(lambda: repository("repo", ["https://example.test/\nsecret"], "", "", True, []), 5)
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
	status := runCommand(ctx, nativeexec.Command{Path: "/usr/bin/python3", Args: []string{"-I", "-c", script}, Stdin: []byte(dnfConfigProbe), Env: []string{"HOME=/"}}, func(reader io.Reader) inventoryv1.CollectionStatus {
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

func TestDNF5CapturedFedora44Configuration(t *testing.T) {
	data, err := os.ReadFile("testdata/dnf5-fedora44/collector-helper.json")
	if err != nil {
		t.Fatal(err)
	}
	got := parsePlatform(data)
	if got.GetReleasever().GetStatus() != success || got.GetReleasever().GetValue() != "44" || got.GetReleaseverLock().GetStatus() != unavailable {
		t.Fatalf("effective releasever confused with explicit release lock: %v", got)
	}
	repos := got.GetRepositories()
	if repos.GetStatus() != success || repos.GetBackend() != "dnf5" || strings.Join(repos.GetIds(), ",") != "fedora,fedora-cisco-openh264,updates" || len(repos.GetConfigurations()) != 3 {
		t.Fatalf("captured enabled repository identity lost: %v", repos)
	}
	for i, config := range repos.GetConfigurations() {
		if config.GetId() != repos.GetIds()[i] || len(config.GetBaseUrls()) != 0 || config.GetMetalink() != "https://mirrors.fedoraproject.org/metalink" || config.GetMirrorlist() != "" || !config.GetGpgcheck() || !config.GetUrlsRedacted() || strings.Join(config.GetGpgKeys(), ",") != "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-aarch64" {
			t.Fatalf("captured native configuration lost: %v", config)
		}
	}
}
