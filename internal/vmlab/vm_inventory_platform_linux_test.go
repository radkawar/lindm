//go:build linux

package vmlab

import (
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/platform"
)

func TestNativeModuleTruthPreservesStreamIdentity(t *testing.T) {
	module := parseTruthModule("nodejs:18:20250101010101:abcdef12")
	if module.status != truthSuccess || !module.modular || module.name != "nodejs" || module.stream != "18" || module.version != "20250101010101" || module.context != "abcdef12" {
		t.Fatalf("lost native module identity: %#v", module)
	}
	if got := parseTruthModule("(none)"); got != (nativeModule{status: truthSuccess}) {
		t.Fatalf("nonmodular package = %#v", got)
	}
	for _, label := range []string{"", "nodejs:18:abcdef", "nodejs:18:wrong:abcdef", "node js:18:20250101:abcdef", "nodejs::20250101:abcdef", "nodejs:18:20250101:"} {
		if got := parseTruthModule(label); got != (nativeModule{status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT}) {
			t.Fatalf("malformed label produced native identity: %#v", got)
		}
	}
	packages, err := parseVMTruth([]byte("nodejs\t1:18.0-1\tx86_64\tnodejs:18:20250101:aaaa\nnodejs\t1:18.0-1\tx86_64\tnodejs:20:20250101:bbbb\n"), "rpm")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatal("distinct module streams collapsed into one package identity")
	}
}

func TestNativeDNFConfigurationPreservesConfiguredOrder(t *testing.T) {
	directories, status, err := parseDNFConfigTruth([]byte(`{"status":"success","varsdirs":["/etc/yum/vars","/etc/dnf/vars"]}`))
	if err != nil || status != truthSuccess || strings.Join(directories, ":") != "/etc/yum/vars:/etc/dnf/vars" {
		t.Fatalf("configuration order = %v %v %v", directories, status, err)
	}
	for _, state := range []string{"unavailable", "denied", "invalid", "failure"} {
		directories, status, err := parseDNFConfigTruth([]byte(`{"status":"` + state + `"}`))
		if err != nil || status == truthSuccess || len(directories) != 0 {
			t.Fatalf("missing source became success: %v %v %v", directories, status, err)
		}
	}
	if _, status, err := parseDNFConfigTruth([]byte(`{"status":"success","varsdirs":["relative"]}`)); err != nil || status != inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT {
		t.Fatalf("relative configuration directory accepted: %v %v", status, err)
	}
	if _, _, err := parseDNFConfigTruth([]byte(`{"status":"unavailable","varsdirs":["/etc/dnf/vars"]}`)); err == nil {
		t.Fatal("failed config carried partial directories")
	}
}

func TestNativeReleaseLockDoesNotInventDetectedVersions(t *testing.T) {
	for _, value := range []string{"9.4", "9.4\n"} {
		lock, err := parseReleaseLockTruth([]byte("success\n" + value))
		if err != nil || lock.Status != truthSuccess || lock.Value != "9.4" {
			t.Fatalf("explicit lock = %v %v", lock, err)
		}
	}
	lock, err := parseReleaseLockTruth([]byte("unavailable\n"))
	if err != nil || lock.Status != truthUnavailable || lock.Value != "" {
		t.Fatalf("absent lock got a release default: %v %v", lock, err)
	}
	for _, value := range []string{"", " 9.4", "9.4 ", "9.4\n\n", "9.4\r\n"} {
		lock, err := parseReleaseLockTruth([]byte("success\n" + value))
		if err != nil || lock.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT || lock.Value != "" {
			t.Fatalf("invalid lock accepted: %v %v", lock, err)
		}
	}
}

func TestNativeRepositoriesCompareIDsNotProductNames(t *testing.T) {
	data := "repo id                                repo name\nrhel-9-for-x86_64-baseos-eus-rpms       Red Hat Enterprise Linux 9 EUS BaseOS\nprivate-appstream                     Organization AppStream\n"
	repos, err := parseDNFRepositoryTruth(guestCommandResult{Stdout: []byte(data)})
	if err != nil || repos.Status != truthSuccess || repos.Backend != "dnf4" || strings.Join(repos.Ids, ":") != "rhel-9-for-x86_64-baseos-eus-rpms:private-appstream" {
		t.Fatalf("repo ID truth = %v %v", repos, err)
	}
	for _, native := range []guestCommandResult{{}, {Stderr: []byte("No repositories available\n")}} {
		repos, err := parseDNFRepositoryTruth(native)
		if err != nil || repos.Status != truthSuccess || len(repos.Ids) != 0 {
			t.Fatalf("actual zero repositories not preserved: %v %v", repos, err)
		}
	}
	for _, native := range []guestCommandResult{{ExitCode: 1}, {Stderr: []byte("private repo configuration unreadable\n")}, {Stdout: []byte(data), Stderr: []byte("No repositories available\n")}} {
		repos, err := parseDNFRepositoryTruth(native)
		if err != nil || repos.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE || len(repos.Ids) != 0 || repos.Backend != "" {
			t.Fatalf("repository error became empty success: %v %v", repos, err)
		}
	}
	for _, invalid := range []string{"wrong header\n", "repo id repo name\nduplicate A\nduplicate B\n", "repo id repo name\n$releasever Unresolved\n"} {
		if _, err := parseDNFRepositoryTruth(guestCommandResult{Stdout: []byte(invalid)}); err == nil {
			t.Fatal("accepted malformed native repository truth")
		}
	}
}

func TestNativePlatformComparisonRequiresFreshCompleteEvidence(t *testing.T) {
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	// Historical observations may all lack the optional platform category.
	if err := compareVMDetails(platform.ForManifest("rhel", "9.6"), "x86_64", before, after, actual); err != nil {
		t.Fatal(err)
	}
	for _, details := range []*inventoryv1.NativeDetails{before, after, actual} {
		details.Platform = &inventoryv1.PlatformDetails{
			Cpe: truthString("cpe:/o:redhat:enterprise_linux:9::baseos"), ReleaseverLock: truthString("9.8"), Releasever: truthString("9.8"),
			Repositories: &inventoryv1.RepositoryObservation{
				Status: truthSuccess, Backend: "dnf4", Ids: []string{"rhel-9-baseos-eus", "rhel-9-appstream-eus"},
				Configurations: []*inventoryv1.RepositoryConfiguration{{Id: "rhel-9-baseos-eus"}, {Id: "rhel-9-appstream-eus"}},
			},
		}
	}
	actual.Platform.Repositories.Ids[0], actual.Platform.Repositories.Ids[1] = actual.Platform.Repositories.Ids[1], actual.Platform.Repositories.Ids[0]
	if err := compareVMDetails(platform.ForManifest("rhel", "9.6"), "x86_64", before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.Platform.ReleaseverLock = truthString("")
	if err := compareVMDetails(platform.ForManifest("rhel", "9.6"), "x86_64", before, after, actual); err == nil {
		t.Fatal("lost release lock accepted")
	}
	actual.Platform = nil
	if err := compareVMDetails(platform.ForManifest("rhel", "9.6"), "x86_64", before, after, actual); err == nil {
		t.Fatal("fresh expected platform accepted omitted category")
	}
}

func TestSecureBootDiagnosticReportsOnlyKnownPostureValues(t *testing.T) {
	hardware := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{SecureBoot: false}}
	details := nativeDetailsFixture()
	details.Firmware.Mode = truthString("uefi")
	details.Firmware.SecureBoot = truthString("")
	err := compareInspectHardware(hardware, details)
	if err == nil || !strings.Contains(err.Error(), `expected "disabled"`) || !strings.Contains(err.Error(), "COLLECTION_STATUS_UNAVAILABLE") {
		t.Fatalf("missing posture diagnostic: %v", err)
	}
	details.Firmware.SecureBoot = truthString("private-unexpected-value")
	err = compareInspectHardware(hardware, details)
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("unsafe posture diagnostic: %v", err)
	}
}

func TestNativeDNF5ConfigurationsPreserveNativeFieldsAndRedactCredentials(t *testing.T) {
	list := guestCommandResult{Stdout: []byte(`[{"id":"fedora","is_enabled":true}]`)}
	info := guestCommandResult{Stdout: []byte(`[
		{"id":"fedora","is_enabled":false,"base_url":["https://user:secret@example.test/44/x86_64?token=secret#private"],"metalink":"https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64","mirrorlist":"","pkg_gpgcheck":true,"gpg_key":["file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"]},
		{"id":"fedora-source","is_enabled":false}
	]`)}
	repos, err := parseDNF5RepositoryTruth(list, info)
	if err != nil {
		t.Fatal(err)
	}
	if repos.Status != truthSuccess || repos.Backend != "dnf5" || len(repos.Ids) != 1 || len(repos.Configurations) != 1 {
		t.Fatalf("wrong native enabled configuration selection: %v", repos)
	}
	config := repos.Configurations[0]
	if config.Id != "fedora" || !config.Gpgcheck || !config.UrlsRedacted || config.Metalink != "https://mirrors.fedoraproject.org/metalink" || config.Mirrorlist != "" || len(config.BaseUrls) != 1 || config.BaseUrls[0] != "https://example.test/44/x86_64" || len(config.GpgKeys) != 1 || config.GpgKeys[0] != "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64" {
		t.Fatal("native configuration fields or credential redaction changed")
	}
}

func TestNativeDNF5RepositoryTruthRejectsIncompleteEvidence(t *testing.T) {
	full := `{"id":"fedora","base_url":[],"metalink":"","mirrorlist":"","pkg_gpgcheck":false,"gpg_key":[]}`
	list := guestCommandResult{Stdout: []byte(`[{"id":"fedora","is_enabled":true}]`)}
	for _, data := range []string{
		`null`, `{}`, `[]`, `[{"id":"fedora"}]`,
		`[` + full + `,` + full + `]`,
		strings.ReplaceAll(`[`+full+`]`, `"pkg_gpgcheck":false,`, ""),
		strings.ReplaceAll(`[`+full+`]`, `"base_url":[]`, `"base_url":null`),
	} {
		if _, err := parseDNF5RepositoryTruth(list, guestCommandResult{Stdout: []byte(data)}); err == nil {
			t.Fatal("accepted missing, duplicate or incomplete native configuration")
		}
	}
	for _, data := range []string{`null`, `[{"id":"fedora"}]`, `[{"id":"fedora","is_enabled":false}]`, `[{"id":"fedora","is_enabled":true},{"id":"fedora","is_enabled":true}]`} {
		if _, err := parseDNF5RepositoryTruth(guestCommandResult{Stdout: []byte(data)}, guestCommandResult{Stdout: []byte(`[` + full + `]`)}); err == nil {
			t.Fatal("accepted malformed enabled repository truth")
		}
	}
	for _, native := range []guestCommandResult{{ExitCode: 1}, {Stderr: []byte("private configuration failure")}} {
		repos, err := parseDNF5RepositoryTruth(list, native)
		if err != nil || repos.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE || len(repos.Ids) != 0 || len(repos.Configurations) != 0 {
			t.Fatal("native failure became partial success")
		}
	}
	empty := guestCommandResult{Stdout: []byte("[]")}
	repos, err := parseDNF5RepositoryTruth(empty, empty)
	if err != nil || repos.Status != truthSuccess || len(repos.Ids) != 0 || len(repos.Configurations) != 0 {
		t.Fatal("successful empty native repository configuration was lost")
	}
}

func TestNativeRepositoryTruthURLRedaction(t *testing.T) {
	for _, test := range []struct {
		raw, clean string
		redacted   bool
	}{
		{"https://user:secret@example.test/path?password=secret#private", "https://example.test/path", true},
		{"https://example.test/path?", "https://example.test/path", true},
		{"https://example.test/path#", "https://example.test/path", true},
		{"https://example.test/a%2Fb", "https://example.test/a%2Fb", false},
		{"file:///etc/pki/key", "file:///etc/pki/key", false},
	} {
		value, redacted, err := redactDNFTruthURL(test.raw)
		if err != nil || value != test.clean || redacted != test.redacted {
			t.Fatal("URL redaction contract mismatch")
		}
	}
	for _, value := range []string{"https://user:private@[bad", "https://example.test/$releasever", "relative/path", "https:opaque-private", "https://example.test/\nprivate"} {
		clean, _, err := redactDNFTruthURL(value)
		if err == nil || clean != "" || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid URL escaped or appeared in diagnostic")
		}
	}
}

func TestNativeDNF5EffectiveReleaseverIsNotAnExplicitLock(t *testing.T) {
	got, err := parseDNF5ReleaseverTruth(guestCommandResult{Stdout: []byte("======== Variables: ========\narch = x86_64\nreleasever = 44\nreleasever_major = 44\nreleasever_minor = \n")})
	if err != nil || got.Status != truthSuccess || got.Value != "44" {
		t.Fatalf("native effective release version lost: %v %v", got, err)
	}
	got, err = parseDNF5ReleaseverTruth(guestCommandResult{Stdout: []byte("======== Variables: ========\narch = x86_64\n")})
	if err != nil || got.Status != truthUnavailable || got.Value != "" {
		t.Fatal("missing native releasever became inferred OS version")
	}
	for _, data := range []string{"releasever = 44\n", "======== Variables: ========\nreleasever = \n", "======== Variables: ========\nreleasever = 44\nreleasever = 45\n"} {
		if _, err := parseDNF5ReleaseverTruth(guestCommandResult{Stdout: []byte(data)}); err == nil {
			t.Fatal("invalid releasever truth accepted")
		}
	}
}

func TestNativePlatformComparisonCoversEveryConfigurationField(t *testing.T) {
	before := nativeDetailsFixture()
	before.Platform = &inventoryv1.PlatformDetails{
		Cpe: truthString("cpe:/o:fedoraproject:fedora:44"), ReleaseverLock: truthString(""), Releasever: truthString("44"),
		Repositories: &inventoryv1.RepositoryObservation{
			Status: truthSuccess, Backend: "dnf5", Ids: []string{"fedora", "updates"},
			Configurations: []*inventoryv1.RepositoryConfiguration{
				{Id: "fedora", BaseUrls: []string{"https://one.test/fedora", "https://two.test/fedora"}, Metalink: "https://mirror.test/metalink", Mirrorlist: "https://mirror.test/list", Gpgcheck: true, GpgKeys: []string{"file:///one", "file:///two"}, UrlsRedacted: true},
				{Id: "updates", Gpgcheck: true},
			},
		},
	}
	after, actual := proto.CloneOf(before), proto.CloneOf(before)
	repositories := actual.Platform.Repositories
	repositories.Configurations[0], repositories.Configurations[1] = repositories.Configurations[1], repositories.Configurations[0]
	config := repositories.Configurations[1]
	config.BaseUrls[0], config.BaseUrls[1] = config.BaseUrls[1], config.BaseUrls[0]
	config.GpgKeys[0], config.GpgKeys[1] = config.GpgKeys[1], config.GpgKeys[0]
	if err := compareVMDetails(platform.ForManifest("fedora", "44"), "x86_64", before, after, actual); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*inventoryv1.PlatformDetails){
		func(p *inventoryv1.PlatformDetails) { p.Releasever.Value = "45" },
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].Id = "other" },
		func(p *inventoryv1.PlatformDetails) {
			p.Repositories.Configurations[0].BaseUrls[0] = "https://changed.test/"
		},
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].Metalink = "" },
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].Mirrorlist = "" },
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].Gpgcheck = false },
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].GpgKeys = nil },
		func(p *inventoryv1.PlatformDetails) { p.Repositories.Configurations[0].UrlsRedacted = false },
	} {
		changed := proto.CloneOf(before)
		mutate(changed.Platform)
		if err := compareVMDetails(platform.ForManifest("fedora", "44"), "x86_64", before, after, changed); err == nil {
			t.Fatal("configuration field mismatch accepted")
		}
	}
}

func TestNativeDNF5CapturedFedora44Truth(t *testing.T) {
	fixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("../agent/inventory/testdata/dnf5-fedora44/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	repos, err := parseDNF5RepositoryTruth(
		guestCommandResult{Stdout: fixture("repo-list-enabled.json")},
		guestCommandResult{Stdout: fixture("repo-info-config-only.json")},
	)
	if err != nil {
		t.Fatal(err)
	}
	captured := new(inventoryv1.PlatformDetails)
	if err := protojson.Unmarshal(fixture("collector-helper.json"), captured); err != nil {
		t.Fatal(err)
	}
	slices.Sort(repos.Ids)
	slices.SortFunc(repos.Configurations, func(a, b *inventoryv1.RepositoryConfiguration) int {
		return strings.Compare(a.Id, b.Id)
	})
	if !proto.Equal(repos, captured.Repositories) {
		t.Fatal("independent native CLI configuration differs from captured supported-binding evidence")
	}
	releasever, err := parseDNF5ReleaseverTruth(guestCommandResult{Stdout: fixture("variables.txt")})
	if err != nil || !proto.Equal(releasever, captured.Releasever) {
		t.Fatalf("native effective releasever differs: %v", err)
	}
}
