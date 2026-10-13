//go:build linux

package sshprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

// Captured evidence tests protect ownership and planning decisions. Actual sshd,
// reload, SSH exchanges and SELinux labels are exercised by the native lane.
func fixtureProvider() *Provider {
	product := &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}
	owner := &agentv1.ResourceOwnershipBinding{AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(), Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}
	return &Provider{config: Config{Ownership: owner, Platform: product, ExecutorIncarnation: uuid.NewString()}, backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_OPENSSH, NativeVersion: "OpenSSH_9.6", ProviderVersion: "1", Product: product}, boot: uuid.NewString(), unit: "ssh.service", creation: func(_ context.Context, image *agentv1.ResourceOwnershipSnapshot) error {
		image.Observation.GetManagedFile().SecurityMetadataSha256 = nativefile.XattrDigest(nil)
		return nil
	}}
}
func fixtureDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: sshRef(), State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Authorized use only.\n")}}}
}
func fixtureFile(path string, content []byte) *agentv1.SSHNativeFileSnapshot {
	state := &resourcev1.ManagedFileObservation{Path: path, NativeIdentitySha256: sum([]byte("identity" + path)), AncestrySha256: sum([]byte("parent" + path)), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
	if content != nil {
		state.Exists = true
		state.File = &resourcev1.FileIdentity{Path: path, Inode: 100, Mode: 0644, Sha256: sum(content)}
	}
	return &agentv1.SSHNativeFileSnapshot{State: state, Content: bytes.Clone(content), Continuity: &agentv1.NativeFileContinuity{InodeGenerationSha256: sum([]byte("generation" + path)), AncestryGenerationSha256: sum([]byte("parent-generation" + path))}}
}
func fixtureSnapshot(t *testing.T, p *Provider, managed bool) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	private := &agentv1.SSHServerOwnership{Directive: fixtureFile(resource.SSHBannerDirectivePath, nil), Banner: fixtureFile(resource.SSHBannerPath, []byte("original notice\n"))}
	path := "none"
	received := sum(nil)
	if managed {
		private.Directive = fixtureFile(resource.SSHBannerDirectivePath, []byte(bannerDirective))
		private.Banner = fixtureFile(resource.SSHBannerPath, []byte(fixtureDesired().GetSshServer().GetBannerText()))
		path = resource.SSHBannerPath
		received = sum(private.Banner.Content)
	}
	public := &resourcev1.SSHServerObservation{IncludeGraphSha256: sum([]byte("graph")), EffectiveConfigurationSha256: sum([]byte("effective")), Effective: &resourcev1.SSHServerDesired{Port: proto.Uint32(22)}, ServiceUnit: p.unit, BannerPath: path, DirectiveFile: proto.CloneOf(private.Directive.State), BannerFile: proto.CloneOf(private.Banner.State), Syntax: receipt(true, nil, "fixture syntax"), Connection: receipt(true, nil, "fixture transport"), ReceivedBannerSha256: received}
	o := &resourcev1.ResourceObservation{Ref: sshRef(), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: sum([]byte("revision")), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_SshServer{SshServer: public}}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: o, SshServer: private}
	if err := validateMessage(snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
func fixtureLedger(p *Provider, baseline, last *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipLedger {
	return &agentv1.ResourceOwnershipLedger{FormatVersion: 1, Revision: 2, Ref: sshRef(), Owner: proto.CloneOf(p.config.Ownership), State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Baseline: baseline, LastApplied: last, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SSH_BANNER}}
}
func TestBannerOnlyAdmission(t *testing.T) {
	if err := validateDesired(fixtureDesired()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*resourcev1.SSHServerDesired){func(s *resourcev1.SSHServerDesired) { s.Port = proto.Uint32(22) }, func(s *resourcev1.SSHServerDesired) { s.PasswordAuthentication = proto.Bool(false) }, func(s *resourcev1.SSHServerDesired) { s.BannerText = nil; s.PublicKeyAuthentication = proto.Bool(true) }} {
		desired := fixtureDesired()
		change(desired.GetSshServer())
		if !errors.Is(validateDesired(desired), ErrUnsupported) {
			t.Fatal("unimplemented SSH controls accepted")
		}
	}
}
func TestBannerAdoptionAndReservedCollision(t *testing.T) {
	p := fixtureProvider()
	before := fixtureSnapshot(t, p, false)
	if err := acquisitionAllowed(p.config.Ownership, nil, before, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrAdoptionRequired) || !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_banner_file" {
		t.Fatal("unowned issue.net overwritten", err)
	}
	p.config.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	p.config.Ownership.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	if err := acquisitionAllowed(p.config.Ownership, nil, before, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
	if err := acquisitionAllowed(p.config.Ownership, nil, fixtureSnapshot(t, p, true), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) || errors.Is(err, ErrAdoptionRequired) || admissiondetail.Of(err) != "existing_banner_dropin" {
		t.Fatal("reserved drop-in silently adopted", err)
	}
}
func TestNativeRefusalDetails(t *testing.T) {
	err := bannerCaptureError(&os.PathError{Op: "openat", Path: resource.SSHBannerPath, Err: unix.ELOOP})
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrAdoptionRequired) || admissiondetail.Of(err) != "existing_banner_symlink" {
		t.Fatal("issue.net symlink not a named precondition", err)
	}
	other := errors.New("io")
	if bannerCaptureError(other) != other {
		t.Fatal("unrelated capture failure reclassified")
	}
	if err := configInvalid(other); !errors.Is(err, ErrConflict) || !errors.Is(err, other) || admissiondetail.Of(err) != "ssh_config_invalid" {
		t.Fatal("sshd -t failure detail", err)
	}
}
func TestContentDriftRepairsButReplacementAndReleaseRefuse(t *testing.T) {
	p := fixtureProvider()
	baseline := fixtureSnapshot(t, p, false)
	last := fixtureSnapshot(t, p, true)
	ledger := fixtureLedger(p, baseline, last)
	drift := proto.CloneOf(last)
	drift.SshServer.Banner.Content = []byte("external content\n")
	drift.SshServer.Banner.State.File.Sha256 = sum(drift.SshServer.Banner.Content)
	drift.Observation.GetSshServer().BannerFile = proto.CloneOf(drift.SshServer.Banner.State)
	drift.Observation.GetSshServer().ReceivedBannerSha256 = sum(drift.SshServer.Banner.Content)
	if err := acquisitionAllowed(p.config.Ownership, ledger, drift, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
	plan, target, err := p.plan(t.Context(), fixtureDesired(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, drift, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !resource.PlanRequiresEffect(plan) || !bytes.Equal(target.GetSshServer().GetBanner().GetContent(), last.GetSshServer().GetBanner().GetContent()) {
		t.Fatal("content drift did not plan exact repair")
	}
	if _, err := p.target(t.Context(), fixtureDesired().GetSshServer(), drift, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatal("release overwrote externally edited banner")
	}
	drift.SshServer.Banner.State.File.Inode++
	if err := acquisitionAllowed(p.config.Ownership, ledger, drift, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatal("replacement inode treated as owned content drift")
	}
}
func TestRepeatAndExactBaselineRelease(t *testing.T) {
	p := fixtureProvider()
	baseline := fixtureSnapshot(t, p, false)
	last := fixtureSnapshot(t, p, true)
	ledger := fixtureLedger(p, baseline, last)
	plan, _, err := p.plan(t.Context(), fixtureDesired(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, last, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if resource.PlanRequiresEffect(plan) {
		t.Fatal("converged banner needs an effect")
	}
	released, err := p.target(t.Context(), fixtureDesired().GetSshServer(), last, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if !targetMatches(released, baseline) {
		t.Fatal("release did not restore captured baseline")
	}
	if !journal.SSHOwnershipMatches(last, proto.CloneOf(last)) {
		t.Fatal("equal owned state differs")
	}
}
func TestVerificationNeedsActualExchange(t *testing.T) {
	p := fixtureProvider()
	after := fixtureSnapshot(t, p, true)
	ledger := fixtureLedger(p, fixtureSnapshot(t, p, false), after)
	plan, target, err := p.plan(t.Context(), fixtureDesired(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, after, ledger)
	if err != nil {
		t.Fatal(err)
	}
	after.Observation.GetSshServer().ReceivedBannerSha256 = sum([]byte("stale daemon notice"))
	result, err := verification(plan, after, target)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetSshServer().GetConverged() || result.GetSshServer().GetBannerExchange().GetPassed() {
		t.Fatal("file/config match substituted for actual SSH exchange")
	}
}
func TestUnknownEffectsAndForeignOwnersStayBlocked(t *testing.T) {
	p := fixtureProvider()
	before := fixtureSnapshot(t, p, true)
	ledger := fixtureLedger(p, fixtureSnapshot(t, p, false), before)
	ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	if !errors.Is(acquisitionAllowed(p.config.Ownership, ledger, before, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE), ErrOutcomeUnknown) {
		t.Fatal("unknown effect replayed")
	}
	ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
	ledger.Owner.Sources[0].ResourceId = uuid.NewString()
	if !errors.Is(acquisitionAllowed(p.config.Ownership, ledger, before, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE), ErrConflict) {
		t.Fatal("foreign ownership adopted")
	}
}
func TestEffectiveBannerParsing(t *testing.T) {
	// OpenSSH 10.5 prints canonical mixed-case keywords (Omarchy 4.0.4, Arch).
	for _, data := range []string{"port 22\nbanner /etc/issue.net\n", "Port 22\nBanner /etc/issue.net\n"} {
		port, path, err := parseEffective([]byte(data))
		if err != nil || port != 22 || path != resource.SSHBannerPath {
			t.Fatal(data, port, path, err)
		}
	}
	if port, path, err := parseEffective([]byte("Port 22\nBanner none\n")); err != nil || port != 22 || path != "none" {
		t.Fatal(port, path, err)
	}
	for _, data := range []string{"port 22\nbanner /foreign\n", "Port 22\nBanner /foreign\n", "port 22\nport 2222\nbanner none\n", "Port 22\nPort 2222\nBanner none\n", "port 0\nbanner none\n"} {
		if _, _, err := parseEffective([]byte(data)); err == nil {
			t.Fatalf("unsafe effective config accepted: %q", data)
		}
	}
}
func TestIncludeAndKeywordParsing(t *testing.T) {
	for _, line := range []string{"Banner /foreign", "Banner=/foreign", "  bAnNeR /foreign # notice"} {
		key, _, err := configLine(line)
		if err != nil || key != "banner" {
			t.Fatal("foreign directive hidden", line, key, err)
		}
	}
	key, paths, err := configLine("Include=/etc/ssh/sshd_config.d/*.conf # comment")
	if err != nil || key != "include" || len(paths) != 1 || paths[0] != "/etc/ssh/sshd_config.d/*.conf" {
		t.Fatal(key, paths, err)
	}
	for _, line := range []string{"\"Banner\" /foreign", `Include /etc/ssh/a\ b.conf`, "Include", `Include "/etc/ssh/incomplete`} {
		if _, _, err := configLine(line); err == nil {
			t.Fatalf("ambiguous config accepted: %s", line)
		}
	}
}

func graphFixture(files map[string]string) *Provider {
	p := fixtureProvider()
	p.resolve = func(path string) (string, error) {
		if _, ok := files[path]; !ok {
			return "", os.ErrNotExist
		}
		return path, nil
	}
	p.glob = func(pattern string) ([]string, error) {
		var paths []string
		for path := range files {
			matches, err := filepath.Match(pattern, path)
			if err != nil {
				return nil, err
			}
			if matches {
				paths = append(paths, path)
			}
		}
		slices.Sort(paths)
		return paths, nil
	}
	p.capture = func(path string, _ *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error) {
		content, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		file := fixtureFile(path, []byte(content))
		return &agentv1.ResourceOwnershipSnapshot{ManagedFileContent: file.Content, Observation: &resourcev1.ResourceObservation{Metadata: &resourcev1.ObservationMetadata{NativeRevision: sum(file.Content)}, Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: file.State}}}, nil
	}
	return p
}

func TestIncludeGraphRefusesEveryForeignBannerAndConditionalInsertion(t *testing.T) {
	for _, files := range []map[string]string{
		{sshConfigPath: "Banner /foreign\nInclude /etc/ssh/sshd_config.d/*.conf\n"},
		{sshConfigPath: "Include /etc/ssh/sshd_config.d/*.conf\nMatch User other\n Banner /foreign\n"},
		{sshConfigPath: "Match User other\nInclude /etc/ssh/sshd_config.d/*.conf\n"},
		{sshConfigPath: "Include /etc/ssh/sshd_config.d/*.conf\n", "/etc/ssh/sshd_config.d/00-a.conf": "Match User other\n"},
		{sshConfigPath: "Include /etc/ssh/sshd_config\n"},
		{sshConfigPath: "Port 22\n"},
	} {
		if _, _, err := graphFixture(files).includeGraph(nil); err == nil {
			t.Fatal("unsafe include graph accepted", files)
		}
	}
	files := map[string]string{sshConfigPath: "Include /etc/ssh/sshd_config.d/*.conf\nMatch User other\n PasswordAuthentication no\n"}
	first, edges, err := graphFixture(files).includeGraph(nil)
	if err != nil || len(edges) != 0 {
		t.Fatal("absent future include was fabricated as observed", edges, err)
	}
	files[resource.SSHBannerDirectivePath] = bannerDirective
	second, edges, err := graphFixture(files).includeGraph(nil)
	if err != nil || len(edges) != 1 || bytes.Equal(first, second) {
		t.Fatal("owned include graph missing from bound revision", edges, err)
	}
}

func TestNativeIncludeSourceAndEmptyGlobCustody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-protected native include ancestry")
	}
	root, err := os.MkdirTemp("/var/lib", "lindm-ssh-include-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	target := filepath.Join(root, "protected.conf")
	if err := os.WriteFile(target, []byte("# protected configuration\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(root, "vendor-hardlink")); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "aliases")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "vendor.conf")
	if err := os.Symlink("../protected.conf", alias); err != nil {
		t.Fatal(err)
	}
	t.Run("protected-vendor-link-and-hardlink", func(t *testing.T) {
		resolved, err := resolveInclude(alias)
		if err != nil || resolved != target {
			t.Fatal("protected vendor alias refused", resolved, err)
		}
		matches, err := globIncludes(filepath.Join(directory, "*.conf"))
		if err != nil || !slices.Equal(matches, []string{alias}) {
			t.Fatal("protected filename glob refused", matches, err)
		}
	})
	t.Run("non-root-link-owner", func(t *testing.T) {
		if err := os.Lchown(alias, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Lchown(alias, 0, 0); err != nil {
				t.Error(err)
			}
		})
		if _, err := resolveInclude(alias); !errors.Is(err, ErrConflict) {
			t.Fatal("non-root source alias did not produce a typed precondition refusal", err)
		}
	})
	for _, mode := range []os.FileMode{0777, 0770} {
		t.Run(mode.String(), func(t *testing.T) {
			if err := os.Chmod(directory, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(directory, 0755); err != nil {
					t.Error(err)
				}
			})
			if _, err := resolveInclude(alias); !errors.Is(err, ErrConflict) {
				t.Fatal("writable original alias ancestry did not produce a typed precondition refusal", err)
			}
			if _, err := globIncludes(filepath.Join(directory, "*.absent")); !errors.Is(err, ErrConflict) {
				t.Fatal("empty writable search directory did not produce a typed precondition refusal", err)
			}
		})
	}
	if _, err := resolveInclude(filepath.Join(root, "absent.conf")); !errors.Is(err, ErrConflict) || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("typed refusal lost missing-path cause needed for future owned drop-in", err)
	}
	for _, pattern := range []string{
		root + "/aliases/../*.conf",
		root + "/*/*.conf",
		root + "/missing/*.conf",
	} {
		if _, err := globIncludes(pattern); err == nil {
			t.Fatal("unsupported search-directory spelling accepted", pattern)
		}
	}
}
