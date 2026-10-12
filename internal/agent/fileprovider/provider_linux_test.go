//go:build linux

package fileprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// The store seam checks provider ordering and uncertainty, not SQLite durability;
// journal/resource_ownership_linux_test.go owns the real protected journal gates.
// Filesystem effects in these tests use the actual exported native helper path.
type memoryOwnership struct {
	ledger       *agentv1.ResourceOwnershipLedger
	owner        *agentv1.ResourceOwnershipBinding
	release      bool
	failComplete bool
}

func (m *memoryOwnership) LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	if m.ledger == nil {
		return nil, journal.ErrResourceOwnershipNotFound
	}
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) ClaimResourceOwnership(_ context.Context, action string, revision int64, before *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	if uint64(revision) != m.ledger.GetRevision() {
		return nil, journal.ErrConflict
	}
	m.ledger = &agentv1.ResourceOwnershipLedger{FormatVersion: 1, InstallationId: uuid.NewString(), DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), Ref: proto.CloneOf(before.GetObservation().GetRef()), Owner: proto.CloneOf(m.owner), Revision: uint64(revision + 1), State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED, Baseline: proto.CloneOf(before), OwnerIntentEnvelope: []byte("test owner binding; not a native qualification signature"), ClaimActionId: action}
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) BeginResourceOwnershipEffect(_ context.Context, action string, revision int64, before *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	if m.ledger == nil || m.ledger.GetRevision() != uint64(revision) || m.ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, journal.ErrConflict
	}
	if m.release && !managedMatch(m.ledger.GetLastApplied(), before, m.ledger.GetOwnedDimensions()) {
		return nil, journal.ErrResourceOwnershipDrift
	}
	for _, dimension := range dimensions {
		if !slices.Contains(m.ledger.OwnedDimensions, dimension) {
			m.ledger.OwnedDimensions = append(m.ledger.OwnedDimensions, dimension)
		}
	}
	m.ledger.BeforeEffect = proto.CloneOf(before)
	m.ledger.EffectActionId = proto.String(action)
	m.ledger.ClaimActionId = action
	m.ledger.Revision++
	m.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) CompleteResourceOwnershipEffect(_ context.Context, action string, revision int64, after *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	if m.failComplete {
		return nil, errors.New("injected journal completion failure")
	}
	if m.ledger.GetRevision() != uint64(revision) || m.ledger.GetEffectActionId() != action || m.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, journal.ErrConflict
	}
	m.ledger.LastApplied = proto.CloneOf(after)
	m.ledger.Revision++
	m.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
	if m.release {
		m.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED
	}
	return proto.CloneOf(m.ledger), nil
}
func fileFixture(t *testing.T) (*Provider, *memoryOwnership, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned real filesystem custody")
	}
	directory, err := os.MkdirTemp("/var/lib", "lindm-fileprovider-test-")
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("requires writable isolated root fixture directory")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	owner := &agentv1.ResourceOwnershipBinding{AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(), Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}
	native := &agentv1.NativeFileProviderConfig{AllowedRoots: []string{directory}}
	platform, err := inventory.HostPlatform(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	incarnation := uuid.NewString()
	protected := []string{"/etc/lindm", "/var/lib/lindm"}
	backend, boot, err := nativeContext(t.Context(), nativeConfig{Native: native, Platform: platform, ExecutorIncarnation: incarnation, ProtectedPaths: protected})
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryOwnership{owner: owner}
	p := &Provider{config: Config{Native: native, Platform: platform, ExecutorIncarnation: incarnation, Ownership: owner, ActionID: uuid.NewString(), DeploymentID: uuid.NewString(), DeviceID: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), ProtectedPaths: protected}, journal: store, backend: backend, boot: boot}
	p.config.ExecuteNative = func(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		request.Nonce = bytes.Repeat([]byte{1}, 32)
		return ApplyNative(ctx, resourceprovider.NativeEnv{Config: &agentv1.AgentConfig{FileProvider: native}, Platform: platform, ExecutorIncarnation: incarnation, ProtectedPaths: protected}, request, gate)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p, store, filepath.Join(directory, "public-data")
}
func fileDesired(t *testing.T, path string, content []byte) *resourcev1.ResourceDesiredState {
	t.Helper()
	d := &resourcev1.ResourceDesiredState{State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, Content: content}}}
	ref, err := resource.CanonicalRef(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Ref = ref
	return d
}
func applyFixture(t *testing.T, p *Provider, m *memoryOwnership, d *resourcev1.ResourceDesiredState, op resourcev1.ResourceOperation) *resourcev1.ResourcePlan {
	t.Helper()
	p.config.ActionID = uuid.NewString()
	m.release = op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	plan, err := p.Plan(t.Context(), d, op)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	verified, err := p.Apply(t.Context(), plan, func(context.Context) error {
		calls++
		if m.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
			t.Error("authority consumed before durable uncertainty")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !verified.GetManagedFile().GetConverged() {
		t.Fatal("missing final gate or native convergence")
	}
	return plan
}
func requireFile(t *testing.T, path, content string, mode uint32, uid, gid uint32) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	if string(data) != content || st.Mode&0777 != mode || st.Uid != uid || st.Gid != gid {
		t.Fatalf("file data/metadata mismatch: content=%q mode=%o uid=%d gid=%d", data, st.Mode&0777, st.Uid, st.Gid)
	}
}

func TestAlreadyAbsentFileNeedsNoInventedOwnership(t *testing.T) {
	p, store, path := fileFixture(t)
	desired := fileDesired(t, path, nil)
	desired.GetManagedFile().Presence = resourcev1.Presence_PRESENCE_ABSENT
	plan, err := p.Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if resource.PlanRequiresEffect(plan) {
		t.Fatal("already absent file requires a native effect")
	}
	verification, err := p.Verify(t.Context(), plan)
	if err != nil || !verification.GetManagedFile().GetConverged() {
		t.Fatalf("already absent file did not converge: %v", err)
	}
	if store.ledger != nil {
		t.Fatal("read-only absence invented an owned before-image")
	}
}
func TestFileCreateIdempotenceDriftAndRelease(t *testing.T) {
	p, m, path := fileFixture(t)
	d := fileDesired(t, path, []byte("public banner\n"))
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	requireFile(t, path, "public banner\n", 0600, 0, 0)
	first := m.ledger.GetLastApplied().GetObservation().GetManagedFile().GetFile().GetInode()
	plan := applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if plan.GetManagedFile().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE || m.ledger.GetLastApplied().GetObservation().GetManagedFile().GetFile().GetInode() != first {
		t.Fatal("idempotent reconciliation replaced the inode")
	}
	if err := os.WriteFile(path, []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := p.Verify(t.Context(), plan)
	if !errors.Is(err, ErrNotConverged) || v.GetManagedFile().GetConverged() {
		t.Fatal("external content drift reported convergence")
	}
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatalf("externally changed owned file released: %v", err)
	}
	requireFile(t, path, "external", 0600, 0, 0)
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created file release did not restore absence")
	}
}
func TestFileAdoptionRestoresContentModeUIDGID(t *testing.T) {
	p, m, path := fileFixture(t)
	if err := os.WriteFile(path, []byte("baseline"), 0644); err != nil {
		t.Fatal(err)
	}
	d := fileDesired(t, path, []byte("managed"))
	d.GetManagedFile().Mode = proto.Uint32(0640)
	d.GetManagedFile().Uid = proto.Uint32(12345)
	d.GetManagedFile().Gid = proto.Uint32(12346)
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrAdoptionRequired) || !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_file" {
		t.Fatalf("create-only adopted existing file: %v", err)
	}
	p.config.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	p.config.Ownership.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	plan := applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if plan.GetSafety().GetConfirmation() != resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_INDEPENDENT_OPERATOR {
		t.Fatal("adoption approval omitted from safety evidence")
	}
	requireFile(t, path, "managed", 0640, 12345, 12346)
	if string(m.ledger.GetBaseline().GetManagedFileContent()) != "baseline" {
		t.Fatal("private prior content lost")
	}
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	requireFile(t, path, "baseline", 0644, 0, 0)
}
func TestFileModeReleasePreservesUnmanagedContent(t *testing.T) {
	p, m, path := fileFixture(t)
	if err := os.WriteFile(path, []byte("baseline"), 0644); err != nil {
		t.Fatal(err)
	}
	p.config.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	p.config.Ownership.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	d := fileDesired(t, path, []byte("unused"))
	d.GetManagedFile().Content = nil
	d.GetManagedFile().Mode = proto.Uint32(0600)
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err := os.WriteFile(path, []byte("unmanaged change"), 0600); err != nil {
		t.Fatal(err)
	}
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	requireFile(t, path, "unmanaged change", 0644, 0, 0)
}
func TestFileRemovalRestoresPrivateBaseline(t *testing.T) {
	p, m, path := fileFixture(t)
	if err := os.WriteFile(path, []byte("preserved original"), 0600); err != nil {
		t.Fatal(err)
	}
	p.config.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	p.config.Ownership.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	d := fileDesired(t, path, []byte("unused"))
	d.GetManagedFile().Presence = resourcev1.Presence_PRESENCE_ABSENT
	d.GetManagedFile().Content = nil
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned removal failed")
	}
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	requireFile(t, path, "preserved original", 0600, 0, 0)
}
func TestFileUncertainEffectsNeverReplay(t *testing.T) {
	for _, failure := range []string{"permit", "helper", "journal"} {
		t.Run(failure, func(t *testing.T) {
			p, m, path := fileFixture(t)
			d := fileDesired(t, path, []byte("managed"))
			plan, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			original := p.config.ExecuteNative
			p.config.ExecuteNative = func(ctx context.Context, r *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
				calls++
				s, err := original(ctx, r, gate)
				if failure == "helper" && err == nil {
					return nil, errors.New("lost helper receipt")
				}
				return s, err
			}
			m.failComplete = failure == "journal"
			_, err = p.Apply(t.Context(), plan, func(context.Context) error {
				if failure == "permit" {
					return errors.New("authority expired")
				}
				return nil
			})
			if !errors.Is(err, ErrOutcomeUnknown) || m.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
				t.Fatalf("uncertain effect not retained: %v", err)
			}
			if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unknown effect replanned")
			}
			if _, err := p.Apply(t.Context(), plan, func(context.Context) error { return nil }); !errors.Is(err, ErrOutcomeUnknown) || calls != 1 {
				t.Fatal("unknown native effect replayed")
			}
		})
	}
}
func TestFileRejectsStalePlansAndForeignInodes(t *testing.T) {
	p, m, path := fileFixture(t)
	d := fileDesired(t, path, []byte("managed"))
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	plan, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := p.Apply(t.Context(), plan, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrConflict) || called {
		t.Fatal("stale plan reached authority gate")
	}
	other := path + "-other"
	if err := os.WriteFile(other, []byte("managed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatal("equal-content foreign inode acquired for release")
	}
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatal("reconcile silently adopted foreign inode")
	}
}
func TestFileRootsCannotDelegateNativeAuthority(t *testing.T) {
	for _, path := range []string{"/etc/passwd", "/etc/pam.d/login", "/etc/systemd/system/example.service", "/etc/apt/sources.list", "/etc/lindm/agent.json", "/var/lib/lindm/executor/state.db", "/etc/ssh/sshd_config", "/usr/local/bin/payload", "/etc/profile.d/payload.sh", "/root/.ssh/authorized_keys", "/etc/sysctl.d/override.conf"} {
		config := &agentv1.NativeFileProviderConfig{AllowedRoots: []string{filepath.Dir(path)}}
		if err := allowedPath(config, path); err == nil {
			t.Fatalf("local root delegated protected native authority: %s", path)
		}
	}
	if err := allowedPath(&agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/srv/public"}}, "/srv/publicity/file"); err == nil {
		t.Fatal("root prefix without path-component boundary accepted")
	}
}

func TestFileOrdinaryModesAndExplicitCreationContent(t *testing.T) {
	p, m, path := fileFixture(t)
	d := fileDesired(t, path, []byte("public bytes"))
	d.GetManagedFile().Mode = proto.Uint32(0750)
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	requireFile(t, path, "public bytes", 0750, 0, 0)
	applyFixture(t, p, m, d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	d.GetManagedFile().Content = nil
	if _, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err == nil {
		t.Fatal("new content synthesized from a mode-only request")
	}
}

func TestFileHelperRecomputesTargetBeforeAuthority(t *testing.T) {
	p, _, path := fileFixture(t)
	d := fileDesired(t, path, []byte("approved"))
	original := p.config.ExecuteNative
	p.config.ExecuteNative = func(ctx context.Context, r *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		r.Target.ManagedFileContent = []byte("unapproved")
		digest := sha256.Sum256(r.Target.ManagedFileContent)
		r.Target.Observation.GetManagedFile().File.Sha256 = digest[:]
		return original(ctx, r, gate)
	}
	plan, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := p.Apply(t.Context(), plan, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrConflict) || called {
		t.Fatalf("independently supplied target authorized: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("tampered target reached filesystem")
	}
}

func TestFileProtectedContextDisallowsCustomExecutorRoots(t *testing.T) {
	p, _, path := fileFixture(t)
	for _, protected := range []string{filepath.Dir(path), path, filepath.Dir(filepath.Dir(path))} {
		_, _, err := nativeContext(t.Context(), nativeConfig{Native: p.config.Native, Platform: p.config.Platform, ExecutorIncarnation: p.config.ExecutorIncarnation, ProtectedPaths: []string{protected}})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("custom executor path overlaps approved file root: %v", err)
		}
	}
}
