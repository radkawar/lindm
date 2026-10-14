// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package packageprovider reconciles native APT, DNF, pacman and zypper packages
// on explicitly registered mutable platforms. It never
// executes shell providers, invents installed provenance, purges data,
// autoremoves dependencies, or downgrades. Approved distro package scriptlets
// still run with native root privileges. Plans bind complete staged solver
// artifacts and source/database snapshots. Apply records UNKNOWN ownership
// before consuming signed beforeEffect authority; a failed/uncertain
// transaction is observed, never automatically replayed. DNF4 never inherits
// DNF5 store/replay: it stages and replays through its own Python API adapter.
package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lindm/internal/custody"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/config"
	"lindm/internal/agent/dnf"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/agent/statefs"
	"lindm/internal/platform"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "package.native.v1"

var (
	ErrUnsupported    = errors.New("packageprovider: unsupported")
	ErrConflict       = errors.New("packageprovider: precondition conflict")
	ErrOutcomeUnknown = errors.New("packageprovider: native outcome unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("packageprovider: not converged"))
	// ErrAdoptionRequired refuses CREATE_ONLY acquisition of an installed
	// package or existing pin. It is also ErrConflict.
	ErrAdoptionRequired = fmt.Errorf("packageprovider: adoption_required: %w", ErrConflict)
	// ErrBusy means another native frontend (for example a distribution
	// release upgrade) held dpkg's frontend lock before any effect.
	ErrBusy = errors.New("packageprovider: native package manager busy")
)

// Config is constructor-only trusted execution context, not a second serialized
// policy schema. Native is the root-provisioned protobuf configuration.
type Config struct {
	Journal              *journal.Store
	ExecutorIncarnation  string
	Ownership            *agentv1.ResourceOwnershipBinding
	Platform             *resourcev1.PlatformProduct
	ActionID             string
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	StateDirectory       string
	Native               *agentv1.NativePackageProviderConfig
	Preparation          *agentv1.ResourceExecutionPreparation
	IntentDigest         []byte
	NativeStage          func(context.Context, *agentv1.NativePackageTransactionRequest) (bool, error)
	NativeStageCancel    func(context.Context, string) error
	NativeTransaction    func(context.Context, *agentv1.NativePackageTransactionRequest, func(context.Context) error) error
}
type Provider struct {
	config      Config
	state       string
	stagingMax  uint64
	boot        string
	backend     *resourcev1.BackendSelection
	ecosystem   resourcev1.PackageEcosystem
	managerPath string
	// manager, interpreter and versionlock describe the identified native DNF
	// generation, the DNF4 entrypoint's own Python and whether the DNF4
	// versionlock plugin natively enforces its fixed lock list.
	manager     dnf.Kind
	interpreter string
	versionlock bool
	// rpmdb is the located native RPM database directory.
	rpmdb string
	// native is the device's own package architecture in the package
	// database's spelling; packages without an architecture follow it.
	native string
	run    nativeRunner
	gate   sync.Mutex
	closed bool
}

var _ resourceprovider.Provider = (*Provider)(nil)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })

func validateMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ErrUnsupported
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	v, err := validator()
	if err != nil {
		return err
	}
	return v.Validate(message)
}

func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil || config.Journal == nil || config.StateDirectory == "" || config.Native == nil || config.Ownership == nil || config.Platform == nil || os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: root execution context and approved sources required", ErrUnsupported)
	}
	if err := validateMessage(config.Native); err != nil {
		return nil, err
	}
	if err := validateMessage(config.Ownership); err != nil {
		return nil, err
	}
	if err := validateMessage(config.Platform); err != nil {
		return nil, err
	}
	for _, marker := range []string{"/run/ostree-booted", "/ostree/repo", "/sysroot/ostree/repo", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return nil, fmt.Errorf("%w: immutable/generation platform", ErrUnsupported)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	p := &Provider{config: config, state: filepath.Join(config.StateDirectory, "packageprovider"), run: runNative}
	var tool string
	var backend resourcev1.Backend
	if err := platform.Of(config.Platform).Gate(platform.Packages); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	switch platform.Of(config.Platform).Native().Packages.Backend.PackageDB() {
	case platform.PackageDBDpkg:
		p.ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB
		tool = "/usr/bin/apt-get"
		backend = resourcev1.Backend_BACKEND_APT
	case platform.PackageDBRPM:
		p.ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
		if platform.Of(config.Platform).Native().Packages.Backend == platform.BackendZypper {
			tool, backend = "/usr/bin/zypper", resourcev1.Backend_BACKEND_ZYPPER
		}
	case platform.PackageDBPacman:
		p.ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM
		tool, backend = "/usr/bin/pacman", resourcev1.Backend_BACKEND_ALPM
	default:
		return nil, fmt.Errorf("%w: platform requires its qualified mutable backend", ErrUnsupported)
	}
	if err := p.checkPlatform(); err != nil {
		return nil, err
	}
	for _, source := range config.Native.GetSources() {
		if err := checkSource(source); err != nil {
			return nil, err
		}
	}
	parent, err := statefs.OpenDirectory(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	if err := unix.Close(parent); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.state, 0700); err != nil {
		return nil, err
	}
	fd, err := statefs.OpenDirectory(p.state)
	if err != nil {
		return nil, err
	}
	if err := unix.Close(fd); err != nil {
		return nil, err
	}
	var version string
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM && tool == "" {
		manager, err := p.selectDNF(ctx, p.state)
		if err != nil {
			return nil, err
		}
		version, backend = manager.Version, resourcev1.Backend_BACKEND_DNF5
		if manager.Kind == dnf.DNF4 {
			backend = resourcev1.Backend_BACKEND_DNF4
		}
	} else {
		result, err := p.run(ctx, tool, []string{"--version"}, "/", nil)
		if err != nil {
			return nil, err
		}
		p.managerPath = tool
		if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
			p.rpmdb, err = rpmDatabase()
			if err != nil {
				return nil, err
			}
		}
		version = strings.SplitN(strings.TrimSpace(string(result.stdout)), "\n", 2)[0]
	}
	if version == "" || len(version) > 128 {
		return nil, errors.New("packageprovider: invalid native backend version")
	}
	p.backend = &resourcev1.BackendSelection{Backend: backend, NativeVersion: version, ProviderVersion: "1", Product: proto.CloneOf(config.Platform)}
	if err := p.resolveNativeArchitecture(ctx); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	p.boot = strings.TrimSpace(string(boot))
	return p, nil
}
func (p *Provider) checkPlatform() error {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	if fields["ID"] != p.config.Platform.GetOsId() || fields["VERSION_ID"] != p.config.Platform.GetVersion() {
		return fmt.Errorf("%w: actual native platform mismatch", ErrUnsupported)
	}
	// VARIANT_ID separates mutable products from their image-based variants.
	if err := platform.Identify(platform.OSRelease{ID: fields["ID"], VersionID: fields["VERSION_ID"], VariantID: fields["VARIANT_ID"]}).Gate(platform.Packages); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	return nil
}
func checkSource(source *agentv1.NativePackageSource) error {
	path := source.GetSigningKeyFile()
	if !filepath.IsAbs(path) || strings.ContainsAny(path, " \t\r\n\"[];") || filepath.Clean(path) != path {
		return errors.New("packageprovider: unsafe approved signing key path")
	}
	if rpm := source.GetRepository().GetRpm(); rpm != nil && (!rpm.GetRequireMetadataSignature() || config.HasEntitledLocation(rpm)) {
		release, err := inventory.HostRelease(context.Background())
		if err != nil {
			return err
		}
		if !config.RPMMetadataTrusted(platform.Identify(release), rpm) {
			return fmt.Errorf("%w: %w", ErrUnsupported, config.ErrUnsignedMetadata)
		}
		if config.HasEntitledLocation(rpm) {
			if err := config.CheckEntitledSource(platform.Identify(release), source); err != nil {
				return fmt.Errorf("%w: %w", ErrUnsupported, err)
			}
		}
	}
	parent, err := statefs.OpenTemporaryParent(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := unix.Close(parent); err != nil {
		return err
	}
	key, err := custody.ReadRoot(path, 4<<20, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(key)
	if !bytes.Equal(digest[:], source.GetSigningKeySha256()) {
		return errors.New("packageprovider: approved signing key bytes changed")
	}
	return nil
}
func sourceRef(source *agentv1.NativePackageSource) *resourcev1.ResourceRef {
	ecosystem := "apt"
	if source.GetRepository().GetRpm() != nil {
		ecosystem = "rpm"
	} else if source.GetRepository().GetAlpm() != nil {
		ecosystem = "alpm"
	}
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: ecosystem + "/" + source.GetRepository().GetRepositoryId()}
}
func (p *Provider) source(d *resourcev1.NativePackageDesired) (*agentv1.NativePackageSource, error) {
	for _, source := range p.config.Native.GetSources() {
		if proto.Equal(sourceRef(source), d.GetRepository()) {
			if err := checkSource(source); err != nil {
				return nil, err
			}
			return source, nil
		}
	}
	return nil, errors.New("packageprovider: desired repository is not root-approved")
}
func (p *Provider) lock() (func(), error) {
	p.gate.Lock()
	if p.closed {
		p.gate.Unlock()
		return nil, errors.New("packageprovider: closed")
	}
	fd, err := unix.Open(filepath.Join(p.state, "provider.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		p.gate.Unlock()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		p.gate.Unlock()
		return nil, fmt.Errorf("%w: package provider already active", ErrConflict)
	}
	return func() { _ = unix.Close(fd); p.gate.Unlock() }, nil
}
func (p *Provider) Close() error { p.gate.Lock(); defer p.gate.Unlock(); p.closed = true; return nil }
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.config.Journal.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}

// Observe requires a complete all-record native database probe. A missing row
// becomes absence only after native success, no diagnostic, and complete parsing.
func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx, desired.GetRef())
	if err != nil {
		return nil, err
	}
	db, err := p.database(ctx)
	if err != nil {
		return nil, err
	}
	return p.observe(ctx, desired, db, ledger, nil)
}
func (p *Provider) validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	d := desired.GetNativePackage()
	if d == nil || d.GetPackage().GetEcosystem() != p.ecosystem {
		return ErrUnsupported
	}
	if d.GetPackage().GetNativeName() == "lindm-agent" {
		return errors.New("packageprovider: agent package belongs to signed self-update authority")
	}
	_, err := p.source(d)
	return err
}
func (p *Provider) observe(ctx context.Context, desired *resourcev1.ResourceDesiredState, db *database, ledger *agentv1.ResourceOwnershipLedger, receipt *resourcev1.PackageTransactionManifest) (*resourcev1.ResourceObservation, error) {
	d := desired.GetNativePackage()
	identity, err := p.resolveIdentity(db, d.GetPackage())
	if err != nil {
		return nil, err
	}
	if db.multiple[packageKey(identity)] {
		return nil, fmt.Errorf("%w: multi-version target", ErrUnsupported)
	}
	record := proto.CloneOf(db.records[packageKey(identity)])
	if record != nil {
		installed, err := p.installedIdentity(ctx, record)
		if err != nil {
			return nil, err
		}
		record.NativeIdentitySha256 = installed
		prior := ledger.GetLastApplied().GetObservation().GetNativePackage().GetRecord()
		if prior.GetProvenanceKnown() && samePackageRecord(prior, record) && bytes.Equal(prior.GetNativeIdentitySha256(), installed) {
			copyProvenance(record, prior)
		}
		if receipt != nil {
			for _, entry := range receipt.GetEntries() {
				if proto.Equal(entry.GetPackage(), record.GetPackage()) && proto.Equal(entry.GetAfter(), record.GetVersion()) && entry.GetArtifact() != nil {
					record.Source = proto.CloneOf(entry.GetSource())
					record.SignerSha256 = bytes.Clone(entry.GetSignerSha256())
					record.MetadataRevisionSha256 = bytes.Clone(entry.GetMetadataRevisionSha256())
					record.ProvenanceKnown = true
				}
			}
			applyInstalledProvenance(record, receipt.GetInstalledProvenance(), d.GetRepository())
		}
	}
	pin, contents, err := readPin(p.pinPath(desired.GetRef()))
	if err != nil {
		return nil, err
	}
	observation := &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.New(time.Now()), Backend: proto.CloneOf(p.backend), NativeRevision: bytes.Clone(db.revision), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: identity, Installed: record != nil, Record: record, DatabaseRevisionSha256: bytes.Clone(db.revision), PinFile: pin, PinContents: contents}}}
	if err := resource.ValidateObservation(observation); err != nil {
		return nil, err
	}
	return observation, nil
}
func copyProvenance(to, from *resourcev1.NativePackageRecord) {
	to.Source = proto.CloneOf(from.GetSource())
	to.SignerSha256 = bytes.Clone(from.GetSignerSha256())
	to.MetadataRevisionSha256 = bytes.Clone(from.GetMetadataRevisionSha256())
	to.ProvenanceKnown = from.GetProvenanceKnown()
}
func nativeMatches(d *resourcev1.NativePackageDesired, record *resourcev1.NativePackageRecord) bool {
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return record == nil
	}
	return record != nil && (d.GetExact() == nil || proto.Equal(d.GetExact(), record.GetVersion()))
}

func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	ledger, err := p.ledger(ctx, desired.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	db, err := p.database(ctx)
	if err != nil {
		return nil, err
	}
	before, err := p.observe(ctx, desired, db, ledger, nil)
	if err != nil {
		return nil, err
	}
	// An installed package lindm did not install is acquired only once
	// preparation has proven its provenance against the approved source.
	prove := p.needsInstalledProvenance(desired, before, ledger, operation)
	if !prove {
		if err := p.acquisitionAllowed(before, ledger, operation); err != nil {
			return nil, err
		}
	}
	effective := proto.CloneOf(desired.GetNativePackage())
	if effective.GetAny() != nil && before.GetNativePackage().GetInstalled() && effective.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		effective.Version = &resourcev1.NativePackageDesired_Exact{Exact: proto.CloneOf(before.GetNativePackage().GetRecord().GetVersion())}
	}
	pin, err := p.renderPin(desired.GetRef(), desired.GetNativePackage(), before.GetNativePackage().GetPinContents())
	if err != nil {
		return nil, err
	}
	var inverse *resourcev1.OwnershipInverseBinding
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		effective, pin, inverse, err = releaseTarget(desired, before, ledger)
		if err != nil {
			return nil, err
		}
	}
	if effective.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		if err := checkNoDowngrade(before.GetNativePackage().GetRecord().GetVersion(), effective.GetExact()); err != nil {
			return nil, err
		}
	}
	transactionID := p.config.ActionID
	if parsed, err := uuid.Parse(transactionID); err != nil || parsed.String() != transactionID {
		return nil, ErrConflict
	}
	directory := filepath.Join(p.state, transactionID)
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := bindPreparationBaseline(directory, before, ledger); err != nil {
		return nil, err
	}
	source, err := p.source(effective)
	if err != nil {
		return nil, err
	}
	if p.config.NativeStage == nil || p.config.Preparation == nil {
		return nil, fmt.Errorf("%w: bounded native preparation unavailable", ErrUnsupported)
	}
	expires := p.config.Preparation.GetDeadline()
	if expires == nil || !time.Now().Before(expires.AsTime()) {
		return nil, errors.New("packageprovider: preparation expired")
	}
	maximum := min(p.config.Preparation.GetMaxCacheBytes(), uint64(512<<20))
	request := &agentv1.NativePackageTransactionRequest{
		Operation: agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_PREPARE,
		Desired:   proto.CloneOf(desired), EffectiveDesired: effective, Source: source,
		TransactionId: transactionID, ExpectedDatabaseRevision: bytes.Clone(db.revision),
		Platform: proto.CloneOf(p.config.Platform), ActionId: p.config.ActionID,
		StagingExpiresAt: proto.CloneOf(expires), StagingMaxBytes: maximum, IntentSha256: bytes.Clone(p.config.IntentDigest),
		ProveInstalledProvenance: prove,
	}
	if !p.rolling() && p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM && before.GetNativePackage().GetPinFile() != nil {
		request.CandidatePinContents = pinProjection(p.backend.GetBackend(), pin)
		digest := sha256.Sum256(request.GetCandidatePinContents())
		request.CandidatePinSha256 = digest[:]
		request.OriginalPin = proto.CloneOf(before.GetNativePackage().GetPinFile())
	}
	ready, err := p.config.NativeStage(ctx, request)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, resource.ErrPreparing
	}
	manifest, err := readPreparedManifest(directory)
	if err != nil {
		return nil, err
	}
	if proof := manifest.GetInstalledProvenance(); proof != nil && (!prove || !applyInstalledProvenance(before.GetNativePackage().GetRecord(), proof, desired.GetNativePackage().GetRepository())) {
		return nil, ErrConflict
	}
	if prove {
		if err := p.acquisitionAllowed(before, ledger, operation); err != nil {
			return nil, err
		}
	}
	changePackages, err := manifestChangesPackages(manifest)
	if err != nil {
		return nil, err
	}
	if err := p.dependencyOwnership(ctx, manifest); err != nil {
		return nil, err
	}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	ownershipDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	claims = append(claims, dependencyClaims(manifest)...)
	if !bytes.Equal(manifest.GetNativeDatabaseRevision(), db.revision) || len(manifest.GetAffectedDesiredSha256()) != 1 || !bytes.Equal(manifest.GetAffectedDesiredSha256()[0], desiredDigest[:]) {
		return nil, ErrConflict
	}
	artifact, err := p.storeManifest(directory, manifest)
	if err != nil {
		return nil, err
	}
	pinMode := uint32(0644)
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED && ledger.GetBaseline().GetObservation().GetNativePackage().GetPinFile() != nil {
		pinMode = ledger.GetBaseline().GetObservation().GetNativePackage().GetPinFile().GetMode()
	}
	plan := &resourcev1.ResourcePlan{
		Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: desiredDigest[:],
		ObservationSha256: observationDigest[:], Backend: proto.CloneOf(p.backend), Claims: claims,
		OwnershipRevisionSha256: ownershipDigest[:], Before: before,
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE},
			Reversibility:         resourcev1.Reversibility_REVERSIBILITY_PARTIAL,
			RollbackScope:         resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS,
			Confirmation:          resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED,
			PrerequisiteManifests: []*resourcev1.ArtifactRef{artifact}},
		Plan: &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{
			Desired: proto.CloneOf(desired.GetNativePackage()), TransactionManifest: artifact,
			NativeDatabaseRevision: bytes.Clone(db.revision), NativeLockIdentity: p.nativeLockIdentity(),
			Inverse: inverse, PinContents: pin, PinMode: pinMode, ChangePackages: changePackages, ChangePin: !bytes.Equal(pin, before.GetNativePackage().GetPinContents()) || (before.GetNativePackage().GetPinFile() != nil && before.GetNativePackage().GetPinFile().GetMode() != pinMode)}},
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		return nil, err
	}
	return plan, nil
}
func (p *Provider) nativeLockIdentity() string {
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		return "alpm:/var/lib/pacman/db.lck"
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		return "dpkg:/var/lib/dpkg/lock-frontend:/var/lib/dpkg/lock"
	}
	return "rpm:" + filepath.Join(p.rpmdb, ".rpm.lock")
}
func (p *Provider) nativeTransactionPath(directory string) string {
	if p.rolling() {
		return filepath.Join(directory, "native-transaction.pb")
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		return filepath.Join(directory, "native-transaction.txt")
	}
	return filepath.Join(directory, "transaction", "transaction.json")
}
func (p *Provider) acquisitionAllowed(before *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return errors.New("packageprovider: release has no ownership baseline")
	}
	o := before.GetNativePackage()
	// lindm knows a package's origin when it installed it, or when preparation
	// proved the installation is the approved source's artifact
	// (provenance_linux.go). Without either, neither CREATE_ONLY nor approved
	// adoption may take it over.
	if o.GetInstalled() && !o.GetRecord().GetProvenanceKnown() {
		return admissiondetail.Wrap(fmt.Errorf("%w: installed provenance unknown; unsafe acquisition refused", ErrConflict), "existing_package_unverified")
	}
	if (o.GetInstalled() || pinClaimsPackage(before.GetRef(), o)) && p.config.Ownership.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		return admissiondetail.Wrap(fmt.Errorf("%w: existing package/pin requires approved adoption", ErrAdoptionRequired), "existing_package")
	}
	return nil
}

// CancelPreparation only stops this signed action's preparation helper. It never
// cancels or deletes an uncertain native APPLY transaction.
func (p *Provider) CancelPreparation(ctx context.Context) error {
	return CancelPreparation(ctx, p.config)
}

// CancelPreparation can expire a staged action after its source, platform, or
// native executable disappeared; none of those are cleanup prerequisites.
func CancelPreparation(ctx context.Context, config Config) error {
	if config.NativeStageCancel == nil {
		return ErrUnsupported
	}
	if id, err := uuid.Parse(config.ActionID); err != nil || id.String() != config.ActionID {
		return ErrConflict
	}
	return config.NativeStageCancel(ctx, config.ActionID)
}
