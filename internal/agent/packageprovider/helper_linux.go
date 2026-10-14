// SPDX-License-Identifier: Apache-2.0

//go:build linux

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

	"lindm/internal/custody"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/dnf"
	"lindm/internal/agent/statefs"
	"lindm/internal/resource"
)

func helperProvider(ctx context.Context, stateDirectory string, request *agentv1.NativePackageTransactionRequest) (*Provider, string, error) {
	if os.Geteuid() != 0 {
		return nil, "", ErrUnsupported
	}
	if err := validateMessage(request); err != nil {
		return nil, "", err
	}
	if err := resource.ValidateDesired(request.GetDesired()); err != nil {
		return nil, "", err
	}
	id, err := uuid.Parse(request.GetTransactionId())
	if err != nil || id.String() != request.GetTransactionId() {
		return nil, "", ErrConflict
	}
	p := &Provider{config: Config{StateDirectory: stateDirectory, Native: &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{request.GetSource()}}, Platform: request.GetPlatform()}, state: filepath.Join(stateDirectory, "packageprovider"), ecosystem: request.GetDesired().GetNativePackage().GetPackage().GetEcosystem(), run: runNative}
	if p.ecosystem != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB && p.ecosystem != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM && p.ecosystem != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		return nil, "", ErrUnsupported
	}
	if err := p.checkPlatform(); err != nil {
		return nil, "", err
	}
	if err := checkSource(request.GetSource()); err != nil {
		return nil, "", err
	}
	if err := p.validateDesired(request.GetDesired()); err != nil {
		return nil, "", err
	}
	if !proto.Equal(request.GetSource(), p.config.Native.GetSources()[0]) || !proto.Equal(sourceRef(request.GetSource()), request.GetEffectiveDesired().GetRepository()) {
		return nil, "", ErrConflict
	}
	directory := filepath.Join(p.state, request.GetTransactionId())
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, "", err
	}
	if err := unix.Close(fd); err != nil {
		return nil, "", err
	}
	for _, marker := range []string{"/run/ostree-booted", "/ostree/repo", "/sysroot/ostree/repo", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return nil, "", ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}
	if p.rolling() {
		if err := p.selectRolling(); err != nil {
			return nil, "", err
		}
	} else if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		if _, err := p.selectDNF(ctx, directory); err != nil {
			return nil, "", err
		}
	}
	if err := p.resolveNativeArchitecture(ctx); err != nil {
		return nil, "", err
	}
	return p, directory, nil
}

// PrepareNative runs only inside the bounded root helper's preparation sandbox.
// It downloads/authenticates to its transaction child, never installs packages or
// changes a persistent native pin. The caller authenticates its local root config.
func PrepareNative(ctx context.Context, stateDirectory string, request *agentv1.NativePackageTransactionRequest) (resultErr error) {
	if request.GetOperation() != agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_PREPARE {
		return ErrConflict
	}
	p, directory, err := helperProvider(ctx, stateDirectory, request)
	if err != nil {
		return err
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		// Staging is effect-free. While another frontend (a release upgrade)
		// holds dpkg, its database moves and APT's install-time locks fail;
		// any staging failure then is that busy state, retried later.
		defer func() { resultErr = classifyDPKGBusy(resultErr) }()
	}
	if request.GetOriginalPin() != nil {
		pin, contents, err := readPin(p.pinPath(request.GetDesired().GetRef()))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(contents)
		if pin == nil || !bytes.Equal(digest[:], request.GetCandidatePinSha256()) || !bytes.Equal(contents, request.GetCandidatePinContents()) {
			return errors.New("packageprovider: isolated native pin projection missing")
		}
	}
	p.stagingMax = min(request.GetStagingMaxBytes(), uint64(512<<20))
	if p.stagingMax == 0 || request.GetStagingExpiresAt() == nil {
		return errors.New("packageprovider: signed staging budget required")
	}
	ctx, cancel := context.WithDeadline(ctx, request.GetStagingExpiresAt().AsTime())
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	restoreLimit, err := nativeFileLimit(p.stagingMax)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, restoreLimit()) }()
	ctx, finishGuard := stagingGuard(ctx, directory, p.stagingMax)
	defer func() { resultErr = errors.Join(resultErr, finishGuard()) }()
	if _, err := os.Lstat(filepath.Join(directory, "native-manifest.pb")); err == nil {
		return errors.New("packageprovider: preparation already committed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := reserveSpace(directory, p.stagingMax+(64<<20)); err != nil {
		return err
	}
	db, err := p.database(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(db.revision, request.GetExpectedDatabaseRevision()) {
		return ErrConflict
	}
	d := request.GetEffectiveDesired()
	target, err := p.nativeTarget(db, d.GetPackage())
	if err != nil {
		return err
	}
	if db.multiple[packageKey(target)] {
		return fmt.Errorf("%w: multi-version target", ErrUnsupported)
	}
	if d.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		if err := checkNoDowngrade(db.records[packageKey(target)].GetVersion(), d.GetExact()); err != nil {
			return err
		}
	}
	var proof *resourcev1.InstalledProvenanceProof
	prove := p.provenanceStep(ctx, directory, request, db.records[packageKey(target)], &proof)
	var entries []*resourcev1.PackageTransactionEntry
	var snapshot *resourcev1.RepositorySnapshot
	if p.rolling() {
		entries, snapshot, err = p.planRolling(ctx, directory, d, db, request.GetSource())
	} else if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		entries, snapshot, err = p.planAPT(ctx, directory, d, db, request.GetSource(), prove)
	} else {
		entries, snapshot, err = p.planDNF(ctx, directory, d, db, request.GetSource(), prove)
	}
	if err != nil {
		return err
	}
	if err := p.validateEntries(entries, d, db); err != nil {
		return err
	}
	if err := validateArtifactCapacity(entries, directory); err != nil {
		return err
	}
	// Source identity includes approved configuration and signing bytes, not
	// merely whichever metadata happened to occupy a native cache directory.
	snapshot.MetadataSha256, err = boundSourceRevision(request.GetSource(), snapshot.GetMetadataSha256())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.GetAfter() != nil {
			entry.MetadataRevisionSha256 = bytes.Clone(snapshot.GetMetadataSha256())
		}
	}
	digest, err := resource.DesiredDigest(request.GetDesired())
	if err != nil {
		return err
	}
	manifest := &resourcev1.PackageTransactionManifest{Entries: entries, NativeDatabaseRevision: bytes.Clone(db.revision), Sources: &resourcev1.SourceSnapshot{Source: &resourcev1.SourceSnapshot_Repositories{Repositories: &resourcev1.RepositorySnapshots{Repositories: []*resourcev1.RepositorySnapshot{snapshot}}}}, NativeLockIdentity: p.nativeLockIdentity(), AffectedResources: []*resourcev1.ResourceRef{proto.CloneOf(request.GetDesired().GetRef())}, AffectedDesiredSha256: [][]byte{digest[:]}}
	manifest.CandidatePinSha256 = bytes.Clone(request.GetCandidatePinSha256())
	manifest.OriginalPin = proto.CloneOf(request.GetOriginalPin())
	manifest.InstalledProvenance = boundProof(proof, snapshot)
	manifest.NativeTransaction, err = artifactFor(p.nativeTransactionPath(directory))
	if err != nil {
		return err
	}
	if err := validateMessage(manifest); err != nil {
		return err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(manifest)
	if err != nil {
		return err
	}
	if len(encoded) > 256<<10 {
		return errors.New("packageprovider: transaction manifest capacity")
	}
	if err := atomicFile(filepath.Join(directory, "native-manifest.pb"), encoded, 0600); err != nil {
		return err
	}
	return syncTree(directory)
}
func readPreparedManifest(directory string) (*resourcev1.PackageTransactionManifest, error) {
	data, err := custody.ReadRoot(filepath.Join(directory, "native-manifest.pb"), 256<<10, false)
	if err != nil {
		return nil, err
	}
	manifest := new(resourcev1.PackageTransactionManifest)
	if err := proto.Unmarshal(data, manifest); err != nil {
		return nil, err
	}
	if err := validateMessage(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}
func boundSourceRevision(source *agentv1.NativePackageSource, metadata []byte) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(source)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.package.source.v1\x00"))
	_, _ = h.Write(encoded)
	_, _ = h.Write(metadata)
	return h.Sum(nil), nil
}
func reserveSpace(directory string, minimum uint64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(directory, &stat); err != nil {
		return err
	}
	if stat.Bsize <= 0 || stat.Bavail < minimum/uint64(stat.Bsize)+1 {
		return errors.New("packageprovider: insufficient durable transaction capacity")
	}
	return nil
}
func validateArtifactCapacity(entries []*resourcev1.PackageTransactionEntry, directory string) error {
	var total uint64
	for _, entry := range entries {
		size := entry.GetArtifact().GetSizeBytes()
		if size > 4<<30 || total > (4<<30)-size {
			return errors.New("packageprovider: native transaction exceeds artifact capacity")
		}
		total += size
	}
	return reserveSpace(directory, 64<<20)
}
func (p *Provider) validateEntries(entries []*resourcev1.PackageTransactionEntry, d *resourcev1.NativePackageDesired, db *database) error {
	// libalpm indexes installed packages by name, not name/architecture.
	// Refuse all architecture transitions before looking up Before, including
	// dependencies: otherwise an implicit replacement masquerades as INSTALL.
	if d.GetPackage().GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		selected := make(map[string]string, len(entries))
		for _, entry := range entries {
			name, arch := entry.GetPackage().GetNativeName(), entry.GetPackage().GetArchitecture()
			if previous, exists := selected[name]; exists && previous != arch {
				return ErrConflict
			}
			selected[name] = arch
		}
		for _, record := range db.records {
			if arch, found := selected[record.GetPackage().GetNativeName()]; found && arch != record.GetPackage().GetArchitecture() {
				return errors.New("packageprovider: ALPM architecture replacement refused")
			}
		}
	}
	seen := make(map[string]bool, len(entries))
	direct := 0
	for _, entry := range entries {
		if entry.GetPackage().GetNativeName() == "lindm-agent" {
			return errors.New("packageprovider: dependency transaction crosses signed self-update authority")
		}
		key := packageKey(entry.GetPackage())
		if seen[key] || db.multiple[key] || !proto.Equal(entry.GetBefore(), db.records[key].GetVersion()) {
			return ErrConflict
		}
		seen[key] = true
		if entry.GetDirectRequest() != p.requests(d.GetPackage(), entry.GetPackage()) {
			return ErrConflict
		}
		if entry.GetDirectRequest() {
			direct++
		}
		if entry.GetDirectRequest() && entry.GetAfter() != nil && d.GetExact() != nil && !proto.Equal(entry.GetAfter(), d.GetExact()) {
			return errors.New("packageprovider: solver did not select exact native version")
		}
		if entry.GetAfter() == nil {
			if !entry.GetDirectRequest() || d.GetPresence() != resourcev1.Presence_PRESENCE_ABSENT {
				return errors.New("packageprovider: hidden dependency removal refused")
			}
		} else if err := checkNoDowngrade(entry.GetBefore(), entry.GetAfter()); err != nil {
			return err
		}
	}
	// A bare native name may resolve to another package that provides it;
	// such a transaction never installs the package that was asked for.
	if d.GetPackage().GetArchitecture() == "" && (direct > 1 || (len(entries) != 0 && direct == 0)) {
		return fmt.Errorf("%w: native solver did not select %s itself", ErrConflict, d.GetPackage().GetNativeName())
	}
	return nil
}

// ExecuteNative is called only by the fixed installed helper. beforeEffect is
// the private readiness/permit handshake, not a locally invented authorization.
// It is invoked exactly once after all preflight work and immediately before the
// first native effect. The caller durably marks its one-shot permit consumed.
func ExecuteNative(ctx context.Context, stateDirectory string, request *agentv1.NativePackageTransactionRequest, beforeEffect func(context.Context) error) error {
	if request.GetOperation() != agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_APPLY || beforeEffect == nil {
		return ErrConflict
	}
	p, directory, err := helperProvider(ctx, stateDirectory, request)
	if err != nil {
		return err
	}
	plan, manifest := request.GetPlan(), request.GetManifest()
	if err := resource.ValidatePlan(plan); err != nil {
		return err
	}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		return err
	}
	if plan.GetNativePackage().GetTransactionManifest().GetArtifactId() != request.GetTransactionId() {
		return ErrConflict
	}
	if err := checkArtifact(filepath.Join(directory, "manifest.pb"), plan.GetNativePackage().GetTransactionManifest()); err != nil {
		return err
	}
	prepared, err := readPreparedManifest(directory)
	if err != nil {
		return err
	}
	if !proto.Equal(manifest, prepared) {
		return ErrConflict
	}
	if err := validateCandidatePin(request); err != nil {
		return err
	}
	if err := checkArtifact(p.nativeTransactionPath(directory), manifest.GetNativeTransaction()); err != nil {
		return err
	}
	if err := p.checkStagedSource(directory, request.GetSource(), manifest); err != nil {
		return err
	}
	var dpkgArgs [][]string
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		lock, err := lockDPKGFrontend()
		if err != nil {
			return err
		}
		defer func() { _ = lock.Close() }()
		dpkgArgs, err = dpkgTransactionArgs(directory, request.GetEffectiveDesired(), manifest)
		if err != nil {
			return err
		}
	}
	before, err := p.database(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(before.revision, manifest.GetNativeDatabaseRevision()) || !bytes.Equal(before.revision, request.GetExpectedDatabaseRevision()) {
		return ErrConflict
	}
	if err := p.validateEntries(manifest.GetEntries(), request.GetEffectiveDesired(), before); err != nil {
		return err
	}
	if err := validateEffectiveTarget(request); err != nil {
		return err
	}
	target, err := p.nativeTarget(before, request.GetEffectiveDesired().GetPackage())
	if err != nil {
		return err
	}
	if err := p.checkStagedArtifacts(ctx, directory, request, manifest, before); err != nil {
		return err
	}
	pin, contents, err := readPin(p.pinPath(plan.GetRef()))
	if err != nil {
		return err
	}
	if !proto.Equal(pin, plan.GetBefore().GetNativePackage().GetPinFile()) || !bytes.Equal(contents, plan.GetBefore().GetNativePackage().GetPinContents()) {
		return ErrConflict
	}
	if err := reserveSpace(directory, 64<<20); err != nil {
		return err
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		return p.executeALPM(ctx, directory, request, beforeEffect)
	}
	if err := beforeEffect(ctx); err != nil {
		return err
	}
	if !p.rolling() && p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		if err := p.applyPin(plan); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if len(manifest.GetEntries()) != 0 {
		if p.rolling() {
			err = p.commitZypper(ctx, directory, request.GetEffectiveDesired(), target, manifest.GetEntries())
		} else if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
			for _, args := range dpkgArgs {
				if _, err = commitNative(ctx, "/usr/bin/dpkg", args, "/", []string{"DPKG_FRONTEND_LOCKED=true"}); err != nil {
					break
				}
			}
		} else if p.manager == dnf.DNF4 {
			_, err = p.dnf4(ctx, "apply", directory, p.versionlock)
		} else {
			_, err = commitNative(ctx, p.managerPath, p.dnfArgs(directory, []string{"--cacheonly", "replay", filepath.Join(directory, "transaction")}), "/", nil)
		}
		if err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if p.rolling() || p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		if err := p.applyPin(plan); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	after, err := p.database(ctx)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if err := transactionMatchesDatabase(manifest, before, after); err != nil {
		return err
	}
	return nil
}

func validateCandidatePin(request *agentv1.NativePackageTransactionRequest) error {
	manifest := request.GetManifest()
	if !proto.Equal(manifest.GetOriginalPin(), request.GetOriginalPin()) || !bytes.Equal(manifest.GetCandidatePinSha256(), request.GetCandidatePinSha256()) {
		return ErrConflict
	}
	if request.GetOriginalPin() != nil {
		digest := sha256.Sum256(request.GetCandidatePinContents())
		plan := request.GetPlan()
		if !bytes.Equal(digest[:], manifest.GetCandidatePinSha256()) || !bytes.Equal(request.GetCandidatePinContents(), pinProjection(plan.GetBackend().GetBackend(), plan.GetNativePackage().GetPinContents())) {
			return ErrConflict
		}
	}
	return nil
}

func (p *Provider) checkStagedSource(directory string, source *agentv1.NativePackageSource, manifest *resourcev1.PackageTransactionManifest) error {
	if err := checkSource(source); err != nil {
		return err
	}
	if config.HasEntitledLocation(source.GetRepository().GetRpm()) {
		expected, err := entitledRepositoryConfig(source, filepath.Join(directory, "signing-key.asc"))
		if err != nil {
			return err
		}
		staged, err := custody.ReadRoot(filepath.Join(directory, "repos", "approved.repo"), 1<<20, false)
		if err != nil || !bytes.Equal(staged, []byte(expected)) {
			return errors.New("packageprovider: entitled repository state changed")
		}
	}
	name := "lists"
	if p.rolling() || p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		name = "cache"
	}
	metadata, err := snapshotDirectory(filepath.Join(directory, name))
	if err != nil {
		return err
	}
	metadata, err = boundSourceRevision(source, metadata)
	if err != nil {
		return err
	}
	snapshots := manifest.GetSources().GetRepositories().GetRepositories()
	if len(snapshots) != 1 || !proto.Equal(snapshots[0].GetRepository(), sourceRef(source)) || !bytes.Equal(snapshots[0].GetMetadataSha256(), metadata) {
		return errors.New("packageprovider: source snapshot changed")
	}
	return nil
}
func validateEffectiveTarget(request *agentv1.NativePackageTransactionRequest) error {
	plan := request.GetPlan()
	effective := request.GetEffectiveDesired()
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		desired := proto.CloneOf(plan.GetNativePackage().GetDesired())
		if desired.GetAny() != nil && plan.GetBefore().GetNativePackage().GetInstalled() && desired.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			desired.Version = &resourcev1.NativePackageDesired_Exact{Exact: proto.CloneOf(plan.GetBefore().GetNativePackage().GetRecord().GetVersion())}
		}
		if !proto.Equal(desired, effective) {
			return ErrConflict
		}
		return nil
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(effective)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.package.release.v1\x00"))
	_, _ = fmt.Fprintf(h, "%d:", len(encoded))
	_, _ = h.Write(encoded)
	_, _ = h.Write(plan.GetNativePackage().GetPinContents())
	if !bytes.Equal(h.Sum(nil), plan.GetNativePackage().GetInverse().GetInverseSha256()) {
		return ErrConflict
	}
	return nil
}
func (p *Provider) checkStagedArtifacts(ctx context.Context, directory string, request *agentv1.NativePackageTransactionRequest, manifest *resourcev1.PackageTransactionManifest, before *database) error {
	if p.rolling() {
		return p.checkRollingArtifacts(ctx, directory, request, manifest)
	}
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		data, err := custody.ReadRoot(p.nativeTransactionPath(directory), 4<<20, false)
		if err != nil {
			return err
		}
		transaction, err := parseDNFTransaction(data)
		if err != nil {
			return err
		}
		snapshot := manifest.GetSources().GetRepositories().GetRepositories()[0]
		entries, err := p.dnfEntries(ctx, directory, transaction, request.GetEffectiveDesired(), before, request.GetSource(), snapshot)
		if err != nil {
			return err
		}
		if !proto.Equal(&resourcev1.PackageTransactionManifest{Entries: entries}, &resourcev1.PackageTransactionManifest{Entries: manifest.GetEntries()}) {
			return ErrConflict
		}
		if p.manager == dnf.DNF4 && len(transaction.RPMs) != 0 {
			// The staged bundle must replay to the identical transaction from
			// local packages alone before authority is consumed. The original
			// lock list is unchanged since staging resolved against its
			// candidate, which is applied only after the permit.
			if _, err := p.dnf4(ctx, "check", directory, false); err != nil {
				return fmt.Errorf("packageprovider: staged DNF4 transaction no longer replays: %w", err)
			}
		}
		return nil
	}
	files, err := os.ReadDir(filepath.Join(directory, "archives"))
	if err != nil {
		return err
	}
	found := make(map[string]bool)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".deb") {
			continue
		}
		path := filepath.Join(directory, "archives", file.Name())
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		matched := false
		for _, entry := range manifest.GetEntries() {
			if entry.GetArtifact() != nil && bytes.Equal(entry.GetArtifact().GetSha256(), digest) && entry.GetArtifact().GetSizeBytes() == size {
				key := packageKey(entry.GetPackage())
				if found[key] {
					return ErrConflict
				}
				found[key] = true
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("packageprovider: unmanifested staged package")
		}
	}
	if len(found) != countInbound(manifest.GetEntries()) {
		return errors.New("packageprovider: missing staged package")
	}
	// Simulation never fetches; --no-download would instead demand archives under
	// APT's native file names, while staged artifacts are digest-named.
	target, err := p.nativeTarget(before, request.GetEffectiveDesired().GetPackage())
	if err != nil {
		return err
	}
	result, err := p.apt(ctx, directory, "/usr/bin/apt-get", append([]string{"--simulate"}, aptTransactionArgs(request.GetEffectiveDesired(), target)...))
	if err != nil {
		return err
	}
	changes, err := parseAPTSimulation(result.stdout)
	if err != nil {
		return err
	}
	if len(changes) != len(manifest.GetEntries()) {
		return ErrConflict
	}
	for _, change := range changes {
		matched := false
		for _, entry := range manifest.GetEntries() {
			if entry.GetPackage().GetNativeName() != change.name {
				continue
			}
			if change.remove {
				matched = entry.GetAfter() == nil && entry.GetBefore().GetDeb() == change.version
			} else {
				matched = entry.GetAfter().GetDeb() == change.version && entry.GetPackage().GetArchitecture() == change.architecture
			}
			if matched {
				break
			}
		}
		if !matched {
			return ErrConflict
		}
	}
	return nil
}
