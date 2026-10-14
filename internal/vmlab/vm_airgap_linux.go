// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	bundlev1 "lindm/gen/lindm/bundle/v1"
	configv1 "lindm/gen/lindm/config/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	"lindm/internal/devlab"
	"lindm/internal/offlinebundle"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const airgapGuestDir = nativeGuestDir + "/airgap"

var manifestSequence = regexp.MustCompile(`("sequence":\s*")`)

// VMAirgapOptions runs one isolated site lane. The caller must already share
// NetworkContainer's loopback-only network namespace (see `lab vm airgap`).
// Every authority is station-provided and out of band; no key is generated.
type VMAirgapOptions struct {
	Repository, CacheDir, WorkDir, LabBinary, ServerBinary, DiagnosticsDir string
	NetworkContainer                                                       string
	FirstBundle, SecondBundle                                              string
	// ExpiredBundle and ReplayBundle are optional signed negative inputs: an
	// expired bundle, and a valid sequence between First and Second that is
	// offered only after Second is admitted.
	ExpiredBundle, ReplayBundle          string
	BundlePublicKey, BundleKeyID         string
	ReleasePublicKey, ReleaseKeyID       string
	ReleaseRoot, ReleaseOnlineCustody    string
	PackagePublicKey, PackageFingerprint string
	Advisories                           string
	Hardware                             *VMHardwareOptions
}

// VMAirgapImport is the nonsecret outcome of one operator import attempt.
type VMAirgapImport struct {
	Name              string                `json:"name"`
	ManifestSHA256    string                `json:"manifest_sha256,omitempty"`
	Accepted          bool                  `json:"accepted"`
	Result            *offlinebundle.Result `json:"result,omitempty"`
	Rejection         string                `json:"rejection,omitempty"`
	ExpectedRejection string                `json:"expected_rejection,omitempty"`
}

// VMAirgapFindings records device advisory freshness bound to a bundle.
type VMAirgapFindings struct {
	FeedID        string    `json:"feed_id"`
	FeedCheckedAt time.Time `json:"feed_checked_at"`
	FeedExpiresAt time.Time `json:"feed_expires_at"`
	SourceSHA256  string    `json:"source_sha256"`
	State         string    `json:"state"`
	Reason        string    `json:"reason,omitempty"`
	Findings      int       `json:"findings"`
	Affected      int       `json:"affected"`
	// Uncovered counts packages a derivative's partial evaluation leaves
	// UNKNOWN (no feed covers their verified origin).
	Uncovered uint64 `json:"uncovered_packages,omitempty"`
	// Truncated means the 20,000-finding read bound was reached; counts are
	// then lower bounds.
	Truncated bool `json:"truncated"`
}

type VMAirgapResult struct {
	ImageID              string                 `json:"image_id"`
	ImageSHA256          string                 `json:"image_sha256"`
	LabSHA256            string                 `json:"lab_sha256"`
	ServerSHA256         string                 `json:"server_sha256"`
	NetworkContainer     string                 `json:"network_container"`
	ServerEgress         *devlab.EgressEvidence `json:"server_egress"`
	GuestEgress          string                 `json:"guest_egress"`
	Runtime              *vmRuntimeEvidence     `json:"runtime"`
	SELinux              string                 `json:"selinux"`
	FirstVersion         string                 `json:"first_version"`
	SecondVersion        string                 `json:"second_version"`
	Imports              []VMAirgapImport       `json:"imports"`
	DeviceID             string                 `json:"device_id"`
	EnrollmentGeneration string                 `json:"enrollment_generation"`
	InitialInventory     *vmInventoryEvidence   `json:"initial_inventory"`
	FinalInventory       *vmInventoryEvidence   `json:"final_inventory"`
	InitialFindings      *VMAirgapFindings      `json:"initial_findings"`
	RefreshedFindings    *VMAirgapFindings      `json:"refreshed_findings"`
	FeedStatus           json.RawMessage        `json:"feed_status,omitempty"`
	Steps                []VMUpdateStep         `json:"steps"`
	StartedAt            time.Time              `json:"started_at"`
	FinishedAt           time.Time              `json:"finished_at"`
	Passed               bool                   `json:"passed"`
	Outcome              string                 `json:"outcome"`
	Failure              string                 `json:"failure,omitempty"`
}

// AirgapVM qualifies offline operation for one guest: the site server imports
// a signed bundle before serving, the guest installs the agent only from the
// server-served signed repository, enrolls, then a second bundle stages a
// newer agent and advisory snapshot; replayed and tampered imports fail.
func AirgapVM(ctx context.Context, manifest *labv1.ImageManifest, options VMAirgapOptions) (result *VMAirgapResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	distribution := manifest.GetDistribution()
	release := manifestRelease(manifest)
	if err := release.LabLaneOn(platform.LaneAirgap, manifest.GetArchitecture()); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Minute)
	defer cancel()
	result = &VMAirgapResult{ImageID: manifest.GetId(), NetworkContainer: options.NetworkContainer, StartedAt: time.Now().UTC()}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if err != nil {
			result.Outcome, result.Failure = "failed", err.Error()
		} else {
			result.Outcome, result.Passed = "passed", true
		}
	}()
	// The isolation claim is observed before any server, database or guest
	// starts, from the namespace they all share.
	result.ServerEgress, err = devlab.ObserveEgress(ctx)
	if err != nil {
		return result, fmt.Errorf("site namespace is not isolated: %w", err)
	}
	first, err := readBundleClaims(options.FirstBundle)
	if err != nil {
		return result, err
	}
	second, err := readBundleClaims(options.SecondBundle)
	if err != nil {
		return result, err
	}
	result.FirstVersion, result.SecondVersion = first.GetRelease().GetVersion(), second.GetRelease().GetVersion()
	if result.LabSHA256, err = dispatchFileDigest(options.LabBinary); err != nil {
		return result, err
	}
	if result.ServerSHA256, err = dispatchFileDigest(options.ServerBinary); err != nil {
		return result, err
	}
	root, err := os.ReadFile(options.ReleaseRoot)
	if err != nil {
		return result, err
	}
	advisoryData, err := os.ReadFile(options.Advisories)
	if err != nil {
		return result, err
	}
	advisories := new(configv1.AdvisoryConfig)
	if err := protojson.Unmarshal(advisoryData, advisories); err != nil {
		return result, fmt.Errorf("advisory configuration: %w", err)
	}
	keyArmor, err := pinnedPackageKey(ctx, options.PackagePublicKey, options.PackageFingerprint, options.WorkDir)
	if err != nil {
		return result, err
	}
	// rejection is empty for an import that must succeed, otherwise the exact
	// reason the server must report; a rejection for any other cause fails.
	importBundle := func(ctx context.Context, run func(context.Context, ...string) ([]byte, error), name, directory, rejection string) (*offlinebundle.Result, error) {
		record := VMAirgapImport{Name: name, ExpectedRejection: rejection}
		if claims, err := readBundleClaims(directory); err == nil {
			record.ManifestSHA256 = claims.manifestSHA256
		}
		output, runErr := run(ctx, "bundle-import", "-bundle", directory)
		if runErr == nil {
			record.Accepted = true
			record.Result = new(offlinebundle.Result)
			if err := json.Unmarshal(output, record.Result); err != nil {
				return nil, fmt.Errorf("decode import result: %w", err)
			}
		} else {
			record.Rejection = runErr.Error()
		}
		result.Imports = append(result.Imports, record)
		if record.Accepted != (rejection == "") || (rejection != "" && !strings.Contains(record.Rejection, rejection)) {
			return nil, fmt.Errorf("import %s: accepted=%t, expected rejection %q: %v", name, record.Accepted, rejection, runErr)
		}
		return record.Result, nil
	}
	fixture, err := devlab.OpenAirgapAuthorityFixture(ctx, options.Repository, options.ServerBinary, devlab.AirgapAuthorityOptions{
		NetworkContainer: options.NetworkContainer, ReleaseRoot: root, ReleaseOnlineCustody: options.ReleaseOnlineCustody,
		OfflineBundles: &configv1.OfflineBundleConfig{SigningPublicKeyFile: options.BundlePublicKey, SigningKeyId: options.BundleKeyID, ReleaseAttestationPublicKeyFile: options.ReleasePublicKey, ReleaseAttestationKeyId: options.ReleaseKeyID, Directory: "replaced-by-fixture"},
		Advisories:     advisories,
		BeforeStart: func(ctx context.Context, run func(context.Context, ...string) ([]byte, error)) error {
			_, err := importBundle(ctx, run, "first bundle initializes the empty site before serve", options.FirstBundle, "")
			return err
		},
	})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	if result.Imports[0].Result.Updates == nil || len(result.Imports[0].Result.Updates.Channels) != 1 {
		return result, errors.New("first import did not stage exactly one paused channel")
	}
	for _, version := range []string{result.FirstVersion, result.SecondVersion} {
		if err := fixture.RegisterRelease(ctx, version); err != nil {
			return result, err
		}
	}
	delegation, err := fixture.ConfigureServiceDispatch(ctx)
	if err != nil {
		return result, err
	}
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, true, options.Hardware)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	vm.captureDiagnostics = options.DiagnosticsDir != ""
	defer func() {
		if err != nil && options.DiagnosticsDir != "" {
			err = errors.Join(err, saveUpdateFailure(ctx, vm, options.DiagnosticsDir))
		}
	}()
	result.ImageSHA256 = verified.SHA256
	if err := vm.connect(ctx); err != nil {
		return result, err
	}
	if result.Runtime, err = vm.runtimeEvidence(ctx); err != nil {
		return result, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return result, err
	}
	result.SELinux = "not applicable"
	if backend, _ := nativeBackend(release); backend.DNF() {
		mode, err := vm.run(ctx, "getenforce", nil, 128, 10*time.Second)
		if err != nil {
			return result, err
		}
		if result.SELinux = strings.TrimSpace(string(mode)); result.SELinux != "Enforcing" {
			return result, errors.New("DNF air-gap lane requires SELinux Enforcing")
		}
	}
	// Prove the guest itself has no external path before it is given only the
	// forwarded site listeners. Each probe is bounded: Arch's systemd-resolved
	// kept retrying unreachable DNS past the whole operation deadline.
	egress, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote("ip -o route show; ip -o -6 route show; if timeout 15 getent ahosts deb.debian.org; then echo dns-resolved; exit 3; fi; if timeout 8 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'; then echo tcp-connected; exit 4; fi; echo public-dns-and-tcp-failed"), nil, 64<<10, time.Minute)
	if err != nil {
		return result, err
	}
	result.GuestEgress = strings.TrimSpace(string(egress.Stdout))
	if egress.ExitCode != 0 {
		return result, fmt.Errorf("guest reached a public destination (exit %d)", egress.ExitCode)
	}
	if err := lifecycleCommand(ctx, vm, "prepare air-gap guest", "test ! -e "+nativeGuestDir+"; install -d -m 0755 "+nativeGuestDir+" "+airgapGuestDir+" "+airgapGuestDir+"/empty "+airgapGuestDir+"/lists "+airgapGuestDir+"/archives "+airgapGuestDir+"/repos"); err != nil {
		return result, err
	}
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return result, err
	}
	caPEM, err := os.ReadFile(filepath.Join(devlab.FixturePath(options.Repository), "transport-ca.crt"))
	if err != nil {
		return result, err
	}
	backend, err := nativeBackend(release)
	if err != nil {
		return result, err
	}
	guest := &nativeGuestPackages{vm: vm, backend: backend}
	for path, data := range map[string][]byte{airgapGuestDir + "/signer.asc": keyArmor, airgapGuestDir + "/site-ca.crt": caPEM} {
		if err := guest.uploadBytes(ctx, path, data); err != nil {
			return result, err
		}
	}
	forwards, err := openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, closeLifecycleForwards(forwards)) }()
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	if err := control.applyExecutionAuthority(ctx, delegation, 1, 1, 0); err != nil {
		return result, err
	}
	architecture := map[string]string{"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[manifest.GetArchitecture()]
	if err := installOfflineAgent(ctx, guest, architecture, result.FirstVersion, options.PackageFingerprint); err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "agent " + result.FirstVersion + " installed only from the site-served signed " + distribution + " repository"})
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return result, err
	}
	material, err := control.BootstrapMaterial(ctx)
	if err != nil {
		return result, err
	}
	issued, err := interruptBootstrap(ctx, vm, material)
	clear(material.GrantSecret)
	material.GrantSecret = nil
	if err != nil {
		return result, err
	}
	if err := control.TrackDevice(issued.GetDeviceId()); err != nil {
		return result, err
	}
	if err := lifecycleCommand(ctx, vm, "resume offline enrollment", packaging.BinaryPath+" resume"); err != nil {
		return result, err
	}
	result.DeviceID, result.EnrollmentGeneration = issued.GetDeviceId(), issued.GetEnrollmentGeneration()
	if err := enableGuestUpdates(ctx, vm, guest); err != nil {
		return result, err
	}
	status, err := waitUpdateObservation(ctx, vm, nil, "no_update")
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "imported channel is staged paused; enrolled agent holds " + result.FirstVersion, Status: status})
	if result.InitialInventory, err = waitLifecycleInventory(ctx, vm, control, release, result.DeviceID, nil); err != nil {
		return result, err
	}
	initialIdentity, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return result, err
	}
	// A derivative is evaluated through its base's bundled feed and must stay
	// partial with its verified-origin reason (vendor packages uncovered).
	feedID, feedDistro, originReason := "", advisoryFeedRow(release).ID, advisoryOriginReason(release)
	for _, snapshot := range first.GetAdvisories() {
		if snapshot.GetSource().GetDistro() == feedDistro {
			feedID = snapshot.GetSource().GetId()
		}
	}
	if feedID == "" {
		return result, errors.New("first bundle has no advisory snapshot for the guest's feed distribution")
	}
	if result.InitialFindings, err = waitDeviceFindings(ctx, control, result.DeviceID, feedID, first.acquiredAt(feedID), originReason); err != nil {
		return result, err
	}
	// Negative imports run against the live server before the genuine update.
	if _, err := importBundle(ctx, fixture.RunServerCommand, "identical first bundle resubmitted after admission is a no-op", options.FirstBundle, ""); err != nil {
		return result, err
	}
	if !result.Imports[len(result.Imports)-1].Result.AlreadyImported {
		return result, errors.New("identical first bundle was not recognized as already imported")
	}
	if options.ExpiredBundle != "" {
		if _, err := importBundle(ctx, fixture.RunServerCommand, "expired signed bundle", options.ExpiredBundle, offlinebundle.ErrExpired.Error()); err != nil {
			return result, err
		}
	}
	tampered, err := tamperedCopy(options.SecondBundle, options.WorkDir, "content")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(filepath.Dir(tampered))) }()
	if _, err := importBundle(ctx, fixture.RunServerCommand, "second bundle with one modified repository byte", tampered, offlinebundle.ErrCorrupt.Error()); err != nil {
		return result, err
	}
	forged, err := tamperedCopy(options.SecondBundle, options.WorkDir, "manifest")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(filepath.Dir(forged))) }()
	if _, err := importBundle(ctx, fixture.RunServerCommand, "second bundle with an unsigned manifest edit", forged, "manifest differs from its signed payload"); err != nil {
		return result, err
	}
	imported, err := importBundle(ctx, fixture.RunServerCommand, "genuine second bundle resumes the admitted sequence", options.SecondBundle, "")
	if err != nil {
		return result, err
	}
	if imported.Updates == nil || len(imported.Updates.Channels) != 1 || !imported.Updates.Channels[0].GetPaused() {
		return result, errors.New("second import did not stage one paused channel")
	}
	if options.ReplayBundle != "" {
		if _, err := importBundle(ctx, fixture.RunServerCommand, "valid never-imported older sequence after a newer admission", options.ReplayBundle, offlinebundle.ErrReplayed.Error()); err != nil {
			return result, err
		}
	}
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "second bundle staged " + result.SecondVersion + " paused; agent still holds " + result.FirstVersion, Status: status})
	if result.RefreshedFindings, err = waitDeviceFindings(ctx, control, result.DeviceID, feedID, second.acquiredAt(feedID), originReason); err != nil {
		return result, err
	}
	channel := imported.Updates.Channels[0]
	if _, err := fixture.SetRollout(ctx, &releasemanagementv1.SetRolloutRequest{RequestId: uuid.NewString(), Ring: channel.GetRing(), Paused: false, EligiblePercentage: 100, ExpectedGeneration: channel.GetGeneration(), Reason: "Air-gap qualification rollout of imported release"}); err != nil {
		return result, err
	}
	status, err = waitInstalledVersion(ctx, vm, result.SecondVersion)
	if err != nil {
		return result, err
	}
	if err := assertOfflineAgentVersion(ctx, guest, result.SecondVersion); err != nil {
		return result, err
	}
	if err := lifecycleCommand(ctx, vm, "verify updated agent daemons", "systemctl is-active --quiet lindm-executor.service; systemctl is-active --quiet lindm-agent.service"); err != nil {
		return result, err
	}
	identity, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return result, err
	}
	if identity.GetDeviceId() != result.DeviceID || identity.GetEnrollmentGeneration() != result.EnrollmentGeneration {
		return result, errors.New("offline update changed protected enrollment identity")
	}
	if identity.GetCommittedSessionEpoch() <= initialIdentity.GetCommittedSessionEpoch() || !identity.GetSessionEpochUsable() {
		return result, errors.New("updated agent did not acquire an authenticated successor session")
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "audited rollout installed " + result.SecondVersion + " from imported TUF targets with enrollment preserved", Status: status})
	if result.FinalInventory, err = waitLifecycleInventory(ctx, vm, control, release, result.DeviceID, result.InitialInventory); err != nil {
		return result, err
	}
	feeds, err := control.session.Admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		return result, err
	}
	if result.FeedStatus, err = protojson.Marshal(feeds.Msg); err != nil {
		return result, err
	}
	return result, nil
}

type bundleClaims struct {
	*bundlev1.OfflineBundleManifest
	manifestSHA256 string
}

// readBundleClaims reads the lane's expectations from bundle.json. Authority
// comes only from the server's verified import; these are comparison values.
func readBundleClaims(directory string) (*bundleClaims, error) {
	data, err := os.ReadFile(filepath.Join(directory, offlinebundle.ManifestName))
	if err != nil {
		return nil, err
	}
	manifest := new(bundlev1.OfflineBundleManifest)
	if err := protojson.Unmarshal(data, manifest); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return &bundleClaims{OfflineBundleManifest: manifest, manifestSHA256: hex.EncodeToString(digest[:])}, nil
}

func (b *bundleClaims) acquiredAt(feedID string) time.Time {
	for _, snapshot := range b.GetAdvisories() {
		if snapshot.GetSource().GetId() == feedID {
			return snapshot.GetAcquiredAt().AsTime()
		}
	}
	return time.Time{}
}

// tamperedCopy hard-links a bundle into a private directory and replaces one
// file: a same-size single-byte change in signed repository metadata
// ("content") or an unsigned sequence edit of bundle.json ("manifest").
func tamperedCopy(source, work, mode string) (string, error) {
	parent, err := os.MkdirTemp(work, "lindm-airgap-tamper-")
	if err != nil {
		return "", err
	}
	destination := filepath.Join(parent, "bundle")
	if err := linkTree(source, destination); err != nil {
		return "", err
	}
	target := filepath.Join(destination, offlinebundle.ManifestName)
	if mode == "content" {
		matches, err := filepath.Glob(filepath.Join(destination, "repositories", "*", "apt", "dists", "stable", "InRelease"))
		if err != nil || len(matches) == 0 {
			return "", errors.New("no repository metadata to tamper")
		}
		target = matches[0]
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return "", err
	}
	if mode == "manifest" {
		changed := manifestSequence.ReplaceAll(data, []byte(`${1}9`))
		if bytes.Equal(changed, data) {
			return "", errors.New("no manifest sequence to edit")
		}
		data = changed
	} else {
		data[len(data)/2] ^= 0x01
	}
	// Unlink first: the copy shares inodes with the genuine bundle.
	if err := os.Remove(target); err != nil {
		return "", err
	}
	return destination, os.WriteFile(target, data, 0644)
}

// linkTree mirrors a bundle with hard links; it never writes shared inodes.
func linkTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if !entry.Type().IsRegular() {
			return errors.New("bundle copy encountered a non-regular file")
		}
		return os.Link(path, target)
	})
}

func pinnedPackageKey(ctx context.Context, path, fingerprint, work string) ([]byte, error) {
	if !nativeFingerprint.MatchString(fingerprint) {
		return nil, errors.New("pinned package fingerprint required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) || len(data) > 1<<20 {
		return nil, errors.New("package public key must be one ASCII-armored public key")
	}
	home, err := os.MkdirTemp(work, "lindm-airgap-key-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	key := filepath.Join(home, "public.asc")
	if err := os.WriteFile(key, data, 0600); err != nil {
		return nil, err
	}
	opened, err := os.Open(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = opened.Close() }()
	listed, err := hostCommand(ctx, home, "gpg", []*os.File{opened}, "--no-options", "--batch", "--homedir", home, "--with-colons", "--show-keys", "/proc/self/fd/3")
	if err != nil {
		return nil, err
	}
	primary, pubs := "", 0
	expecting := false
	for _, line := range strings.Split(string(listed), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}
		switch fields[0] {
		case "sec", "ssb":
			return nil, errors.New("package trust input contains secret keys")
		case "pub":
			pubs++
			expecting = true
		case "fpr":
			if expecting {
				primary, expecting = fields[9], false
			}
		}
	}
	if pubs != 1 || primary != fingerprint {
		return nil, errors.New("package public key does not match pinned fingerprint")
	}
	return data, nil
}

// installOfflineAgent uses only the site server's signed repository through
// the forwarded administrative listener, with the station key pinned locally.
func installOfflineAgent(ctx context.Context, guest *nativeGuestPackages, architecture, version, fingerprint string) error {
	base := "https://localhost:18444/offline/repositories/" + architecture
	switch guest.backend {
	case platform.BackendPacman:
		// As the console's pacman enrollment command, the pinned station key is
		// locally signed into the system keyring: the agent's later pacman -U of
		// the TUF-staged update verifies its detached signature there. The site
		// CA authenticates transport only; database and package signatures are
		// both required, so a byte change anywhere fails before install.
		if err := guest.command(ctx, "trust pinned station key in system pacman keyring", "pacman-key --init; pacman-key --add "+airgapGuestDir+"/signer.asc; pacman-key --lsign-key "+nativeQuote(fingerprint), nil); err != nil {
			return err
		}
		config := "[options]\nArchitecture = auto\nCacheDir = " + airgapGuestDir + "/archives\nSigLevel = PackageRequired DatabaseRequired TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nXferCommand = /usr/bin/curl --fail --silent --show-error --cacert " + airgapGuestDir + "/site-ca.crt --output %o %u\n[lindm]\nServer = " + base + "/arch\n"
		if err := guest.uploadBytes(ctx, airgapGuestDir+"/pacman.conf", []byte(config)); err != nil {
			return err
		}
		if err := guest.command(ctx, "install agent from site pacman repository", "pacman --noconfirm --config "+airgapGuestDir+"/pacman.conf -Syy lindm/"+packaging.PackageName, nil); err != nil {
			return err
		}
	case platform.BackendAPT:
		source := "Types: deb\nURIs: " + base + "/apt/\nSuites: stable\nComponents: main\nSigned-By: " + airgapGuestDir + "/signer.asc\n"
		if err := guest.uploadBytes(ctx, airgapGuestDir+"/offline.sources", []byte(source)); err != nil {
			return err
		}
		apt := "apt-get -q -y -o Dir::Etc::sourcelist=" + airgapGuestDir + "/offline.sources -o Dir::Etc::sourceparts=" + airgapGuestDir + "/empty -o Dir::State::lists=" + airgapGuestDir + "/lists -o Dir::Cache::archives=" + airgapGuestDir + "/archives -o Acquire::https::CAInfo=" + airgapGuestDir + "/site-ca.crt -o Acquire::Retries=0 -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any "
		if err := guest.command(ctx, "authenticate site APT metadata", apt+"update", nil); err != nil {
			return err
		}
		if err := guest.command(ctx, "install agent from site APT repository", apt+"install --no-install-recommends "+nativeQuote(packaging.PackageName+"="+version), nil); err != nil {
			return err
		}
	case platform.BackendZypper:
		// As the console's zypper command: the site CA joins the system trust
		// store and the fingerprint-pinned station key the RPM keyring (libzypp
		// has no per-repository CA file). Only the site repository is
		// configured; the distribution repositories are unreachable here.
		trust := "install -m 0644 " + airgapGuestDir + "/site-ca.crt /etc/pki/trust/anchors/lindm-site.crt; update-ca-certificates; rpm --import " + airgapGuestDir + "/signer.asc"
		if err := guest.command(ctx, "trust site CA and pinned station key", trust, nil); err != nil {
			return err
		}
		repo := "[lindm-offline]\nname=lindm offline bundle\nbaseurl=" + base + "/rpm/\nenabled=1\nautorefresh=0\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\n"
		if err := guest.uploadBytes(ctx, airgapGuestDir+"/repos/lindm-offline.repo", []byte(repo)); err != nil {
			return err
		}
		zypper := "zypper --non-interactive --reposd-dir " + airgapGuestDir + "/repos --cache-dir " + airgapGuestDir + "/zypp-cache "
		if err := guest.command(ctx, "authenticate site zypper metadata", zypper+"refresh --force lindm-offline", nil); err != nil {
			return err
		}
		if err := guest.command(ctx, "install agent from site zypper repository", zypper+"--no-refresh install --no-recommends --from lindm-offline "+nativeQuote(packaging.PackageName+"="+version+"-"+packaging.RPMRelease), nil); err != nil {
			return err
		}
	default:
		repo := "[lindm-offline]\nname=lindm offline bundle\nbaseurl=" + base + "/rpm/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://" + airgapGuestDir + "/signer.asc\nsslverify=1\nsslcacert=" + airgapGuestDir + "/site-ca.crt\n"
		if err := guest.uploadBytes(ctx, airgapGuestDir+"/repos/lindm-offline.repo", []byte(repo)); err != nil {
			return err
		}
		dnf := "dnf -y --setopt=reposdir=" + airgapGuestDir + "/repos --setopt=install_weak_deps=False --setopt=keepcache=False "
		if err := guest.command(ctx, "install agent from site RPM repository", dnf+"install "+nativeQuote(packaging.PackageName+"-"+version), nil); err != nil {
			return err
		}
	}
	return assertOfflineAgentVersion(ctx, guest, version)
}

func assertOfflineAgentVersion(ctx context.Context, guest *nativeGuestPackages, version string) error {
	query, record := "rpm -q --qf '%{VERSION}\\n' lindm-agent", version
	switch guest.backend {
	case platform.BackendAPT:
		query, record = "dpkg-query -W -f='${db:Status-Status} ${Version}\\n' lindm-agent", "installed "+version
	case platform.BackendPacman:
		// pacman reports pkgver-pkgrel; lindm packages use pkgrel 1.
		query, record = "pacman -Q lindm-agent", "lindm-agent "+version+"-1"
	}
	result, err := guest.result(ctx, query+"; "+packaging.BinaryPath+" version", nil)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(result.Stdout)), "\n")
	if result.ExitCode != 0 || len(lines) != 2 || lines[0] != record || !strings.HasSuffix(version, lines[1]) {
		return fmt.Errorf("installed agent is %q, expected %s", strings.TrimSpace(string(result.Stdout)), record)
	}
	return nil
}

func waitInstalledVersion(ctx context.Context, vm *guestVM, version string) (*agentv1.AgentUpdateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last *agentv1.AgentUpdateStatus
	var lastErr error
	for {
		if vm.client == nil {
			lastErr = vm.connect(ctx)
		}
		if vm.client != nil {
			last, lastErr = readUpdateStatus(ctx, vm)
			if lastErr != nil && updateObservationTransportLost(lastErr) {
				_ = vm.client.Close()
				vm.client = nil
			}
		}
		if lastErr == nil && last.GetPhase() == "installed" && last.GetVersion() == version {
			return last, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for installed %s (phase=%s outcome=%s): %w", version, last.GetPhase(), last.GetLastOutcome(), errors.Join(ctx.Err(), lastErr))
		case <-ticker.C:
		}
	}
}

// waitDeviceFindings waits for the device evaluation bound to the feed
// publication acquired at the bundle's signed time; with originReason, that
// evaluation must be a derivative's verified-origin PARTIAL with the reason.
func waitDeviceFindings(ctx context.Context, control *vmControlPlane, deviceID, feedID string, acquired time.Time, originReason string) (*VMAirgapFindings, error) {
	if acquired.IsZero() {
		return nil, errors.New("bundle has no acquisition time for the device feed")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last *VMAirgapFindings
	for {
		findings := &VMAirgapFindings{}
		token := ""
		var freshness *adminv1.AdvisoryFreshness
		var err error
		for range 100 {
			var response *connect.Response[adminv1.ListDeviceFindingsResponse]
			response, err = control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200, PageToken: token}))
			if err != nil {
				break
			}
			freshness = response.Msg.GetFreshness()
			for _, finding := range response.Msg.GetFindings() {
				findings.Findings++
				if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
					findings.Affected++
				}
			}
			if token = response.Msg.GetNextPageToken(); token == "" {
				break
			}
			findings.Truncated = findings.Findings >= 20000
		}
		if err == nil && freshness != nil {
			findings.FeedID, findings.State, findings.Reason, findings.SourceSHA256 = freshness.GetFeedId(), freshness.GetState().String(), freshness.GetReason(), freshness.GetSourceSha256()
			findings.FeedCheckedAt, findings.FeedExpiresAt, findings.Uncovered = freshness.GetFeedCheckedAt().AsTime(), freshness.GetFeedExpiresAt().AsTime(), freshness.GetUncoveredPackages()
			last = findings
			// The state is recorded as evaluated; coverage policy (complete or
			// partial) is the parser's, not this lane's, decision, except that
			// a derivative's base feed is never complete for it.
			bound := findings.FeedID == feedID && findings.FeedCheckedAt.Sub(acquired).Abs() < time.Microsecond
			if bound && (originReason == "" || (findings.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL.String() && findings.Reason == originReason && findings.Uncovered > 0)) {
				return findings, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device findings never bound feed %s acquired %s (last %+v): %w", feedID, acquired.Format(time.RFC3339Nano), last, errors.Join(ctx.Err(), err))
		case <-ticker.C:
		}
	}
}
