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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

// RHELServerDependenciesOptions requires private entitlement custody and an
// actual matching guest helper. The command's existing VM admission queue owns
// the slot; this function creates at most one fresh guest at a time.
type RHELServerDependenciesOptions struct {
	CacheDir, WorkDir, DependencyCache, LabBinary, RedHatTokenFile, Custody string
	Packages                                                                []string
	MaxBytes                                                                uint64
	MaxPackages                                                             uint32
	Hardware                                                                *VMHardwareOptions
}

const rpmServerDepsGuestRoot = "/var/tmp/lindm-serverdeps-rpm/repository"

// CaptureRHELServerDependencies performs authenticated native acquisition and a
// separate fresh-baseline offline replay. Neither phase uses a prepared golden,
// installs capture tooling from a fallback repo, or changes the lab host's RPM
// state. A failed replay or owned RHSM cleanup cannot publish a closure.
func CaptureRHELServerDependencies(ctx context.Context, image *labv1.ImageManifest, o RHELServerDependenciesOptions) (_ *serverdepsv1.Manifest, err error) {
	release := manifestRelease(image)
	if release.LabLaneOn(platform.LaneDeploy, image.GetArchitecture()) != nil || release.Packages.Backend.PackageDB() != platform.PackageDBRPM || image.GetArchitecture() != "x86_64" || image.GetVersion() == release.Version.Value {
		return nil, errors.New("RHEL server dependencies require an authenticated RHEL 9 x86_64 image")
	}
	if o.RedHatTokenFile == "" || o.LabBinary == "" || o.DependencyCache == "" || (o.Custody != "development-lab" && o.Custody != "entitled-customer-private") {
		return nil, errors.New("RHEL server dependency capture requires protected token file, guest lab binary, private store and explicit entitlement custody")
	}
	if len(o.Packages) == 0 || len(o.Packages) > 5000 || o.MaxBytes == 0 || o.MaxBytes > 16<<30 || o.MaxPackages == 0 || o.MaxPackages > 5000 {
		return nil, errors.New("RHEL server dependency capture requires explicit bounded native solver inputs")
	}
	for _, pkg := range o.Packages {
		if !validSnapshotSolverInput(pkg) {
			return nil, errors.New("invalid RHEL server dependency package input")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	if err := os.MkdirAll(o.DependencyCache, 0700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(o.DependencyCache, ".serverdeps-rhel-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	repository := filepath.Join(stage, "repository")
	if err := os.Mkdir(repository, 0700); err != nil {
		return nil, err
	}
	input := &serverdepsv1.Manifest{Distribution: image.GetDistribution(), Version: release.Version.Value, Architecture: "amd64", Backend: serverdepsv1.Backend_BACKEND_RPM, BaseImageSha256: image.GetSha256(), RequestedPackages: slices.Clone(o.Packages), MaxBytes: o.MaxBytes, MaxPackages: o.MaxPackages, Custody: o.Custody}
	registration := new(VMRedHatEvidence)
	captured, err := acquireRHELServerDependencies(ctx, image, o, input, repository, registration)
	if err != nil {
		return nil, err
	}
	if !registration.Registered || !registration.IdentityObserved || !registration.RepositoryMetadataRefreshed || !registration.Unregistered || !registration.ActivationKeyDeleted {
		return nil, errors.New("RHEL server dependency acquisition lacks complete owned registration and cleanup evidence")
	}
	replayed, runtime, err := replayRHELServerDependencies(ctx, image, o, captured, repository)
	if err != nil {
		return nil, err
	}
	evidence, err := json.Marshal(struct {
		Image        string             `json:"base_image_sha256"`
		Registration *VMRedHatEvidence  `json:"redhat"`
		Runtime      *vmRuntimeEvidence `json:"offline_replay_runtime"`
		Egress       string             `json:"offline_replay_external_egress"`
	}{image.GetSha256(), registration, runtime, "denied-by-restricted-QEMU-user-network; native-transaction-empty-network-namespace"})
	if err != nil {
		return nil, err
	}
	name := "evidence/vm-custody.json"
	if err := os.WriteFile(filepath.Join(repository, name), evidence, 0400); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(evidence)
	replayed.Files = append(replayed.Files, &serverdepsv1.File{Path: name, Sha256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(evidence)), Kind: serverdepsv1.FileKind_FILE_KIND_EVIDENCE})
	replayed.TotalBytes += uint64(len(evidence))
	slices.SortFunc(replayed.Files, func(a, b *serverdepsv1.File) int { return strings.Compare(a.Path, b.Path) })
	published, _, err := serverdeps.Publish(ctx, o.DependencyCache, stage, replayed)
	return published, err
}

func newRHELDependencyGuest(ctx context.Context, image *labv1.ImageManifest, o RHELServerDependenciesOptions, connected bool) (_ *guestVM, err error) {
	hardware := VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm"}
	if o.Hardware != nil {
		hardware = *o.Hardware
	}
	hardware.AllowNetwork = connected
	vm, _, err := newVerifiedGuestWithHardware(ctx, image, o.CacheDir, o.WorkDir, false, &hardware)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, vm.close())
		}
	}()
	vm.captureDiagnostics = false
	if err := vm.connect(ctx); err != nil {
		return nil, fmt.Errorf("RHEL dependency guest SSH readiness: %w", err)
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait", nil, 64<<10, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("RHEL dependency guest cloud-init readiness: %w", err)
	}
	return vm, nil
}

func acquireRHELServerDependencies(ctx context.Context, image *labv1.ImageManifest, o RHELServerDependenciesOptions, input *serverdepsv1.Manifest, repository string, evidence *VMRedHatEvidence) (_ *serverdepsv1.Manifest, err error) {
	vm, err := newRHELDependencyGuest(ctx, image, o, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	registration, err := registerConsoleEnrollmentRedHat(ctx, vm, VMConsoleEnrollmentOptions{LabBinary: o.LabBinary, RedHatTokenFile: o.RedHatTokenFile}, evidence)
	if err != nil {
		return nil, fmt.Errorf("RHEL dependency guest RHSM registration: %w", err)
	}
	defer func() { err = errors.Join(err, releaseConsoleEnrollmentRedHat(ctx, vm, o.LabBinary, registration)) }()
	if err := uploadLifecycleProbe(ctx, vm, o.LabBinary); err != nil {
		return nil, fmt.Errorf("RHEL dependency guest capture probe upload: %w", err)
	}
	manifest, err := runRHELDependenciesGuest(ctx, vm, "serverdeps-rpm-capture", input)
	if err != nil {
		return nil, err
	}
	if manifest.GetTotalBytes() > o.MaxBytes || manifest.GetPackageCount() > o.MaxPackages || len(manifest.GetFiles()) > 5256 {
		return nil, errors.New("RHEL guest dependency closure exceeds admitted transfer bounds")
	}
	var total uint64
	for _, item := range manifest.GetFiles() {
		if item.GetSizeBytes() == 0 || item.GetSizeBytes() > o.MaxBytes-total {
			return nil, errors.New("RHEL guest dependency transfer exceeds admitted byte bound")
		}
		total += item.GetSizeBytes()
	}
	if total != manifest.GetTotalBytes() {
		return nil, errors.New("RHEL guest dependency transfer differs from manifest total")
	}
	for _, item := range manifest.GetFiles() {
		if err := receiveRHELDependencyFile(ctx, vm, repository, item); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func replayRHELServerDependencies(ctx context.Context, image *labv1.ImageManifest, o RHELServerDependenciesOptions, captured *serverdepsv1.Manifest, repository string) (_ *serverdepsv1.Manifest, _ *vmRuntimeEvidence, err error) {
	vm, err := newRHELDependencyGuest(ctx, image, o, false)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	if err := lifecycleCommand(ctx, vm, "stage offline dependency probe", "install -d -m 0755 "+nativeGuestDir+"; install -d -m 0700 "+rpmServerDepsGuestRoot); err != nil {
		return nil, nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, o.LabBinary); err != nil {
		return nil, nil, err
	}
	root, err := os.Open(repository)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	for _, item := range captured.GetFiles() {
		if err := serverdeps.CheckRetained(root, item); err != nil {
			return nil, nil, err
		}
		file, err := serverdeps.OpenRetained(root, item)
		if err != nil {
			return nil, nil, err
		}
		destination := rpmServerDepsGuestRoot + "/" + item.GetPath()
		command := "set -eu; umask 077; install -d -m 0700 " + nativeQuote(filepath.Dir(destination)) + "; cat > " + nativeQuote(destination) + "; printf '%s  %s\\n' " + nativeQuote(item.GetSha256()) + " " + nativeQuote(destination) + " | sha256sum --check --status"
		_, transferErr := vm.run(ctx, "sudo -n sh -c "+nativeQuote(command), io.LimitReader(file, int64(item.GetSizeBytes())+1), 4096, 5*time.Minute)
		if err := errors.Join(transferErr, file.Close()); err != nil {
			return nil, nil, err
		}
	}
	replayed, err := runRHELDependenciesGuest(ctx, vm, "serverdeps-rpm-replay", captured)
	if err != nil {
		return nil, nil, err
	}
	var replayFile *serverdepsv1.File
	for _, item := range replayed.GetFiles() {
		if item.GetPath() == replayed.GetReplayEvidencePath() {
			replayFile = item
		}
	}
	if replayFile == nil || replayFile.GetKind() != serverdepsv1.FileKind_FILE_KIND_EVIDENCE {
		return nil, nil, errors.New("RHEL native replay produced no retained evidence")
	}
	if err := receiveRHELDependencyFile(ctx, vm, repository, replayFile); err != nil {
		return nil, nil, err
	}
	runtime, err := vm.runtimeEvidence(ctx)
	return replayed, runtime, err
}

func runRHELDependenciesGuest(ctx context.Context, vm *guestVM, operation string, input *serverdepsv1.Manifest) (*serverdepsv1.Manifest, error) {
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(input)
	if err != nil {
		return nil, err
	}
	result, err := vm.runResult(ctx, "sudo -n "+guestLifecycleProbe+" guest "+operation, bytes.NewReader(payload), 8<<20, 35*time.Minute)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil {
		return nil, fmt.Errorf("RHEL dependency guest %s transport: %w", operation, err)
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		return nil, fmt.Errorf("RHEL dependency guest %s failed (%s)", operation, rpmDependencyGuestFailure(result.Stderr))
	}
	manifest := new(serverdepsv1.Manifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(result.Stdout, manifest); err != nil {
		return nil, errors.New("RHEL dependency guest emitted invalid bounded manifest")
	}
	return manifest, nil
}

func rpmDependencyGuestFailure(stderr []byte) string {
	message := string(bytes.TrimSuffix(stderr, []byte("\n")))
	if stage, ok := strings.CutPrefix(message, "lab: serverdeps: RPM capture failed at "); ok {
		if stage, ok := strings.CutSuffix(stage, " (native diagnostics suppressed)"); ok && serverdeps.RPMCaptureStageKnown(stage) {
			return "native RPM capture stage " + stage + " failed; diagnostics suppressed"
		}
	}
	for _, program := range []string{"/usr/bin/python3", "/usr/bin/python3.9", "/usr/bin/rpmkeys", "/usr/bin/rpm", "/usr/bin/unshare"} {
		for _, status := range []string{"1", "2", "127"} {
			if message == "lab: serverdeps: native "+program+" operation failed (native diagnostics suppressed): exit status "+status {
				return "native " + program + " operation failed; diagnostics suppressed"
			}
		}
	}
	return "native operation failed; unrecognized diagnostics suppressed"
}

func receiveRHELDependencyFile(ctx context.Context, vm *guestVM, repository string, item *serverdepsv1.File) (err error) {
	// This untrusted guest path is a bounded allowlist member, never an archive
	// pathname. The staging tree was just created by this controller.
	name := item.GetPath()
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(name, "\\") || strings.HasPrefix(name, "../") || name == ".." || item.GetSizeBytes() == 0 || item.GetSizeBytes() > 16<<30 {
		return errors.New("unsafe RHEL dependency transfer path or size")
	}
	path := filepath.Join(repository, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := vm.client
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	hash := sha256.New()
	bounded := &rpmDependencySink{Writer: io.MultiWriter(file, hash), Remaining: item.GetSizeBytes()}
	session.Stdout, session.Stderr = bounded, io.Discard
	if err := session.Run("sudo -n cat -- " + nativeQuote(rpmServerDepsGuestRoot+"/"+name)); err != nil {
		return fmt.Errorf("stream RHEL dependency file: %w", err)
	}
	if ctx.Err() != nil || bounded.Remaining != 0 || hex.EncodeToString(hash.Sum(nil)) != item.GetSha256() {
		return errors.New("RHEL dependency transfer differs from exact native capture digest")
	}
	return file.Sync()
}

type rpmDependencySink struct {
	Writer    io.Writer
	Remaining uint64
}

func (w *rpmDependencySink) Write(data []byte) (int, error) {
	if uint64(len(data)) > w.Remaining {
		return 0, errors.New("RHEL dependency stream exceeds manifest size")
	}
	n, err := w.Writer.Write(data)
	w.Remaining -= uint64(n)
	return n, err
}
