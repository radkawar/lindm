// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

// ServerDependenciesOptions bounds a server-only closure and two fresh VM passes.
type ServerDependenciesOptions struct {
	CacheDir, SnapshotCache, WorkDir, Custody string
	LabBinary, LabSHA256                      string
	RequestedPackages                         []string
	MaxBytes                                  uint64
	MaxPackages                               uint32
	Hardware                                  *VMHardwareOptions
}

func dependencyBase(ctx context.Context, vm *guestVM) ([]string, error) {
	data, err := vm.run(ctx, "dpkg-query -W -f='${binary:Package}=${Version} ${Architecture} ${db:Status-Status}\\n'", nil, 2<<20, time.Minute)
	if err != nil {
		return nil, err
	}
	var packages []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasSuffix(line, " installed") {
			packages = append(packages, line)
		}
	}
	if len(packages) == 0 || len(packages) > int(serverdeps.HardMaxPackages) {
		return nil, errors.New("fresh base inventory is missing or exceeds bound")
	}
	slices.Sort(packages)
	return packages, nil
}

// CaptureServerDependencies uses native APT in an admitted disposable VM with
// no origin access. A second freshly booted copy installs only the retained files.
func CaptureServerDependencies(ctx context.Context, image *labv1.ImageManifest, o ServerDependenciesOptions) (_ *serverdepsv1.Manifest, err error) {
	if len(o.RequestedPackages) == 0 || len(o.RequestedPackages) > int(serverdeps.HardMaxPackages) {
		return nil, errors.New("requested server package count exceeds bound")
	}
	for _, input := range o.RequestedPackages {
		if !validSnapshotSolverInput(input) {
			return nil, errors.New("invalid native package input")
		}
	}
	if o.Custody != "development-lab" && o.Custody != "production-vendor" {
		return nil, errors.New("server dependencies: Ubuntu capture requires explicit custody")
	}
	release := manifestRelease(image)
	if release.LabLaneOn(platform.LaneDeploy, image.Architecture) != nil || !release.Server.DependencySnapshots || release.Packages.Backend.PackageDB() != platform.PackageDBDpkg || image.Architecture != "amd64" {
		return nil, errors.New("APT server closure requires a registry-qualified dependency snapshot recipe on amd64")
	}
	if o.CacheDir == "" {
		o.CacheDir = ".cache/lab/images"
	}
	if o.SnapshotCache == "" {
		o.SnapshotCache = o.CacheDir
	}
	o.CacheDir, err = filepath.Abs(o.CacheDir)
	if err != nil {
		return nil, err
	}
	o.SnapshotCache, err = filepath.Abs(o.SnapshotCache)
	if err != nil {
		return nil, err
	}
	if err := InitializeImageCache(ctx, o.CacheDir); err != nil {
		return nil, err
	}
	hardware, err := hardwareForManifest(image, o.Hardware, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	hardware.AllowNetwork = false
	vm, _, err := newRepositorySnapshotGuest(ctx, image, o.CacheDir, o.WorkDir, "", &hardware)
	if err != nil {
		return nil, err
	}
	defer func() {
		if vm != nil {
			err = errors.Join(err, vm.close())
		}
	}()
	base, err := dependencyBase(ctx, vm)
	if err != nil {
		return nil, err
	}
	version, err := vm.run(ctx, "apt-get --version; dpkg --version; gpgv --version", nil, 16<<10, time.Minute)
	if err != nil {
		return nil, err
	}
	key, err := vm.run(ctx, "cat /usr/share/keyrings/ubuntu-archive-keyring.gpg", nil, 4<<20, time.Minute)
	if err != nil {
		return nil, err
	}
	m := &serverdepsv1.Manifest{Distribution: image.Distribution, Version: image.Version, Architecture: image.Architecture, Backend: serverdepsv1.Backend_BACKEND_DEB, BaseImageSha256: image.Sha256, BasePackages: base, RequestedPackages: o.RequestedPackages, SolverVersion: strings.TrimSpace(string(version)), MaxBytes: o.MaxBytes, MaxPackages: o.MaxPackages, Custody: o.Custody, AcquiredAt: time.Now().UTC().Format(time.RFC3339), CaptureEvidencePath: "evidence/capture.txt", ReplayEvidencePath: "evidence/replay.txt"}
	capture, err := serverdeps.NewAPTCapture(ctx, o.SnapshotCache, m, key)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, capture.Close()) }()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: capture, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		serveErr := <-serveDone
		if !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
	}()
	forward, err := newGuestForward(ctx, vm, "127.0.0.1:0", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	closedForward := false
	defer func() {
		if !closedForward {
			err = errors.Join(err, forward.Close())
		}
	}()
	guestRoot := "/var/tmp/lindm-serverdeps-capture"
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote("umask 022; mkdir -p "+guestRoot+"/keys; cat > "+guestRoot+"/keys/ubuntu-archive.gpg"), bytes.NewReader(key), 1024, time.Minute); err != nil {
		return nil, err
	}
	script, err := serverdeps.APTScript(guestRoot, "/var/tmp/lindm-serverdeps-solver", m, true, true)
	if err != nil {
		return nil, err
	}
	repositoryURL := "http://" + forward.Addr()
	script = strings.ReplaceAll(script, "file:"+guestRoot, repositoryURL)
	script = strings.Replace(script, "--download-only install", "--print-uris -o Acquire::ForceHash=SHA256 --download-only install", 1)
	result, err := dependencyNative(ctx, vm, "sudo -n sh -s", strings.NewReader(script))
	if err != nil {
		return nil, fmt.Errorf("native APT empty-status solver: %w", err)
	}
	if err := capture.ResolveURIs(ctx, string(result), repositoryURL); err != nil {
		return nil, fmt.Errorf("native APT URI admission: %w\n%s", err, result)
	}
	captureEvidence := "image=" + image.Sha256 + "\nnetwork=denied; metadata-only loopback forward\nstatus=empty; full native dependency graph\n" + string(version) + string(result)
	if err := capture.Add(m.CaptureEvidencePath, []byte(captureEvidence), serverdepsv1.FileKind_FILE_KIND_EVIDENCE); err != nil {
		return nil, err
	}
	if err := forward.Close(); err != nil {
		return nil, err
	}
	closedForward = true
	if err := vm.close(); err != nil {
		return nil, err
	}
	vm = nil
	// Reboot from the original authenticated image, not a solver-mutated overlay.
	replay, _, err := newRepositorySnapshotGuest(ctx, image, o.CacheDir, o.WorkDir, "", &hardware)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, replay.close()) }()
	replayBase, err := dependencyBase(ctx, replay)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(base, replayBase) {
		return nil, errors.New("offline replay baseline differs from native capture baseline")
	}
	repository := "/var/tmp/lindm-serverdeps-replay/repository"
	root, err := os.Open(filepath.Join(capture.Staging, "repository"))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	for _, entry := range m.Files {
		input, err := serverdeps.OpenRetained(root, entry)
		if err != nil {
			return nil, err
		}
		command := "umask 022; mkdir -p " + nativeQuote(repository+"/"+path.Dir(entry.Path)) + "; cat > " + nativeQuote(repository+"/"+entry.Path) + "; printf '%s  %s\\n' " + nativeQuote(entry.Sha256) + " " + nativeQuote(repository+"/"+entry.Path) + " | sha256sum --check --status"
		_, uploadErr := replay.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), io.LimitReader(input, int64(entry.SizeBytes)+1), 4096, 5*time.Minute)
		if err := errors.Join(uploadErr, input.Close()); err != nil {
			return nil, err
		}
	}
	script, err = serverdeps.APTScript(repository, "/var/tmp/lindm-serverdeps-replay/native", m, false, false)
	if err != nil {
		return nil, err
	}
	script += "dpkg --audit\ndpkg-query -W -f='${binary:Package}=${Version} ${Architecture} ${db:Status-Status}\\n'"
	result, err = dependencyNative(ctx, replay, "sudo -n unshare --net -- sh -s", strings.NewReader(script))
	if err != nil {
		return nil, fmt.Errorf("fresh offline native APT install: %w", err)
	}
	replayEvidence := "image=" + image.Sha256 + "\nnetwork=QEMU denied plus unshare --net; only captured file repositories\nbaseline=exact native package inventory match\n" + string(result)
	if err := capture.Add(m.ReplayEvidencePath, []byte(replayEvidence), serverdepsv1.FileKind_FILE_KIND_EVIDENCE); err != nil {
		return nil, err
	}
	published, _, err := capture.Publish(ctx)
	return published, err
}

// ReplayServerDependencies consumes an existing immutable closure with a matching
// native product helper. It never recaptures metadata or replaces old evidence.
func ReplayServerDependencies(ctx context.Context, image *labv1.ImageManifest, digest string, o ServerDependenciesOptions) (_ *serverdepsv1.Manifest, _ []byte, err error) {
	release := platform.ForManifest(image.GetDistribution(), image.GetVersion())
	if release.Server == nil || !release.Server.DependencySnapshots || release.Packages.Backend.PackageDB() != platform.PackageDBDpkg || release.LaneGateOn(platform.LaneDeploy, image.GetArchitecture()) != "" || o.LabBinary == "" || len(o.LabSHA256) != 64 || strings.Trim(o.LabSHA256, "0123456789abcdef") != "" {
		return nil, nil, errors.New("existing server closure replay requires a registry-qualified amd64 recipe and a SHA256-pinned native helper")
	}
	if o.CacheDir == "" {
		o.CacheDir = ".cache/lab/images"
	}
	if o.SnapshotCache == "" {
		o.SnapshotCache = o.CacheDir
	}
	m, _, err := serverdeps.Load(o.SnapshotCache, digest)
	if err != nil {
		return nil, nil, err
	}
	if err := dependencyReplayTarget(image, m); err != nil {
		return nil, nil, err
	}
	if err := InitializeImageCache(ctx, o.CacheDir); err != nil {
		return nil, nil, err
	}
	hardware, err := hardwareForManifest(image, o.Hardware, runtime.GOARCH)
	if err != nil {
		return nil, nil, err
	}
	hardware.AllowNetwork = false
	vm, _, err := newRepositorySnapshotGuest(ctx, image, o.CacheDir, o.WorkDir, "", &hardware)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	base, err := dependencyBase(ctx, vm)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Equal(base, m.BasePackages) {
		return nil, nil, errors.New("offline consumer baseline differs from retained native capture baseline")
	}
	cache := "/var/tmp/lindm-serverdeps-consumer/cache"
	if _, err := vm.run(ctx, "sudo -n install -d -m 0755 /var/tmp/lindm-native-lab; sudo -n install -d -m 0700 "+cache, nil, 4096, time.Minute); err != nil {
		return nil, nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, o.LabBinary); err != nil {
		return nil, nil, err
	}
	checkHelper := "printf '%s  %s\\n' " + nativeQuote(o.LabSHA256) + " " + nativeQuote(guestLifecycleProbe) + " | sha256sum --check --status"
	if _, err := vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(checkHelper), nil, 4096, time.Minute); err != nil {
		return nil, nil, fmt.Errorf("native consumer helper SHA256 differs: %w", err)
	}
	reader, writer := io.Pipe()
	exportDone := make(chan error, 1)
	go func() {
		exportErr := serverdeps.Export(ctx, o.SnapshotCache, digest, writer)
		exportDone <- errors.Join(exportErr, writer.CloseWithError(exportErr))
	}()
	command := "sudo -n unshare --net -- " + guestLifecycleProbe + " serverdeps import -cache " + nativeQuote(cache) + " -sha256 " + nativeQuote(digest)
	importOutput, importErr := dependencyNative(ctx, vm, command, reader)
	readerErr := reader.CloseWithError(importErr)
	if err := errors.Join(importErr, readerErr, <-exportDone); err != nil {
		return nil, nil, fmt.Errorf("offline product helper snapshot import: %w", err)
	}
	script := guestLifecycleProbe + " serverdeps install -cache " + nativeQuote(cache) + " -sha256 " + nativeQuote(digest) + "\ndpkg --audit\ndpkg-query -W -f='${binary:Package}=${Version} ${Architecture} ${db:Status-Status}\\n'\n"
	result, err := dependencyNative(ctx, vm, "sudo -n unshare --net -- sh -eu -c "+nativeQuote(script), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("fresh offline product helper install: %w", err)
	}
	evidence := "image=" + image.Sha256 + "\nsnapshot=" + digest + "\nhelper_sha256=" + o.LabSHA256 + "\nnetwork=QEMU denied plus unshare --net; existing captured snapshot only\nbaseline=exact native package inventory match\n" + string(importOutput) + string(result)
	return m, []byte(evidence), nil
}

func dependencyReplayTarget(image *labv1.ImageManifest, m *serverdepsv1.Manifest) error {
	if m.GetBackend() != serverdepsv1.Backend_BACKEND_DEB || m.GetDistribution() != image.GetDistribution() || m.GetVersion() != image.GetVersion() || m.GetArchitecture() != image.GetArchitecture() || m.GetBaseImageSha256() != image.GetSha256() {
		return errors.New("existing server dependency closure differs from authenticated replay image")
	}
	return nil
}

func dependencyNative(ctx context.Context, vm *guestVM, command string, input io.Reader) ([]byte, error) {
	result, err := vm.runResult(ctx, command, input, 8<<20, 30*time.Minute)
	if err != nil {
		return nil, err
	}
	output := append(result.Stdout, result.Stderr...)
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("native dependency transaction exited %d: %s", result.ExitCode, output)
	}
	return output, nil
}
