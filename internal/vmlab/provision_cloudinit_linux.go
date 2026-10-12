//go:build linux

package vmlab

import (
	"context"
	"errors"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// ProvisionCloudInitVM boots a verified vendor cloud image whose NoCloud seed
// carries the console's cloud-init snippet verbatim as the first MIME part and
// only the lab's SSH access and hosts line as the second. No lindm agent,
// repository, CA or bootstrap is staged: the snippet alone installs and
// enrolls, waiting for the independent approval the lane obtains through the
// console. The read-only observer is uploaded only after cloud-init finished.
func ProvisionCloudInitVM(ctx context.Context, manifest *labv1.ImageManifest, options VMProvisionOptions) (result *VMProvisionResult, err error) {
	defer func() {
		if err != nil {
			result = nil
		} else if result != nil {
			result.OwnedCleanupComplete = true
		}
	}()
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	release := manifestRelease(manifest)
	format := string(platform.ProvisionCloudInit)
	if err := provisionRelease(release, format, manifest.GetArchitecture()); err != nil {
		return nil, err
	}
	// The snippet runs at first boot, before the lab could bind a rolling
	// release to its retained snapshot. An entitled (RHEL) guest stays
	// unregistered: the snippet needs no vendor repository when the image
	// already carries its prerequisites, and installs only from lindmd's.
	if manifest.GetRepositorySnapshotManifestSha256() != "" {
		return nil, errors.New("cloud-init provisioning needs vendor repositories reachable at first boot without lab preparation")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	snippet, pins, digest, err := captureProvisionSnippet(options, format, release.Native().Packages.Backend)
	if err != nil {
		return nil, err
	}
	defer clear(snippet)
	hardware := VMHardwareOptions{StorageBus: "virtio-blk"}
	if options.Hardware != nil {
		hardware = *options.Hardware
	}
	hardware.AllowNetwork, hardware.stockAcceptance = true, true
	seed := &provisionSeed{snippet: snippet, host: options.PublicHost}
	vm, image, err := newVerifiedSeededGuest(ctx, manifest, options.CacheDir, options.WorkDir, false, &hardware, seed)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	clear(snippet)
	result = &VMProvisionResult{Format: format, ImageID: manifest.GetId(), ImageSHA256: image.SHA256, SnippetSHA256: digest}
	result.Pristine = VMProvisionPristine{VendorImageVerified: true, LabPartsSHA256: seed.labPartsSHA256, LabPartsLindmFree: true, SnippetOnlyLindmInput: true}
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	// The snippet's runcmd installs the agent and starts its unit without
	// blocking on approval, so cloud-init finishes first.
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 30*time.Minute); err != nil {
		return nil, err
	}
	if result.Runtime, err = vm.runtimeEvidence(ctx); err != nil {
		return nil, err
	}
	if err := awaitProvisionedEnrollment(ctx, vm, release, options, pins, result); err != nil {
		return nil, err
	}
	return result, nil
}
