//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// The native agent still comes exclusively from the console repository. This
// authenticated vendor DVD supplies the unregistered guest's OS dependencies.
func openDemoRepositoryMedia(ctx context.Context, manifest *labv1.ImageManifest, recipe *platform.LabRPMMedia, cacheDir string) (_ *os.File, err error) {
	if recipe == nil {
		return nil, nil
	}
	verified, err := (Fetcher{}).Fetch(ctx, manifest, cacheDir)
	if err != nil {
		return nil, err
	}
	file, err := openRegular(verified.Path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	// Hash the descriptor that QEMU will inherit, not a pathname reopened at
	// launch. This is the same cache-to-VM boundary as native cloud images.
	pinned, err := digestInstalledImage(ctx, file)
	if err != nil {
		return nil, err
	}
	if pinned.Size != verified.Size || pinned.SHA256 != verified.SHA256 {
		return nil, errors.New("verified repository DVD changed before VM launch")
	}
	return file, nil
}

func encryptedRepositoryMediaArguments(architecture string) []string {
	args := []string{"-drive", "if=none,id=vendor-media,media=cdrom,readonly=on,format=raw,file=/proc/self/fd/3"}
	if architecture == "aarch64" {
		return append(args, "-device", "virtio-scsi-pci,id=vendor-scsi", "-device", "scsi-cd,bus=vendor-scsi.0,drive=vendor-media,bootindex=9")
	}
	return append(args, "-device", "ide-cd,drive=vendor-media,bootindex=9")
}

func demoRepositoryMediaScript(recipe *platform.LabRPMMedia) string {
	var script strings.Builder
	script.WriteString(`set -eu
install -d -m 0755 /mnt/lindmvendor
cat > /etc/systemd/system/mnt-lindmvendor.mount <<'LINDM_MEDIA_UNIT'
[Unit]
Description=Authenticated read-only vendor DVD (lab)
[Mount]
What=/dev/sr0
Where=/mnt/lindmvendor
Type=iso9660
Options=ro
[Install]
WantedBy=local-fs.target
LINDM_MEDIA_UNIT
systemctl daemon-reload
# Guest operations reject stderr; enable otherwise reports its symlink there.
systemctl --quiet enable --now mnt-lindmvendor.mount
cat > /etc/yum.repos.d/lindm-vendor-media.repo <<'LINDM_MEDIA_REPOSITORIES'
`)
	for _, repository := range recipe.Repositories {
		fmt.Fprintf(&script, "[lindm-vendor-%s]\nname=Authenticated vendor DVD %s (lab)\nbaseurl=file:///mnt/lindmvendor/%s\nenabled=1\ngpgcheck=1\nlocalpkg_gpgcheck=1\ngpgkey=file://%s\n\n", repository, repository, repository, recipe.Key)
	}
	script.WriteString("LINDM_MEDIA_REPOSITORIES\n")
	return script.String()
}
