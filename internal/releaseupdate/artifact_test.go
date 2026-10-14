// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestRecoveryArtifactAuthenticatedLength(t *testing.T) {
	f := newRepositoryFixture(t)
	payload := bytes.Repeat([]byte{0x5a}, 4097)
	digest := sha256.Sum256(payload)
	name, err := RecoveryTargetPath(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "recovery.efi")
	mustWrite(t, source, payload)
	if err := f.publisher.PublishArtifact(context.Background(), name, source); err != nil {
		t.Fatal(err)
	}
	client := f.client(t, "", nil)
	info, err := client.Artifact(context.Background(), name)
	if err != nil || info.Length != int64(len(payload)) || !bytes.Equal(info.SHA256, digest[:]) {
		t.Fatalf("exact signed descriptor: %v %v", info, err)
	}
	if _, err := client.Artifact(context.Background(), "recovery/missing.efi"); err == nil {
		t.Fatal("unregistered recovery image accepted")
	}
	wrong := sha256.Sum256([]byte("different image"))
	wrongName, err := RecoveryTargetPath(wrong[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.publisher.PublishArtifact(context.Background(), wrongName, source); err == nil {
		t.Fatal("recovery path naming different image accepted")
	}
}

func TestMeasuredRecoveryPairRequiresInitramfsFirst(t *testing.T) {
	f := newRepositoryFixture(t)
	directory := t.TempDir()
	initrd, kernel := filepath.Join(directory, "recovery.initrd"), filepath.Join(directory, "vmlinuz")
	mustWrite(t, initrd, bytes.Repeat([]byte{0x1d}, 4097))
	mustWrite(t, kernel, bytes.Repeat([]byte{0x4b}, 5000))
	initrdDigest := sha256.Sum256(bytes.Repeat([]byte{0x1d}, 4097))
	kernelDigest := sha256.Sum256(bytes.Repeat([]byte{0x4b}, 5000))
	initrdName, err := RecoveryInitrdTargetPath(initrdDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	kernelName, err := RecoveryKernelTargetPath(initrdDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.publisher.PublishArtifact(t.Context(), kernelName, kernel); err == nil {
		t.Fatal("kernel companion published before its initramfs")
	}
	if err := f.publisher.PublishArtifact(t.Context(), initrdName, kernel); err == nil {
		t.Fatal("initramfs path naming different bytes accepted")
	}
	if err := f.publisher.PublishArtifact(t.Context(), initrdName, initrd); err != nil {
		t.Fatal(err)
	}
	otherName, err := RecoveryKernelTargetPath(kernelDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.publisher.PublishArtifact(t.Context(), otherName, kernel); err == nil {
		t.Fatal("kernel companion keyed by an unpublished initramfs accepted")
	}
	if err := f.publisher.PublishArtifact(t.Context(), kernelName, kernel); err != nil {
		t.Fatal(err)
	}
	info, err := f.client(t, "", nil).Artifact(t.Context(), kernelName)
	if err != nil || info.Length != 5000 || !bytes.Equal(info.SHA256, kernelDigest[:]) {
		t.Fatalf("signed kernel companion: %v %v", info, err)
	}
}

func TestArtifactModifiedTargetMetadataRejected(t *testing.T) {
	f := newRepositoryFixture(t)
	fetch := DirectoryFetch(f.directory)
	client := f.client(t, "", func(ctx context.Context, name string, limit int64) ([]byte, error) {
		data, err := fetch(ctx, name, limit)
		if err != nil {
			return nil, err
		}
		if filepath.Base(name) == "2.targets.json" {
			targets, err := metadata.Targets().FromBytes(data)
			if err != nil {
				return nil, err
			}
			targets.Signed.Targets[f.channel.Artifacts[0].TargetPath].Length = 1
			return json.Marshal(targets)
		}
		return data, nil
	})
	if _, err := client.Artifact(context.Background(), f.channel.Artifacts[0].TargetPath); err == nil {
		t.Fatal("forged smaller unsigned target length admitted")
	}
}

func TestOnlineCustodyCannotRegisterRecoveryArtifact(t *testing.T) {
	f := newRepositoryFixture(t)
	f.publisher.cfg.Signers.Targets = nil
	source := filepath.Join(t.TempDir(), "recovery.efi")
	mustWrite(t, source, []byte("native artifact"))
	if err := f.publisher.PublishArtifact(context.Background(), "recovery/image.efi", source); err == nil {
		t.Fatal("online-only custody registered offline artifact")
	}
}
