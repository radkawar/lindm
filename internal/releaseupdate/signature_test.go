package releaseupdate

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

// Native signature bytes are opaque to this core. These tests exercise genuine
// TUF signatures over both descriptors; pacman's OpenPGP verification belongs to
// the native executor and is not claimed by these transport-boundary tests.
func TestArchDetachedSignatureBoundToSelection(t *testing.T) {
	fixture := newRepositoryFixture(t)
	channel := proto.CloneOf(fixture.channel)
	channel.Generation++
	artifact := channel.Artifacts[0]
	artifact.PackageFormat = "arch"
	artifact.TargetPath = "packages/lindm-agent/1.2.3/lindm-agent-amd64.pkg.tar.zst"
	artifact.SignatureTargetPath = artifact.TargetPath + ".sig"
	packageFile := filepath.Join(t.TempDir(), "package.pkg.tar.zst")
	signatureFile := filepath.Join(t.TempDir(), "package.pkg.tar.zst.sig")
	signatureBytes := []byte("opaque detached native signature bytes")
	mustWrite(t, packageFile, fixture.payload)
	mustWrite(t, signatureFile, signatureBytes)
	files := map[string]string{artifact.TargetPath: packageFile}
	if err := fixture.publisher.Publish(context.Background(), channel, files); err == nil {
		t.Fatal("published Arch channel without its signed native signature target")
	}
	files[artifact.SignatureTargetPath] = signatureFile
	if err := fixture.publisher.Publish(context.Background(), channel, files); err != nil {
		t.Fatal(err)
	}
	client := fixture.client(t, "", nil)
	request := fixtureRequest()
	request.PackageFormat = "arch"
	selection, err := client.Select(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if selection.SignatureLength != int64(len(signatureBytes)) || selection.SignatureSHA256 != digestBytes(signatureBytes) || selection.SignaturePath == "" {
		t.Fatal("detached signature metadata was not verified with the package")
	}
	selection.SignatureLength = 1
	selection.SignatureSHA256 = "untrusted hint"
	selection.SignaturePath = "targets/foreign.sig"
	destination := filepath.Join(t.TempDir(), "private", "agent.pkg.tar.zst.sig")
	if err = client.StageSignature(context.Background(), selection, bytes.NewReader(signatureBytes), destination); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, destination), signatureBytes) {
		t.Fatal("staged native signature changed")
	}
	if err = client.StageSignature(context.Background(), selection, bytes.NewReader(fixture.payload), destination); err == nil {
		t.Fatal("native signature substitution accepted")
	}
	if !bytes.Equal(mustRead(t, destination), signatureBytes) {
		t.Fatal("failed signature verification replaced protected signature")
	}
	other := fixture.client(t, "", nil)
	if err = other.StageSignature(context.Background(), selection, bytes.NewReader(signatureBytes), destination); err == nil {
		t.Fatal("native signature selection transplanted across clients")
	}
}

func TestArchSignatureSchemaBindingAndBound(t *testing.T) {
	fixture := newRepositoryFixture(t)
	channel := proto.CloneOf(fixture.channel)
	channel.Generation++
	artifact := channel.Artifacts[0]
	artifact.PackageFormat = "arch"
	artifact.TargetPath = "packages/lindm-agent/1.2.3/amd64.pkg.tar.zst"
	if err := validateChannel(fixture.publisher.validator, channel, fixture.now); err == nil {
		t.Fatal("Arch package without detached native signature permitted")
	}
	artifact.SignatureTargetPath = "packages/lindm-agent/foreign.pkg.tar.zst.sig"
	if err := validateChannel(fixture.publisher.validator, channel, fixture.now); err == nil {
		t.Fatal("native signature path detached from package identity")
	}
	artifact.SignatureTargetPath = artifact.TargetPath + ".sig"
	packageFile := filepath.Join(t.TempDir(), "package")
	signatureFile := filepath.Join(t.TempDir(), "signature")
	mustWrite(t, packageFile, fixture.payload)
	mustWrite(t, signatureFile, bytes.Repeat([]byte{1}, int(MaxSignatureBytes+1)))
	if err := fixture.publisher.Publish(context.Background(), channel, map[string]string{artifact.TargetPath: packageFile, artifact.SignatureTargetPath: signatureFile}); err == nil {
		t.Fatal("oversized native signature target published")
	}
	client := fixture.client(t, "", nil)
	selection, err := client.Select(context.Background(), fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err = client.StageSignature(context.Background(), selection, bytes.NewReader(nil), filepath.Join(t.TempDir(), "signature")); err == nil {
		t.Fatal("invented signature staged for a package without one")
	}
}
