// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"

	"lindm/internal/packaging"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

// InstallerInputs is explicit release-custodian material, not host defaults.
// Snapshot digests optionally pin per-platform offline closures authenticated by
// serverdeps.Load. Connected installs use configured native distro repositories.
// RHEL redistribution/entitlement remains custodian policy for offline add-ons.
type InstallerInputs struct{ TUFRoot, TUFRootSHA256, SnapshotCache, UbuntuSnapshot, RHELSnapshot string }

// ExportInstaller attaches a separately authenticated native installer to a full
// release export. Call before the full export's atomic publication, never from
// the agent-only repository builder. Source is the already captured build input.
func ExportInstaller(ctx context.Context, source, work, exported string, request Request, inputs InstallerInputs) error {
	signer, err := loadSigner(request.AttestationSigner)
	if err != nil {
		return err
	}
	root, err := readBounded(inputs.TUFRoot, maxDocument)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(root)
	if hex.EncodeToString(digest[:]) != inputs.TUFRootSHA256 {
		return errors.New("installer TUF root independent digest mismatch")
	}
	trusted, err := trustedmetadata.New(root)
	if err != nil {
		return err
	}
	if !time.Now().Before(trusted.Root.Signed.Expires) {
		return errors.New("installer TUF root expired")
	}
	if request.AttestationSigner.Custody == "production" {
		inventoryData, _, err := pinnedDocument(request.AttestationSigner.TrustInventory, request.AttestationSigner.TrustInventorySHA256, 4<<20)
		if err != nil {
			return err
		}
		inventory := new(releasev1.SigningTrustInventory)
		if err := protojson.Unmarshal(inventoryData, inventory); err != nil {
			return err
		}
		if !bytes.Equal(root, inventory.GetTufRootJson()) {
			return errors.New("installer TUF root must match authenticated signing trust inventory")
		}
	}
	nativeFingerprint := strings.ToUpper(strings.TrimSpace(request.PackageSigner.Fingerprint))
	nativeKey, err := readBounded(filepath.Join(exported, "agent-repository", "package-signing.asc"), 1<<20)
	if err != nil {
		return err
	}
	if err := packaging.ValidateNativePublicKey(nativeKey, nativeFingerprint); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(exported, "native-package.fingerprint"), []byte(nativeFingerprint+"\n"), 0644); err != nil {
		return err
	}
	var binaries []string
	var binaryDigests []string
	for _, label := range []string{"installer-first", "installer-second"} {
		builder := filepath.Join(work, label)
		if err := os.Mkdir(builder, 0700); err != nil {
			return err
		}
		checkout := filepath.Join(builder, "source")
		if err := copySource(source, checkout); err != nil {
			return err
		}
		binary := filepath.Join(builder, "lindm-install")
		environment := append(builderEnvironment(builder, request.SourceDateEpoch, request.tools), "CGO_ENABLED=0", "GOARCH=amd64")
		if _, err := command(ctx, checkout, environment, request.tools.goBinary, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", binary, "./cmd/lindm-install"); err != nil {
			return err
		}
		sum, _, err := digestFile(binary)
		if err != nil {
			return err
		}
		binaries = append(binaries, binary)
		binaryDigests = append(binaryDigests, sum)
	}
	if binaryDigests[0] != binaryDigests[1] {
		return errors.New("installer isolated builds are not reproducible")
	}
	if err := copyNew(binaries[0], filepath.Join(exported, "lindm-install"), 0755); err != nil {
		return err
	}
	assets := map[string][]byte{"release-root.json": root}
	script, err := readBounded(filepath.Join(source, "deploy/server/install.sh"), 1<<20)
	if err != nil {
		return err
	}
	assets["install.sh"] = script
	var sums strings.Builder
	fmt.Fprintf(&sums, "%s  lindm-install\n", binaryDigests[0])
	for _, name := range []string{"install.sh", "release-root.json"} {
		mode := os.FileMode(0644)
		if name == "install.sh" || name == "lindm-install" {
			mode = 0755
		}
		if err := writeNew(filepath.Join(exported, name), assets[name], mode); err != nil {
			return err
		}
		sum := sha256.Sum256(assets[name])
		fmt.Fprintf(&sums, "%x  %s\n", sum, name)
	}
	if err := exportInstallerSnapshots(ctx, exported, request.AttestationSigner.Custody, &inputs, &sums); err != nil {
		return err
	}
	for _, name := range []string{"agent-repository/package-signing.asc", "native-package.fingerprint"} {
		sum, _, err := digestFile(filepath.Join(exported, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", sum, name)
	}
	// Include release.json so installer supplemental authority cannot be mixed
	// with a separately valid older package export.
	manifestSum, _, err := digestFile(filepath.Join(exported, "release.json"))
	if err != nil {
		return err
	}
	fmt.Fprintf(&sums, "%s  release.json\n", manifestSum)
	payload := []byte(sums.String())
	if err := writeNew(filepath.Join(exported, "installer.sha256"), payload, 0644); err != nil {
		return err
	}
	sig, err := signer.signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(exported, "installer.sha256.sig"), sig, 0644)
}

// exportInstallerSnapshots retains native vendor authentication and legal custody
// gates before adding the streamed dependency assets to the signed inventory.
func exportInstallerSnapshots(ctx context.Context, exported, custody string, inputs *InstallerInputs, sums *strings.Builder) error {
	if (inputs.UbuntuSnapshot != "" || inputs.RHELSnapshot != "") && inputs.SnapshotCache == "" {
		return errors.New("offline installer add-ons require an explicit snapshot cache")
	}
	for _, item := range []struct{ key, digest string }{{"ubuntu-24.04", inputs.UbuntuSnapshot}, {"rhel-9", inputs.RHELSnapshot}} {
		if item.digest == "" {
			continue
		}
		release, ok := platform.Lookup(item.key)
		if !ok {
			return errors.New("installer server release missing from registry")
		}
		name := release.Server.SnapshotName
		manifest, _, err := serverdeps.Load(inputs.SnapshotCache, item.digest)
		if err != nil {
			return err
		}
		if manifest.GetArchitecture() != "amd64" || manifest.GetDistribution() != release.ID || manifest.GetVersion() != release.Version.Value {
			return errors.New("installer snapshot platform mismatch")
		}
		if custody == "production" && (manifest.GetCustody() == "development-lab" || (release.Lab.Entitlement && manifest.GetCustody() != "entitled-customer-private")) {
			return errors.New("production export requires vendor/customer custody; RHEL requires entitled customer private content")
		}
		f, err := os.OpenFile(filepath.Join(exported, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		err = errors.Join(serverdeps.Export(ctx, inputs.SnapshotCache, item.digest, f), f.Close())
		if err != nil {
			return err
		}
		sum, err := digestSnapshot(filepath.Join(exported, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(sums, "%s  %s\n", sum, name)
		pinName := name + ".digest"
		data := []byte(item.digest + "\n")
		if err := writeNew(filepath.Join(exported, pinName), data, 0644); err != nil {
			return err
		}
		pinSum := sha256.Sum256(data)
		fmt.Fprintf(sums, "%x  %s\n", pinSum, pinName)
	}
	return nil
}

// VerifyInstaller checks supplemental assets with the same externally pinned
// key as the release. Bundled keys or root documents never establish authority.
func VerifyInstaller(ctx context.Context, directory, keyPath, expectedKeyID string) error {
	key, err := readBounded(keyPath, 16384)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(key)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid installer public key")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	id, _, err := keyID(public)
	if err != nil {
		return err
	}
	if id != expectedKeyID {
		return errors.New("installer key pin mismatch")
	}
	verifier, err := signature.LoadVerifier(public, crypto.Hash(0))
	if err != nil {
		return err
	}
	payload, err := readBounded(filepath.Join(directory, "installer.sha256"), 16384)
	if err != nil {
		return err
	}
	sig, err := readBounded(filepath.Join(directory, "installer.sha256.sig"), 4096)
	if err != nil {
		return err
	}
	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload)); err != nil {
		return err
	}
	allowed := map[string]bool{"install.sh": true, "lindm-install": true, "release-root.json": true, "ubuntu24.04.snapshot": true, "rhel9.snapshot": true, "ubuntu24.04.snapshot.digest": true, "rhel9.snapshot.digest": true, "release.json": true, "agent-repository/package-signing.asc": true, "native-package.fingerprint": true}
	for _, line := range strings.Split(strings.TrimSuffix(string(payload), "\n"), "\n") {
		if err := ctx.Err(); err != nil {
			return err
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || !allowed[name] {
			return errors.New("unexpected installer asset")
		}
		delete(allowed, name)
		var actual string
		if name == "ubuntu24.04.snapshot" || name == "rhel9.snapshot" {
			actual, err = digestSnapshot(filepath.Join(directory, name))
		} else {
			actual, _, err = digestFile(filepath.Join(directory, name))
		}
		if err != nil {
			return err
		}
		if actual != sum {
			return errors.New("installer asset digest mismatch")
		}
	}
	return verifyInstallerAssetPresence(directory, allowed)
}

func verifyInstallerAssetPresence(directory string, absent map[string]bool) error {
	for _, name := range []string{"install.sh", "lindm-install", "release-root.json", "release.json", "agent-repository/package-signing.asc", "native-package.fingerprint"} {
		if absent[name] {
			return errors.New("installer asset missing")
		}
	}
	for _, snapshot := range []string{"ubuntu24.04.snapshot", "rhel9.snapshot"} {
		if absent[snapshot] != absent[snapshot+".digest"] {
			return errors.New("installer offline add-on requires both snapshot and digest")
		}
		if !absent[snapshot] {
			continue
		}
		for _, name := range []string{snapshot, snapshot + ".digest"} {
			if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
				if err != nil {
					return err
				}
				return errors.New("unsigned installer offline add-on")
			}
		}
	}
	return nil
}

// Native dependency closures have a maintained larger bound than application artifacts.
func digestSnapshot(path string) (sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() || stat.Size() > int64(serverdeps.HardMaxBytes) {
		return "", errors.New("server dependency snapshot exceeds regular-file bound")
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(f, int64(serverdeps.HardMaxBytes)+1))
	if err != nil {
		return "", err
	}
	if size > int64(serverdeps.HardMaxBytes) {
		return "", errors.New("server dependency snapshot grew beyond bound")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
