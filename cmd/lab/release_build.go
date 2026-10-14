// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
)

func runReleaseBuild(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "source checkout; tracked and nonignored source is captured once")
	output := flags.String("output", "", "new release export directory; parent must exist")
	version := flags.String("version", "", "numeric upstream version")
	revision := flags.String("revision", "", "source revision label; source tree digest is independently captured")
	epoch := flags.Int64("source-date-epoch", 0, "required deterministic source timestamp")
	home := flags.String("signer-home", "", "explicit native-package GnuPG home")
	fingerprint := flags.String("fingerprint", "", "pinned native-package signing fingerprint")
	passphrase := flags.String("passphrase-file", "", "production package-signing passphrase file")
	key := flags.String("attestation-key", "", "dedicated release PKCS8 Ed25519 key; .purpose sidecar required")
	keyID := flags.String("attestation-key-id", "", "externally pinned SHA256 of release public key SPKI DER")
	inventory := flags.String("signing-trust-inventory", "", "required production protobuf public trust inventory")
	inventorySHA := flags.String("signing-trust-inventory-sha256", "", "independently authenticated inventory SHA256")
	caBundle := flags.String("oci-ca-bundle", "", "explicit maintained CA PEM bundle embedded in OCI images; never read from host defaults")
	caSHA := flags.String("oci-ca-sha256", "", "independently pinned OCI CA bundle SHA256")
	development := flags.Bool("development-key", false, "explicitly use conspicuously marked development package and attestation keys")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" || *key == "" {
		return errors.New("release build requires -output, -version, -revision, -source-date-epoch, both explicit signing keys and no positional arguments")
	}
	if err := resolvePackagePaths(repository, output, home, passphrase, key, inventory, caBundle); err != nil {
		return err
	}
	custody := "production"
	if *development {
		custody = "development"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	manifest, err := releasebuild.Build(ctx, releasebuild.Request{Repository: *repository, Output: *output, Version: *version, Revision: *revision, SourceDateEpoch: *epoch, OCICABundle: *caBundle, OCICASHA256: *caSHA, PackageSigner: packaging.SigningKey{Home: *home, Fingerprint: *fingerprint, Custody: packaging.Custody(custody), PassphraseFile: *passphrase}, AttestationSigner: releasebuild.AttestationKey{Path: *key, KeyID: *keyID, Custody: custody, TrustInventory: *inventory, TrustInventorySHA256: *inventorySHA}})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s release export: %s\n%d artifacts; two isolated clean builds with equal unsigned archive digests\nnot an independently trusted builder or certified SLSA level\n", manifest.GetCustody(), filepath.Join(*output, "release.json"), len(manifest.GetArtifacts()))
	return err
}

func runReleaseAttestationKeygen(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release attestation-keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "new dedicated DEVELOPMENT signing directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" || flags.NArg() != 0 {
		return errors.New("release attestation-keygen requires -output DIR")
	}
	id, err := releasebuild.GenerateDevelopmentKey(*output)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "DEVELOPMENT ONLY release attestation key\nkey %s\nkey-id %s\nnot a production, package, TUF, execution or TLS key\n", filepath.Join(*output, "attestation.pem"), id)
	return err
}

func runReleaseVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "release export directory")
	public := flags.String("public-key", "", "trusted attestation public key PEM")
	id := flags.String("key-id", "", "externally pinned public-key ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *public == "" || *id == "" || flags.NArg() != 0 {
		return errors.New("release verify requires -directory, -public-key and -key-id")
	}
	manifest, err := releasebuild.Verify(ctx, *directory, *public, *id)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %s release %s: %d artifact hashes, DSSE signatures, SBOM/provenance bindings and unsigned digest comparisons\n", manifest.GetCustody(), manifest.GetVersion(), len(manifest.GetArtifacts()))
	return err
}
