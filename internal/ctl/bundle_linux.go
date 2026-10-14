// SPDX-License-Identifier: Apache-2.0

package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/offlinebundle"
	"lindm/internal/packaging"
)

const bundleUsage = "usage: lindmctl bundle {export|verify|development-key} [flags]"

type ringFlags []string

func (r *ringFlags) String() string     { return "ring" }
func (r *ringFlags) Set(v string) error { *r = append(*r, v); return nil }

// runBundle executes local station commands. Export contacts only the
// configured advisory vendors; no lindm server session is used.
func runBundle(ctx context.Context, args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New(bundleUsage)
	}
	flags := flag.NewFlagSet("lindmctl bundle "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	switch args[0] {
	case "development-key":
		output := flags.String("output", "", "new DEVELOPMENT bundle-signing key directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *output == "" || flags.NArg() != 0 {
			return errors.New("bundle development-key requires -output DIR")
		}
		id, err := offlinebundle.GenerateDevelopmentKey(*output)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "DEVELOPMENT ONLY offline bundle signing key\nkey %s\nkey-id %s\nnot a release attestation, package, TUF, execution or TLS key\n", filepath.Join(*output, "bundle.pem"), id)
		return err
	case "verify":
		directory := flags.String("bundle", "", "bundle directory")
		public := flags.String("public-key", "", "independently obtained bundle public key PEM")
		id := flags.String("key-id", "", "pinned bundle key SPKI SHA-256")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *directory == "" || *public == "" || *id == "" || flags.NArg() != 0 {
			return errors.New("bundle verify requires -bundle, -public-key and -key-id")
		}
		verifier, err := offlinebundle.LoadVerifier(*public, *id)
		if err != nil {
			return err
		}
		bundle, err := offlinebundle.Open(ctx, *directory, verifier, now())
		if err != nil {
			return err
		}
		if err := bundle.VerifyFiles(ctx); err != nil {
			return err
		}
		m := bundle.Manifest
		_, err = fmt.Fprintf(stdout, "verified %s offline bundle sequence %d release %s: %d files, %d repositories, TUF targets v%d, %d advisory snapshots; expires %s\nsignature and file digests only: import re-verifies release attestations and TUF metadata; clients verify native repository signatures\n", m.GetCustody(), m.GetSequence(), m.GetRelease().GetVersion(), len(m.GetFiles()), len(m.GetRepositories()), m.GetUpdates().GetTargetsVersion(), len(m.GetAdvisories()), m.GetExpiresAt().AsTime().Format(time.RFC3339))
		return err
	case "export":
		return runBundleExport(ctx, flags, args[1:], stdout, now)
	default:
		return errors.New(bundleUsage)
	}
}

func runBundleExport(ctx context.Context, flags *flag.FlagSet, args []string, stdout io.Writer, now func() time.Time) error {
	output := flags.String("output", "", "new bundle directory; its parent must exist")
	sequence := flags.Uint64("sequence", 0, "strictly increasing bundle sequence for this signing authority")
	validity := flags.Duration("validity", 14*24*time.Hour, "signed bundle validity (at most 720h)")
	release := flags.String("release", "", "release export directory from lab release build")
	releaseKey := flags.String("release-public-key", "", "trusted release attestation public key PEM")
	releaseKeyID := flags.String("release-key-id", "", "pinned release attestation key ID")
	home := flags.String("signer-home", "", "native package signing GnuPG home (the release package signer)")
	fingerprint := flags.String("fingerprint", "", "pinned native package signing fingerprint")
	passphrase := flags.String("passphrase-file", "", "production package-signing passphrase file")
	updates := flags.String("updates", "", "station TUF release repository")
	updatesRoot := flags.String("updates-root", "", "authenticated TUF root JSON anchoring -updates")
	var rings ringFlags
	flags.Var(&rings, "ring", "channel ring proposal to carry (repeatable)")
	advisories := flags.String("advisories", "", "strict protobuf JSON lindm.config.v1.AdvisoryConfig whose feeds are acquired")
	caFile := flags.String("ca-file", "", "additional PEM trust roots for advisory HTTPS")
	key := flags.String("key", "", "bundle signing PKCS#8 key with .purpose sidecar")
	keyID := flags.String("key-id", "", "pinned bundle signing key ID")
	development := flags.Bool("development-key", false, "explicitly use development package and bundle signing custody")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" || *release == "" || *updates == "" || *updatesRoot == "" || *key == "" {
		return errors.New("bundle export requires -output, -sequence, -release, -release-public-key, -release-key-id, signer flags, -updates, -updates-root, -key and -key-id")
	}
	for _, path := range []*string{output, release, releaseKey, home, passphrase, updates, updatesRoot, advisories, caFile, key} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	custody := "production"
	if *development {
		custody = "development"
	}
	root, err := readDocument(*updatesRoot)
	if err != nil {
		return fmt.Errorf("read TUF root: %w", err)
	}
	request := offlinebundle.ExportRequest{
		Output: *output, Sequence: *sequence, Validity: *validity,
		Release: *release, ReleasePublicKey: *releaseKey, ReleaseKeyID: *releaseKeyID,
		PackageSigner:     packaging.SigningKey{Home: *home, Fingerprint: *fingerprint, Custody: packaging.Custody(custody), PassphraseFile: *passphrase},
		UpdatesRepository: *updates, UpdatesRoot: root, Rings: rings,
		Signer: offlinebundle.SigningKey{Path: *key, KeyID: *keyID, Custody: custody},
		Now:    now,
	}
	if *advisories != "" {
		data, err := readDocument(*advisories)
		if err != nil {
			return fmt.Errorf("read advisory configuration: %w", err)
		}
		cfg := new(configv1.AdvisoryConfig)
		if err := protojson.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("advisory configuration must be strict AdvisoryConfig protobuf JSON: %w", err)
		}
		request.Feeds = cfg.GetFeeds()
		request.HTTPClient, err = stationClient(*caFile)
		if err != nil {
			return err
		}
		defer request.HTTPClient.CloseIdleConnections()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	manifest, err := offlinebundle.Export(ctx, request)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s offline bundle %s\nsequence %d release %s; %d files, %d repositories, TUF root v%d targets v%d, channels %v, %d advisory snapshots; expires %s\n", manifest.GetCustody(), *output, manifest.GetSequence(), manifest.GetRelease().GetVersion(), len(manifest.GetFiles()), len(manifest.GetRepositories()), manifest.GetUpdates().GetRootVersion(), manifest.GetUpdates().GetTargetsVersion(), manifest.GetUpdates().GetChannels(), len(manifest.GetAdvisories()), manifest.GetExpiresAt().AsTime().Format(time.RFC3339))
	return err
}

// stationClient uses the host trust store plus explicit extra roots; vendor
// feed TLS verification is never disabled.
func stationClient(caFile string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no PEM certificates")
		}
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: time.Minute, TLSHandshakeTimeout: 30 * time.Second}
	return &http.Client{Transport: transport}, nil
}
