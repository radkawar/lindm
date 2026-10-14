// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/advisory"
	"lindm/internal/config"
	"lindm/internal/offlinebundle"
	"lindm/internal/releaseupdate"
)

// runBundleImport is the offline operator path. It reuses the server's
// validated configuration, authenticated release root, online TUF custody and
// advisory publication; it performs no network requests.
func runBundleImport(ctx context.Context, args []string) (resultErr error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("config", "", "protobuf JSON server configuration")
	bundle := flags.String("bundle", "", "signed offline bundle directory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || *bundle == "" || flags.NArg() != 0 {
		return errors.New("bundle-import requires -config FILE and -bundle DIR; positional arguments are not accepted")
	}
	document, err := config.Load(*path)
	if err != nil {
		return err
	}
	resources, err := document.Resolve()
	if err != nil {
		return err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	cfg := resources.Proto.GetOfflineBundles()
	if cfg == nil || resources.ExecutionBootstrap == nil || resources.ReleaseSigningDirectory == "" {
		return errors.New("bundle-import requires offline_bundles, execution_bootstrap and a signing release_repository")
	}
	signers, err := releaseupdate.LoadOnlineSigners(resources.ReleaseSigningDirectory)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startup, resources.Database)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Check(startup, pool); err != nil {
		return err
	}
	advisories, err := advisory.New(startup, pool, resources.Proto.GetAdvisories(), resources.HTTPClient)
	if err != nil {
		return err
	}
	cancel()
	importer, err := offlinebundle.NewImporter(offlinebundle.ImporterConfig{
		Pool: pool, Directory: resources.OfflineBundleDirectory,
		SigningPublicKey: resources.OfflineBundleSigningPublicKey, SigningKeyID: cfg.GetSigningKeyId(),
		ReleasePublicKey: resources.OfflineBundleReleasePublicKey, ReleaseKeyID: cfg.GetReleaseAttestationKeyId(),
		ReleaseRepository: resources.ReleaseRepositoryDirectory, ReleaseSigners: signers,
		ReleaseRoot: resources.ExecutionBootstrap.ReleaseRootJSON, Advisories: advisories,
	})
	if err != nil {
		return err
	}
	result, err := importer.Import(ctx, *bundle)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
