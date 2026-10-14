// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// RemoteLabDependencies owns the disposable PostgreSQL instance for one staged
// remote repository. Individual authority fixtures still own their own databases
// and dynamic TLS listeners. No shared development service is used or changed.
type RemoteLabDependencies struct {
	cluster *loadPostgres
}

// OpenRemoteLabDependencies requires a fresh, run-owned repository. It initializes
// private trust and binds its strict fixture manifest to the dedicated cluster.
// Callers close all lane fixtures before closing these dependencies.
func OpenRemoteLabDependencies(ctx context.Context, repository string) (_ *RemoteLabDependencies, err error) {
	if _, err := os.Lstat(FixturePath(repository)); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("remote lab dependencies require an absent, run-owned development fixture")
	}
	if err := Init(ctx, repository, "keycloak"); err != nil {
		return nil, err
	}
	shared := FixturePath(repository)
	cluster, err := openLoadPostgres(ctx, repository, shared, LoadAuthorityOptions{DatabaseStorage: "tmpfs"})
	if err != nil {
		return nil, err
	}
	dependencies := &RemoteLabDependencies{cluster: cluster}
	defer func() {
		if err != nil {
			err = errors.Join(err, dependencies.Close())
		}
	}()
	m, err := readManifest(shared)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"postgres-password", "migration-database-url"} {
		data, err := os.ReadFile(filepath.Join(cluster.directory, name))
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		err = os.WriteFile(filepath.Join(shared, name), data, 0600)
		clear(data)
		if err != nil {
			return nil, err
		}
		m.Files[name] = hex.EncodeToString(digest[:])
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(shared, "manifest.json"), data, 0600); err != nil {
		return nil, err
	}
	if err := Trust(ctx, repository); err != nil {
		return nil, err
	}
	return dependencies, nil
}

func (d *RemoteLabDependencies) Close() error {
	return d.cluster.Close()
}
