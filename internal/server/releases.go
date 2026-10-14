// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/config"
	"lindm/internal/releaseupdate"
)

// The repository is public read-only data, including for unsupported agents.
// Only the separately authenticated management API can request publication.
func newReleaseRepository(resources *config.Resources) (http.Handler, *releaseupdate.Publisher, error) {
	if resources.ReleaseRepositoryDirectory == "" {
		return nil, nil, nil
	}
	directory, err := filepath.EvalSymlinks(resources.ReleaseRepositoryDirectory)
	if err != nil {
		return nil, nil, err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, nil, err
	}
	handler, err := releaseupdate.NewRepositoryHandler(directory)
	if err != nil {
		return nil, nil, err
	}
	if resources.ReleaseSigningDirectory == "" {
		return handler, nil, nil
	}
	custody, err := filepath.EvalSymlinks(resources.ReleaseSigningDirectory)
	if err != nil {
		return nil, nil, err
	}
	custody, err = filepath.Abs(custody)
	if err != nil {
		return nil, nil, err
	}
	relative, err := filepath.Rel(directory, custody)
	if err != nil {
		return nil, nil, err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, errors.New("release signing custody must be outside the published repository")
	}
	signers, err := releaseupdate.LoadOnlineSigners(custody)
	if err != nil {
		return nil, nil, err
	}
	publisher, err := releaseupdate.NewPublisher(releaseupdate.PublisherConfig{Directory: directory, Signers: signers, Now: time.Now})
	if err != nil {
		return nil, nil, err
	}
	return handler, publisher, nil
}

// Recovery admission uses the installation's authenticated bootstrap, never
// repository/root.json as a new trust anchor. Its checkpoint stays private.
func newRecoveryArtifacts(resources *config.Resources) (*releaseupdate.Client, error) {
	state := resources.ReleaseVerificationStateDirectory
	if state == "" {
		return nil, nil
	}
	if resources.ReleaseRepositoryDirectory == "" || resources.ExecutionBootstrap == nil || len(resources.ExecutionBootstrap.ReleaseRootJSON) == 0 {
		return nil, errors.New("recovery artifact verification requires repository and authenticated execution bootstrap")
	}
	directory, err := filepath.Abs(resources.ReleaseRepositoryDirectory)
	if err != nil {
		return nil, err
	}
	state, err = filepath.Abs(state)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(directory, state)
	if err != nil {
		return nil, err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("release verification checkpoint must be outside the published repository")
	}
	// NewClient and DirectoryFetch reject linked directories and files.
	return releaseupdate.NewClient(releaseupdate.ClientConfig{
		StateDir: state, BootstrapRoot: resources.ExecutionBootstrap.ReleaseRootJSON,
		Fetch: releaseupdate.DirectoryFetch(directory),
	})
}
