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
