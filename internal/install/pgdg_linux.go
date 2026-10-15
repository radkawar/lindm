// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const pgdgKeyPath = "/etc/apt/keyrings/lindm-pgdg.asc"

// PGDG is added only when the registry requires it. Never install downloaded
// setup scripts, add global trust, or adopt an unrelated source/key pathname.
func preparePGDG(ctx context.Context, repository *platform.PostgreSQLRepository) error {
	// Fresh minimal images may not yet have the distro CA bundle. Bootstrap it
	// using the already authenticated distribution sources, never TLS bypass.
	if err := installAPTDependencies(ctx, []string{"ca-certificates"}); err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("PGDG key redirects are not accepted") },
	}
	key, err := fetchPGDGKey(ctx, client, repository)
	if err != nil {
		return err
	}
	for _, path := range []string{"/etc/apt/keyrings", "/etc/apt/sources.list.d"} {
		if err := os.Mkdir(path, 0755); err == nil {
			// The installer retains a private umask; APT metadata must still
			// be traversable by the unprivileged _apt downloader.
			if err := os.Chmod(path, 0755); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
		parent, stat, err := custody.OpenRoot(path, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		if err := parent.Close(); err != nil {
			return err
		}
		if stat.Mode&0005 != 0005 {
			return errors.New("PGDG APT metadata directory must be publicly readable and traversable")
		}
	}
	if err := publishRepositoryFile(pgdgKeyPath, key); err != nil {
		return err
	}
	return publishRepositoryFile("/etc/apt/sources.list.d/lindm-pgdg.sources", pgdgSource(repository))
}

func fetchPGDGKey(ctx context.Context, client *http.Client, repository *platform.PostgreSQLRepository) (key []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, repository.KeyURL, nil)
	if err != nil {
		return nil, err
	}
	if request.URL.Scheme != "https" {
		return nil, errors.New("PGDG key requires authenticated HTTPS")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch pinned PGDG signing authority: %w", err)
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK || response.ContentLength > 64<<10 {
		return nil, errors.New("invalid PGDG key response")
	}
	key, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(key) == 0 || len(key) > 64<<10 {
		return nil, errors.New("PGDG key exceeds bounded public-key input")
	}
	if err := packaging.ValidateNativePublicKey(key, repository.KeyFingerprint); err != nil {
		return nil, fmt.Errorf("PGDG signing authority: %w", err)
	}
	return key, nil
}

func pgdgSource(repository *platform.PostgreSQLRepository) []byte {
	return []byte("Types: deb\nURIs: " + repository.URL + "\nSuites: " + repository.Suite +
		"\nArchitectures: " + runtime.GOARCH + "\nComponents: " + repository.Component +
		"\nSigned-By: " + pgdgKeyPath + " " + repository.KeyFingerprint + "\n")
}

func publishRepositoryFile(path string, content []byte) error {
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	if err := parent.Close(); err != nil {
		return err
	}
	actual, err := protected(path, false)
	if err == nil {
		if !bytes.Equal(actual, content) {
			return errors.New("existing PGDG repository file differs; refusing to overwrite operator configuration")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return newFile(path, content, 0, 0, 0644)
}
