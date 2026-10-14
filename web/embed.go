// SPDX-License-Identifier: Apache-2.0

// Package web serves the built console without a separate frontend runtime.
package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

// Vite's route chunks can start with "_"; Go's default embedding skips them.
//
//go:embed all:dist
var assets embed.FS

// Handler serves immutable build assets and HTML navigation requests. Missing
// assets and non-browser/API requests remain 404s rather than returning index.html.
func Handler() (http.Handler, error) {
	files, err := fs.Sub(assets, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded console: %w", err)
	}
	if _, err := fs.Stat(files, "index.html"); err != nil {
		return nil, fmt.Errorf("console build is missing: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		info, err := fs.Stat(files, name)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeFileFS(w, r, files, name)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/lindm.") ||
			(r.URL.Path != "/" && !strings.Contains(r.Header.Get("Accept"), "text/html")) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, files, "index.html")
	})
	return mux, nil
}
