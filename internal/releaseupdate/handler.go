package releaseupdate

import (
	"context"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var publicMetadataName = regexp.MustCompile(`^(root|timestamp|[1-9][0-9]*\.(root|targets|rollout|snapshot))\.json$`)
var publicTargetName = regexp.MustCompile(`(^|/)[a-f0-9]{64}\.[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// NewRepositoryHandler serves only committed public TUF names. Mount with
// http.StripPrefix; no writes, directory indexes, redirects or private files.
func NewRepositoryHandler(directory string) (http.Handler, error) {
	root, err := openDirectoryNoLinks(directory)
	if err != nil {
		return nil, err
	}
	if err = root.Close(); err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if !safePath(name) || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		public := false
		if rest, ok := strings.CutPrefix(name, "metadata/"); ok {
			public = publicMetadataName.MatchString(rest)
		}
		if rest, ok := strings.CutPrefix(name, "targets/"); ok {
			public = safeTargetPath(rest) && publicTargetName.MatchString(rest)
		}
		if !public {
			http.NotFound(w, r)
			return
		}
		if err := serveRepositoryFile(w, r, directory, name); err != nil {
			http.Error(w, "repository read failed", http.StatusInternalServerError)
		}
	}), nil
}

func serveRepositoryFile(w http.ResponseWriter, r *http.Request, directory, name string) (err error) {
	root, err := openDirectoryNoLinks(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	file, err := openRegular(root, name)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	st, err := file.Stat()
	if err != nil {
		return err
	}
	if st.Size() > MaxTargetBytes || (strings.HasPrefix(name, "metadata/") && st.Size() > MaxMetadataBytes) {
		http.NotFound(w, r)
		return nil
	}
	if name == "metadata/timestamp.json" || name == "metadata/root.json" {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if strings.HasPrefix(name, "metadata/") {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, name, st.ModTime(), file)
	return nil
}

// DirectoryFetch provides bounded air-gap transport, not a trusted/unsafe mode.
// Metadata still passes the identical go-tuf refresh and freshness workflow.
func DirectoryFetch(directory string) FetchFunc {
	return func(ctx context.Context, name string, limit int64) (data []byte, err error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if limit < 1 || limit > MaxMetadataBytes {
			return nil, errors.New("releaseupdate: invalid fetch bound")
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, root.Close()) }()
		data, err = readBounded(root, name, limit)
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return data, err
	}
}
