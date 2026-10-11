package offlinebundle

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var servedComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+~-]*$`)

// NewRepositoryHandler serves only the published repositories/ and release/
// trees below directory. Mount it with http.StripPrefix. It accepts GET/HEAD,
// rejects queries, indexes, dot names (including staging), links and
// non-regular files, and never writes.
func NewRepositoryHandler(directory string) (http.Handler, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("offlinebundle: repository directory must be a real directory")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path
		if r.URL.RawQuery != "" || r.URL.RawPath != "" || len(name) > 1024 || (!strings.HasPrefix(name, reposDir+"/") && !strings.HasPrefix(name, releaseDir+"/")) {
			http.NotFound(w, r)
			return
		}
		for _, component := range strings.Split(name, "/") {
			if !servedComponent.MatchString(component) {
				http.NotFound(w, r)
				return
			}
		}
		if err := serveFile(w, r, directory, name); err != nil {
			http.Error(w, "repository read failed", http.StatusInternalServerError)
		}
	}), nil
}

func serveFile(w http.ResponseWriter, r *http.Request, directory, name string) (err error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	// Reject a link at any component, not only links escaping the root.
	components := strings.Split(name, "/")
	for index := range components {
		info, err := root.Lstat(strings.Join(components[:index+1], "/"))
		if err != nil {
			http.NotFound(w, r)
			return nil
		}
		last := index == len(components)-1
		if (last && !info.Mode().IsRegular()) || (!last && !info.IsDir()) {
			http.NotFound(w, r)
			return nil
		}
	}
	file, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return nil
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "", info.ModTime(), file)
	return nil
}
