package labhost

import (
	"errors"
	"path/filepath"
)

// DemoDirectory confines a simple, bounded demo name to the host's persistent
// work directory. Device and fixture subdirectories are owned by their layers.
func DemoDirectory(work, name string) (string, error) {
	if name == "" || len(name) > 32 {
		return "", errors.New("demo name must be 1–32 ASCII letters, digits, underscores or hyphens, starting with a letter or digit")
	}
	for i, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-') {
			continue
		}
		return "", errors.New("invalid demo name")
	}
	if !filepath.IsAbs(work) {
		return "", errors.New("persistent demo work directory must be absolute")
	}
	return filepath.Join(work, "demos", name), nil
}
