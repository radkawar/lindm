package dnf

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// VersionlockPath is DNF5's single shared exact-version lock document.
const VersionlockPath = "/etc/dnf/versionlock.toml"

type VersionlockCondition struct {
	Key        string `toml:"key"`
	Comparator string `toml:"comparator"`
	Value      string `toml:"value"`
}

type VersionlockPackage struct {
	Name       string                 `toml:"name"`
	Comment    string                 `toml:"comment,omitempty"`
	Conditions []VersionlockCondition `toml:"conditions"`
}

// Versionlock is the closed native document; unknown fields are refused.
type Versionlock struct {
	Version  string               `toml:"version"`
	Packages []VersionlockPackage `toml:"packages,omitempty"`
}

func ParseVersionlock(data []byte) (Versionlock, error) {
	if len(data) == 0 {
		return Versionlock{Version: "1.0"}, nil
	}
	var document Versionlock
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("dnf: invalid native versionlock: %w", err)
	}
	if document.Version != "1.0" {
		return document, errors.New("dnf: unsupported native versionlock version")
	}
	for _, entry := range document.Packages {
		if entry.Name == "" || len(entry.Conditions) == 0 {
			return document, errors.New("dnf: incomplete native versionlock entry")
		}
		for _, condition := range entry.Conditions {
			if condition.Key != "evr" && condition.Key != "epoch" && condition.Key != "arch" {
				return document, errors.New("dnf: unknown native versionlock dimension")
			}
			if condition.Comparator != "=" && condition.Comparator != "!=" && condition.Comparator != "<" && condition.Comparator != "<=" && condition.Comparator != ">" && condition.Comparator != ">=" {
				return document, errors.New("dnf: unknown native versionlock comparator")
			}
		}
	}
	return document, nil
}

// VersionlockMarker is the comment binding an entry to one lindm resource key.
func VersionlockMarker(canonicalKey string) string { return "lindm:" + canonicalKey }

// versionlockTOMLClaims is VersionlockClaims for DNF5's TOML document.
func versionlockTOMLClaims(contents []byte, canonicalKey, name string) bool {
	document, err := ParseVersionlock(contents)
	if err != nil {
		return true
	}
	for _, entry := range document.Packages {
		if entry.Comment == VersionlockMarker(canonicalKey) {
			return true
		}
		if match, err := filepath.Match(entry.Name, name); err != nil || match {
			return true
		}
	}
	return false
}
