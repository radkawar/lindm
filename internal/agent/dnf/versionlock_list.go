package dnf

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// VersionlockListPath is the DNF4 versionlock plugin's lock list. The plugin
// reads one NEVRA pattern per line ('!' excludes); lines starting with '#' are
// comments. Its location is plugin configuration, so callers must confirm the
// native plugin is enabled with exactly this list before relying on it.
const VersionlockListPath = "/etc/dnf/plugins/versionlock.list"

// VersionlockPathFor is the shared native lock document of a manager generation.
func VersionlockPathFor(kind Kind) string {
	if kind == DNF4 {
		return VersionlockListPath
	}
	return VersionlockPath
}

// VersionlockClaims reports whether the shared native lock document at path
// already locks name: lindm's own entry for canonicalKey or any entry whose
// pattern can match it. Entries for other packages are not this package's
// pin. An unknown document or unreadable contents fail closed.
func VersionlockClaims(path string, contents []byte, canonicalKey, name string) bool {
	switch path {
	case VersionlockPath:
		return versionlockTOMLClaims(contents, canonicalKey, name)
	case VersionlockListPath:
		return versionlockListClaims(contents, canonicalKey, name)
	default:
		return true
	}
}

type listLine struct {
	text  string
	entry bool
	// owner is the canonical key of a lindm marker comment.
	owner string
}

const maxListLines = 4096

func parseVersionlockList(data []byte) ([]listLine, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("dnf: invalid native versionlock list")
	}
	text := string(data)
	if text == "" {
		return nil, nil
	}
	rows := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(rows) > maxListLines {
		return nil, errors.New("dnf: native versionlock list capacity")
	}
	lines := make([]listLine, 0, len(rows))
	for _, row := range rows {
		line := listLine{text: row}
		if owner, ok := strings.CutPrefix(row, "# "+VersionlockMarker("")); ok {
			line.owner = owner
		} else if !strings.HasPrefix(row, "#") && strings.TrimSpace(row) != "" {
			line.entry = true
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// ValidateVersionlockList checks that data is a bounded DNF4 plugin list.
func ValidateVersionlockList(data []byte) error {
	_, err := parseVersionlockList(data)
	return err
}

// ownedEntry reports whether line i is lindm's marker for canonicalKey and is
// immediately followed by an entry for name. A marker whose entry an operator
// removed or replaced is orphaned: the following line is never taken as ours.
func ownedEntry(lines []listLine, i int, canonicalKey, name string) bool {
	return lines[i].owner == canonicalKey && i+1 < len(lines) && lines[i+1].entry && strings.HasPrefix(strings.TrimSpace(lines[i+1].text), name+"-")
}

// listPatternNames reports whether a native lock pattern can select name. The
// plugin tries NEVRA, NEVR, NEV, NA and NAME forms; every plausible name split
// is considered, so ambiguous patterns fail closed.
func listPatternNames(pattern, name string) bool {
	pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "!")
	candidates := []string{pattern}
	if dot := strings.LastIndexByte(pattern, '.'); dot > 0 {
		candidates = append(candidates, pattern[:dot])
	}
	for _, base := range candidates { // Range evaluates the original slice once.
		for range 2 {
			dash := strings.LastIndexByte(base, '-')
			if dash <= 0 {
				break
			}
			base = base[:dash]
			candidates = append(candidates, base)
		}
	}
	for _, candidate := range candidates {
		if match, err := filepath.Match(candidate, name); err != nil || match {
			return true
		}
	}
	return false
}

func versionlockListClaims(contents []byte, canonicalKey, name string) bool {
	lines, err := parseVersionlockList(contents)
	if err != nil {
		return true
	}
	for i, line := range lines {
		if line.owner == canonicalKey || line.entry && listPatternNames(line.text, name) {
			return true
		}
		if ownedEntry(lines, i, canonicalKey, name) {
			return true
		}
	}
	return false
}

// RenderVersionlockList removes lindm's entry for canonicalKey, preserves every
// other line byte for byte and, when entry is nonempty, appends a marked exact
// lock. An unowned entry that can select name is an external pin: refused.
func RenderVersionlockList(contents []byte, canonicalKey, name, entry string) ([]byte, error) {
	lines, err := parseVersionlockList(contents)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for i := 0; i < len(lines); i++ {
		if ownedEntry(lines, i, canonicalKey, name) {
			i++
			continue
		}
		if lines[i].owner == canonicalKey {
			continue // Orphaned marker; the following line is not ours.
		}
		if lines[i].entry && listPatternNames(lines[i].text, name) {
			return nil, errors.New("dnf: externally owned overlapping versionlock")
		}
		out.WriteString(lines[i].text)
		out.WriteByte('\n')
	}
	if entry != "" {
		if strings.ContainsAny(entry, "\n#!*?[") || !strings.HasPrefix(entry, name+"-") {
			return nil, errors.New("dnf: invalid exact versionlock entry")
		}
		out.WriteString("# " + VersionlockMarker(canonicalKey) + "\n" + entry + "\n")
	}
	return out.Bytes(), nil
}

// VersionlockListOwned returns lindm's well-formed entries for canonicalKey and
// whether the document parsed. Orphaned markers are reported as empty entries.
func VersionlockListOwned(contents []byte, canonicalKey, name string) ([]string, bool) {
	lines, err := parseVersionlockList(contents)
	if err != nil {
		return nil, false
	}
	var owned []string
	for i, line := range lines {
		if line.owner != canonicalKey {
			continue
		}
		if ownedEntry(lines, i, canonicalKey, name) {
			owned = append(owned, strings.TrimSpace(lines[i+1].text))
		} else {
			owned = append(owned, "")
		}
	}
	return owned, true
}
