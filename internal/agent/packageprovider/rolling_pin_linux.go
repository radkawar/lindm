//go:build linux

package packageprovider

import (
	"bytes"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/packagepin"
)

const (
	pacmanConfigPath = packagepin.PacmanPath
	zypperLocksPath  = packagepin.ZypperPath
)

// removeOwnedPin removes only one complete, exactly labelled block. A damaged
// marker is never interpreted as permission to replace the surrounding file.
func removeOwnedPin(current []byte, ref *resourcev1.ResourceRef) ([]byte, []byte, error) {
	remaining, block, err := packagepin.RemoveBlock(current, ref.GetCanonicalKey())
	if err != nil {
		return nil, nil, ErrConflict
	}
	return remaining, block, nil
}

func rollingPinBlock(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, alpm bool) []byte {
	if d.GetExact() == nil || d.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	body := "IgnorePkg = " + d.GetPackage().GetNativeName() + "\n"
	if !alpm {
		// PoolQuery ORs ordinary attributes. A single predicated name matcher
		// is required to conjoin the name, architecture and excluded EVR.
		body = "type: package\nmatch_type: exact\ncase_sensitive: on\ncomplex: AttrMatchData solvable:name " + d.GetPackage().GetNativeName() + " T SolvableRange\\ !=\\ " + nativeVersion(d.GetExact()) + "\\ " + d.GetPackage().GetArchitecture() + "\n"
	}
	return []byte("# " + pinMarker(ref) + " begin\n" + body + "# " + pinMarker(ref) + " end\n")
}

func renderRollingPin(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte, alpm bool) ([]byte, error) {
	remaining, _, err := removeOwnedPin(current, ref)
	if err != nil {
		return nil, err
	}
	block := rollingPinBlock(ref, d, alpm)
	if alpm {
		// IgnorePkg is an options directive, not a repository directive. Keep
		// every unowned byte and put the owned block inside the options section.
		position := -1
		inOptions := false
		offset := 0
		for line := range strings.SplitSeq(string(remaining), "\n") {
			text, _, _ := strings.Cut(line, "#")
			text = strings.TrimSpace(text)
			if strings.HasPrefix(text, "[") {
				if text == "[options]" {
					if position >= 0 || inOptions {
						return nil, ErrConflict
					}
					inOptions = true
				} else if inOptions {
					position, inOptions = offset, false
				}
			}
			if inOptions {
				key, value, _ := strings.Cut(text, "=")
				if strings.TrimSpace(key) == "IgnorePkg" {
					for _, pattern := range strings.Fields(value) {
						match, err := filepath.Match(pattern, d.GetPackage().GetNativeName())
						if err != nil || match {
							return nil, errors.New("packageprovider: externally owned overlapping IgnorePkg")
						}
					}
				}
			}
			offset += len(line) + 1
		}
		if inOptions {
			position = len(remaining)
		}
		if position < 0 || (len(remaining) > 0 && remaining[len(remaining)-1] != '\n') {
			return nil, errors.New("packageprovider: unsafe pacman options section")
		}
		result := make([]byte, 0, len(remaining)+len(block))
		result = append(result, remaining[:position]...)
		result = append(result, block...)
		result = append(result, remaining[position:]...)
		if len(result) > maxPin {
			return nil, errors.New("packageprovider: native pin capacity")
		}
		return result, nil
	}
	if err := checkZypperExternalLocks(remaining, d.GetPackage()); err != nil {
		return nil, err
	}
	if len(block) == 0 {
		return remaining, nil
	}
	if len(remaining) != 0 && !bytes.HasSuffix(remaining, []byte("\n\n")) {
		remaining = append(remaining, '\n')
		if len(remaining) > 1 && remaining[len(remaining)-2] != '\n' {
			remaining = append(remaining, '\n')
		}
	}
	remaining = append(remaining, block...)
	if len(remaining) > maxPin {
		return nil, errors.New("packageprovider: native pin capacity")
	}
	return remaining, nil
}

func checkZypperExternalLocks(data []byte, identity *resourcev1.PackageIdentity) error {
	for _, block := range strings.Split(string(data), "\n\n") {
		fields := make(map[string]string)
		for line := range strings.SplitSeq(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !ok || fields[key] != "" {
				return ErrConflict
			}
			fields[key] = value
		}
		if len(fields) == 0 || (fields["type"] != "" && fields["type"] != "package") {
			continue
		}
		for key := range fields {
			switch key {
			case "type", "match_type", "case_sensitive", "version", "solvable_name", "complex", "comment":
			default:
				// Ordinary solvable attributes are ORed, not restrictions
				// on the name. Never dismiss an unrecognized matcher.
				return errors.New("packageprovider: ambiguous externally owned zypp lock")
			}
		}
		if complex := fields["complex"]; complex != "" {
			parts := strings.Split(complex, " ")
			if len(parts) != 8 || parts[0] != "AttrMatchData" || parts[1] != "solvable:name" || parts[3] != "T" || parts[4] != "SolvableRange\\" || parts[5] != "!=\\" || !strings.HasSuffix(parts[6], "\\") || fields["solvable_name"] != "" {
				return errors.New("packageprovider: unsupported external zypp predicate")
			}
			if parts[7] != identity.GetArchitecture() {
				continue
			}
			fields["solvable_name"], fields["match_type"] = parts[2], "exact"
		}
		pattern, candidate := fields["solvable_name"], identity.GetNativeName()
		if pattern == "" || fields["query_string"] != "" {
			return errors.New("packageprovider: ambiguous externally owned zypp lock")
		}
		if fields["case_sensitive"] != "on" && fields["case_sensitive"] != "true" {
			pattern, candidate = strings.ToLower(pattern), strings.ToLower(candidate)
		}
		var match bool
		var err error
		switch fields["match_type"] {
		case "exact":
			match = pattern == candidate
		case "glob":
			match, err = filepath.Match(pattern, candidate)
		case "regex":
			match, err = regexp.MatchString(pattern, candidate)
		case "", "substring", "word":
			match = strings.Contains(candidate, pattern)
		default:
			return ErrConflict
		}
		if err != nil || match {
			return errors.New("packageprovider: externally owned overlapping zypp lock")
		}
	}
	return nil
}

func rollingPinMatches(ref *resourcev1.ResourceRef, d *resourcev1.NativePackageDesired, current []byte, alpm bool) bool {
	_, block, err := removeOwnedPin(current, ref)
	return err == nil && bytes.Equal(block, rollingPinBlock(ref, d, alpm))
}
