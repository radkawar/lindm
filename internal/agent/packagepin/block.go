// Package packagepin shares native package ownership framing between the
// provider and the durable ownership journal. Native policy parsing remains
// manager-specific; a malformed owner marker always claims the resource.
package packagepin

import (
	"bytes"
	"errors"
)

const PacmanPath = "/etc/pacman.conf"
const ZypperPath = "/etc/zypp/locks"

// RemoveBlock returns the unowned bytes and the one complete owned block.
// It never treats partial, repeated or nested markers as absence of ownership.
func RemoveBlock(current []byte, canonicalKey string) ([]byte, []byte, error) {
	marker := "# lindm:" + canonicalKey
	begin, end := marker+" begin\n", marker+" end\n"
	start := bytes.Index(current, []byte(begin))
	if start < 0 {
		if bytes.Contains(current, []byte(marker)) {
			return nil, nil, errors.New("packagepin: damaged owner marker")
		}
		return bytes.Clone(current), nil, nil
	}
	if start != 0 && current[start-1] != '\n' {
		return nil, nil, errors.New("packagepin: unanchored owner marker")
	}
	tail := current[start+len(begin):]
	stop := bytes.Index(tail, []byte(end))
	if stop < 0 || (stop != 0 && tail[stop-1] != '\n') || bytes.Contains(tail[:stop], []byte("# lindm:")) || bytes.Contains(tail[stop+len(end):], []byte(marker)) || bytes.Contains(current[:start], []byte(marker)) {
		return nil, nil, errors.New("packagepin: damaged owner block")
	}
	finish := start + len(begin) + stop + len(end)
	return append(bytes.Clone(current[:start]), current[finish:]...), bytes.Clone(current[start:finish]), nil
}

// ClaimsBlock is shared by preflight and journal acquisition checks.
func ClaimsBlock(contents []byte, canonicalKey string) bool {
	_, block, err := RemoveBlock(contents, canonicalKey)
	return err != nil || len(block) != 0
}
