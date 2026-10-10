package feed

import (
	"errors"
	"strings"
)

// compareArch follows libalpm's alpm_pkg_vercmp, not modern RPM or dpkg:
// separators' lengths matter, an unseparated alpha suffix precedes the empty
// suffix, and pkgrel is compared only when both versions provide it. The pinned
// upstream behavioral vectors and source provenance are in testdata/arch-*.
func compareArch(a, b string) (int, error) {
	ae, av, ar, ok := splitArchVersion(a)
	if !ok {
		return 0, errors.New("feed: invalid Arch package version")
	}
	be, bv, br, ok := splitArchVersion(b)
	if !ok {
		return 0, errors.New("feed: invalid Arch package version")
	}
	if n := numericCompare(ae, be); n != 0 {
		return n, nil
	}
	if n := archPart(av, bv); n != 0 {
		return n, nil
	}
	if ar != "" && br != "" {
		return archPart(ar, br), nil
	}
	return 0, nil
}

func splitArchVersion(version string) (epoch, upstream, release string, ok bool) {
	if version == "" || len(version) > 4096 {
		return "", "", "", false
	}
	epoch, upstream = "0", version
	if i := strings.IndexByte(upstream, ':'); i >= 0 {
		epoch, upstream = upstream[:i], upstream[i+1:]
		if epoch == "" {
			return "", "", "", false
		}
		for i := range len(epoch) {
			if !digit(epoch[i]) {
				return "", "", "", false
			}
		}
	}
	if i := strings.LastIndexByte(upstream, '-'); i >= 0 {
		upstream, release = upstream[:i], upstream[i+1:]
		if release == "" {
			return "", "", "", false
		}
	}
	if upstream == "" {
		return "", "", "", false
	}
	for _, part := range []string{upstream, release} {
		for i := range len(part) {
			c := part[i]
			if c <= ' ' || c >= 127 || c == ':' || c == '-' || c == '/' {
				return "", "", "", false
			}
		}
	}
	return epoch, upstream, release, true
}

func archPart(a, b string) int {
	if a == b {
		return 0
	}
	for a != "" && b != "" {
		i, j := 0, 0
		for i < len(a) && !digit(a[i]) && !letter(a[i]) {
			i++
		}
		for j < len(b) && !digit(b[j]) && !letter(b[j]) {
			j++
		}
		a, b = a[i:], b[j:]
		if a == "" || b == "" {
			break
		}
		if i < j {
			return -1
		}
		if i > j {
			return 1
		}
		numeric := digit(a[0])
		if numeric != digit(b[0]) {
			if numeric {
				return 1
			}
			return -1
		}
		i, j = 0, 0
		for i < len(a) && (numeric && digit(a[i]) || !numeric && letter(a[i])) {
			i++
		}
		for j < len(b) && (numeric && digit(b[j]) || !numeric && letter(b[j])) {
			j++
		}
		var n int
		if numeric {
			n = numericCompare(a[:i], b[:j])
		} else {
			n = strings.Compare(a[:i], b[:j])
		}
		if n != 0 {
			return n
		}
		a, b = a[i:], b[j:]
	}
	if a == "" && b == "" {
		return 0
	}
	if a == "" && !letter(b[0]) || a != "" && letter(a[0]) {
		return -1
	}
	return 1
}
