// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"errors"
	"strings"
)

// Compare orders native package versions, not upstream semantic versions. It
// implements dpkg epoch:upstream-revision and RPM epoch:version-release ordering.
func Compare(manager, a, b string) (int, error) {
	if manager == "pacman" {
		return compareArch(a, b)
	}
	if manager != "dpkg" && manager != "rpm" {
		return 0, errors.New("feed: unsupported package manager")
	}
	ae, av, ar, ok := splitVersion(manager, a)
	if !ok {
		return 0, errors.New("feed: invalid native package version")
	}
	be, bv, br, ok := splitVersion(manager, b)
	if !ok {
		return 0, errors.New("feed: invalid native package version")
	}
	if n := numericCompare(ae, be); n != 0 {
		return n, nil
	}
	compare := dpkgPart
	if manager == "rpm" {
		compare = rpmPart
	}
	if n := compare(av, bv); n != 0 {
		return n, nil
	}
	return compare(ar, br), nil
}

func splitVersion(manager, version string) (epoch, upstream, revision string, ok bool) {
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
		upstream, revision = upstream[:i], upstream[i+1:]
		if revision == "" {
			return "", "", "", false
		}
	}
	if upstream == "" {
		return "", "", "", false
	}
	if manager == "dpkg" {
		if !digit(upstream[0]) {
			return "", "", "", false
		}
		for i := range len(upstream) {
			c := upstream[i]
			if !digit(c) && !letter(c) && !strings.ContainsRune(".+~:-", rune(c)) {
				return "", "", "", false
			}
		}
		for i := range len(revision) {
			c := revision[i]
			if !digit(c) && !letter(c) && !strings.ContainsRune(".+~", rune(c)) {
				return "", "", "", false
			}
		}
		if revision == "" {
			revision = "0"
		}
	} else {
		for _, part := range []string{upstream, revision} {
			for i := range len(part) {
				if part[i] <= ' ' || part[i] >= 127 || part[i] == ':' || part[i] == '-' {
					return "", "", "", false
				}
			}
		}
	}
	return epoch, upstream, revision, true
}

func digit(c byte) bool  { return c >= '0' && c <= '9' }
func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func numericCompare(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

func dpkgOrder(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	if c == '~' {
		return -1
	}
	if digit(c) {
		return 0
	}
	if letter(c) {
		return int(c)
	}
	return int(c) + 256
}

func dpkgPart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !digit(a[0]) || b != "" && !digit(b[0]) {
			x, y := dpkgOrder(a), dpkgOrder(b)
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
			if a != "" {
				a = a[1:]
			}
			if b != "" {
				b = b[1:]
			}
		}
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if n := numericCompare(a[:i], b[:j]); n != 0 {
			return n
		}
		a, b = a[i:], b[j:]
	}
	return 0
}

// rpmPart follows rpmvercmp's ASCII segment rules, including post-release ^
// snapshots: 1.0 < 1.0^git1 < 1.0.1, while ~ sorts before even the empty suffix.
func rpmPart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !digit(a[0]) && !letter(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for b != "" && !digit(b[0]) && !letter(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		at, bt := strings.HasPrefix(a, "~"), strings.HasPrefix(b, "~")
		if at || bt {
			if !at {
				return 1
			}
			if !bt {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		ac, bc := strings.HasPrefix(a, "^"), strings.HasPrefix(b, "^")
		if ac || bc {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !ac {
				return 1
			}
			if !bc {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := digit(a[0])
		if numeric != digit(b[0]) {
			if numeric {
				return 1
			}
			return -1
		}
		i, j := 0, 0
		for i < len(a) && (numeric && digit(a[i]) || !numeric && letter(a[i])) {
			i++
		}
		for j < len(b) && (numeric && digit(b[j]) || !numeric && letter(b[j])) {
			j++
		}
		n := strings.Compare(a[:i], b[:j])
		if numeric {
			n = numericCompare(a[:i], b[:j])
		}
		if n != 0 {
			return n
		}
		a, b = a[i:], b[j:]
	}
	if a != "" {
		return 1
	}
	if b != "" {
		return -1
	}
	return 0
}
