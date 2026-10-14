// SPDX-License-Identifier: Apache-2.0

// Package custody defines the filesystem boundary used by privileged agent
// readers, native providers and local tooling: the directory predicate for
// agent configuration and runtime paths, a strict no-follow walk for
// root-protected native files and directories, and private-leaf checks.
// Callers retain descriptors and reject symlinks while traversing. It is not an
// authorization API and never creates, repairs or chmods anything.
package custody

import "golang.org/x/sys/unix"

// TrustedDirectory reports whether a pinned directory can be replaced only by
// root or members of root's group. Apply it to every ancestor, including /.
// Group zero is privileged custody: never assign an untrusted account to it.
// A symlink's own metadata is rejected; callers must use O_NOFOLLOW when opening
// components, rather than passing metadata obtained by following a link.
func TrustedDirectory(stat *unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 &&
		stat.Mode&0002 == 0 && (stat.Mode&0020 == 0 || stat.Gid == 0)
}
