//go:build linux

// Package packaging builds signed native lindm-agent artifacts with the host's
// package tools. It does not install packages, change host trust, or invent an
// RPM repository when createrepo_c is absent.
//
// Build executes the agent binary's version command and requires it to print
// the requested upstream version and a newline. The linker stamps are
// -X lindm/internal/agent/buildinfo.Version and
// -X lindm/internal/agent/buildinfo.Revision. Revision is not part of that line.
//
// DEB authentication is an APT repository: signed InRelease, hashed Packages,
// and a separate Signed-By key. A built .deb is not an APT authentication
// claim. RPM artifacts are signed and checked in a private rpmdb. PublishRPM
// is the only path that writes repodata, and only with createrepo_c.
//
// Artifact stdout is streamed without the diagnostic capture limit; captured
// stdout and stderr remain bounded. APT Release generation occurs outside the
// hashed distribution tree. RPM payload paths are escaped for both RPM and the
// shell, and services are configured after upgrade removal scriptlets finish.
// Every signer home is exclusively guarded by a cross-process flock on its
// checked private directory, from before GPG validation through agent shutdown.
// Contention returns ErrSignerBusy without touching the owner's agent; separate
// homes remain independent. BuildSource does not hold this lock while compiling.
// Signing-agent shutdown is bounded independently of cancellation; cleanup
// failures are returned alongside any operation failure, before publishing new
// signed output. Development-key generation and temporary wrong-signer fixtures
// retain the same ownership across their nested GPG operations.
// Newly generated repository signatures are made 0644 before publication,
// independent of the caller's umask; evidence readers still reject writable input.
package packaging
