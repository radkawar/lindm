//go:build linux

// Package packaging builds signed native lindm-agent, lindmd and lindmctl artifacts.
// DEB/RPM use host package tools; agent Arch archives use the pinned Go zstd
// dependency. It does not install packages, change host trust, or invent an RPM
// repository when createrepo_c is absent.
//
// Build, BuildServer and BuildCLI validate the selected binary's version command
// on the host architecture, or its ELF-linked stamp for foreign architectures.
// The linker stamps for all products are
// -X lindm/internal/agent/buildinfo.Version and
// -X lindm/internal/agent/buildinfo.Revision. Revision is not part of that line.
//
// DEB authentication is an APT repository: signed InRelease, hashed Packages,
// and a separate Signed-By key. A built .deb is not an APT authentication
// claim. RPM artifacts are signed and checked in a private rpmdb. PublishRPM
// is the only path that writes repodata, and only with createrepo_c.
// RPM signing pins the primary key and freezes signature time at the later of
// SourceDateEpoch and key creation. Only deterministic RSA/EdDSA signing keys are
// accepted, after checking present-day validity. Reproducing bytes requires the
// same binary, source epoch, key and native tool versions.
// Artifact.UnsignedSHA256 records the whole native archive before signing, not
// only its executable. internal/releasebuild compares this field across two
// independently staged source/cache builds and signs the exported observations.
// All explicit and implicit directory mtimes are normalized after final staging
// and copying, including DEB control directories. Native tools' upper-bound
// SOURCE_DATE_EPOCH clamping alone cannot reproduce future-epoch builds.
// lindmctl packages contain no services, lifecycle scripts or configuration.
//
// FormatArch is explicitly selected; default builds remain DEB/RPM. Arch agent
// packages contain .PKGINFO, compressed .MTREE, .BUILDINFO and fixed .INSTALL
// callbacks to the shared lifecycle asset. Payloads, metadata and zstd archives
// are streamed deterministically; .BUILDINFO describes this assembler rather
// than claiming makepkg or an Arch build chroot. Detached .sig files use the
// same primary-key, deterministic-time policy as RPM and are verified with gpgv.
// PublishArch implements repo-add's tar/desc database format in Go, snapshots
// and authenticates every package and signs/verifies lindm.db. It accepts one
// version per product and one architecture per repository. ArchRepoConfig
// requires trusted package and database signatures; guest key import/local
// trust remains the caller's explicit responsibility. No host trust is changed.
// Arch RejectionRequest inputs generate separate unsigned, tampered and
// wrong-signer artifacts, never evidence of pacman rejection or installation.
//
// Server packages never enable/start services, migrate or bootstrap on install.
// Operators provision strict protobuf JSON at /etc/lindm/server.json and separate
// migrator config at /etc/lindm/migrate/server.json. Config and referenced secrets
// are mode 0600, owned by lindmd or lindmd-migrate respectively. The migration
// directory is root:lindmd-migrate 0750 and inaccessible to the runtime unit.
// No operator config/key is a package-owned conffile; remove and purge retain it
// and all database contents. The embedded console is supplied by the binary.
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
