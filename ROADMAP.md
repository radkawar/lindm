# Roadmap

lindm is a v0.1 preview. This page records planned work, not delivery dates or support guarantees.
Use the [capability matrix](docs/verification.md#tier-capability-matrix) for recorded results.

## Qualification

- Complete arm64 release and platform requalification. Individual native passes do not qualify the full release path.
- Test on authorized physical hardware, including TPM, firmware, storage erasure and recovery. VM results do not settle those hardware properties.
- Qualify remote assistance Tiers 2 and 3 on their native desktop and device paths, with user consent and custody checks.

## Platform work

Implement and qualify [Fedora Atomic and NixOS](docs/platforms/atomic-nixos.md).
The current pages describe designs, not supported platforms.

## Releases

v0.1 uses [self-built releases and operator signing keys](docs/self-built-releases.md).
Official project-signed releases need an approved key-custody plan before they can ship.
That work must keep signature verification, independently retained trust pins and trust-domain separation.

- After v0.1.0, implement and qualify an authenticated RHEL 9 offline add-on with
  explicit PostgreSQL 16 server/client resolution, retained module capability and
  safe offline installation. Preserve distro package signatures, existing module
  policy and clusters; never fall back to PostgreSQL 13 or weaken database auth.
- After v0.1.0, implement and qualify PostgreSQL 17/18 support with a matching
  backup and restore client. Keep version-skew preflight and verified database
  authentication; v0.1.0 supports PostgreSQL 16 only for local and external databases.

Read [GOVERNANCE](GOVERNANCE.md) for project decisions and [CONTRIBUTING](CONTRIBUTING.md) to propose work.
