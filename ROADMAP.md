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

Extend vulnerability coverage on RHEL, Rocky Linux and AlmaLinux devices to every installed package from verified vendor repository data. Packages without vendor coverage are listed as not checked until then.

## Releases

v0.1 uses [self-built releases and operator signing keys](docs/self-built-releases.md).
Official project-signed releases need an approved key-custody plan before they can ship.
That work must keep signature verification, independently retained trust pins and trust-domain separation.

- Implement and qualify authenticated offline installation for RHEL-family servers,
  with explicit PostgreSQL server/client resolution, retained module capability and
  safe offline installation. Preserve distro package signatures, existing module
  policy and clusters; never fall back to an unsupported PostgreSQL major or weaken database auth.
- Server installation on arm64.

Read [GOVERNANCE](GOVERNANCE.md) for project decisions and [CONTRIBUTING](CONTRIBUTING.md) to propose work.
