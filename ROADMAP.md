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

Read [GOVERNANCE](GOVERNANCE.md) for project decisions and [CONTRIBUTING](CONTRIBUTING.md) to propose work.
