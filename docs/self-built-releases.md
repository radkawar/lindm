# Self-built releases and signing keys

lindm v0.1 has no official release-signing key or public package service.
Each operator builds and signs a release for their own deployment.
A source tag identifies code. It does not authenticate a binary or package.

## Separate the keys

Keep these trust domains separate:

| Material                                                   | Purpose                                                | Custody                                    |
| ---------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------ |
| Native package key and public fingerprint                  | Sign native packages and repository metadata           | Operator's release custodian               |
| Ed25519 release-attestation key and public SPKI SHA-256 ID | Sign release, artifact, SBOM and provenance statements | Separate release custody                   |
| Execution-authority keys                                   | Authorize privileged device operations                 | Deployment's execution custodians          |
| TUF root and delegated keys                                | Authorize agent updates                                | Separate offline and online update custody |
| TLS and device-CA keys                                     | Authenticate listeners and devices                     | Deployment's protected server custody      |
| Backup key or recipient                                    | Protect deployment backups                             | Backup custodian, separate from the server |

The release builder checks actual public key material for cross-domain reuse.
A different key name or fingerprint format does not make reused material safe.
Do not use a TLS, execution, TUF or device key to sign packages or release statements.

## Keep private material outside the source tree

1. Use a dedicated signing workstation or protected operator directory.
2. Give private directories mode `0700` and private files mode `0600`.
3. Back up private keys through a separate, encrypted custody process.
4. Keep signing keys off managed devices and the installed control plane.
5. Transfer only public trust material and authenticated release artifacts to the installation host.
6. Pin the public key and its identifier through an independently authenticated channel.

Do not commit private keys, passphrases, enrollment codes or `.cache/dev`.
Do not put passphrases in command arguments or environment variables.
The package tool accepts a protected `-passphrase-file`.
The release export excludes private signing custody.

## Build an operator release

Use the pinned Go and Node versions from `go.mod` and `.node-version`.
Install the native packaging tools listed in [CONTRIBUTING](../CONTRIBUTING.md).
Run `make bootstrap` in your clone.

Create the production-purpose key set, then build your signed installer bundle:

```sh
make release-keys
make release
```

`release-keys` creates a new `release-keys/` directory.
It prompts twice for an encryption passphrase of at least 20 bytes.
The default workflow stores private custody in `custody.age`, not plaintext key files.
It also generates separate backup custody.
Keep that directory and its unlock material off the installation host.
Back them up through your protected custody process before installation.

The quickstart keeps control with the holder of one passphrase.
It does not create separation between independent humans.
The inventory's separate execution, TLS and TUF keys enforce release-signing exclusions.
They do not replace the live server's independently provisioned keys.

Run the helper as your normal user, not root.
It disables core dumps and checks active swap before it unlocks custody.
No swap, RAM-only zram and dm-crypt-protected swap are accepted.
zram disk writeback also needs protection.

Do not change swap topology while the command runs.
Private keys never reach unencrypted swap or disk; on hosts with unencrypted swap, signing refuses until swap is safe.
Follow its named `swapoff`, encrypted-swap or RAM-only zram remedy.
Process memory locking does not protect a native GPG helper from unencrypted disk swap.
Encrypted custody protects storage; it does not protect a compromised signing workstation.

The default CA source is `/etc/ssl/certs/ca-certificates.crt`.
The helper excludes non-CA certificates and reports their subjects and SHA-256 values.
It pins the usable exported CA bytes, not the unfiltered source file.
It refuses an empty usable root set.
Select your approved roots explicitly when the default is not appropriate:

```sh
make release-keys RELEASE_KEYS_ARGS='--ca-bundle /approved/roots.pem'
```

Use repeated `--recipient age1...` options for recipient-based custody.
Each recipient can decrypt the archive.
The first recipient becomes the public installer backup recipient.
Keep every private age identity with its custodian.

For automation, supply a protected anonymous pipe on stdin with `--passphrase-fd 0` or `--identity-fd 0`.
Init requires two matching LF-terminated passphrase lines; build requires one.
The helper rejects secret input from disk files, argv and environment variables.
Use the built helper directly for descriptors above `2`.
`go run` closes those descriptors; protected stdin can use descriptor `0`.

The public attestation key is `release-keys/attestation.pub`.
Keep its key-ID pin through an independently authenticated channel.
The public backup recipient is `release-keys/backup-recipient.txt`.
Its private identity remains inside encrypted custody.

`make release` builds the full production-purpose release and Turnkey bundle in `artifacts/release/`.
Use `RELEASE_ARGS` for documented public options, such as `--version 0.1.1`.
The default build is connected. Offline closures require explicit per-platform inputs.
Do not assume a connected installer includes every offline dependency.

Verify the directory against the independent public trust material:

```sh
go run ./cmd/release verify --directory artifacts/release --keys release-keys
```

This verification does not unlock private custody.
The default deliverable is a directory, not an archive that requires extraction.
Transfer that directory through an authenticated channel.
Transfer public trust material separately.
Never transfer `custody.age` or its unlock secret to the server.
Follow [installation](install.md) for the exact verification and `install.sh` procedure.
See [release custody](engineering.md#clean-release-exports-and-custody-p20l17) for the lower-level `lab release build` and `release verify` commands.
Production trust inventory, purpose checks and CA pins remain required.
The helper does not relabel development keys or remove trust-domain separation.

The builder compares two isolated builds of the complete native release matrix and OCI artifacts.
Both builds use the selected source snapshot and toolchain on one host.
This is not independent-builder, hermetic-network or SLSA certification.
The complete build can take much longer than installation.

Native build staging uses a private `0700` directory under a validated temporary root.
The helper verifies the export before it moves or copies the directory atomically to the selected output.
Normal errors and cancellation remove temporary staging.

A reproducibility mismatch retains unsigned diagnostics in `artifacts/reproducibility-mismatch-<timestamp>/`.
This is not a verified release bundle.
Read the printed logical size and quoted removal command.
Keep useful evidence, then remove the diagnostic directory when you no longer need it.

## Generate evaluation keys

The existing key generators create explicitly marked **development-only** keys:

```sh
umask 077
mkdir -p "$HOME/lindm-evaluation-keys"
go run ./cmd/lab packages keygen -output "$HOME/lindm-evaluation-keys/package"
go run ./cmd/lab release attestation-keygen -output "$HOME/lindm-evaluation-keys/attestation"
```

The first command prints the signing home and native fingerprint.
The second prints the attestation key path and SPKI SHA-256 ID.
It also writes `attestation.pub` and the development purpose sidecar.
An evaluation release requires the explicit `release build -development-key` option.
Production release and installer gates still apply their production custody requirements.
Do not relabel evaluation keys as production keys or disable verification to install their output.

## Understand the consequences

You are the release signer and trust distributor for your deployment.
Users must authenticate your public trust material before they install the bundle.
A signature proves control of its signing key, not code safety or platform qualification.
The server supplies agents from your authenticated release, not a project-hosted repository.

If a signing key is exposed, stop using it and follow the relevant trust-rotation procedure.
Replacing a file does not update pinned keys, TUF roots or installed trust automatically.
If an offline signing key is lost, you cannot sign future artifacts under that identity.
If a backup key is lost, encrypted backups can become unreadable.
Preserve recovery custody independently before installation.

The project's original code is licensed under [Apache-2.0](../LICENSE).
Third-party components and data retain their own terms.
Preserve the separate third-party notices in [NOTICE](../NOTICE).
