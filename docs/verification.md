# Distro support and lifecycle verification

Status: qualification plan. **No matrix cell is certified.** Installation, unit tests,
containers, simulations and a source-code review cannot substitute for the required
machine evidence. All supported claims are capability-specific.

## 1. Launch platform qualification

Every family/branch row below is a launch requirement, in both connected and
air-gapped modes, with x86_64 desktop/server and the listed aarch64 server
architectures. Build order prioritizes Ubuntu LTS, Fedora and RHEL, but no row is
optional. Atomic Linux and NixOS use their own native management models rather than
inherited mutable-provider behavior. The table allocates qualification work; it
does not declare support.

Versions are branches, not mutable download URLs. Pin exact vendor/minor/snapshot,
verified image digest, repositories, architecture and installer recipe in executable
evidence. Upstream maintenance does not prove product support. A branch reaching EOL
before its release must be explicitly replaced or supported with entitled content.

Pinned cloud-server inputs for the remaining public priority branches are
[`ubuntu-resolute-amd64.json`](../lab/images/ubuntu-resolute-amd64.json)
(Ubuntu 26.04 LTS release 20260927, generic amd64 rather than amd64v3) and
[`fedora-43-x86_64.json`](../lab/images/fedora-43-x86_64.json)
(Fedora Cloud Base Generic 43-1.6). Run `lab images fetch -manifest FILE`, then
`lab images verify -manifest FILE` against the offline cache before the maintained
`lab vm inspect`, [packaged lifecycle and signed service](agent-enrollment.md#running-the-native-lifecycle-lane),
[control-plane trust](agent-enrollment.md#running-the-control-plane-authority-lane)
and [dispatch](agent-enrollment.md#running-the-connected-service-dispatch-lane)
commands. The signature trust anchors and exact image sizes/digests are in the
manifests; acquisition alone does not qualify any lifecycle or desktop cell.

The 2026-10-10 expanded-platform native inspection records are under
`$HOME/.cache/lindm-platformlanes-20261009/`. Each command used
`lab vm inspect -manifest lab/images/IMAGE.json -agent AGENT -record RECORD
-diagnostics "$HOME/.cache/lindm-platformlanes-20261009"`, sequentially in one
KVM/QEMU 8.2.2 slot (SeaBIOS 1.16.3, x86_64, one virtio disk, no TPM/desktop).
The static agent digest was
`7099ace55825dc55a36900ce38ab367863acc6c91a42f0b53c901d8ae9c1e9b7`.
Ubuntu/Fedora used `$HOME/.cache/lindm-platformlanes-inspect-lab` (SHA-256
`85523c9f4033ebe6383ca7ffb42f128981e47216a407c010d2d3774f405e0e52`);
RHEL used `$HOME/.cache/lindm-platformlanes-inspect-lab-rhel` (SHA-256
`753878cbc2301a3dced008265b7d20cfb5e6adadada5197d296672ef2d7242e2`).
The RHEL 9 oracle needed portable `lscpu --json`, with regression-tested flat and
hierarchical JSON handling, instead of the newer `--hierarchic=never` option.

| Image manifest stem     | Record                  | Matched native packages | Record SHA-256                                                     |
| ----------------------- | ----------------------- | ----------------------- | ------------------------------------------------------------------ |
| `ubuntu-resolute-amd64` | `ubuntu26-inspect.json` | 678                     | `5ad1c66303ef9edbe59dd25154da06994145dcf4c80e0e5b1611d8cfd269c061` |
| `fedora-43-x86_64`      | `fedora43-inspect.json` | 430                     | `3972591860a7edc1b876d4670880fb0ef13856904878bd6c08e281f32ab6e8ba` |
| `rhel-9.8-x86_64`       | `rhel98-inspect.json`   | 490                     | `1384880d89e86844a86176327b7441cd5892df6dccaecbddc9d1356f2e2b98bf` |
| `rhel-10.2-x86_64`      | `rhel102-inspect.json`  | 528                     | `1915d5a79e808af498a1bc5f161b9f75ac99788e90fd1c21be5302b95d20bbe0` |

These are native package/detail comparisons, not lifecycle, registration, desktop,
air-gap or physical-machine certification. Optional unavailable capabilities remain
explicit in the records; Ubuntu's installed Snap backend reported native-command
failure, not an invented empty successful application inventory.

Fresh RHEL captures additionally qualify the subsequent RPM modularity and platform
CPE/release-lock/repository observations. Both used
`$HOME/.cache/lindm-platformlanes-20261009/lab-observation-current` (SHA-256
`55d85b0309e5d111e1a27da85dce4706fbfd47a3eb691950b2b199bea08b127a`)
and `agent-observation-current` in that directory (SHA-256
`e2239c4e0f7c00e0e20b703bf9fcddb175e072d6840a0b5822fa204035af76f6`):

```sh
work="$HOME/.cache/lindm-platformlanes-20261009"
"$work/lab-observation-current" vm inspect -manifest lab/images/rhel-9.8-x86_64.json \
  -agent "$work/agent-observation-current" -record "$work/rhel98-inspect-platform.json" \
  -inventory-record "$work/rhel98-native-observation.json" -diagnostics "$work"
"$work/lab-observation-current" vm inspect -manifest lab/images/rhel-10.2-x86_64.json \
  -agent "$work/agent-observation-current" -record "$work/rhel102-inspect-platform.json" \
  -inventory-record "$work/rhel102-native-observation.json" -diagnostics "$work"
```

| RHEL               | Inspection record SHA-256                                          | Private native-observation SHA-256                                 |
| ------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| 9.8, 490 packages  | `e4c35c2983b756c425cba8bc2dda1cef8b9535dfeb7b027cc471be552a411b3e` | `31d8897f2c71163279bd6ff2e66c9fdf1288450b3f8dc58839a2b0c28a733a1a` |
| 10.2, 528 packages | `4a816ba7914ad40c42e02bdad8cddaf9f593bac61e6809fabf8a9b75ab662468` | `6d2572d691e4601a949c91445db02be7d045962fd1f0eef77a8bb8fb5a9939bb` |

The raw observations are opt-in mode-0600 files with local account/network facts,
not public attachments. These unregistered image captures report no configured
release lock and successful empty enabled-repository observations; they do not
establish authenticated repository access or EUS/E4S stream provenance.

| Family / branch                           | Build priority      | Native host acceptance                                                     | Architecture scope                      |
| ----------------------------------------- | ------------------- | -------------------------------------------------------------------------- | --------------------------------------- |
| Ubuntu 24.04 and 26.04 LTS                | 1 (major releases)  | Official GNOME Desktop and Server/minimal; Kubuntu/KDE separately          | x86_64 desktop/server; aarch64 server   |
| Fedora 43 and 44 while upstream-supported | 1 (major releases)  | Workstation GNOME and KDE editions; Server/minimal                         | x86_64 desktop/server; aarch64 server   |
| RHEL 9 and 10, supported minor            | 1 (major releases)  | Vendor GNOME-capable and minimal/server installations                      | x86_64; aarch64 server on vendor images |
| Rocky Linux 9 and 10, current minor       | 2                   | Separate derivative lifecycle, not RHEL evidence                           | x86_64; aarch64 server                  |
| AlmaLinux 9 and 10, current minor         | 2                   | Separate derivative lifecycle, not Rocky evidence                          | x86_64; aarch64 server                  |
| Debian 13                                 | 2                   | GNOME/KDE and minimal separately                                           | x86_64 desktop/server; aarch64 server   |
| openSUSE Leap 16.0                        | 2                   | GNOME/KDE and headless separately                                          | x86_64                                  |
| Ubuntu 22.04 LTS; Debian 12 LTS           | 3 (legacy)          | Separate branch/content/runtime evidence                                   | x86_64; aarch64 server                  |
| RHEL 8, Rocky 8, AlmaLinux 8              | 3 (legacy)          | Independent vendor rows and maintained security content                    | x86_64                                  |
| SLES 15 SP7 and 16; SLED 15 SP7           | 3 (SUSE enterprise) | Each vendor product/desktop/server installation separately                 | x86_64                                  |
| Arch Linux; openSUSE Tumbleweed           | 3 (rolling)         | Separate pinned snapshots, whole-system update and rollback semantics      | x86_64                                  |
| Fedora Silverblue and Kinoite             | 3 (atomic)          | Actual atomic installer, deployment/layering, booted checksum and rollback | x86_64                                  |
| NixOS stable 26.05 and successor          | 3 (declarative)     | Owner-approved configuration/closure and system-generation activation      | x86_64                                  |

RHEL is not certified by testing Rocky; Alma is not certified by testing Rocky; a GUI
installed on a server is not proof of a vendor's separate desktop product. RPM format
alone is not a shared OS contract. Record CPU baselines (including x86-64-v2/v3), DNF
major version, SELinux/AppArmor mode and kernel. Emulation alone does not establish
native aarch64 performance/hardware support.

Mutable-family qualification uses pinned manifests under `lab/images/` and records
under `~/.cache/lindm-mutabledistros-20261010/`. This is per-image evidence, not
desktop, physical, air-gap or full-release certification. The additional native
paths explicitly route Debian/Ubuntu through authenticated APT, Rocky/Alma through
DNF, and openSUSE through zypper with pinned imported keys and independently
signature-checked local RPMs. SUSE package identities remain canonical `rpm`;
zypper is independently observed as an available backend. The local agent RPM
transactions need no external dependency repository and do not disable signature
checks. Repository-backed RPM delivery retains signed `repomd.xml`.

| Image                                          | Authenticated acquisition                                                                                                                  | Independent native observation                                                                                                                                                                                                                                     | Packaged lifecycle / dispatch                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rocky 9.8 GenericCloud Base 20260525.0         | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 422 RPM records, explicit UEFI/Secure Boot disabled                                                                                                                                                                                                        | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| Rocky 10.2 GenericCloud Base 20260525.0        | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 443 RPM records, explicit UEFI/Secure Boot disabled                                                                                                                                                                                                        | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| AlmaLinux 9.8 GenericCloud 20261005            | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Passed, 387 RPM records                                                                                                                                                                                                                                            | Earlier lifecycle failed signed service after enrollment/upgrade. After removing the dbus-broker v28 argument-filter optimization, independent connected dispatch passed all 10 scenarios with SELinux Enforcing; packaged lifecycle rerun remains required                                                                                                   |
| AlmaLinux 10.2 GenericCloud 20260817.0         | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| Ubuntu 22.04 release 20261004                  | Ubuntu signed SHA256SUMS verified and cache reverified offline                                                                             | Passed, 597 dpkg records                                                                                                                                                                                                                                           | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| Rocky 8.10 GenericCloud Base 20240528.0        | Pinned manifest uses aggregate CHECKSUM.sig; 2.06 GB image download incomplete and cancelled at handoff, so actual bytes not authenticated | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| AlmaLinux 8.10 GenericCloud 20260928           | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| openSUSE Leap 16.0 Minimal-VM Cloud Build18.75 | Vendor checksum signature verified; fixed vendor-listed mirror avoids cross-origin redirect relaxation                                     | BIOS exits; UEFI exposed nonportable uptime/date oracle, now replaced by strict native btime parsing. After SSH readiness correction, agent inspection exits 1 (63 stderr bytes); current runner preserves private bounded stderr for diagnosis. No passing record | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| openSUSE Tumbleweed Cloud Snapshot20261007     | Vendor checksum signature verified and cache reverified offline; fixed vendor-listed mirror avoids cross-origin redirect relaxation        | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                              |
| Debian 13.7.0 netinst                          | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Passed after privileged source-marker correction: 355 dpkg records, explicit UEFI/Secure Boot disabled                                                                                                                                                             | Current-schema 0.5.0→0.5.1 signed-service lane reached enrollment, upgrade, reboot, reinstall, spool recovery and denied-collection preservation with 356 packages. Final independent revocation approval failed unauthenticated after 1,909 seconds; no lifecycle pass. Lazy approver-session correction has focused regression evidence, not a native rerun |
| Debian 12.15.0 netinst                         | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Not executed                                                                                                                                                                                                                                                       | Not executed                                                                                                                                                                                                                                                                                                                                                  |

The Debian [official image publication](https://cloud.debian.org/images/cloud/)
explicitly distinguishes unsigned current cloud checksums from legacy signed
OpenStack images. The verifier's detached SHA512 mode authenticates signed
metadata and both SHA512 and the SHA256 cache pin in one streaming pass; adding
that capability does not invent signatures for current Debian cloud images.
Rocky's successful UEFI inspection used installed `ovmf` `2024.02-2ubuntu0.10`,
`/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` and unenrolled `OVMF_VARS_4M.fd`;
the plain code image omits the SecureBoot variable on these guests and is not
equivalent to independently observed disabled enforcement. Lifecycle and dispatch
accept the same explicit `-firmware-code`, `-firmware-vars`, `-firmware-package`,
and `-firmware-version` flags as inspect. No BIOS-to-UEFI fallback is implicit.
The shared runtime evidence boundary also independently checks requested firmware
mode, Secure Boot on/off and SetupMode before publishing lifecycle/dispatch evidence;
requested flags alone are not accepted as observations.
The initial failed attempts are retained separately in `initial-failures.json`.
`evidence-index.json` pins the original 18 nonsecret acquisition/inspection/failure
records; `continuation-index.json` pins subsequent Debian inspection/failure records
and the separate Alma dispatch evidence. `final-failures.json` describes the earlier
handoff, not the now-passing Debian 13 inspection. Private cloud-init/journal
diagnostics are excluded. The owner's host-overload restriction stopped new mutable
guests after the active Debian lifecycle; remaining unexecuted cells are not distro
failures. Exact restart commands and unresolved diagnoses are in
`local://mutabledistros2-handoff.md`.
The signed netinst path is explicitly different from an official Debian cloud
image: the authenticated ISO is remastered only for GRUB/preseed, the native
installer uses signed Debian repositories, and a local installed ext4 disk is
integrity-pinned and rechecked before creating disposable cloud-init overlays.
The derived disk is not claimed vendor-signed or a reproducible archive snapshot.

RHEL 9/10 remain required launch cells, not derivative-qualified cells. Qualification
requires an eligible
[Red Hat Developer subscription](https://developers.redhat.com/products/rhel/download),
Customer Portal access to each supported-minor x86_64 **RHEL KVM Guest Image**
(QCOW2, with vendor integrity/authenticity metadata), and authorized guest
registration or an entitled mirror. Provide the matching
`rhel-9-for-x86_64-baseos-rpms` / `rhel-9-for-x86_64-appstream-rpms` and
`rhel-10-for-x86_64-baseos-rpms` / `rhel-10-for-x86_64-appstream-rpms`
repositories, including update access, with credentials kept outside manifests
and evidence. Record exact minor/image digest and repository snapshot; then run
the same inspect, signed-package lifecycle, trust and dispatch lanes on each
vendor image. Rocky/Alma images cannot close this gap. See the vendor
[RHEL 10 repository list](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/upgrading_from_rhel_9_to_rhel_10/appendix-rhel-10-repositories).

The initial 2026-10-09 access investigation found no usable local entitlement.
The owner subsequently supplied a protected offline token and activated the
Developer subscription: authenticated catalog requests and entitled download
resolution now succeed for RHEL 9.8 and 10.2. The maintained
`lab images redhat {discover|fetch}` command uses the
[Red Hat API authentication flow](https://access.redhat.com/articles/3626371)
without persisting tokens or temporary CDN URLs. Vendor-catalog SHA-256 provenance
is explicitly distinct from Ubuntu/Fedora OpenPGP signatures; offline verification
checks the pinned image and sanitized acquisition receipt, not a vendor signature.
An offline token is not a `subscription-manager` registration credential.
The maintained client can create and delete uniquely named disposable activation
keys; guest registration, authorized repository access, unregister cleanup and the
complete native lifecycle still require execution evidence. No RHEL pass is implied
by API access or download entitlement.

Ubuntu 26.04's full packaged signed-service lifecycle passed after the custody and
lab clock-window fixes. The exact successful command was:

```sh
work="$HOME/.cache/lindm-platformlanes-20261009"
"$work/lab-current-final" vm lifecycle -manifest lab/images/ubuntu-resolute-amd64.json \
  -first-build "$work/0.2.0/build.json" -second-build "$work/0.2.1/build.json" \
  -apt-repository "$work/repo-final/repository.json" \
  -rejections "$work/rejections-final/fixtures.json" \
  -public-key "$work/0.2.0/lindm-package-signing.asc" \
  -fingerprint 5AC60BB0C3272FB8B51883C5177E74CD6623FF7E \
  -service-execution -diagnostics "$work" -record "$work/ubuntu26-service-final.json"
```

The record SHA-256 is
`4c6f5bcde5b225c335568b6d4893e1827e3e08e9a04c9687033d4060f8b3eefe`,
device `1149fe71-3dfa-403a-8bd8-e14260153fa1`, generation
`b88a7233-d49e-456c-9a78-ef360aac474a`. Five successful package publications each
matched 679 native packages; failed collection retained snapshot sequence 5.
All three real package-authentication rejection fixtures, lost issuance, native
upgrade/reboot/reinstall, corrupt-spool recovery, transport revocation,
missing-journal hold, execution-root rotation/revocation, signed service effects
and authenticated retained service history passed. Session epoch advanced 1→2.
This used lab SHA-256
`ca6d731b44f81bb1ff251139def0db8b9b575cef723dc55b895b966849230ba7`
and shared server SHA-256
`6ade5000200f854012e73d6b87e41f5e4f54ee5fe449d91c8645bf68fffe12ef`.
The two current-tree DEBs were
`09bedd9ec8788786f8d0a4db216f21da2574374912a8479f7dcb428b8a79815f`
and `7d3645d7f286c1ab0a344933bd3f0be846b57c579442693b6e3215951c9e6ec0`.
It predates the subsequent server release-registry gate and native platform/module
field extension; those capabilities are not retroactively claimed by this record.
The earlier 0.1 package run was deliberately cancelled for the coordinated dev
fixture reset and is not a pass (`ubuntu26-service-cancelled.log`, SHA-256
`5422fe35ace4bd6b8b65fa9d129f129774c862a6b182a125ae6e8d1b24954d4b`).

The later Ubuntu 26.04 automatic control-plane trust run did **not** pass.
With current-tree 0.3.0/0.3.1 packages it reached enrolled/upgraded native matches
(679 packages, device `0698dcbc-b453-40e6-b35e-ad1ace985357`), then failed at the
scheduled-reboot SSH reconnect: `unexpected packet in response to channel open:
<nil>`, followed by EOF. No successful JSON record or usable guest diagnostics
was emitted. Exact command/output are retained in
`$HOME/.cache/lindm-platformlanes-20261009/ubuntu26-control-trust-failure.log`,
SHA-256 `a0d46308493a1762acf074c75c4cf2389e6e04ae6ac6a9a7c639d3a1cf0d883f`.
The lab was `lab-platform-release`, SHA-256
`55abb0c74224d4146388b95ae5bfc1340f8a86e130481d0e07eb16dc79e08bcd`;
the version-0.1.0-stamped server was `lindmd-platform-release`, SHA-256
`dcafb9a97e96d7698178203e667de963838d0013fe834c76c230086068ed5ec3`.
`rebootLifecycleGuest` schedules reboot two seconds later, closes the existing
client and immediately reconnects; **[INFERENCE]** the new connection raced the
old boot's shutdown. This remains an unresolved laboratory failure, not a proven
external condition. Completed pre-reboot steps are not a full trust-lane pass.

The 2026-10-10 continuation records remain under that same private evidence root.
Ubuntu 26.04 connected dispatch now **passed**:
`ubuntu26-dispatch-platform2.json`, SHA-256
`a255d80d4df67104f017c4262f3adb8f62a0c681df0d975d50d153ba0ee8e441`,
device `41c6b266-aa7a-42d2-9092-c3494e544767`, generation
`b728b31d-73c3-4199-82c7-10e849c34e3d`. The maintained command was
`lab-reconnect3 vm dispatch -manifest lab/images/ubuntu-resolute-amd64.json
-lindmd ROOT/lindmd-platform2 -record ROOT/ubuntu26-dispatch-platform2.json`,
where `ROOT` is the evidence root. It used lab SHA-256
`6039691c97dc76ccb73d074a2fc459db79e8a7513e9f85fc83e746f6a7550be7`,
server `760ea798e26c3b11a9d0ba5e3c9aa6e024736e3b8d6160c599d27677b0048a46`
and authenticated DEB `9e9c1a595e5998e3ceb17b21ccf079c42177bd2ad992e002a225d89e76aac673`.
Nine native scenarios passed, including both real five-minute periodic checks,
drift remediation, retained open action across server restart, ±90-second clocks
and two-human revocation without effect. The tenth record entry explicitly marks
unstarted supersession as integration-only, **not natively exercised**.
Revocation approval was `3a692e1f-85ca-41ce-afe9-6d15427463d8`.

The reboot harness now waits for the old pinned SSH transport to close and proves
a changed boot ID. Authentication/host-key/permanent channel failures are terminal;
only classified boot transport readiness polls a fresh pinned connection with a
15-second no-effect probe, inside the original five-minute deadline. Fake-transport
and encrypted-SSH regression cases are added; their execution is not yet claimed.
Intermediate attempts are retained: `ubuntu26-trust-reconnect2-failure.json`
SHA-256 `debf52a2e185060b5baa48dd5599020ed4f1afebfe9d5707b45accf90a70769c`
records device `ed4d81ae-9e6d-42a4-9a09-8e211f42d891` reaching upgrade, then
a newly authenticated command channel exhausting its earlier five-minute timeout.
The library's `unexpected packet(nil)` was a closed response channel; the actual
transport/deadline cause is now retained instead of treating it as authentication.

The subsequent 0.3.0→0.4.1 attempt reached device
`bb743e10-a661-4081-a8f9-f02fb4367dfa` and correctly held an incompatible
unreleased development journal after account-lock tables became required.
Per the owner's greenfield/no-pre-release-migration policy, this is fail-closed
evidence, not a product defect or a completed trust pass. The initial escalation in
`ubuntu26-trust-reconnect3-failure.json` is superseded by
`ubuntu26-trust-reconnect3-disposition.json`, SHA-256
`552b14772870a8093c7b1fe7f7acf4f5a4044c2e41b09679c75d2dd9573b9fd4`.
Private diagnostics `lindm-cloud-init-1272581645.json` have SHA-256
`6a3586b3f9d08788e860c35af8ffcf3571dd65ee67d3852c5e7e5d8bd211b83b`.
Upgrade qualification therefore uses same-current-tree 0.5.0→0.5.1 packages.

Ubuntu 26.04 **automatic control-plane trust passed** with that 0.5.0→0.5.1
pair: `ubuntu26-trust-platform2.json`, SHA-256
`8a53652f7a2068710ce07726cb9b337709e6a67091a93b387bb9d4dcb33b6148`,
device `275af9ef-4d9f-436d-88b7-204053f77b62`, generation
`6794dcd6-01a5-4076-b967-4c4adad6134b`. The command used
`lab-platform2-final vm lifecycle -manifest lab/images/ubuntu-resolute-amd64.json
-first-build ROOT/0.5.0/build.json -second-build ROOT/0.5.1/build.json
-apt-repository ROOT/repo-platform2/repository.json
-rejections ROOT/rejections-platform2/fixtures.json
-public-key ROOT/0.5.0/lindm-package-signing.asc
-fingerprint 5AC60BB0C3272FB8B51883C5177E74CD6623FF7E
-control-plane-trust -lindmd ROOT/lindmd-platform2 -diagnostics ROOT
-record ROOT/ubuntu26-trust-platform2.json`.
The lab SHA-256 was
`10be1bbde31f236afa24a4bde709b2441be397f34ecfa80b3ba8dfe3036ed7bf`;
server digest is the same as the dispatch run above. Authenticated DEBs were
`9de6b5a03fdbfb21d6206413aaea552da9a2abb37b356184c9ba8779563582cb`
and `fc74876305398f7ad58c31e9ef09492831151bde702c016067e733ed051f7b22`.
Five native publications matched 679 packages; denied collection preserved
snapshot 5 at attempt 6. Quorum/delegation/epoch rollback rejections, automatic
root rotation/delegate revocation, exact historical retry across server restart,
unchanged TLS identity, no unintended service effects, and reboot/reinstall
retention all passed. Epoch advanced 1→3; revocation and missing-journal hold
passed. This closes the formerly failing Ubuntu reboot/trust lane, not physical,
desktop, air-gap or unrelated platform qualification.

Fedora 43 and both RHEL full lifecycle/trust/dispatch lanes remain unproven at this
point; no matrix requirement is waived.

Focused race tests passed for `internal/custody`, `internal/agent/{config,statefs,
localrpc,serviceprovider,actionprovider}`, `cmd/lindm-agent`, `internal/vmlab`,
`internal/redhatimages` and `cmd/lab`. A root execution of
`TestPeerCredentialRootGroupMembership` also passed all six real-kernel cases,
including primary/supplemental group zero, empty groups and the larger-group-list
allocation path. The final expanded-package golangci run failed on concurrent
recovery/update/Arch/inventory changes outside the custody/registration edits
(`artifact://2624`, 18 findings); a whole touched-package lint pass is not claimed.

Alpine/OpenRC, Ubuntu Core, Amazon Linux, unrelated transactional products, containers
as devices, WSL and arbitrary derivatives are not implicitly included. Unsupported
resources report limitations instead of guessing a provider. Every row's minimum
managed-device gate includes install/enroll/renew/revoke, native inventory, typed
baseline enforcement/drift, native software/OS update, interruption/reboot, agent
upgrade/recovery, encryption inventory/escrow where the topology supports it and
retirement/re-enrollment in both connectivity modes. Desktop rows additionally need
real-session self-service and assistance/consent paths; headless rows need
workload-safe unattended maintenance.
Neither a rolling/atomic/Nix product nor a new mutable distribution is certified by
inventory or package installation alone.

Arch qualification is snapshot-specific, never a claim about a moving `latest`.
The official cloud input is
[`arch-20261001-x86_64.json`](../lab/images/arch-20261001-x86_64.json):
arch-boxes `20261001.604814`, SHA-256
`360f0fa49db6813bdc8e35bed230a2dc2ae3567b7b5ab74719c0a706e4e34e87`,
with the separately pinned Arch Linux Archive repository date `2026-10-02`.
The maintained guest lanes replace the image's rolling mirrorlist before any
package transaction. The immutable image determines initial installed packages;
the Archive pin determines subsequent vendor content. The signed lindm-only
pacman repository is separate and admits no vendor partial upgrade. Promoting
a newer image/repository snapshot requires new evidence; it is a candidate until
the same gates pass, and cannot inherit the previous cell's status. Whole-system
upgrade, interrupted transaction and rollback qualification remain distinct from
agent-package upgrade and cannot be inferred from these lanes.

The pacman inventory collector reads bounded local `desc` records without invoking
a shell, preserves native epoch/pkgver/pkgrel and `any`/machine architecture, and
fails the complete observation on malformed, inaccessible or over-limit input.
Native inspection independently compares `pacman -Q` and `pacman -Qi`. Arch's
absent `VERSION_ID` remains an unavailable observation, not a fabricated version.

| Arch snapshot capability                                                 | Recorded native evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inventory, cloud x86_64 snapshot `20261001.604814`, Archive `2026-10-02` | `~/.cache/lindm-arch-20261010/inspect-fixed.json`, SHA-256 `952222918ef4787b221d926887a4f6dea8ebd15fabcd592145bbf68f0539cf89`: all 184 installed pacman identities and bounded host-detail observations matched independent native queries. Agent SHA-256 `ca18d860e9a7e5494c2caefe8a0e30f4d7e60e3c428df3461f64967a24ee7d8f`; QEMU 8.2.2/KVM, SeaBIOS, virtio-blk, no TPM, no desktop, explicit user-mode egress. No physical, encrypted-install or whole-system upgrade claim.     |
| Packaged lifecycle / dispatch, same snapshot                             | Signed pacman install and service startup were reached, but the control-plane inventory wait expired; no lifecycle pass or dispatch pass is recorded. Private failure diagnostics: `~/.cache/lindm-arch-20261010/lindm-cloud-init-1560727248.json`. The installed executor and network units were active; the observed terminal network diagnostic was connection refusal to the guest-loopback authority forward. This does not establish the cause of the earlier inventory wait. |

Connected service-state qualification also requires periodic compliant rechecks
without start grants and out-of-band drift detection/remediation through fresh start
authority. The maintained `lab vm dispatch` uses the API's five-minute minimum
interval, independent systemctl state and a persistent native-start witness; a passing
initial convergence alone is not continuous-compliance evidence. Server integration
regressions additionally cover stale evidence, exact-result replay, dependency order
and bounded read-only history without deleting granted or unsuccessful actions.

Support follows published vendor maintenance and security-content availability.
Fedora moving-window changes trigger qualification and a communicated transition;
never substitute a prerelease for a GA image. Publish EOL warnings at least 90 days
in advance when vendor schedules permit; continued inventory must not imply continued
security coverage. Entitlement-gated/EUS/ESM branches have explicit rows.

### Resource-kind coverage

Coverage is per resource **and** platform; a shared protobuf vocabulary does not
create native implementations. `S` means specified/planned only; `I` means code
exists but the end-to-end platform contract is unqualified; `N` means a named native
subset was exercised; `Q` would mean full release qualification. `S*` means planned
through that platform's own native model rather than a mutable-distro provider:
writable `/etc` and rpm-ostree layering/deployments on Atomic; configuration
composed into the owner's declaration and activated as a generation on NixOS (only
runtime state is changed outside the generation). `—` means not applicable.
There are currently **no Q cells**.

The code column separates implementation from platform evidence. `N24`/`N26`
identify Ubuntu 24.04/26.04 and `N43`/`N44` identify Fedora 43/44 x86_64 cloud
guests. `N26` and `N43` currently cover baseline host/native-package `inspect`
only, not the expanded inventory-depth contract or a successful packaged
lifecycle. Existing `N24`/`N44` service evidence includes provider, packaged
local execution/history and connected dispatch; continuous-compliance additions
have their own evidence. None covers RHEL/derivatives, aarch64 or desktop workflows.
Exact builds and observed limits are in the
[evidence ledger](implementation-plan.md#2-evidence-ledger).

| Resource kind                                     | Code | Ubuntu LTS | Fedora   | RHEL | Debian/SUSE | Arch/Tumbleweed | Atomic product | NixOS product |
| ------------------------------------------------- | ---- | ---------- | -------- | ---- | ----------- | --------------- | -------------- | ------------- |
| Host and native package inventory                 | I    | N24, N26   | N43, N44 | S    | S           | N Arch; S TW    | S              | S             |
| Systemd service state                             | I    | N24        | N44      | S    | S           | S               | S*             | S*            |
| Device local accounts/groups                      | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Sudo policy                                       | S    | S          | S        | S    | S           | S               | S*             | S*            |
| SSH configuration                                 | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Session/password settings                         | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Firewall                                          | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Time synchronization                              | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Trust stores                                      | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Wi-Fi/Ethernet                                    | S    | S          | S        | S    | S           | S               | S*             | S*            |
| VPN                                               | S    | S          | S        | S    | S           | S               | S*             | S*            |
| DNS/proxy                                         | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Native repositories/packages                      | S    | S          | S        | S    | S           | S               | S*             | S*            |
| OS/security-update lifecycle                      | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Device/user certificates and directory client     | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Recovery escrow, lock/quarantine and sanitization | S    | S          | S        | S    | S           | S               | S*             | S*            |
| Atomic OS deployment/boot/rollback                | S    | —          | —        | —    | —           | —               | S              | —             |
| Declarative system generation/activation          | S    | —          | —        | —    | —           | —               | —              | S             |

Every applicable resource/platform cell is launch-required; inventory and service
state are build-order priorities, and `S` records missing implementation or evidence,
not deferred scope. Debian/SUSE and Arch/Tumbleweed are compact planning columns, **not**
shared qualification: each native backend, vendor, version and snapshot needs its
own executable evidence row. Atomic/NixOS cells reuse the shared typed vocabulary
only where native semantics match; their provider must say how it persists through
deployments or generations before a control is claimed. Bind identity, audit and
evidence metadata across products; do not force package transactions or generated
configuration into a universal mutable-resource API.

#### Generic resource control-plane gate (C0 Phase 1)

The closed resource vocabulary and heterogeneous profile/targeting implementation
do not upgrade any native-provider cell above. The affected acceptance suite uses
isolated real PostgreSQL schemas: cross-kind conflicts, typed dynamic inventory
predicates, scoped device/group targets and exclusions, pinned preview/activation,
stable percentage cohorts, soak/promotion and durable automatic pause. Tests must
also prove configured approval policy cannot be bypassed through preview activation,
stale/unknown dynamic data cannot silently unassign prior resources, and old-head
results cannot refresh a current rollout.

Security regressions distinguish heartbeat-only preview stability from genuine
last-contact membership changes. Rollout coverage separately expires contact,
native receipt age and native validity, and rejects superseded heads/generations.
Authenticated sync and accepted dispatch/start/result refresh contact without
rejuvenating retained native proof; trust and empty-work polls remain read-only.
Concurrent enrollment coverage uses generic profile revisions without bypassing
pending approval or fixed authorization-version fences.

On 2026-10-10 the landed tree passed `make generate`, `go build ./...`,
`go vet ./...`, `npm run build:web`, `npm run typecheck:web`, and unit race
tests for resource, policy, targeting, device, identity, ctl, loadlab and devlab.
Complete real-PostgreSQL race suites passed for device (333.816s), policy
(3.852s), identity (120.417s), targeting (81.840s), integrations (36.911s) and
reports (9.947s), using isolated schemas and the protected migration-role URL.
The post-cutover Ubuntu 24.04 dispatch lane was not started: six host QEMUs
exceeded the authorized start threshold of five. The integration owner retains
that native gate; pre-cutover dispatch evidence is not relabeled as a new pass.

Retained systemd signed dispatch must still pass its existing integration suite
and the maintained Ubuntu 24.04 `lab vm dispatch` lane after the cutover. The server
now stores kind/key identities and shows unsupported nonservice resources and
`baseline_unknown` release requests. Neither status establishes a native effect or
safe restoration. Phase 2 requires independent generic executor/journal/ownership
verification; these schemas alone do not qualify it.

### Capability matrix dimensions

The executable manifest must express distro/vendor/minor, architecture/CPU baseline,
image source/digest/signature, desktop edition/session or headless, provider versions,
network backend, package backend, boot/firmware/Secure Boot, encryption layout/owner,
TPM type, connected/air-gapped mode and scenario selection. A row has owner, evidence
URL/digest, tested product release and status: planned, qualifying, passed, blocked,
failed or retired. Skipped is not passed.

Lock/wipe, encryption recovery and hardware-attestation claims additionally require
hardware model/firmware/media/controller/TPM records. GNOME/KDE tests include logged
in, locked, logged out and multi-user sessions; Wayland and X11 are separate where
actually shipped and claimed. Headless tests have no user bus, display manager or
polkit prompt agent. No graphical-lock requirement applies to a headless system.

### Control-plane deployment matrix

Managed endpoint support does not establish server-host support. Initial target
server hosts are Ubuntu Server 24.04/26.04 x86_64; native package/systemd and OCI/Docker
Compose are independent rows. Pin supported Docker Engine/Compose, PostgreSQL and
host prerequisites in each manifest. Other endpoint platforms do not implicitly
become supported server installation hosts.

| Deployment                                                | Mandatory coverage                                                                                                                                           | Observed status                                                                                                                                                                                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native server package/systemd                             | L01 installation/permissions/restart; L14 migration/upgrade/backup/restore/rotation; L16 complete isolated install/upgrade/restore; single-host L18 capacity | Ubuntu24 x86_64 signed install, explicit migration, LOCAL bootstrap, TLS/401, confinement, restart, same-schema upgrade, backup/destroy/restore and retained-data purge passed; rotation/stale-restore/Ubuntu26/air-gap/capacity remain |
| OCI/Docker Compose single host                            | Same L01/L14/L16/single-host L18, with container volume ownership and image rollback independently observed                                                  | Docker 29.5.0 / Compose 5.1.3 boot, explicit migration, TLS and confinement passed; rollback/restore/capacity/rotation gates remain                                                                                                     |
| Replicated API/workers + HA PostgreSQL + shared artifacts | L14 rolling upgrade/restore fences; L16 isolated HA topology; replicated L18 load/failover/queue fencing and artifact availability                           | Planned, not qualified                                                                                                                                                                                                                  |
| Built-in assistance relay                                 | Local TURN and no-relay/direct variants, certificate/credential rotation and bandwidth limits; L09/L12/L16 consent/termination/relay-only behavior           | Planned, not qualified                                                                                                                                                                                                                  |

Maintained implementation: `lab vm server` selects the pinned Ubuntu 24.04 image
and qualifies signed package installation, explicit migration, LOCAL one-shot owner
bootstrap, verified HTTPS/public surfaces and protected RPC denial, restart,
same-schema upgrade, `pg_dump`/config backup, database destruction/restore and
retained-data purge. The device row in this restore proof is an explicit pending
backup fixture, not enrollment or dispatch evidence. `lab server compose` separately
proves image boot, explicit migration, TLS/role separation and actual non-root
container confinement. Both write immutable new `-record` files; observed runs and
remaining gates are in the [evidence ledger](implementation-plan.md#2-evidence-ledger).
Neither lane substitutes for a browser WebAuthn ceremony, stale-backup security
reconciliation, key rotation, measured capacity or full release certification.

Both single-host rows need connected and air-gapped acceptance. Native
dependencies/hardening/migration invocation cannot be inferred from container
success. Single-host capacity is a measured published limit, separate from the
replicated 100,000-device target. Relay media bandwidth has
its own measured concurrent-session and bitrate gate.

### Authorization and approval boundaries

P03 checks use isolated real PostgreSQL schemas. The role matrix enumerates the
generated AdminService methods so a new RPC needs an explicit authorization case.
Test each built-in role, explicit custom grants, unknown grants, and in/out-of-scope
targets. Fleet filtering assertions compare list pages, counts and exports with the
same scope predicate; target detail and package cursors must not survive loss of
scope. Scope-label and static-group changes must serialize with in-flight mutations
and require authority to change authorization inputs.

Approval scenarios require two real principal records and the actual database
transaction fence: deny self-approval and service-account approval; reject changed
payloads, targets, request IDs, expired requests and either human's stale
authorization version. Exact response-loss retries must preserve the original
approval and one mutation rather than minting replacement authority. Configured
service/trust approvals exercise the same lifecycle as mandatory revocation
approvals. Run `TestAdminRPCDenialMatrix`, the `TestApproval*` and
`TestConfiguredAssignmentApproval` integration tests, and the `TestDeviceScope*`,
`TestDeviceGroupMembership*` and `TestDeviceMutationUsesFreshCapturedScope` tests
together with the identity worker-fence and policy-version suites.

The maintained `lab auth check-fresh` maps a temporary real Keycloak group to a
custom role with explicit permissions and an exact device/label scope. It checks
the captured scope and rejects undeclared account/destructive permissions in
addition to membership removal, disable, version invalidation and commit/rollback.
It needs a fixture generated by the current schema; an older shared fixture is not
silently migrated. Console qualification must separately exercise effective-permission
navigation, account scopes, static groups, a different-human approval, rejection,
expiry, and exact approved execution. Unit/SQL assertions do not replace that
browser evidence.

### L02 external directories, broker lineage and SCIM

`go test -race ./internal/identity ./internal/config` exercises TLS fixture shapes,
real signed OIDC/service JWTs, immutable subjects, Google hosted-domain rejection,
Okta lifecycle states, pagination confinement, quota deadlines and concurrent token
refresh. These are **not live vendor tenant evidence**. Entra, Okta and Google
Workspace still require the exact README setup/operator lifecycle procedures,
recorded separately per provider. Preserve mutation time, first original-directory
visibility and Lindm denial time; only the final interval has the 60-second bound.

`lab auth check-entra -repo . -lindmd FILE -record NEW_FILE` provisions exact
UUID-prefixed test-owned Entra apps, service principals, two users and a group
using the current Azure CLI tenant. It runs real Chromium authorization-code/S256
PKCE login against an isolated migrated `lindmd`, with owner bootstrap by tenant
and object ID. Existing-session protected reads measure direct group removal,
account disable and Graph outage through an owned CONNECT fault proxy; live
upstream propagation is reported separately from the 60-second enforcement bound.
The original owner's session survives across scenarios until the Graph outage.
No mutation scenario performs another login. Records contain cleanup results and
sanitized permission/MFA/conditional-access blockers, never credentials.
`-cleanup-prefix lindm-entra-check-FULL-UUID` removes only exact owned names and
markers after interrupted runs. See the README for prerequisites and broader
tenant cases not covered by this focused command.

Observed 2026-10-10: the signed-in Azure CLI identity had Global Administrator;
real app/user/group creation and application/delegated consent succeeded, as did
isolated server owner bootstrap. The real username/password code flow reached
mandatory MFA. TAP configuration read returned Graph `accessDenied` (the delegated
CLI authorization did not permit this policy read); no policy was changed.
An explicitly authorized no-sandbox lab browser continued into Microsoft's real
security-info software-authenticator setup, but live lifecycle timings are **not
yet qualified**. Record `/home/r/.cache/lindm-entra-live-20261010-18.json`,
SHA-256 `79de84687ba65a5577fa58a9a1b66b79249cd7065b5d1dad43f31433ba2c89f2`,
records the precise sanitized setup stage and complete owned cleanup.
Earlier browser sandbox and MFA blockers remain separate failed records, not passes.

`go test -race -tags=integration ./internal/identity -run SCIM` requires
`LINDM_TEST_DATABASE_URL` and isolated real Postgres schemas. It qualifies connector
correlation/isolation, one-time bearer issuance and rotation, tombstones, conditional
ETags, concurrent mutations and lifecycle fences. It cannot certify a live sender
configuration. Require rename/recycled-email and old-claim resurrection denial;
SCIM group membership must never widen the original directory's authority.

The maintained `lab auth check-broker` uses the real development Keycloak's separate
authoritative upstream SAML realm and broker realm, an isolated database/server,
and test-owned users/groups/clients. It must prove original group removal and
disable during an existing brokered application session, plus unavailable upstream
with a healthy broker, without another SAML login for revocation. Imported broker
groups alone cannot establish freshness. Fixture realm changes require the
coordinated reset described in engineering; do not run reset while another lane
uses the shared IdP. A missing fixture or a pending reset is not a passing result.

The real fixture run on 2026-10-09 (owned prefix
`lindm-broker-check-49dad024-daa5-4e4e-8d37-946fab216fad`) passed all three
revocation cases with three initial signed SAML/OIDC PKCE logins and **zero**
additional SAML logins. Original group removal propagated in 4 ms and removed
active-session grants/denied the protected Admin RPC in 29.764 s; original disable
propagated in 3 ms and denied the session (401) and RPC in 258 ms; upstream outage
with the broker still enabled and grouped denied the session (403) and RPC in
30.009 s. Group removal intentionally leaves an authenticated, grant-free session
(200); the check requires empty role, permissions and bindings **and** a denied
protected RPC, not merely an HTTP success or changed display name. All owned
users, groups and the exact-redirect client were deleted after the run; the
isolated database/server and fault proxy were closed. This qualifies this real
Keycloak fixture, not Entra/Okta/Google tenants or a production SAML IdP.

The full real-Postgres identity suite also passed with
`go test -p 2 -race -tags=integration ./internal/identity`, including SCIM
correlation/tombstone/reactivation/ETag races and the delayed-observation broker
lineage fence. The broker fixture regression tests are included in
`go test -race ./internal/devlab`.

The Accounts console's read-only source panel is a separate browser gate:
unrestricted account management only, no credentials/private paths, configured
freshness bounds, and observation/current state labeled as the signed-in principal
rather than whole-directory coverage.

### L03 unattended, offline and recovery enrollment

Run the real-Postgres identity/device integration suites with an isolated schema
per test. Provisioning coverage must include concurrent same-attempt retries and
competing maximum-use consumers, expiration/revocation and creator-authority
changes, immutable CSR/installation binding, hash-only secret persistence,
lost issuance responses, fixed preassignments and independent approval. A pending
reservation must have neither a usable certificate nor an executable profile
head. A denied or expired approval cannot be bypassed through issuance retrieval.

Recovery coverage must bind two-person approval to the selected device, expected
generation and revocation state. Assert a fresh key, one replacement generation,
old-certificate/session denial, exact interrupted-response replay, competing
replacement rejection and later-revocation fencing. Signed installation conflict
and consumed-predecessor collision must commit recovery hold before returning a
denial; a legitimate next boot of the same installation must not be held.

Offline tests must use real signed authorization/request/response envelopes and
PostgreSQL reservation state. Reject wrong key/deployment/request/digest, expired
or revoked delegation, foreign installation and post-install replay. Exercise
crash-safe root journal import/export rather than treating envelope parsing as an
installed identity. Device file exchange must require no public-service contact.

The [native unattended lane](agent-enrollment.md#native-unattended-qualification)
must pass Ubuntu 24.04 and Fedora 44, plus an approval-required run. It must consume
the cloud-init-delivered token using the installed signed package, report actual
native inventory, retain fixed assignments and reject a third reservation for a
max-uses-two token. Approval mode must deny device authority before approval and
complete the same protected transaction through bounded root resume afterward.
Capture immutable evidence and successful owned-resource cleanup. Unit snippet
tests, compilation, a seed file, or skipped root/VM tests are not native evidence.

Browser acceptance covers all five provisioning formats, component-memory-only
secret handling and teardown, ambiguous one-time issuance, pagination/revocation,
nonself approval and requester execution, the signed offline file pair and
explicit clone/reinstall recovery. A NixOS module must never put a plaintext
provisioning token in the Nix store; verify its target-local encrypted credential
delivery procedure separately from module generation.

The 2026-10-10 Ubuntu 24.04 x86_64 KVM run passed two fresh cloud-init
enrollments, each reporting 665 packages and all eleven network/root privilege
boundaries, fixed label/group/profile assignments, distinct installation/device
identities and exact third-use exhaustion. Run-owned cleanup completed.
Evidence: `artifacts/enrollment-ubuntu2404-unattended.json`, SHA-256
`726e89d0d42e04c4ed79683444923ecce593f6d769c27f1613bc1a42c615849b`.
This BIOS/SeaBIOS, no-TPM, virtio-blk VM evidence is not physical or TPM
qualification.

The Fedora 44 x86_64 KVM approval-required run passed in 45.49 seconds:
two distinct fresh cloud-init installations each remained certificate-free with
no executable profile until independent approval, denied creator self-approval
and premature execution, then resumed with the retained key and reported 429
packages plus all eleven privilege boundaries. Fixed assignments, two-use
exhaustion and owned cleanup passed. Evidence:
`artifacts/enrollment-fedora44-approval-unattended.json`, SHA-256
`4768ce90f0e800da885225fb120a41ea7ad58d7e420905a69cf7c6ce663131f6`.
This run used the same BIOS/no-TPM/virtio-blk VM topology; it does not qualify
physical hardware or the four non-cloud-init installer formats.

The integrated full real-Postgres device suite passed with
`go test -p 2 -race -tags=integration ./internal/device` (268.091 s);
the identity suite passed separately (147.821 s). Following the distinct RPC
response-schema cutover, the provisioning/offline/recovery/installation subset
passed again (35.493 s). `buf lint`, main-tree build/vet, web TypeScript/ESLint
and all six generated provisioning-snippet tests passed. Snippet tests verify
protected credential delivery and shell syntax, not each installer's live behavior.

Real Chromium acceptance used isolated dynamic-origin console fixtures, trusted
development CA validation and user-verifying WebAuthn for two independent owners.
It passed token create/list/revoke, all five explicit snippet downloads, pending
certificate-free reservation/inbox, self-approval exclusion, independent approval
and requester consumption, explicit recovery approval/grant issuance and
secret dismissal/navigation teardown. An admin without the labeled token's
additional `accounts.manage` authority was correctly denied approval. The checks
found and corrected three forms whose buttons needed explicit submit types.
Only theme data remained in local storage; session storage stayed empty, and the
390-pixel layout had no document overflow. Owned browser profiles, downloaded
credentials, isolated servers and databases were removed.

The console fixture lacked explicit `enrollment.offline.v1` signing authority,
so a complete browser-driven offline file pair remains unproven; no trust bypass
was used. The server now reports missing PLAN/START authority as actionable
FailedPrecondition, covered by a passing real-Postgres regression. Actual signed
offline request/response installation, replay rejection and approval are covered
by the PostgreSQL plus root-executor integration suite, not by that browser run.
Browser network-loss ambiguity, scoped pagination and actual cloned-device
recovery consumption remain separate from the exercised browser paths.

## 2. Repeatable laboratory

Use QEMU/KVM with libvirt-managed isolated networks and immutable signature-verified
base images. Each test receives a disposable qcow2 overlay, unique instance/device
identity, fresh secrets, and its own UEFI/NVRAM/swtpm state. Snapshot/restore covers the
whole machine state; a disk-only rollback is not a TPM reset. Tests never enroll the
developer's host, use a production grant, or mutate host networking/disks.

Two image routes are required:

1. Cached official cloud images plus cloud-init/NoCloud for fast agent regression.
2. Actual Desktop/Server installation ISOs for release acceptance: Ubuntu autoinstall,
   Debian preseed, Fedora/RHEL Kickstart, SUSE AutoYaST/Agama as appropriate, Arch's
   pinned installation recipe and NixOS's declarative installer closure. Atomic
   desktops use their actual installer/deployment. Include encrypted install, first
   boot, desktop login, native update/rollback and default security policy.

Use openQA for installer/desktop/boot visual flows instead of maintaining a custom
screen-clicking framework. A Go lifecycle runner owns API assertions, scenario state,
artifacts, deterministic fault injection and libvirt orchestration. Declarative image
manifests and shared providers replace distro-specific ad hoc shell scripts. Thin
installer/package lifecycle glue is versioned and checked where native formats need
it. Tools are pinned; fixtures and license notices accompany redistributed images.

Test packages are built DEB/RPM artifacts from the release pipeline, not `go run` in
a VM. Production TLS/mTLS, migrations and local IdP are exercised. Harness-only
credentials/certificates are clearly isolated; no insecure production mode is used.
The scenario driver may use SSH/serial for out-of-band observation but must not use
that channel to fake a policy result the agent was supposed to produce.

`lab vm encrypted` implements the Ubuntu 24.04 live-server and Fedora 44 Server
DVD routes using the `*-encrypted-*.json` manifests. Its assertions require two
actual serial-passphrase cold boots with different boot IDs, an encrypted root
ancestor, the requested TPM2/absent and Secure Boot states, and complete semantic
LUKS2 metadata equality between guest cryptsetup and a powered-off, read-only
libguestfs appliance. `-record NEW_FILE` contains the signed ISO digest, installer
recipe revision, package-pinned firmware/digests, selected emulated hardware,
boot outcomes and both independent header observations. Unlock/SSH secrets and
raw installer console are never evidence fields. A failed or timed-out boot
is not an unlock pass and an oracle error is not evidence of header destruction.

Observed 2026-10-10: Ubuntu 24.04.5 amd64, UEFI Secure Boot enabled with enrolled
keys, swtpm TPM2 and virtio-blk passed both passphrase cold boots and independent
header equality. The cached-golden smoke completed in 180.64 seconds. Record:
`artifacts/encrypted-ubuntu2404-amd64-secureboot-20261010.json`, SHA-256
`e21191c8b7b149299f6f51b1e7164d239271c047772ced0d8114d4a2c5e1dc69`.
This record uses the stock initramfs and no desktop; it does not qualify TPM-token
unlock, recovery-key rotation, wipe, Fedora, ARM or the Secure Boot off variant.

Fedora 44 Server amd64 with real GNOME packages and the TPM-capable dracut stack
passed the same two cold boots, TPM2/Secure Boot observations and independent
LUKS2 header equality in 118.46 seconds on 2026-10-10. Record:
`artifacts/encrypted-fedora44-x86_64-secureboot-qualified-20261010.json`, SHA-256
`f8b5fe1c35c8cbb242628aa26d5760b9234e36ee5f3b6991b450d5b8209f9866`.
Its initial installer run published the golden but the first smoke exposed an
immediate-shutdown SSH exit-status race; the retained failed record is
`artifacts/encrypted-fedora44-x86_64-secureboot-20261010.json`. The qualified run
uses an acknowledged shutdown timer and requires successful QEMU termination.
Installing a TPM-capable stack does not itself qualify TPM enrollment or unlock.

Run Secure Boot on/off variants explicitly with matching package-owned NVRAM
templates. `-tpm=false`, `-storage-bus`, `-extra-disks` and the shared inventory
hardware options expose absent TPM, SCSI/virtio/NVMe/SATA and multi-disk variants.
Native QEMU controller capabilities, including Format NVM/Sanitize support or
refusal, must be observed separately; selecting `nvme` does not certify either
operation. ARM EFI/TCG cloud guests provide architecture coverage rather than an
x86 result relabeled ARM. Real GNOME/KDE installer-package variants and their
private VNC displays provide session-test inputs, not an assertion that lock,
consent, Wayland or remote assistance already passed.

Virtual evidence explicitly records emulation and is never physical L15 evidence.
Recovery-VM target attachment isolates an off-target journal from the disk under
test; the journal disappears when that owned recovery VM is deleted unless the
calling lane exported evidence first. Cloned golden disks and stored golden
passphrases are intentional recoverable lab copies: deleting a test keyslot cannot
establish fleet-wide crypto-erase or destruction of escrow/header backups.

The maintained CLI lane is `go run ./cmd/lab cli check -root . -record NEW_FILE`.
It requires the running development server and real Keycloak fixture, drives
explicit browser approval and the actual client loopback/S256-PKCE exchange, and
asserts owner `whoami`, a bounded AdminService read, logout and revoked-token
denial on both surfaces. Optional `-lindmd FILE` uses an owned migrated database
and real server instead, requiring the console port to be free; neither mode
resets or stops shared development dependencies. Evidence is nonsecret JSON
created exclusively with mode `0600`, never passwords, tokens, cookies or PKCE
verifiers. A successful recorded run qualifies this Keycloak path only, not full
L12 CLI/UI parity or local-mode browser authentication. Local-mode evidence must
combine the existing real-database software-WebAuthn identity integration with a
separately exercised manual browser login/approval flow; no live local-mode result
is claimed by this lane.

### Integration delivery and archive regression lane

`go test -race -tags=integration ./internal/integrations ./internal/reports`
uses real PostgreSQL isolated schemas through `LINDM_TEST_DATABASE_URL`, never the
public application schema. Local HTTPS and TLS-syslog receivers bind dynamic
loopback ports and independently validate HMAC and octet-counted RFC 5424 frames.
The lane exercises outbox rollback/redaction, two-worker `SKIP LOCKED` claims,
expired-token fencing, retry/backoff, dead-letter ordering/replay, secret rotation,
untrusted TLS/redirect refusal, and destination mutation/version receipts.

Report acceptance independently checks manifest signatures for Ed25519,
ECDSA-SHA256 and RSA-PSS-SHA256, the externally pinned key, artifact digest, chain
links and continuation checkpoints. PostgreSQL regressions cover serial head
capture/rollback, immutable audit records, schedule/artifact leases, atomic chunk
publication, retention and revoked scheduling authority. Compliance regressions
cover pending-only dependency propagation, transactional event rollback and
once-only stale transitions. Protected integration-key file failures are covered
by `go test -race ./internal/config -run TestIntegrationEncryptionKeyProtection`.

These receiver/database tests do not establish browser accessibility, actual
third-party SIEM indexing, large-fleet capacity, geographic HA or external archive
key-custody policy. Console qualification must exercise create/edit/disable/delete,
write-only rotation, ambiguous-response exact retry, dead-letter replay, schedule
changes and artifact/manifest downloads under allowed and denied identities.

### L11 distro advisory classification

`go test -race ./internal/advisory/...` checks 43 native dpkg, 91 RPM and 46 libalpm
upstream comparison vectors plus genuine pinned vendor data. Source URLs, digests,
licenses and extraction provenance accompany `internal/advisory/feed/testdata`.
The PostgreSQL lane is `go test -race -tags=integration ./internal/advisory/...`,
using isolated `testdb` schemas and `LINDM_TEST_DATABASE_URL`. It exercises
Ubuntu/Fedora/Debian/Rocky/Alma/SLES/Leap/Arch backports and genuine Red Hat
mainstream, EUS/module and E4S fixes. Controlled installed versions and enabled
repository fixtures are boundary regressions, not claims of historical VM installs.
Debian source/binary-version divergence, undetermined/not-affected/open-no-DSA,
nullable publication dates, module mismatch and signed-snapshot age persistence
have dedicated cases. Existing atomic publication, unchanged-byte reconfiguration,
fresh/stale inventory/feed, scoped counts, pagination and exception replay remain.

Retained Red Hat and SUSE detached signatures are checked against pinned genuine
vendor keys. Negatives mutate the decoded RSA signature integer and rearmor it;
changing only an OpenPGP packet-length header is not an authentication mutation.
Payload corruption, wrong signer, revoked key, future time, malformed/multiple
signatures, checksum mismatch and second-archive failure must not publish
provenance or leave temporary files. Full live weekly-corpus ingestion is distinct
from the deterministic retained-record/archive-container tests.

The real-inventory replay is `go test -race -tags=integration ./internal/device
-run 'TestAdvisoriesMatchRecordedNativeInventory|TestAdvisoryAcceptanceFreshActorScopeAndDurableRetry'`.
It publishes the retained generated-schema PackageBatch fixtures through the real
device begin/put/commit RPCs, ingests pinned vendor subsets and reads admin findings
from PostgreSQL. `internal/advisory/testdata/provenance.txt` binds the exact selected
records to native-oracle runs, full observation hashes and pinned image/agent hashes:
Ubuntu noble's installed OpenSSH `1:9.6p1-3ubuntu13.19` is beyond USN-6859-1's
backported `.3` fix; Fedora 44's actual sudo `0:1.9.17-7.p2.fc44` is affected by
FEDORA-2026-7d4732cbab until `0:1.9.17-10.p2.fc44`. The maintained `lab vm inspect
-inventory-record NEW_FILE` runs independently matched all 664/427 native package
records respectively. These are x86_64 KVM/SeaBIOS VM observations, not physical
hardware or desktop-session certification. Receipt/collection timestamps are
controlled only in deterministic replay, never substituted for the recorded package
versions. Selected advisory subsets still report UNKNOWN for incomplete coverage;
the fixed Ubuntu packages do not imply that the entire device is clean.
The console must display both independent freshness clocks and distinguish
accepted risk from a native fix. A third retained replay binds actual RHEL 9.8
`openssl-libs` `1:3.5.5-2.el9_8` and native module/platform evidence to the maintained
490-package oracle run. The package exceeds RHSA-2024:6783's genuine
`1:3.0.7-28.el9_4` backport. That guest was unregistered, with no enabled repositories:
the real RPC replay therefore requires `rhel_platform_stream_unavailable`, not
invented EUS/mainstream entitlement. Controlled database stream fixtures are
explicitly separate. This lane does not certify subscription entitlement, arbitrary
module contexts, a full live weekly corpus, full offline-bundle custody, SCAP
tailoring or automatic package remediation.

## 3. Acceptance scenario families

Each family maps to product requirement IDs. Individual deterministic tests must
assert externally meaningful results, not merely process existence or successful RPC.

| ID                               | Scenarios and required result                                                                                                                                                                                                                                              | Evidence surface                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L01                              | Fresh single-host server installation, first-owner binding, restart and invalid configuration                                                                                                                                                                              | Actual installer/console/CLI; same pinned owner bootstrap is idempotent, replacement owner denied; persisted state recovered                                                                                                                                                                                                                                                                                                                                                 |
| L02                              | Real Keycloak/Entra/Okta/Google and SAML broker login, MFA/step-up, SCIM correlation, upstream disable/group removal during direct and brokered sessions without re-login, healthy broker with stale upstream, source outage, rename/recycled email                        | Original-directory propagation and local enforcement measured separately; no freshness reset from broker imports, stale-claim resurrection, source ambiguity or permissions beyond bound                                                                                                                                                                                                                                                                                     |
| L03                              | Package enrollment, lost secret-issuance response, redaction/hash-only persistence, grant race, lost cert response, TPM/software key, renewal/revocation, cloned image and reinstall                                                                                       | Retry never recovers a bearer secret or creates a second credential; distinct device generation, correct denial and no secret in database/audit/outbox                                                                                                                                                                                                                                                                                                                       |
| L04                              | Native hardware/OS/package collection, absent serial, package epochs, pagination/filters, delta duplicate/out-of-order ingestion, stale/offline device                                                                                                                     | Guest truth compared with API/export; stale evidence never compliant                                                                                                                                                                                                                                                                                                                                                                                                         |
| L05                              | Profile preview/conflict/drift, trust bootstrap and quorum rotation, tampered/stale trust and plans, missing/corrupt executor journal, compromised network-process replay and restart during apply                                                                         | Actual state/revision, root-only replay fences and fail-closed recovery; unknown capability or trust never becomes privileged execution                                                                                                                                                                                                                                                                                                                                      |
| L06                              | Native package/image/generation and repository transactions, invalid signatures, dependencies/locks/interruption, device/person catalog entitlements and UID/account reuse                                                                                                 | Native package database or booted generation and application health; no partial Arch upgrade, mutable-image overwrite, unapproved source or cross-person install                                                                                                                                                                                                                                                                                                             |
| L07                              | Patch/advisory rings, canary pause, maintenance window/DST, desktop deferral/deadline, server availability budget, kernel update and reboot inhibitor                                                                                                                      | New boot/kernel and workload health, not just agent reconnect; no reboot outside policy                                                                                                                                                                                                                                                                                                                                                                                      |
| L08                              | Agent install/upgrade/failed-upgrade recovery, purge/reinstall, journal migration, owner-safe config removal, supported OS upgrade or reinstall migration                                                                                                                  | Package/service/filesystem state and preserved/rotated identities as specified                                                                                                                                                                                                                                                                                                                                                                                               |
| L09                              | GNOME/KDE sessions, built-in support consent/indicator/local stop/input, self-service/notices, Wayland/X11 as claimed, UID reuse/shared-device/ownership transfer, suspend/resume and accessibility                                                                        | Actual session evidence and isolated person binding; lock/logout/revocation terminates support; no tray or unattended-control dependency                                                                                                                                                                                                                                                                                                                                     |
| L10                              | Network rollback, EAP-TLS/VPN, firewall, certificates/trust/SSSD, account controls, encryption escrow and person-certificate binding/deprovisioning                                                                                                                        | Real credential/network behavior and cold-boot recovery; no cross-person secret or competing native owner                                                                                                                                                                                                                                                                                                                                                                    |
| L11                              | Compliance pass/fail/error/unknown/N/A, expiring exceptions, SCAP tailoring/content, distro backports/epochs, stale or conflicting advisories                                                                                                                              | Native findings linked to content/version/freshness; no false healthy status                                                                                                                                                                                                                                                                                                                                                                                                 |
| L12                              | CLI/UI parity, idempotency, webhooks retry/signature/dedup, export access, typed diagnostics, bounded scripts and consent-controlled remote support                                                                                                                        | Receiver/user-visible outcomes, consent termination, redacted support bundle and action audit                                                                                                                                                                                                                                                                                                                                                                                |
| L13                              | Approval separation, changed targets/authority, executor challenge replay/expiry/restart, restore epoch and actual lock/quarantine effects                                                                                                                                 | No high-risk start without a fresh verified one-use grant; the bounded residual authorization window is measured                                                                                                                                                                                                                                                                                                                                                             |
| L14                              | Migration under traffic, DB/worker crash, both server installation modes, restore hold/epoch, revoked identity, key rotation/loss, audit/retention                                                                                                                         | Usable restored system with fresh authority; no stale destructive replay or revived directory access                                                                                                                                                                                                                                                                                                                                                                         |
| L15                              | Real TPM/Secure Boot/recovery, lock boundaries, authenticated recovery-media handoff, wrong target/expiry/power loss, off-target state, sanitize/reinstall and key-copy implications                                                                                       | Physical signed evidence and separate verification/validation; lost state/report stays unknown rather than restarting wipe                                                                                                                                                                                                                                                                                                                                                   |
| L16                              | Full isolated management LAN with public egress blocked, local IdP/DNS/time/PKI, signed content import, expiry/replay/corruption and missed key rotation                                                                                                                   | Network capture/deny counters and successful offline lifecycle; no disabled integrity checks                                                                                                                                                                                                                                                                                                                                                                                 |
| L17                              | Cross-version contracts, generated code and two-clean-builder unsigned release-payload digest equality, TUF/freeze/rollback, native package/image trust, provenance/SBOM/licenses                                                                                          | Both build manifests and comparisons plus actual installed release artifacts; signatures/attestations verified separately from deterministic payload equality                                                                                                                                                                                                                                                                                                                |
| L17 release archive matrix       | Passed two isolated clean source/HOME/Go/npm cache builds of all three products × amd64/arm64 × DEB/RPM, plus server/CLI OCI; complete unsigned archive equality and separate native/DSSE verification                                                                     | `artifacts/release-matrix-20261011.json` SHA-256 `dd92786edd9b97e2f8289b9d921ecb23c33edbdf42c5369199f8952117f8f668`; adjacent DSSE `270e32716f2e17609dd8abb73ebcfa1b34d764236606c08aa424ba1dbf9fde08`. Export includes dependency SBOMs, provenance and explicitly pinned OCI CA bytes. Development keys/CA, same host/toolchain; does not qualify native update transactions, independent builders, license approval or physical hardware.                                  |
| L08/L17 unattended native update | **Not yet qualified.** Maintained Ubuntu/Fedora lane exists; Ubuntu exercised real pause/cohort and signed rollback/mix/freeze rejection. Native target tampering, successful update, interrupted unpack/boot recovery and downgrade refusal still require a complete run. | Attempt3 SHA-256 `8ef175661774ebfa6bd0ffe9cc46bffcae9e6e3273aef8662f6b6a76f6e002e7` and attempt4 `fbb4df4e4423b0a7e21a88ca6c94389131ec606aed327525519df4c4480969dd` in `artifacts/updates-ubuntu-20261011-attempt{3,4}.json` retain failures. Isolated-bootstrap selection and large-target fixture bounds were corrected with real/focused regressions. Attempt4 lost pinned SSH; further VM starts were suspended by the parent under host overload. Fedora remains unrun. |
| L18                              | Single-host and replicated load/soak, reconnect storm, storage full, queue fairness and worker/DB failover                                                                                                                                                                 | Workload manifest and measured budgets from security/operations; accepted work preserved                                                                                                                                                                                                                                                                                                                                                                                     |
| L18 single-host launch gate      | Maintained `lab load`: real lindmd/disposable PostgreSQL, grants/mTLS, jittered sync/trust/work, full snapshots, signed service cycles; explicit CPU/pool/storage and iostat/QEMU evidence                                                                                 | Durable co-resident baselines and WAL-pressure failures are documented in security/operations. `artifacts/load-isolated-tmpfs.json` (SHA-256 `8efe8ec08315276197d527618050035deeb4b0147215195ce991ab4fd1e7c193`) passes only the completed non-durable 5,000-device plateau; 10,000 interrupted by parent scheduling directive. Dedicated tmpfs and NVMe fixture integration passes, not capacity qualification. Isolated durable ramp, two-hour soak and HA remain open.    |

### Fault injection and oracle requirements

Inject actual process kills, VM power cuts, network partitions, DNS failure, proxy
failure, TLS expiry, clock skew, exhausted disk/inodes, database disconnects and
package-manager locks. Inject at durable state transitions, not only between happy
path steps. Report whether a transaction can be retried, needs reconciliation, or
requires human recovery. Exercise schema incompatibility and rollback without
silently resetting the database/journal to make a test pass.

Native truth is the oracle: package database/application health, service readiness,
boot ID, network reachability, actual credential acceptance, unlocked data and desktop
effect. The API must report those observations correctly. A mocked agent echoing its
requested values proves nothing about Linux enforcement.

P05 inventory-depth qualification uses the maintained `lab vm inspect` lane with
the pinned Ubuntu 24.04 and Fedora 44 manifests. Its independent native oracle
must compare the CPU/memory, storage/filesystem/encryption, interfaces,
firmware/Secure Boot, TPM, chassis/battery, logind counts, local accounts,
kernel-module and uptime/boot observations, plus backend availability and
Flatpak/Snap applications. Dynamic comparisons bracket the agent run: available
memory tolerates the greater of 64 MiB or 5% of total RAM, uptime/boot timestamps
two seconds, and battery charge one percentage point. Other changing truth produces
no collector verdict. Absent firmware, TPM, battery or application backends remain
absent/unsupported, not fabricated successful data. This does not qualify
encryption recovery, TPM custody, desktop surveillance or application installation.

`lab vm inspect -inventory-record NEW_FILE` optionally retains the exact validated
`NativeObservation` protobuf JSON after successful comparison and complete owned
VM cleanup. The file is create-only, mode `0600`; the ordinary run record binds
its absolute path and SHA-256 to the pinned image and agent digests. This opt-in
record contains local account and network identifiers and requires appropriate
retention/access handling. Default run records retain counts/statuses, not these
identifiers.

The same inspect oracle accepts the shared emulation options: `-tpm`,
`-storage-bus nvme|sata|virtio-scsi|virtio-blk`, `-extra-disks`, explicit pinned
EFI code/variable files and package version, and `-secure-boot`. Requested TPM2,
firmware and Secure Boot state are checked in the guest; Secure Boot also requires
SetupMode to be false. `-encryption-fixture luks1|luks2|lvm-luks2` formats only
the serial-pinned disposable extra disk and asserts the resulting layers. Guest
`cryptsetup`, `wipefs`, `mkfs.ext4` and, for LVM, its native tools must already be
available. The lane does not silently install guest prerequisites. Matching
aarch64 image/agent inputs use explicit ARM EFI and may use `-accelerator tcg`.
These are emulated observations, not physical-media, TPM-custody or Secure Boot
certification; `-display-device` provides a GPU/private VNC, not a desktop install.

#### Inventory hardware observations (2026-10-10)

The following independent `lab vm inspect` comparisons passed on pinned Ubuntu
24.04 snapshot 20260926 and Fedora Cloud 44-1.7. Each compares firmware/Secure
Boot, TPM presence/version, CPU/memory, block topology/filesystems/encryption,
native package identities and the remaining typed native details. Disk counts
below exclude the NoCloud seed. Roots are unencrypted; extra disks are blank,
with unavailable filesystem/encryption observations rather than invented values.
This does not qualify encrypted-root or physical-media behavior.

| Guest / architecture | Firmware / Secure Boot             | TPM       | Root bus / data disks | Packages matched | Dimension                             | Record filename / SHA-256                                                                                           |
| -------------------- | ---------------------------------- | --------- | --------------------- | ---------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Ubuntu 24.04 x86_64  | OVMF UEFI / enforced, SetupMode=0  | swtpm 2.0 | NVMe / 1              | 664              | KVM, emulated; physical=false         | `ubuntu-amd64-secure-tpm-nvme.json` / `3d6d7cd22e9f185d0b62ed9ba1c4a50d315e993c6cdc4580df709faf53184f91`            |
| Fedora 44 x86_64     | OVMF UEFI / enforced, SetupMode=0  | swtpm 2.0 | NVMe / 1              | 427              | KVM, emulated; physical=false         | `fedora-amd64-secure-tpm-nvme.json` / `ddcf5855ac2a80f2592018b45f1284c7fdf3e80a22f9c88073abea5cac3d05c8`            |
| Ubuntu 24.04 x86_64  | OVMF UEFI / disabled, SetupMode=1  | absent    | SATA/AHCI / 1         | 664              | KVM, emulated; physical=false         | `ubuntu-amd64-off-notpm-sata.json` / `2012729f3e141fa14632c94bcfb4e6435f17e2f0ca12d4cf3ef9a1839935f5f4`             |
| Fedora 44 x86_64     | OVMF UEFI / disabled, SetupMode=1  | absent    | SATA/AHCI / 1         | 427              | KVM, emulated; physical=false         | `fedora-amd64-off-notpm-sata.json` / `c7943a60e7c45b85f77b61b65eb530619c8cce309d7114951aaf48b0182296ce`             |
| Ubuntu 24.04 x86_64  | OVMF UEFI / disabled, SetupMode=1  | absent    | virtio-scsi / 3       | 664              | KVM, emulated; physical=false         | `ubuntu-amd64-off-notpm-scsi-three-disks.json` / `9bbc6127e2fdd9d5acb749af73055af4c5b085c16abe5b7ff5222a616d463398` |
| Fedora 44 x86_64     | OVMF UEFI / disabled, SetupMode=1  | absent    | virtio-scsi / 3       | 427              | KVM, emulated; physical=false         | `fedora-amd64-off-notpm-scsi-three-disks.json` / `c6052e2fb1c48252ee63279c89f552971ac9e28d52b9f0ea107ebedbfae79bec` |
| Ubuntu 24.04 aarch64 | AAVMF UEFI / disabled, SetupMode=1 | absent    | virtio-blk / 1        | 663              | TCG, 2 vCPU, emulated; physical=false | `ubuntu-arm64-off-notpm-virtio-tcg.json` / `cab966ad113fff699c508421ab8e39dc361c887ea43b6269b01e2f025518ddca`       |

Records reside in `~/.cache/lindm-hwmatrix-2026-10-10/`. The x86 runs bind agent
SHA-256 `21decd5e202d60a6f4bf35373817dcb0fdeb9cbec890eb1e94123aaeaea5c797`
and lab SHA-256 `6940862609c031ebd090250c13fdf3f9474e1e6913828cdf311313ad8561bd8b`.
QEMU is 8.2.2; package-pinned OVMF is `2024.02-2ubuntu0.10`, with exact firmware
digests in every record. Both variants use Secure-Boot-capable
`OVMF_CODE_4M.secboot.fd`; enforcement uses enrolled `OVMF_VARS_4M.ms.fd`,
while disabled uses unenrolled `OVMF_VARS_4M.fd`.

The initial Ubuntu off/SATA attempt used non-Secure-Boot `OVMF_CODE_4M.fd`:
both collector and oracle reported SecureBoot unavailable, so requested disabled
correctly failed. This was incorrect lab firmware selection/documentation, not a
product collector defect. The retained first-failure JSON has SHA-256
`62b0dc34bd8bc66acbdc676a08a37f66e9c1ac63acf425b3fc1f8636c16879b5`.
No missing-variable result is promoted to disabled.

The ARM row uses the separately verified arm64 cloud image and GOARCH=arm64
agent SHA-256 `c9308cd833ceb59b2e72aad9953d06c703d107b307521315ce49ef0310ddeba7`,
lab SHA-256 `fb9df1860c37d4f2179f5ace73f71263ecf192f4cbccdef90a5b7cd1afab8c78`,
and package-pinned AAVMF `2024.02-2ubuntu0.10` (`AAVMF_CODE.secboot.fd` /
`AAVMF_VARS.fd`). Its independent comparison passed in 462.95 seconds; ARM
CPU model and x86 ISA level correctly remain unavailable rather than fabricated.
Two earlier attempts failed before collector execution because SSH authentication
did not imply first-session readiness: the firmware probe's ten-second
channel-open deadline expired. The shared lab fix proves one quiet command under
the existing bounded boot-readiness deadline, without retries; a real encrypted
SSH regression rejects authentication followed by first-channel failure.
Retained first and diagnostic failures have SHA-256
`057f0b73d891afa44859394d18d234784cce0f046dae10a6a5039d2e39391974`
and `d1bb82b1701393903cb3140a2fbc648695e600bd9523132b07fdb0b67cd84e9e`.
The evidence directory's `SHA256SUMS` binds each record and all three lab builds.
No product collector defect was found in these seven hardware variants.

Final matrix quality-gate attempts passed the inventory race package (cached),
but shared `releaseupdate` edits blocked vmlab compilation/lint: initially
unchecked two-result `key.ID()`, then an unused `os` import in `mirror.go`.
These are not hardware-oracle failures; vmlab race and focused golangci-lint
remain required after that independent work lands. `quality-gates.json` retains
the commands and failures; no package-wide lint pass is claimed here.

Collector regressions retain captured Linux procfs/sysfs fixture provenance.
Real-PostgreSQL inventory regressions additionally cover latest typed-status
replacement, replay conflicts, source-package identity, JSON-expansion response
bounds, metadata typing and scoped search/export cursor behavior. A passing
collector fixture test or database test does not replace either guest comparison.

### Encryption and imperative-action evidence (L10, L13, L15)

Run the maintained action lane on disposable installer-encrypted Ubuntu 24.04
and Fedora 44 guests using the actual packaged root executor and its installed
per-target sandbox exception. A private real-PostgreSQL control plane and two
distinct local WebAuthn users provide plan approval and reveal authority; native
setup commands cannot substitute for the action API effects being qualified.
Record package/server/image digests, firmware and TPM state, device topology,
action/approval IDs, native before/after evidence, boot IDs and exact fault point.
Do not retain plaintext owner or revealed recovery credentials in the evidence.

The maintained entrypoint is `lab vm device-actions`. For the baseline Ubuntu
installer and matching cloud recovery environment:

```sh
artifacts/bin/lab vm device-actions -repo . \
  -manifest lab/images/ubuntu-noble-encrypted-amd64.json \
  -recovery-manifest lab/images/ubuntu-noble-amd64.json \
  -lab artifacts/bin/lab -lindmd artifacts/bin/lindmd \
  -firmware-code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.ms.fd \
  -firmware-package ovmf -firmware-version 2024.02-2ubuntu0.10 \
  -secure-boot -record device-actions-ubuntu24.json
```

Use the installed firmware's actual package/version and the corresponding Fedora
encrypted/recovery manifests for Fedora qualification. The lane builds real guest
packages, configures a GNOME installer and TPM-capable boot stack without a
prebound token, then uses sequential disposable clones, with at most one active
guest. `-storage-bus`, `-architecture` and `-accelerator` select the shared VM
hardware contract; unavailable signed installer/firmware/architecture combinations
are errors, not emulated passes. A native device lacking the required stable
identity is refused rather than assigned an invented serial or WWN.

For separately attributable wipe records use `-scenario wipe` with
`-wipe-phase lock-quarantine`, `live-erase`, `live-report-loss`, `recovery-nvme`
or `recovery-sata`, and a new `-record` path for each invocation. Omitting
`-wipe-phase` runs all five phases sequentially. Recovery-only phases use the
original cloud-installed disk and do not require an encrypted installer golden.
Live-root erase retains its own escrow/reveal and pre-erase cold-boot proof; the
reported-result phase also rejects self-approval, expired approval and a changed
complete-target-set ordering at real server start authorization. A phase record
does not certify omitted phases.

The 2026-10-10 wipe qualification records under
`$HOME/.cache/lindm-wipequal-20261010/` have **not passed**. The continuation ran
every requested phase; these are failure records, not destructive qualification:

| Record                            | SHA-256                                                            | Observed boundary                                                                                                              |
| --------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `ubuntu-live-erase-05.json`       | `8a64121e4db78b168b7599f1698c29ed2926601c2ae6e827e10b2b18ee5b37ad` | Real root escrow succeeded; second action creation rejected stale device presence.                                             |
| `ubuntu-live-report-loss-01.json` | `c933e1c26d5a6a819493c572ea5cd88adb1b22c86a1f8aa66d924ea63f4f576b` | Root/data LUKS identities established; artificial relay restart failed before erase.                                           |
| `ubuntu-recovery-nvme-12.json`    | `6425bd3b012d27fd4ec8e747243104fbc5e640716e28a8424fbe5c8a64141b7c` | Signed ordinary boot, recovery UKI/closure and two-human approval established; relay start-limit hit before recovery dispatch. |
| `ubuntu-recovery-sata-01.json`    | `37984f63a7942d18d5f6dca556c5ae6dacebd4f649862e7ec37ca1c1110338ad` | Signed recovery image and two-human approval established; same dispatch restart failed.                                        |
| `ubuntu-lock-quarantine-02.json`  | `0bf8edad98e3ffb5815de567202da7f967a73847685b61b646983f1d41aaeb52` | Desktop readiness deadline expired before lock/account/quarantine effects.                                                     |
| `fedora-live-erase-02.json`       | `14b3f2416533882ef77632d5cdf8fd4bf5ba2948dc6ebbdfe4ac3c0aa3c5a78e` | Qualified GNOME/TPM golden booted; root/data identities established, then secret delivery failed.                              |

Sanitized journal diagnoses are in `diagnoses-20261010.json`, SHA-256
`9a9096f17e2c421e9ba2e3874a0a689bd36b083c409b49fc8e7e7e81f5ab463e`.
Native Ubuntu journals prove harness-induced `start-limit-hit` (six relay starts
within the packaged five-per-minute limit); the runner now uses the continuous
management loop instead of restarting it per action/credential. Fedora journals
prove enforcing SELinux refused D-Bus receipt of an SSH-labelled stdin pipe.
Native secret commands now use a local transient scope, with no-core/no-swap and
exact exit-propagation preflight, rather than weakening SELinux or writing keys.
Recovery staging is recreated after the owned-boot transition and the actual
mounted FAT ESP UUID is supplied to the signed artifact builder. Fresh LUKS
formatting explicitly publishes and settles its udev identity before observation.

Historical enrollment/trust SSH timeout records had already deleted their guest
state; no surviving serial/journal proves their cause. Current enrollment runs
passed that boundary. Host contention is an inference, not a demonstrated SSH
cause: the nearby `artifacts/load-ramp-readonly-pool8.json` record (SHA-256
`8e9ee09264bacf4035f571ed84841cb3ca4701a110d3b29248f924bc4a5b7a78`)
ends at 00:51:37 UTC, before the old failures completed. The runner now preserves
bounded private post-unlock serial plus independent pinned-SSH unit/kernel
diagnostics on failure, and retains the last completed trust/desktop observation
when an outer polling deadline closes the SSH transport. No retry, longer action
deadline or erased failure is treated as evidence.

For encryption-only qualification use `-scenario encryption` and a distinct
`-record` path. This excludes desktop/network restrictions and destructive erase.
The record compares public server keyslot/token inventory with stopped-disk
host inspection, verifies actual KEK-protected custody and committed reveal audit,
rejects missing reason, restricted-reader permission and expired real step-up,
boots with approved revealed keys, rejects a retired key at the serial prompt,
and requires both root and server `outcome_unknown` after interrupted rotation.
TPM qualification compares the bound token to the host oracle and requires
unattended cold boot followed by PCR7-policy rejection and a cold recovery boot
with a separately escrowed, two-human-revealed key. Native token blobs, raw
headers and recovery keys are never written to this evidence. The real five-minute
step-up expiry is intentional, not a test clock override.

Ubuntu24 run `ubuntu24-encryption-04.json` under
`$HOME/.cache/lindm-encryptionqual-20261010/`, SHA-256
`2a08c5003cdd14028ea0da65ab506d11efd14e6d302efe45a1df8fc552c2663d`,
passed native inventory/host header comparison, actual KEK custody and audited
two-human reveal, dedicated permission/reason/expired-step-up denials, revealed
recovery and retired-key cold boots, committed rotation, and hard-crash recovery
with both old/new keys. Owner/old/new slots `[0,1,2]` survived; root and server
converged to `OUTCOME_UNKNOWN`. The overall record is **failed**, not full
qualification: TPM bind admission rejects actual native version `2` because the
server predicate expects `2.0`. Unattended TPM and PCR fallback remain unproven;
Fedora action qualification remains unrun despite its ready GNOME/TPM golden.

The initial 2026-10-10 Ubuntu encryption invocation is a **failed** prerequisite
record, not action qualification: `$HOME/.cache/lindm-encryptionqual-20261010/ubuntu24-encryption-01.json`,
SHA-256 `ccd7a5a40691dbe51e664f7f61f62a622510561e8311d974ac9f9ed6dbea5b29`.
It stopped before enrolled action evidence on unexpected package-install stderr;
the maintained helper now checks the actual install exit status.

Prerequisites are current development PostgreSQL/trust fixtures, prebuilt lab and
server binaries, QEMU/KVM, swtpm, matching OVMF, xorriso/mtools, libguestfs with
cryptsetup, and access to the guest's signed package repositories. An unusual host
kernel layout may require `SUPERMIN_KERNEL` and `SUPERMIN_MODULES` to name a matching
existing kernel image and module tree; the lane does not modify host boot state.
Evidence must identify its execution mode: original-device live-root LUKS erase,
original-device signed recovery handoff, or the separately provisioned
external-operator recovery environment. The last mode cannot satisfy the remote
wipe requirement for a lost or stolen original device. Live-root qualification
requires both successful attestation before forced power-off and a deliberately
blocked-report case that still powers off and remains unknown at the server.
Each must independently demonstrate absent raw headers and failed cold unlock
with previously valid owner/recovery credentials. Recovery handoff qualification
must exercise the original device on SATA and NVMe, exact signed-image/media
bindings, fresh post-boot authorization and durable off-target consumption.
`-record` exclusively creates nonsecret evidence; the presence of this command or
an unexecuted scenario is not a passing L10/L13/L15 gate.

| Gate             | Required independent observation                                                                                                                                                                                                                                           |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L10 escrow       | Server-attested escrow commit, audited authorized reveal, complete power-off and cold-boot unlock using the revealed literal recovery passphrase; inventory and same-boot key testing are insufficient                                                                     |
| L10 rotation     | Hard VM cut after adding the new slot but before prior managed-slot retirement; old and new unlock paths remain usable, independent owner path survives, restart never guesses that escrow was durable                                                                     |
| L10 TPM          | PCR-bound TPM2 enrollment followed by unattended cold boot; separately exercise TPM-absent and policy-mismatch refusal/recovery                                                                                                                                            |
| L13 approval     | Self-approval, expired approval, changed digest/generation, revoked approver and stale challenge all deny effects; no grant crosses process restart, boot or the thirty-second local deadline                                                                              |
| L13 restriction  | Observe real desktop-session lock and nftables traffic restriction, control-plane/DNS preservation, explicit release and automatic expiry while executor is stopped                                                                                                        |
| L13 account lock | On Ubuntu 24.04, compare protected native shadow state before lock, after password lock/account expiry, and after release; require exact restoration only for unchanged owned accounts, preserve an intervening admin edit, and independently observe logind session state |
| L15 erase        | Recovery execution retains identity/journal off target; erased target fails cold boot and independent powered-off inspection rejects both LUKS metadata headers/keyslots; missing report remains unknown                                                                   |
| L15 sanitize     | Exact non-encrypted offline target, expected overwrite/discard behavior and independent verification samples, unaffected other disks, interrupted operation and fresh installation afterward                                                                               |

Use QEMU's available emulation rather than treating missing physical equipment as
a reason not to build the scenario: OVMF UEFI with enrolled Secure Boot keys both
enforced and disabled; swtpm TPM2 and absent TPM; NVMe, SATA/AHCI, virtio-blk/SCSI
and multi-disk; LUKS1/LUKS2 and LVM-on-LUKS; aarch64 under KVM or TCG; installer
GNOME/KDE with graphical-console evidence; explicit virtual network partition.
Each run declares which configuration and native operations were actually exercised.
Unsupported emulated firmware sanitize commands are refused and recorded, never
counted as passing merely because the command was accepted.

VM evidence establishes software protocol behavior and the tested emulated native
interfaces only. It does not establish real TPM resistance to extraction, physical
Secure Boot firmware behavior, SSD remapped-cell erasure, NVMe/SATA manufacturer
sanitize semantics, power-loss behavior of an actual controller, or destruction
of historical escrow/header/snapshot copies. Those exact hardware/firmware tuples
remain separately attributable physical L15 gates below. A passed VM lane cannot
silently promote an unqualified hardware method to supported sanitization.

## 4. Scheduling and release gates

| Lane              | Trigger                           | Scope                                                                                                                             |
| ----------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Local inner loop  | Each relevant edit                | Focused Go tests/real PostgreSQL integration as needed; cached representative VM for changed provider                             |
| Pull request      | Every change                      | Formatting/lint/generation/breaking/schema/auth tests; representative Debian-family and RPM-family lifecycle; affected UI surface |
| Nightly           | Main and dependency/image changes | Entire VM matrix and interrupted operations; isolated-network subset, cross-version and graphical sessions                        |
| Release candidate | Every signed release              | Full applicable connected and air-gapped suite, actual ISO installs, physical capability gates, security/load/restore evidence    |

PR reduction is a feedback optimization, not a waiver of launch certification. An
unavailable licensed image, unavailable KVM, unavailable physical machine or skipped
scenario blocks the corresponding claim. Every matrix cell must list required vs
not-applicable scenarios with reasons; a missing capability is not a passing test.

Store run ID, commit/build IDs, image and repository digests, toolchain/firmware/CPU,
configuration, operation IDs, structured assertions, native observations, serial
console, redacted journals, screenshots and fault timing. Failed-run artifacts have
retention/access controls; never archive grant values or encryption keys. Results
are machine-readable JSON/JUnit plus a concise human report. Preserve reproducible
seeds. Automatic reruns retain the first failure and cannot turn an unexplained
flaky security/destructive scenario into a passing release gate.

## 5. Physical qualification prerequisites

Before implementing a supported sanitize method, select actual sacrificial company-
owned devices with explicit destructive-test authorization, firmware and media
inventories, out-of-band power/recovery access, and a retention/disposal policy. At
least each advertised hardware/storage/encryption tuple must be represented. A generic
"one laptop passed" is not coverage. Local workstation resources currently do not
establish availability of this laboratory; this remains a procurement/access gate.

Validate real TPM and software-key paths, NVMe/SATA as advertised, interrupted erase,
alternate boot and recovery media, lost network/ack, multi-disk/swap, escrow/header
backup implications and fresh OS installation afterward. Where firmware behavior or
full key destruction cannot be verified, report unsupported or require physical
destruction; do not redefine the acceptance test to obtain a green result.
