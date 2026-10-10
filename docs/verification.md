# Distro support and lifecycle verification

Status: qualification plan. **No matrix cell is certified.** Installation, unit tests,
containers, simulations and a source-code review cannot substitute for the required
machine evidence. All supported claims are capability-specific.

## Restart, shutdown and inventory-refresh actions

| Gate                             | Required evidence                                                                                                                                                                                                      | Current status                                                                               |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Signed authority and replay      | Race-enabled unit and real-PostgreSQL regressions for remote-execution versus inventory permissions, independent scopes, configured approval, offline admission, exact grants/results, and published snapshot receipts | Affected-package race suites and real-PostgreSQL action/approval races passed on 2026-10-10  |
| Restart recovery                 | Consumed grant plus changed boot UUID; same-boot executor restart and unconsumed grants cannot succeed or replay                                                                                                       | Executor races and native Ubuntu 24.04 changed-boot/reconnected SUCCEEDED result passed      |
| Refresh inventory                | Immediate full host/package collection, committed publication, signed receipt and matching result snapshot sequence                                                                                                    | Transport/executor/PostgreSQL races and native Ubuntu 24.04 committed sequence 2 passed      |
| Shutdown uncertainty             | Signed action remains outcome unknown; independent guest shutdown and successful QEMU exit, never disconnection alone                                                                                                  | Interrupted-call/recovery races and native Ubuntu 24.04 scheduled shutdown/QEMU exit passed  |
| Deployment capability enablement | Missing signer capability produces typed failed-precondition; offline owner selects exact capabilities; real console fixture publishes correctly signed delegates and admits actions                                   | Owner CLI, signer-denial PostgreSQL and real isolated console/server/PostgreSQL races passed |

Native Ubuntu 24.04 proof passed in
`$HOME/.cache/lindm-power-native-20261010/ubuntu-power-02.json`, SHA-256
`0678c16c09e67053b3c207332b8aa737d8f1deafd02a46b23a79397b560d7f56`.
The maintained `lab vm dispatch -local-authority -power-actions` mode used a private
build tree based on checkpoint `9138d17`, with source delta `source-02.patch`
SHA-256 `4347f9e537ccdb6669bf9b6f159ca05d2bcd8d12b9dcd013b04d7523cc9534c8`
in that evidence directory and the shared fixture repository (no fixture copies).
Independent native boot IDs changed from
`c88c5739-6cd0-47b7-bef2-42f14a750498` to
`19333751-e17f-4977-a4f1-f328de992def`; the reconnected agent's signed restart
result was `SUCCEEDED` with the same new boot ID. Refresh returned signed published
sequence 2. A 20-second logind shutdown reported `outcome_unknown_until_contact`,
then QEMU exited successfully. Guest, isolated server and database cleanup passed.
This is x86_64/KVM/SeaBIOS/virtio-blk emulation without TPM, not physical proof.
The first attempt (`ubuntu-power-01.json`, SHA-256
`63ece7423ce533b041b02e6c043ff10ab36ec1be15ab9b3823ab0430469206a0`)
already proved restart/refresh but exposed a lab observer bug: provisional
grant-only UNKNOWN was mistaken for the root's reported shutdown result. The
corrected observer waits for verification before inspecting it; no product
authority, result semantics or native power command was relaxed.

Executed verification: `go build ./...`; `go test -race -p 2` for
`internal/agent/{actionprovider,executor,journal,transport,localrpc}`,
`internal/{trust,device,identity,ctl,devlab,loadlab}`; and real-PostgreSQL
`go test -race -p 2 -tags=integration -count=1 -timeout=15m ./internal/device ./internal/identity -run 'Test(Imperative|Restart|Shutdown|Refresh|DeviceAction|Approval)'`.
The console regression used a freshly built version-stamped real `lindmd`:
`go test -race -p 2 -count=1 -tags='integration consolelab' ./internal/loadlab -run '^TestConsoleDefaultDelegationAdmitsDeviceActions$'`.
Its actual default signed delegation covered every closed action plus service
execution, admitted refresh/restart/lock, and rejected restricted/self-approval
requests. Its synthetic device transports are not native power evidence.
The owner CLI's initial test-fixture directory mode failure was corrected without
weakening protected-file checks; its separate `go test -race ./internal/ctl`
rerun passed.
Additional real-PostgreSQL `go test -race -tags=integration ./internal/device -run TestApproval`
passed after adding closed-oneof coverage for all eleven device-action inbox
permissions and current requester/approver/hostname projections. Scoped reviewers
without account-management permission see only authorized rows, labels and counts;
outside-scope decisions return no response. Projection lifecycle tests use direct
hostname fixture changes rather than bypassing the ordinary host-upload cooldown.
Supplemental grants use the same registry in decisions and inbox SQL: refresh
projections/counts independently intersect `fleet.read` with `inventory.manage`
and approval-management scope. Missing-read public RPC denial and disjoint-read
real-SQL scope regressions passed in the final `TestApproval` race/PostgreSQL run
(46.220 seconds); identity/device unit races also passed.

The later SATA06 wipe preparation exposed an independent backlog bug: old routine
spool uploads could repeatedly hit the ordinary limiter before explicit refresh
collected anything. Corrected with durable action-owned host/package admission
slots, fresh-before-supersede spool transactions, quota-safe old staging retirement,
and action-only receipt recovery before recollection. Existing root-only recovery
readiness augmentation remains on the refresh collection path.
Integrated `go build ./...` and spool/transport/device race suites passed; real
PostgreSQL `go test -race -p 2 -tags=integration -count=1 ./internal/device -run 'Test(Refresh|DeviceAction|Snapshot|Package|HostObservation|Approval)'`
passed in 116.185 seconds. Regressions cover routine throttling, stale/partial/mixed
backlog, sequence and receipt replay, one-use admission, quota rollback, collection
failure/cancellation and lost confirmation followed by process reopen. The older
successful Ubuntu power record did not contain a stale backlog; WipeQual3 owns
the separate native recovery rerun of this correction.

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

| Image                                          | Authenticated acquisition                                                                                                                  | Independent native observation                                                                                                                                                                                                                                     | Packaged lifecycle / dispatch                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rocky 9.8 GenericCloud Base 20260525.0         | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 422 RPM records, explicit UEFI/Secure Boot disabled                                                                                                                                                                                                        | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rocky 10.2 GenericCloud Base 20260525.0        | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 443 RPM records, explicit UEFI/Secure Boot disabled                                                                                                                                                                                                        | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| AlmaLinux 9.8 GenericCloud 20261005            | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Passed, 387 RPM records                                                                                                                                                                                                                                            | Earlier lifecycle failed signed service after enrollment/upgrade. After removing the dbus-broker v28 argument-filter optimization, independent connected dispatch passed all 10 scenarios with SELinux Enforcing; packaged lifecycle rerun remains required                                                                                                                                                      |
| AlmaLinux 10.2 GenericCloud 20260817.0         | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Ubuntu 22.04 release 20261004                  | Ubuntu signed SHA256SUMS verified and cache reverified offline                                                                             | Passed, 597 dpkg records                                                                                                                                                                                                                                           | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rocky 8.10 GenericCloud Base 20240528.0        | Pinned manifest uses aggregate CHECKSUM.sig; 2.06 GB image download incomplete and cancelled at handoff, so actual bytes not authenticated | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| AlmaLinux 8.10 GenericCloud 20260928           | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| openSUSE Leap 16.0 Minimal-VM Cloud Build18.75 | Vendor checksum signature verified; fixed vendor-listed mirror avoids cross-origin redirect relaxation                                     | BIOS exits; UEFI exposed nonportable uptime/date oracle, now replaced by strict native btime parsing. After SSH readiness correction, agent inspection exits 1 (63 stderr bytes); current runner preserves private bounded stderr for diagnosis. No passing record | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| openSUSE Tumbleweed Cloud Snapshot20261007     | Vendor checksum signature verified and cache reverified offline; fixed vendor-listed mirror avoids cross-origin redirect relaxation        | Not yet recorded                                                                                                                                                                                                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Debian 13.7.0 netinst                          | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Passed after privileged source-marker correction: 355 dpkg records, explicit UEFI/Secure Boot disabled                                                                                                                                                             | Historical 0.5.0→0.5.1 signed-service lane reached reinstall/spool recovery/denied-collection preservation (356 packages), then failed final approver authentication. Post-fix 0.6.0→0.6.1 automatic-trust run was **aborted: host contention** after enrolled/upgraded/rebooted publications (356 packages each), before final revocation. Neither a full pass nor a new distro failure; dispatch remains unrun |
| Debian 12.15.0 netinst                         | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Not executed                                                                                                                                                                                                                                                       | Not executed                                                                                                                                                                                                                                                                                                                                                                                                     |

The 2026-10-10 continuation used source checkpoint
`9138d17f8ff6c3673f82cea1590c36c33fca2d22`, same-tree signed 0.6.0→0.6.1
packages, explicit UEFI and isolated local password/WebAuthn authority. The owner
stopped its Debian 13 automatic-trust lifecycle because the shared host was swapping
at 56/62 GiB with approximately 25% I/O wait, restricting local guests to the two
encrypted qualification lanes. Record
`~/.cache/lindm-mutabledistros3-20261010/debian13-trust-aborted-host-contention.json`
has SHA-256 `8f6fe2d5b783ce6904db89ce55757098c1884a8f2218742de914a8de54251c34`.
Device `2f916abe-fd7d-4e91-814c-8fed33658689` independently matched 356 native
packages at enrolled, upgraded and rebooted sequences 1, 2 and 3. Cancellation
left no owned guest or server process; isolated-database cleanup was not
independently observed. Final revocation was not reached, so this does not qualify
the approver fix natively on Debian. The separately attempted shared-server
startup found missing migration 10 before any guest; Main recreated the development
database explicitly, and the pinned server subsequently started successfully.
No later mutable guest was launched: Debian 12, Rocky 9/10, Alma 9 lifecycle,
Alma 10/8, Leap 16 diagnosis, pinned Tumbleweed and Arch retain their prior gaps.
New signed Arch 0.6.0/0.6.1 packages, repositories and rejection fixtures were built
from the same checkpoint under this evidence directory; preparation is not a native
lifecycle pass. No timeout, security or provenance gate was weakened.

The shared laboratory approval session defect is independently reproduced without
a VM against a real isolated `lindmd` and PostgreSQL database. Race-enabled
regressions cover idle expiry for local WebAuthn and Keycloak code/PKCE sessions,
local approver revoke/restore, disabled-account login rejection, fresh authority
on successive approvals, and actual consumption of the approval by device
revocation. The original session returns HTTP 401; only a real fresh login lets
the shared helper proceed. Server lifetimes and security gates are unchanged.
Under `$HOME/.cache/lindm-approvals-20261010/`, `approvals-regressions.jsonl`
has SHA-256 `a5c867cf190078dd8ab99e413c973d03dce9fd67481410eedb949ff0209fbba2`;
focused lifecycle-wrapper race evidence `revocation-regressions.jsonl` has
SHA-256 `16ebaf76f1df86ce10d18597b38632c7111581d12d620ba376965a82a2d2ef20`.
This fixes the shared helper and its lane callers, not the historical Debian
lifecycle result. Ubuntu 24.04 native dispatch subsequently passed in 938 seconds
with isolated local password/WebAuthn authority, actual independent revocation
approval and revoked-device no-effect denial. Record
`ubuntu24-dispatch-approval-01.json` in the same directory has SHA-256
`604764b079ed97e51b54ed1962adfab20783cb3f6475b6fca7ba5f6831a03318`.
The requester `4752c0cd-d37d-411d-aa08-917fcacbe345` and approver
`208546ef-7728-4e60-9f4c-a35634035598` are distinct; approval
`11b8f893-ab60-42fe-a4b4-2223b3813fcb` binds device
`7ff35a8c-acf8-4114-b6ef-06e2e09b1d0f`. This is KVM/QEMU 8.2.2,
SeaBIOS 1.16.3, virtio-blk, no TPM/desktop, two vCPUs/2 GiB, not physical proof.
Nine scenarios are native; unstarted supersession stays integration-only.
The immutable source checkpoint is
`9138d17f8ff6c3673f82cea1590c36c33fca2d22` with no private patch; lab SHA-256
`811162b4bae7ae7eb5348bfe5b9ba67997690113d520ca485800e5428ab07c75`,
server `3ebdbf8ffd3e17543a6453811eb3914f07b6bf4c8264025b18be2f151ec5f316`.
The command used `vm dispatch -local-authority -repo /home/r/dev/minor/lindm
-build-repo /home/r/dev/minor/clones/lindm-vmlanes -manifest
lab/images/ubuntu-noble-amd64.json` with those binaries and a new `-record` path.
Owned guest, isolated process/database and ephemeral credentials were cleaned.

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
That runner scheduled reboot two seconds later, closed the existing client and
immediately reconnected; **[INFERENCE]** the new connection raced old-boot shutdown.
At the first-owner handoff this was an unresolved laboratory failure, not a proven
external condition. The corrected successful trust run below supersedes that
incomplete attempt; completed pre-reboot steps alone were never a full pass.

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

The reboot harness now independently proves a changed boot ID over fresh pinned
SSH transports before accepting the reboot. The first correction awaited old
transport FIN; WipeQual2 later proved that QEMU/slirp can retain this host socket
after a completed guest boot, so FIN is no longer the required boundary.
Authentication/host-key/permanent channel failures are terminal; only classified
boot transport readiness polls a fresh pinned connection with a 15-second
no-effect probe, inside the original five-minute connection deadline.
Changed-boot/no-FIN, unchanged-boot deadline, auth/invalid-ID and encrypted-SSH
regression cases are added; their execution is not yet claimed here.
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

RHEL 9.8 **packaged signed-service lifecycle passed** with maintained registration:
`rhel98-service-egress-platform2.json`, SHA-256
`6378848308eecfaad17e38ff76d7d0b275688f4f7618f6d7f3d618cedcd30ee8`,
device `6c4c88a2-3aae-4401-9035-3315e8659668`, generation
`d74b5bf2-7e63-47e4-a390-51896fcbbc68`. The command used the same 0.5.0/0.5.1
build records, `rejections-platform2`, public key and fingerprint as above, with
`lab-platform2-approval vm lifecycle -manifest lab/images/rhel-9.8-x86_64.json
-service-execution -allow-network
-redhat-token-file "$HOME/.config/lindm/redhat-offline-token"
-diagnostics ROOT -record ROOT/rhel98-service-egress-platform2.json`.
The laboratory SHA-256 was
`65ea371f7708aee71e9413246c57a81424e68722278b38fe33372d2a8a6a169b`;
shared server was `lindmd-platform2` with its digest above. Native signed RPMs were
`003f5a96584568ae8d5bf96022cbd43d290625e26da0394a1f37575d20471944`
and `9937ca792715965e06f9419c842ea052a7c4304abd690be288d9064f48efe1e1`.
Five publications each independently matched 492 packages. Signed service effects,
retained device-signed history, upgrade/reboot/reinstall, corrupted-spool recovery,
failed collection preserving snapshot 5, revocation and missing-journal hold passed.
SELinux remained Enforcing before/after. The record explicitly reports
`network_access=user-egress` and all five Red Hat outcomes true: registration,
native identity, authenticated repository metadata refresh, guest unregistration
and owned activation-key deletion. Credentials were not recorded.

Its initial restricted-network attempt was a laboratory prerequisite failure,
not an agent result: `rhel98-service-restricted-failure.json`, SHA-256
`36bad86b993c56bd1ca9faa910e08b797456ed2237a7f2eb2f8336e158f21d78`.
Default QEMU `restrict=on` correctly blocked vendor egress. Explicit
`-allow-network` changes only disposable guest user-mode networking and is required
for the maintained registration hook; defaults and host security remain unchanged.
No authenticated EUS/E4S stream, desktop or physical-machine claim follows.

RHEL 10.2 **packaged signed-service lifecycle also passed** using the same
0.5.0/0.5.1 RPMs, signer, rejection fixtures and shared `lindmd-platform2`.
The command above substituted `lab-platform2-bootid`, manifest
`lab/images/rhel-10.2-x86_64.json` and record
`ROOT/rhel102-service-egress-platform2.json`, retaining `-service-execution
-allow-network -redhat-token-file "$HOME/.config/lindm/redhat-offline-token"`.
Laboratory SHA-256:
`1b3f0a0eff58069b493220bc56e778ac386a3c16206a0619f1fdf1e656d6d956`.
Record SHA-256:
`3d0eebd689834efa9f7daf766a9bc8cdd29f994a3306360b9fda0a249751b78f`;
device `a1baa993-341f-4789-a2e9-5f9eaee6ccbb`, generation
`a5985cc1-0860-4c55-ae6a-8e386db7a218`. All five Red Hat registration and
cleanup outcomes were true; SELinux remained Enforcing and user-egress was
explicitly recorded. Five publications independently matched 530 packages,
epoch advanced 1→3, denied collection retained snapshot 5 at attempt 6, and the
same signed effects/history, upgrade/reboot/reinstall, trust retention,
spool recovery, revocation and missing-journal hold checks passed. This run
used the changed-boot-ID reconnect boundary rather than requiring old TCP FIN.
Its service-execution trust exercise is not automatic control-plane trust
or connected-dispatch qualification.

RHEL 9.8 automatic control-plane trust was resumed on checkpoint
`9138d17f8ff6c3673f82cea1590c36c33fca2d22` with a new same-checkpoint
0.6.0→0.6.1 package pair, but is **aborted: host contention**, not a product
failure or a pass. Record `ROOT/rhel98-trust-9138d17-aborted.json`, SHA-256
`c3bab4f7304cf2d708d5c17cda352c30608a0f549fb02df6c3915f35aa2e2a97`,
device `75a4fc8d-b6dd-4e13-b674-13c6267b0071`: enrollment, upgrade and reboot
published independently matched 492-package snapshots 1–3 before the owner
ordered cancellation for host swap/iowait pressure. SIGINT used normal runner
cancellation; QEMU exit was observed. Guest unregistration could not reconnect
after cancellation, so unregistration is **not established** and the hosted
system registration may remain. Independent activation-key deletion reported
no error; its success is inferred from the joined-error cleanup path, not
claimed as native cleanup evidence. No credential material was recorded.
Exact package and executable hashes are retained in that abort record.

The hosted orphan was subsequently **deleted through the maintained cleanup**,
with explicit owner authorization for the sole legacy system in the lab-only
account: consumer `f71e7a26-a3d3-498b-98d9-b1c1b662d713`,
`localhost.localdomain`, created `2026-10-10T02:42:15.000Z` inside the aborted
registration window. Record `ROOT/rhel98-orphan-cleanup-01495af.json`, SHA-256
`bf6ce05fde94350b1067429ad06f761a1d02c0d59a8fa6307669ac7c001340d0`.
DELETE was acknowledged, a subsequent exact GET returned404, and a separate
read-only maintained inventory returned `[]`: **zero account systems**.
Owned activation keys were already absent; zero remaining was independently
verified. No guest-unregister or trust-lifecycle pass is retroactively inferred.
The runner was built privately from
`01495afab18b08dcec438f973ce43728156c235c`, source patch
`redhat-cleanup-01495af.patch` SHA-256
`f2da9f8699418bd9a350c6879f40c069f42d7f872bef4d1017cd83216051c860`;
runner SHA-256
`c7b8ed07065158db31bfb489477bb4279566c5e600cc0a92c5274594dfde95a6`.
No fixtures or credentials were copied into the build worktree.
The maintained CLI now offers read-only `images redhat inventory` and
`images redhat cleanup -confirm-delete-lab-registrations`, deleting only exact
owned public names unless an independently authorized `-legacy-consumer-uuid`
is supplied. Future native registrations receive independent public
`lindm-lab-<32 lowercase hex>` names and persist actual consumer UUID receipts
outside disposable VM state. Regressions were added; no new native registration
run or unit-test execution is claimed here.

RHEL 9.8 dispatch, RHEL 10.2 automatic trust/dispatch and Fedora 43
signed-service lifecycle/trust/dispatch remain unrun. Local guests are restricted
to the two owner-designated encryption/wipe lanes until the restriction is lifted.
Continuation commands and custody notes are in `local://platformlanes2-handoff.md`.
The abort's build provenance is `ROOT/checkpoint-9138d17-build.json`, SHA-256
`7aebb17cf8038d23e2ed9d77ac2ec218c82f92df6d3bf3bc7ec02685b88a186f`.
The shared read-only build snapshot subsequently advanced to checkpoint
`01495af`; future runs must record their actual new base and matching artifacts,
not relabel earlier evidence. Keep real fixture `-repo` separate from
source-building `-build-repo`; do not copy or rebind fixture secrets.

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

The Ubuntu 24.04.5 ARM64 encrypted installer attempt under two-vCPU TCG did not
qualify: it reached the 45-minute installer deadline without a completed install
(2728.16 seconds including setup/cleanup). Failure record:
`artifacts/encrypted-ubuntu2404-arm64-secureboot-20261010.json`.
Both official ARM installer ISOs passed pinned signature/digest verification,
but that is media provenance, not boot or recovery proof. No encrypted ARM
golden, Secure Boot observation or successful cold boot is claimed by this run.

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

| ID                               | Scenarios and required result                                                                                                                                                                                                                                                                                 | Evidence surface                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L01                              | Fresh single-host server installation, first-owner binding, restart and invalid configuration                                                                                                                                                                                                                 | Actual installer/console/CLI; same pinned owner bootstrap is idempotent, replacement owner denied; persisted state recovered                                                                                                                                                                                                                                                                                                                                              |
| L02                              | Real Keycloak/Entra/Okta/Google and SAML broker login, MFA/step-up, SCIM correlation, upstream disable/group removal during direct and brokered sessions without re-login, healthy broker with stale upstream, source outage, rename/recycled email                                                           | Original-directory propagation and local enforcement measured separately; no freshness reset from broker imports, stale-claim resurrection, source ambiguity or permissions beyond bound                                                                                                                                                                                                                                                                                  |
| L03                              | Package enrollment, lost secret-issuance response, redaction/hash-only persistence, grant race, lost cert response, TPM/software key, renewal/revocation, cloned image and reinstall                                                                                                                          | Retry never recovers a bearer secret or creates a second credential; distinct device generation, correct denial and no secret in database/audit/outbox                                                                                                                                                                                                                                                                                                                    |
| L04                              | Native hardware/OS/package collection, absent serial, package epochs, pagination/filters, delta duplicate/out-of-order ingestion, stale/offline device                                                                                                                                                        | Guest truth compared with API/export; stale evidence never compliant                                                                                                                                                                                                                                                                                                                                                                                                      |
| L05                              | Profile preview/conflict/drift, trust bootstrap and quorum rotation, tampered/stale trust and plans, missing/corrupt executor journal, compromised network-process replay and restart during apply                                                                                                            | Actual state/revision, root-only replay fences and fail-closed recovery; unknown capability or trust never becomes privileged execution                                                                                                                                                                                                                                                                                                                                   |
| L06                              | Native package/image/generation and repository transactions, invalid signatures, dependencies/locks/interruption, device/person catalog entitlements and UID/account reuse                                                                                                                                    | Native package database or booted generation and application health; no partial Arch upgrade, mutable-image overwrite, unapproved source or cross-person install                                                                                                                                                                                                                                                                                                          |
| L07                              | Patch/advisory rings, canary pause, maintenance window/DST, desktop deferral/deadline, server availability budget, kernel update and reboot inhibitor                                                                                                                                                         | New boot/kernel and workload health, not just agent reconnect; no reboot outside policy                                                                                                                                                                                                                                                                                                                                                                                   |
| L08                              | Agent install/upgrade/failed-upgrade recovery, purge/reinstall, journal migration, owner-safe config removal, supported OS upgrade or reinstall migration                                                                                                                                                     | Package/service/filesystem state and preserved/rotated identities as specified                                                                                                                                                                                                                                                                                                                                                                                            |
| L09                              | GNOME/KDE sessions, built-in support consent/indicator/local stop/input, self-service/notices, Wayland/X11 as claimed, UID reuse/shared-device/ownership transfer, suspend/resume and accessibility                                                                                                           | Actual session evidence and isolated person binding; lock/logout/revocation terminates support; no tray or unattended-control dependency                                                                                                                                                                                                                                                                                                                                  |
| L10                              | Network rollback, EAP-TLS/VPN, firewall, certificates/trust/SSSD, account controls, encryption escrow and person-certificate binding/deprovisioning                                                                                                                                                           | Real credential/network behavior and cold-boot recovery; no cross-person secret or competing native owner                                                                                                                                                                                                                                                                                                                                                                 |
| L11                              | Compliance pass/fail/error/unknown/N/A, expiring exceptions, SCAP tailoring/content, distro backports/epochs, stale or conflicting advisories                                                                                                                                                                 | Native findings linked to content/version/freshness; no false healthy status                                                                                                                                                                                                                                                                                                                                                                                              |
| L12                              | CLI/UI parity, idempotency, webhooks retry/signature/dedup, export access, typed diagnostics, bounded scripts and consent-controlled remote support                                                                                                                                                           | Receiver/user-visible outcomes, consent termination, redacted support bundle and action audit                                                                                                                                                                                                                                                                                                                                                                             |
| L13                              | Approval separation, changed targets/authority, executor challenge replay/expiry/restart, restore epoch and actual lock/quarantine effects                                                                                                                                                                    | No high-risk start without a fresh verified one-use grant; the bounded residual authorization window is measured                                                                                                                                                                                                                                                                                                                                                          |
| L14                              | Migration under traffic, DB/worker crash, both server installation modes, restore hold/epoch, revoked identity, key rotation/loss, audit/retention                                                                                                                                                            | Usable restored system with fresh authority; no stale destructive replay or revived directory access                                                                                                                                                                                                                                                                                                                                                                      |
| L15                              | Real TPM/Secure Boot/recovery, lock boundaries, authenticated recovery-media handoff, wrong target/expiry/power loss, off-target state, sanitize/reinstall and key-copy implications                                                                                                                          | Physical signed evidence and separate verification/validation; lost state/report stays unknown rather than restarting wipe                                                                                                                                                                                                                                                                                                                                                |
| L16                              | Full isolated management LAN with public egress blocked, local IdP/DNS/time/PKI, signed content import, expiry/replay/corruption and missed key rotation                                                                                                                                                      | Network capture/deny counters and successful offline lifecycle; no disabled integrity checks                                                                                                                                                                                                                                                                                                                                                                              |
| L17                              | Cross-version contracts, generated code and two-clean-builder unsigned release-payload digest equality, TUF/freeze/rollback, native package/image trust, provenance/SBOM/licenses                                                                                                                             | Both build manifests and comparisons plus actual installed release artifacts; signatures/attestations verified separately from deterministic payload equality                                                                                                                                                                                                                                                                                                             |
| L17 release archive matrix       | Passed two isolated clean source/HOME/Go/npm cache builds of all three products × amd64/arm64 × DEB/RPM, plus server/CLI OCI; complete unsigned archive equality and separate native/DSSE verification                                                                                                        | `artifacts/release-matrix-20261011.json` SHA-256 `dd92786edd9b97e2f8289b9d921ecb23c33edbdf42c5369199f8952117f8f668`; adjacent DSSE `270e32716f2e17609dd8abb73ebcfa1b34d764236606c08aa424ba1dbf9fde08`. Export includes dependency SBOMs, provenance and explicitly pinned OCI CA bytes. Development keys/CA, same host/toolchain; does not qualify native update transactions, independent builders, license approval or physical hardware.                               |
| L08/L17 unattended native update | **Not yet qualified.** Ubuntu24 passed real pause/cohort and signed rollback/mix/freeze/target-tamper rejection, then native APT exited 100 before unpack. Successful update, interrupted recovery and downgrade refusal remain unproven. Fedora44 was aborted for host contention, not failed qualification. | Ubuntu `~/.cache/lindm-updatequal-20261010/ubuntu24-updates-02.json` SHA-256 `f6f897129092afae416df87186501a6cb6baf4cecf26d3758ac2b5c26dfd9620`; Fedora cancellation `fedora44-updates-01.json` SHA-256 `e6aa331a1ac0bf6cab7d19ba903beff36e2078ac8b022910245fc869ededfda8`. Earlier attempt4 retains the closed-SSH observer defect; current root diagnosis, diagnostic propagation checks and cancellation limitations are detailed below.                               |
| L18                              | Single-host and replicated load/soak, reconnect storm, storage full, queue fairness and worker/DB failover                                                                                                                                                                                                    | Workload manifest and measured budgets from security/operations; accepted work preserved                                                                                                                                                                                                                                                                                                                                                                                  |
| L18 single-host launch gate      | Maintained `lab load`: real lindmd/disposable PostgreSQL, grants/mTLS, jittered sync/trust/work, full snapshots, signed service cycles; explicit CPU/pool/storage and iostat/QEMU evidence                                                                                                                    | Durable co-resident baselines and WAL-pressure failures are documented in security/operations. `artifacts/load-isolated-tmpfs.json` (SHA-256 `8efe8ec08315276197d527618050035deeb4b0147215195ce991ab4fd1e7c193`) passes only the completed non-durable 5,000-device plateau; 10,000 interrupted by parent scheduling directive. Dedicated tmpfs and NVMe fixture integration passes, not capacity qualification. Isolated durable ramp, two-hour soak and HA remain open. |

Attempt4's last completed observation was the signed zero-percent hold at
`2026-10-10T01:17:32Z`, with phase `idle`, version `0.1.0` and no admitted
transaction. Its five-minute rollback-rejection observer ended with an SSH
channel-open deadline, not a returned agent status. The harness repeatedly
reused the client that its own command-deadline handler had closed, erased prior
status on failed reads, and tried to collect diagnostics through that same closed
socket. This is an identified observer-liveness defect, not evidence of a native
update hang or a helper restarting the agent mid-command. The original initiating
stall cannot be retrospectively attributed to guest/host pressure versus SSH
transport loss: attempt4 retained neither an independent guest journal nor its
first transport error. Read-only status/unpack observers now reconnect with the
original host-key pin inside unchanged deadlines; mutations are never replayed.
Fresh-connection diagnostics and last successful state are retained on failure.
Encrypted-SSH regressions cover lost/already-closed clients, service restart
freshness, changed host keys, malformed replies, unpack observation and cancellation
state preservation. Their addition alone is not native qualification.

The subsequent native Ubuntu24 run is
`$HOME/.cache/lindm-updatequal-20261010/ubuntu24-updates-02.json`, SHA-256
`f6f897129092afae416df87186501a6cb6baf4cecf26d3758ac2b5c26dfd9620`.
All six pause/cohort/rollback/mix/freeze/target-tamper observations passed. The
positive helper then exited with native `apt-get` status 100 before any unpack
witness. The unpack-only observer waited ten minutes and its last command crossed
the deadline, misleadingly surfacing another SSH deadline. Fresh pinned diagnostics
successfully reached the same boot: SSH and executor had zero restarts, guest load
was `0.00 0.01 0.00`, and 1604 MiB of 1967 MiB was available. The native helper
failed at boot-relative 149.77 seconds; no reboot/reset occurred. Thus this run
isolates native transaction failure from guest load or an agent-restart transport
race. The private diagnostic record `lindm-cloud-init-3300314646.json` in the same
directory has SHA-256
`eb9b1a4474879b4c0c4f40fc4c550486e2b01d8ce88d01f6dc79d7afaea54e1f`.
The unpack observer now also reads protected update status and stops on a terminal
failure or completion instead of concealing it behind a later SSH deadline.
At this point APT's underlying error text was suppressed by the product; exit 100
alone does not establish the package-manager root cause or a successful upgrade.
Source checkpoint `9138d17f8ff6c3673f82cea1590c36c33fca2d22` plus recorded
router-only patch SHA-256
`05dc0e66cc75dc68298331955110b95c8478fd94915a19a1bd4e5cc611f1b0ee`
produced the immutable run. The initial invocation failed before VM creation
because the host router injected unsupported `-accelerator` into the fixed-KVM
updates lane; the shared router now selects hardware-capable lanes explicitly.

Bounded native diagnostics now carry manager, failed phase, exit code and the
sanitized final eight error lines through protected helper result/journal/status,
authenticated heartbeat, durable scoped device projection and audited events.
The console's existing Diagnostics section renders that observation as historical
telemetry, not update authority. Native update race tests, transport/SSH race
regressions, real PostgreSQL ordering/projection/atomic-audit regressions and web
typecheck passed; `go build ./...` passed after those changes. The executed check
summary is `$HOME/.cache/lindm-updatequal-20261010/diagnostic-verification.json`.
No instrumented native update or browser rendering is claimed by those checks.

Fedora44 was stopped on the owner's host-swapping/iowait directive. Its explicit
`$HOME/.cache/lindm-updatequal-20261010/fedora44-updates-01.json` cancellation record
has SHA-256 `e6aa331a1ac0bf6cab7d19ba903beff36e2078ac8b022910245fc869ededfda8`
and status **aborted: host contention**. The tool cancelled job `bg_906` before the
runner emitted a final result; this record is not a `VMUpdateResult`, and does not
invent phase outcomes or a Fedora product failure. Source/runner provenance is
the same checkpoint/router patch as Ubuntu above. Post-cancel process inspection
found no update guest/server/runner. Retained owned source, signing material and
overlay were removed; the isolated database and authority directory were matched
by the exact built RPM digest and removed without FORCE or shared-fixture reset.
The tool's termination signal/grace was not recorded, so this is not evidence that
the existing SIGINT/SIGTERM context handler itself was absent or ineffective.
Local starts are suspended under the owner's two-guest priority cap. Ubuntu's
underlying APT error and both successful native recovery paths remain unproven
until the instrumented lane can run without contending with those priority guests.

The lane now distinguishes `outcome: cancelled`, preserves cancellation identity
through native-tool error wrappers, and skips the independent failure probe when
cancelled. Real SIGINT/SIGTERM during native signing staging passed the race
regression: owned source/signing bytes and processes were gone before the command
emitted its cancelled record. Evidence
`$HOME/.cache/lindm-updatequal-20261010/signal-cancellation-verification.json`
has SHA-256 `793c6c2029d1978dd2a1985f3bffe507c2e144b8241883ad2ddd0e9a65331b89`.
This exercised the actual updates command/evidence writer as a focused file-list
test, not a whole `cmd/lab` package pass: that package initially failed compilation
on concurrent Red Hat CLI work (`client.CleanupRegistrations` undefined). No guest
or authority fixture was admitted in this regression; post-admission native
cancellation and forced/SIGKILL termination are not claimed as proven.

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

#### Native ARM lab host baselines (2026-10-10)

The maintained `lab hosts baseline` command prepared both Spark hosts with native,
exact-pinned Ubuntu packages rather than a runner container. Readiness includes an
actual fresh-user `/dev/kvm` open, package-owned AAVMF/OVMF digest observations and
QEMU 8.2.2; this is infrastructure evidence, not guest qualification by itself.
Only the authorized `kvm` group membership was added. Baseline records contain
complete before/after package inventories and transaction output.

| Host / observation      | Result                                                            | Record / SHA-256                                                                                                             |
| ----------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| dgx20 native baseline   | Ready; 113 package changes; `kvm` membership added                | `artifacts/lab-baseline-dgx20-20261010-attempt2.json` / `54b6c54aafc5f9a5a54832df6c998fd1291c8cdf59b13459d0ee6fa960b82764`   |
| dgx21 native baseline   | Ready; prior transaction retained; zero package changes on repeat | `artifacts/lab-baseline-dgx21-20261010-attempt2.json` / `4700486f496c1125e3b6e52ebac55c7c6c5b1540b76a9247a5c57f53aa260e59`   |
| dgx20 repeated baseline | Ready; zero package or group changes                              | `artifacts/lab-baseline-dgx20-20261010-idempotent.json` / `818d4e6530002ff6c4aedf19b4d1a8c7748ca9b113b56a36caa161628aa3e1b4` |

The first dgx20 attempt failed closed on an unrelated existing GitHub APT key;
the maintained command now scopes APT to validated official Ubuntu sources without
changing third-party keys or repositories. Its failure record SHA-256 is
`b68192592d38f20e3c1183357c80af19a335d715fbf6815c15e75bb59499d6ac`.
The first dgx21 attempt installed the pins but correctly returned incomplete
readiness because `swtpm_setup` does not support the attempted `--version` probe;
the corrected probe records package-owned executable/version evidence. That failure
record SHA-256 is `85617ce2624b8a2f4b5523d5197362edda720c32761411356ace0404414c360a`.
Both failed records remain beside the successful records; no failed readiness is
promoted to success.
The initial packaged arm64 dispatch reached the remote worker but rejected the
existing group-writable `/home/r/work` ancestor before packaging. No package or
dispatch success is claimed for that attempt. Spark configurations now use
`/home/r/lindm-lab`; the maintained baseline validates private ancestry without
changing the unrelated shared work directory.

| Native guest qualification              | Result                                                                                                                              | Record / SHA-256                                                                                                                           |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Ubuntu 24.04 arm64 cloud image on dgx20 | PASS; native ARM KVM, 663 package identities and typed native details matched; UEFI/AAVMF, Secure Boot disabled, no TPM, virtio-blk | `artifacts/inspect-ubuntu2404-arm64-dgx20-kvm-20261010-attempt5.json` / `de6ac6e6b4accbb1123149288f477ec69b0cf4429b00356d6abf699bb6738205` |

The passed record measures 54.65 seconds in its host execution envelope; the
invoking command took 102.40 seconds including local staging/build overhead.
Source is checkpoint `fa2bd15183a8376e01179cb8ec68302d777e6d96` plus binary diff
SHA-256 `5407cde9c2d69a090871ea1ecbfeb27ffe35db28a1d6b9c79a03e7f40573c004`.
The earlier same-image ARM TCG inspect record matched 663 packages but did not
record elapsed time, so no inspect speedup ratio is claimed. The earlier encrypted
ARM TCG installer timed out after its 45-minute budget (2728.16 seconds including
setup/cleanup); that is a different workload, not a timing-equivalent benchmark.

Failed native ARM attempts exposed an independent oracle issue: logical `lscpu`
IDs collapsed physical cores 0 and 1 in package 36 into one synthetic core while
kernel sysfs and `lscpu --physical` both reported two. The maintained CPU oracle
now counts physical package/core IDs on every architecture without weakening the
comparison. The retained counterexample is
`artifacts/lab-arm-kvm-diagnostics/lindm-cloud-init-3263763983.json`, SHA-256
`5f61b9016d83873862a01bf6bd6a59373b0f695b2d76e456ee6842beca20976d`.
The passing private source also includes the matching collector/oracle storage
semantics from the independently qualified encrypted-storage capture worktree.

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

#### Stable storage selection

| Gate                             | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Collector and schema             | `go test -race ./internal/agent/inventory ./internal/device ./internal/vmlab` passed in the isolated storage worktree. Covers per-field availability, inherited exact identities, topology ambiguity, public LUKS summaries, NVMe scope/basis binding, and independent-oracle identity mismatch.                                                                                                                                                    |
| Published API and admission      | Real-PostgreSQL `go test -race -tags=integration -timeout=15m ./internal/device -run 'Test(ListDeviceStorageTargets\|StorageAction\|DeviceScopeReadMatrix\|DeviceAction)'` passed. Covers scoped reads, historical/missing/stale observations, every storage action's mismatched tuple, start revalidation, complete live-root sets and durable create replay.                                                                                      |
| Native encrypted fixture capture | Ubuntu 24.04 and Fedora 44 passed maintained `lab vm inspect-storage` on immutable encrypted golden clones: packaged root identities matched stopped host LUKS UUID/partition size and host-owned virtio-SCSI serial/WWN; headers unchanged and guests cleaned. Public fixtures and digest-bound provenance are retained in `internal/agent/inventory/testdata/storage/{ubuntu24,fedora44}` and replayed by `TestCapturedEncryptedStorageIdentity`. |

The generated target-selection contract was delivered to ConsoleQA. A selectable
inventory record is not destructive qualification or proof of completed erasure.
The combined root-storage/readiness attachment additionally passed
`go test -race ./internal/agent/inventory ./internal/agent/executor
./internal/agent/transport ./internal/agent/localrpc ./internal/vmlab` in the
isolated storage worktree, including strict bounded protobuf attachment and
stale/changed-boot/unknown-field rejection. The maintained `lab vm inspect-storage`
capture lane passed deterministic public-projection/cleanup regressions and
built from checkpoint `9138d17` plus its recorded private source overlay. The
native capture row above is separate from these deterministic test results.

Native run evidence lives under `~/.cache/lindm-storage-captures-20261010/`:
Ubuntu `ubuntu24-evidence.json` SHA-256
`6f4da5149da8d242fe02a4c36faf70e45ec4714cc1f5744163981ca24c7774c3`;
Fedora `fedora44-evidence.json` SHA-256
`b730527c64ac2af90c4dccaa77a23bb2e4a0b439365a0d012f6ae20707e1d323`.
Both bind base commit `9138d17f8ff6c3673f82cea1590c36c33fca2d22`,
tracked overlay SHA-256
`15349ec86fd85d55a39fefc882adf48eab81246bf06ff1b49ecb8e15ef0bdf0b`
and individual untracked-source digests. The common installed agent SHA-256 is
`2b098f9c4b2a61c519bf2a209b98f310d29b8eb71d31a019c524a72aeadd34cb`.
Ubuntu observed util-linux 2.39.3/cryptsetup 2.7.0/systemd-udev 255;
Fedora observed util-linux 2.41.3/cryptsetup 2.8.4/systemd-udev 259.
The full inventory race package passed with both retained native fixtures.
These virtio-SCSI VM results do not qualify physical-media destruction or a
native NVMe namespace capture.

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

The lock continuation isolates the graphical prerequisite instead of relaxing
the provider's filter. The executor pins the root-owned system D-Bus/logind peer,
enumerates `ListSessions`, reads each session's properties, and includes only
`Class=user` with `Type=wayland` or `x11`; it does not filter on `Desktop`.
`$HOME/.cache/lindm-lockqual-20261010/ubuntu24-lock-quarantine-01.json`
(SHA-256 `a75d089cb45d355df174faeac87d5cc5161c3546626b51642ede71294d97a8be`)
records only SSH/TTY sessions before preparation, then a genuine password-enabled
`lindm-desktop-test` GDM autologin with `Class=user`, `Type=wayland`, user-owned
`gnome-shell` and working GNOME ScreenSaver. Logind's optional `Desktop` property
was empty. The lab oracle incorrectly rejected that label; it now accepts an
empty label while retaining all real-user/process/lock-state requirements.
No executor session-filter or lock security gate was weakened. Deterministic
oracle regressions include empty/Ubuntu/GNOME labels, both display types, greeter
and SSH rejection, and disagreement between the two independent lock oracles.

The same directory's `ubuntu24-lock-quarantine-02.json` (SHA-256
`3c573f53b79b6a2ed1db0fa6d7cccbd8e53ef2a20c3dc0c22956087f30647335`)
proves native GNOME/Wayland lock and signed release, with both lock oracles
remaining true after release, plus password disable/account expiry, byte-exact
shadow restoration and preservation of an intervening administrator expiry edit.
The overall record is still failed: its first quarantine action failed preflight.
The product used an unqualified nft `type integer` timeout-set key, rejected by
the native parser. The set now derives its fixed-width key with
`typeof numgen inc mod 1`, matching every lookup. Native nft 1.0.9 accepted the
corrected rule in a disposable network namespace and retained JSON type `integer`;
the root-only regression checks the complete generated IPv4/IPv6 rules through
native `nft --check` in a new network namespace. No host firewall was changed.

The corrected full restriction lane **passed** on 2026-10-10 in 603.91 seconds:
`$HOME/.cache/lindm-lockqual-20261010/ubuntu24-lock-quarantine-07.json`,
SHA-256 `bbe1b82c0a0fc5da50b842b46b6fd2d0d1186d59a2d62686998b42172cfa7a64`.
Checkpoint `9138d17f8ff6c3673f82cea1590c36c33fca2d22` supplied matching lab/server
and agent package inputs through `-build-repo`; the initialized fixture stayed
in its original `-repo` location. `source-provenance.json` in the same directory
(SHA-256 `41f955e4b8cbaaee227796e18697fd2ca968375f174525886c1ec75741d36175`)
binds that base, empty applied diff, all executable/package digests and preserved
failed prerequisites. No fixture path-binding or custody gate was relaxed.

The native tuple is Ubuntu 24.04, GNOME/Wayland, KVM/QEMU 8.2.2, virtio-scsi,
OVMF `2024.02-2ubuntu0.10`, Secure Boot enforced and swtpm2. The record proves:

- Real GDM user login and transition of both logind `LockedHint` and GNOME
  ScreenSaver from false to true through the signed lock action.
- Signed release preserves the locked screen pending local authentication.
- A password-enabled account becomes password-locked and expired; unchanged
  owned shadow state is restored byte-for-byte, while an intervening admin expiry
  edit is preserved. Passwords and complete shadow rows are never exported.
- Two native quarantine/release cycles block the guest namespace peer and routed
  host endpoint while preserving the allowed management endpoint and explicit DNS.
  Explicit release restores traffic; kernel expiry also restores traffic with
  both agent and executor stopped, followed by signed release of the server fence.
- An offline action request is rejected with `device_action_offline`.

This is not physical-display, boot-lock, X11, KDE, multi-user or other-distro
qualification. The action-provider logind filter required no product change.

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

Subsequent original-device recovery attempts retained serial and unit journals.
`ubuntu-recovery-nvme-14.json` (SHA-256
`e16de0906394545fe8a4a07527b8d229ca564f42d298fc95a4c3d0886ee7ccd2`)
proved that the guest had completed its real reboot while the obsolete host-side
SSH socket remained open. The reconnect boundary now requires a changed native
boot UUID through a fresh pinned SSH connection, not a QEMU/slirp TCP FIN. No
reboot is replayed and the existing deadline is unchanged. Sanitized evidence
`reboot-transport-diagnosis.json` has SHA-256
`1d688ad58950882dbdf6e4219308cf96fdbd6c9624a1f9148de1a3e2b1b71195`.

The corrected path reached signed ordinary boot and two-human recovery approval
in `ubuntu-recovery-nvme-15.json` (SHA-256
`49eb11fb2afb9b6a761db7a565b5f694c85717d98445939379953c055d840666`).
Linux discarded QEMU's bogus namespace IDs, exposing the canonical controller
fallback WWN; the then-current NID-only provider refused preflight. This is also
a real consumer-device limitation, not grounds to invent an EUI-64 or relax the
gate. The explicit, immutable NVMe identity bases documented in architecture now
cover that case; corrected native execution remains unverified.

`ubuntu-recovery-sata-02.json` (SHA-256
`c049c8ffcf408de030d675a5b13d9ba596e86110fa339463a4d9a0add577eda2`)
also passed real reboot, signed ordinary/recovery UKI construction and two-human
approval. It remained in the ordinary boot and timed out: serial repeatedly
reported `device_action_ungranted_result`; no recovery poweroff, server-verified
sanitize result or host read-only erase sample was observed. This is distinct
from the NVMe identifier refusal. Its private executor action record was not
captured before cleanup, so its specific native failure was initially unknown.

The retained-root continuation `ubuntu-recovery-sata-03.json` (SHA-256
`b91d0b57888add2e71f1cef30b8170e8361f6054a9a83315c5ade0cdd8741b7b`)
reproduced that symptom and established the actual failure. Protected status and
the bounded executor journal, `/tmp/lindm-cloud-init-1807594397.json` (SHA-256
`5287af24b0f39a74fb254f3ff3047cfb64494381264c6dc3b63e26cb15317202`),
prove the boot grant **was accepted**, followed 217 milliseconds later by
`no space left on device` copying the 69,788,216-byte signed recovery UKI into
the unchanged vendor ESP. The executor retained `OUTCOME_UNKNOWN/INTERRUPTED`;
it did not arm the recovery entry or reboot. This was not a grant/boot-binding
or thirty-second clock-window refusal. Subsequent ordinary relay reports used
the ordinary result endpoint, whose missing ordinary start-grant guard emitted
`device_action_ungranted_result`; that is the downstream symptom, not the cause.
SATA02's identical staging cause remains an inference because its root record
was not retained. These are failure records, not native sanitize passes.

The capacity/readiness continuation `ubuntu-recovery-sata-04.json` (SHA-256
`d718d3017b00042d63a59a229d46a744ad05a8048f2f61a0a896042ca91ee755`)
reduced the actual signed UKI to 38,644,280 bytes, without resizing the ESP.
The server authenticated that exact release size. It refused readiness before
requesting either human approval because the last published root observation
still said `recovery_readiness_not_configured`; restarting after configuration
resumed previously collected inventory rather than publishing new readiness.
No sanitize action was created. Retained unit diagnostics are
`/tmp/lindm-cloud-init-2885912046.json` (SHA-256
`e2ac335a0f1335f8a7b5cecb9cffbf0e5fc4cf3006cde0c2137a5cc03f9573c7`).
The lab now requests a real signed inventory refresh after configuration and
waits for its committed publication before approval. SATA05 exercised that
refresh successfully at both the root executor and server.

This run used checkpoint `9138d17f8ff6c3673f82cea1590c36c33fca2d22`
plus retained source patch `readiness-source-9138d17-03.patch`, SHA-256
`b2745eaa2303de46d098ff68248a34192320853421196d819bed57fed2f77659`.
The refresh correction is patch `readiness-source-9138d17-04.patch`, SHA-256
`691d7cb8af4d6022b36f54078a15a17748196b92107446bd931ed86a1c5a16b1`,
in the same private evidence directory. Stamped whole-tree builds, focused
recovery/readiness tests, and the real-PostgreSQL approval refusal/recheck
regression passed.

`ubuntu-recovery-sata-05.json` (SHA-256
`7ee84afb35f28fd8996c1c4dfa40404e0b692457df28103350149395bd6263b8`)
then retained a fresh root observation: ESP `103C-DA09`, 57,928,704 free bytes,
512-byte allocation units, Secure Boot enabled, 38,644,280-byte signed UKI
(38,644,736 allocation-rounded bytes). No sanitize approval/action was created:
the observation refused `recovery_readiness_loader_esp_unavailable`.
The new readiness check incorrectly required lowercase UUID text for the
firmware's `LoaderDevicePartUUID`. Pinned upstream systemd v255 commit
`db11bab38ccf1ed257f310d29070843d4c58ea01`,
[`util.h` GUID_FORMAT_STR](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/boot/efi/util.h#L132)
and `part-discovery.c:294` establish that systemd-boot writes uppercase UUIDs.
Firmware partition UUID validation now accepts either hexadecimal case without
loosening canonical boot-ID validation or exact ESP equality. The regression
passed; retained journal diagnostic `/tmp/lindm-cloud-init-2852315950.json`
has SHA-256 `d4c20b966a678dee4be84f890722d564b6744258b025d6eb75ba90a896921aea`.
The corrected source patch `readiness-source-9138d17-05.patch` has SHA-256
`9a4e3394ce37fc424ae44cfe15d7a5e988bfdaf0beb276eb47c017d2a944c665`.
These failure records are not native SATA/NVMe erase, Ubuntu live-root
report-loss, or Fedora wipe qualification passes.

The firmware-UUID correction ran as `ubuntu-recovery-sata-06.json`, SHA-256
`e6d583e2bac58d43e3e5729f0f110a6683dbd51820f607999e7210a7a12390bf`.
Its real refresh action could not publish while older prechallenge inventory
remained rate-limited; retained journal `lindm-cloud-init-1495454141.json`
(copied alongside the record; SHA-256
`8ded0d204ebeeeb6dcef3e45ba1b8208f202cb3dac7a0200d3b22b4549410de4`)
records repeated `publish refreshed inventory: resource_exhausted: rate_limited`.
The final SSH/deadline failure occurred during the owner-identified host swapping
window, **not a qualified product failure**. No sanitize approval/action or
erasure occurred. A fresh diagnostic connection also encountered the abandoned
request filename from the closed original transport; each status request now
uses a unique filename while preserving exclusive creation.
Owner-directed isolated reruns limit local guests to wipe and Fedora encryption
only (two guests). Host load, available memory and cumulative swap-in/out counters
now accompany the maintained preflight and failure evidence; action diagnostics
also capture them before guest cleanup. Old records remain unchanged.

The contention-window `ubuntu-live-erase-06.json`, SHA-256
`8bb9d62561de5e29883ffd12e00160930d6c39630d83741aad0ba088bec1ae13`,
completed real root and data escrow, revealed-key data unlock, cold root boot,
three destructive authorization denials, and distinct requester/approver
authorization. It observed original-machine poweroff before a successful server
attestation; header absence and rejected post-erase boots were not checked.
The already-off guest could not return executor status/journal; that explicit
failure is retained in `lindm-cloud-init-2182716954.json`, SHA-256
`20ad2aa49d60e9c58e3918658553c15a8147a2d53d072a4178917fdd74177498`.
This is not an erase pass or an isolated product-failure diagnosis. Its source
patch `readiness-source-9138d17-06.patch` has SHA-256
`c8d93abf7be0662613c3433c0cfe0d23bf095abd3a419b7084fa9c7c00126655`.
The isolated continuation adds host sampling, with source patch
`readiness-source-9138d17-07.patch`, SHA-256
`e56137ed92e902b72eb62685d80e8d8d7490e6d25e96ab59f3e50e05c1b78c12`;
focused host/action-diagnostic regressions and the runner build passed.

The isolated `ubuntu-live-erase-07.json`, SHA-256
`c92efa86345932f03806323b452bfd64a71094a616afade5d90d7dece8c86d52`,
reproduced poweroff before successful attestation after the same real escrow,
unlock and approval milestones. Host available memory was 51,511,152 KiB at
start and 54,541,008 KiB at failure; one-minute load fell from 2.95 to 2.14.
Swap counters advanced 51,099 pages in and only 10 pages out during the run.
This isolated repeat is not dismissed as the earlier contention-window timeout.
The powered-off executor was unreachable, retained explicitly in
`lindm-cloud-init-2045413201.json`, SHA-256
`5394c1d3699b5cd708b458363bbd41ed7c79daea5960728c5bdcfe118386410c`.
The next diagnostic runner retains the post-unlock console through live
poweroff and the last observed server status, closing that console observer
before any later credential-rejection boot. Patch
`readiness-source-9138d17-08.patch` has SHA-256
`0d4086849aec0babe1c2e699ad896e5d698746f124adff9b51f07ba3f0c914de`;
focused live/diagnostic regressions and build passed.

Further retained records under the same private evidence directory:

| Record                              | SHA-256                                                            | Observed boundary                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu-live-erase-08.json`         | `4dd75969eb2c6601787e8472aaa48eae7e2a597b1a60617b36feede7bfca5b01` | Server stayed `OUTCOME_UNKNOWN`; retained console shows graceful PID 1 shutdown before successful attestation. No swap-out occurred during this isolated run.                                                                                                                                                                                                                          |
| `ubuntu-live-erase-09.json`         | `67f5d3f53453a805bac74e5edee49c0d72559c412cbee7138dd0d86fe86efc00` | Fixture correctly refused an unstamped server binary before creating a guest.                                                                                                                                                                                                                                                                                                          |
| `ubuntu-recovery-sata-07.json`      | `85d33e8d6f8829265cdb1e0f10bd5d8ef74bff8caa0befbe534b70de2b08c9cf` | Same missing explicit linker-version stamp; no native recovery attempt.                                                                                                                                                                                                                                                                                                                |
| `ubuntu-live-erase-10.json`         | `2f3d4d1c8e2c9f91686769a8578f9017d60492614bf8311838e6e92838c6c8e7` | Root escrow succeeded; current storage admission correctly rejected the newly formatted data volume until its new LUKS identity was published. The lab now performs a real signed refresh before escrow.                                                                                                                                                                               |
| `ubuntu-recovery-sata-08.json`      | `ec5dad55f2aa770472814454cc208c35a572373676b17347da6eaa8ba0228d7a` | Backlog-aware signed refresh and remote readiness passed; exact signed size38,700,600bytes, allocation-rounded38,701,056, available57,928,704. Two humans approved and the original device rebooted through its signed loader, but no scoped recovery result arrived.                                                                                                                  |
| `ubuntu-recovery-sata-09.json`      | `4ebb3e2e7ce403c407d3d84efb84c2b947976f4d1a22b15ee6fb4f9368e7701e` | The signed recovery init and DHCP ran; protected configuration admission refused replaceable ancestry. The archive omitted `"."`, leaving rootfs's inherited root-directory mode. The builder now explicitly archives UID0/GID0 mode0755 root; the ancestry validator is unchanged.                                                                                                    |
| `ubuntu-recovery-sata-10.json`      | `d45811c9e235078dbf6990517d27cfba3c3315ddfd6a25996860635bd47043b2` | Protected configuration now passes; native `sbverify` exec was refused because the collected ELF interpreter lacked its executable bit. The builder now rejects that malformed closure before signing, and the lab identifies the executable loader from each approved helper's `PT_INTERP`, rather than marking every shared library executable.                                      |
| `ubuntu-recovery-sata-11.json`      | `061b4b64e81a4a8900c31b256519e09b30a8415697d1f5b81e8ee17ebcd8defe` | Protected config and native image verification pass; the signed client receives HTTP405 because the production public mux omitted `RecoveryHandler`. The handler is now registered beside enrollment on the pinned admin/enrollment TLS origin, retaining its dedicated scoped-proof validation and no ordinary session/device authority.                                              |
| `ubuntu-recovery-sata-12.json`      | `b47aa8f1f2ad6d6862946ebb8c121870071596cdde9088062064da0b8bde5d46` | Scoped TLS recovery RPC now works; native fail-closed verification rejects omitted current trust. The ordinary-device trust API omits an unchanged delegation, but recovery requires it on every acquire. The server now includes the authenticated current snapshot's exact signed delegation in this case; the client's mandatory revalidation is unchanged.                         |
| `ubuntu-recovery-sata-13.json`      | `8563b47be716ca11d016d7998b136e95e7e669640d474c470fdd6be80683c19f` | Signed recovery stops at `recovery_request_rejected`; the previous generic reason did not distinguish payload binding from the proof clock window. Verified-signature diagnostics now distinguish those cases while retaining identical rejection gates.                                                                                                                               |
| `ubuntu-recovery-sata-14.json`      | `944f58440730afd597440ecc0e5815cd7106455a9114c0c605b08b6c4cde7080` | Recovery receives a signed checkpoint receipt, then refuses its binding/time predicate; no effect or success is inferred. The diagnostic now separates identity binding from a signed server receipt ahead of local recovery time and retains both nonsecret UTC timestamps.                                                                                                           |
| `ubuntu-recovery-sata-15.json`      | `dcf1f17c5e93e4acf8699db50961d08ecd616c024edde5d6bf518440a3a8d660` | **Readiness/approval/handoff pass; sanitize is not passed.** Exact38,700,600-byte image fits the unchanged ESP, both humans approve, and signed original-device recovery boots. The server authenticates the scoped proof but rejects `recovery_request_clock_ahead`: its issued-at exceeds the server database clock. No erase or success is claimed.                                 |
| `ubuntu-recovery-nvme-16.json`      | `e4d66519858fd8e11c28594f0a462baf30658f4e12389a9c0a7a59d4d8be97df` | No approval/action was requested. After the owned ordinary reboot, Linux renumbered the NVMe controllers: retained kernel evidence places root on `nvme1n1`, while the fixture probed the prior `nvme0n1` path. The lab now resolves current whole-media paths against the frozen WWN/serial/size and rejects absent or duplicate identity before native scope observation.            |
| `ubuntu-recovery-nvme-17.json`      | `c880491db3307d6959d7dc196c509e0e8bc8af46410a06a515ae03fa7b1277fb` | **Identity/approval/handoff pass; sanitize is not passed.** QEMU Identify binds controller-serial-nsid (basis2), serial `lindm-lab-0`, NSID1, namespace3,758,096,384bytes and LBA shift9. Exact39,441,976-byte image passes readiness on the unchanged ESP. Two humans approve and original-device signed recovery boots, then strictly refuses `recovery_request_clock_ahead`.        |
| `ubuntu-live-erase-11.json`         | `0a1df0b4973eea23180d28af0511c41cef3700a41ec97d7d6181d7f2045a952f` | **Passed on Ubuntu 24.04 encrypted golden.** Two distinct humans, negative approval bindings, root/data escrow and cold unlock, native live-root crypto-erase, successful attestation before poweroff, both16MiB LUKS headers absent under independent stopped-disk inspection, and original/revealed credential boot rejection.                                                       |
| `ubuntu-live-report-loss-02.json`   | `318cb7d00e8004f8afb39643123a7883ad8f9972d8eeaec9d252b698520a1ae9` | **Passed on Ubuntu 24.04 encrypted golden.** The result channel was deliberately blocked after independent approval; the server remained `OUTCOME_UNKNOWN`, never successful. The fixed120s timer powered off the guest; independent stopped-disk inspection found both headers absent and both post-erase credential boots failed.                                                    |
| `fedora44-live-erase-01.json`       | `e3ebee1defb2bddd33fe8ec39938457968cd1a22eda39a3a7d5e4033d4b3605f` | **Passed on Fedora44 encrypted golden.** Distinct human approval plus self/digest/expiry denials, root/data escrow and recovery unlock, native erasure and successful pre-poweroff attestation, fixed120s forced poweroff, independently absent headers, and rejected owner/revealed credential boots. The public volatile root result and bounded journal are retained in the record. |
| `fedora44-live-report-loss-01.json` | `d647fc632174c6bc251a491f3eb16d9e84038fe3c909e8acfaa9abdee903e1f6` | **Passed on Fedora44 encrypted golden.** Two-human approval, successful root/data escrow and cold recovery, deliberate result-channel loss, server `OUTCOME_UNKNOWN`, fixed120s forced poweroff, independently absent headers and rejected owner/revealed post-erase boots.                                                                                                            |

The live helper's unit had a real sandbox contradiction: `ProtectClock=yes`
removes its required `CAP_WAKE_ALARM`, as shown by pinned systemd v255
[`unit.c:4361–4362`](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/unit.c#L4361).
The correction retains the capability only for the fixed wake-capable alarm,
denies `@clock` syscalls explicitly, and does not add clock-setting or RTC-device
authority. Packaging/provider regressions pass. Native live11 now proves the
correction: root retained a volatile report-only result, the server acknowledged
success while the guest was running, and the fixed120s alarm powered it off.
Volatile root status and bounded journals are sampled while the live guest is
still running, rather than waiting until poweroff. This is crypto-erasure, not
physical-media sanitization; backups, golden images and external key copies are
outside its claim. Ubuntu and Fedora normal/report-loss runs qualify their own
distinct outcomes; only the delivered, verified result is called successful.

SATA08's retained console ends at the original signed systemd-boot entry; its
recovery image had no serial console and init had not reopened standard streams
after devtmpfs. The next signed artifact binds the lab UART and reopens
`/dev/console` without adding an interactive fallback. Console regression tests
pass. Diagnostic `lindm-cloud-init-3817167847.json` has SHA-256
`f094826cb9d1cbd2c52339444d2274d718cf9447e8a12f4ffc0c11e58337b3ef`;
the explicit unreachable-root diagnostic `lindm-cloud-init-3649033626.json` has
SHA-256 `07ab26c2f1c0e17962b1e81462263b282e3deb3fb27a6144b3689471c9a0b111`.

SATA09's signed console exposes the next exact refusal, rather than obscuring it
behind a recovery-result timeout. Retained `lindm-cloud-init-1961485954.json`
has SHA-256 `5b56274d1b288de24b41b83209a02506a5abdb67474d613dd124ba52d4658cd9`;
the independent root probe `lindm-cloud-init-1168573763.json` has SHA-256
`5314ec158fc9959bea619693602651bd813d7d3e9f89c9ef0fa32921a63ad230`.
The deterministic archive regression now requires the root entry and its exact
owner/mode, without weakening descriptor-based protected-configuration checks.
SATA10's serial `lindm-cloud-init-3656915980.json` has SHA-256
`69e8c22ff491b755099e279cb4be9d6f889dc35a6fe516855e5f52c56d58f349`;
root probe `lindm-cloud-init-1067769389.json` has SHA-256
`9493dc345641c6a9210d2961e1b2650b56fa29b608279737179f0025c90d10a0`.
The executable-interpreter regression includes both refusal and admission cases.
SATA11's console `lindm-cloud-init-340625354.json` has SHA-256
`aa4096d9d997296a5c26aa9a7eed759e2c24dcccff16214e85ed0b310bab1232`;
root probe `lindm-cloud-init-3240257971.json` has SHA-256
`37ebb4f0be09be3b740cad5d300a6fd9dd05077392d7939b8d8f4cab495b3079`.
SATA12's console `lindm-cloud-init-3604538400.json` has SHA-256
`cc929ae0e6d97dc19b9dd0bede3997ee8754c4b7c954b897b0d1fe34af046521`;
root probe `lindm-cloud-init-144639348.json` has SHA-256
`503a66d31daef00bca487c782a203fa1cd0a666694f70ee1eb4c83f4c2d05e65`.
The real-PostgreSQL recovery race suite, including unchanged-trust delivery and
durable checkpoint/replay/terminal checks, passes in9.081s.
SATA13's console `lindm-cloud-init-3640399681.json` has SHA-256
`c2632b05a49cd3f8e5cd9f9fa8c6ca46b1c5623d76c340fccdc796244d615816`;
root probe `lindm-cloud-init-1384431512.json` has SHA-256
`3d6759c688951b2d91977f4491104d0eabd32d17b0321109b50a5bb6fef8e7a4`.
Recovery proof errors distinguish payload mismatch, future issuance and expiry
only after authenticating the signature and credential/operation/boot binding.
The one-nanosecond future and exact-expiry boundaries still reject in regression.
NVMe16's retained lifecycle/kernel journal `lindm-cloud-init-1249337287.json`
has SHA-256 `8161b29e33c8448db4d1fba86985e28c511d36891a24bd1a0cddd5fd6f0a3dab`.
The post-reboot identity resolver regression rejects changed WWN, serial, size,
LUKS identity, duplicate disks and missing frozen identity. The native identity probe now
retains its bounded nonsecret stderr instead of only its byte count.
SATA14's console `lindm-cloud-init-63802455.json` has SHA-256
`b02cefa69619b9a5606a15306d05c3be2b99bc91def69a3f0c912d2431b78f11`;
root probe `lindm-cloud-init-981707828.json` has SHA-256
`1a18bcb98cbb8ab332e8dae146fd28670da452a04144a2f2a996b7ab0dc5b9e6`.
NVMe17's console `lindm-cloud-init-2552937792.json` has SHA-256
`9a90bf3660b49673eacb192914bc6df52b39dce2b9d29ed368020f6c9842f96c`;
root probe `lindm-cloud-init-3599471030.json` has SHA-256
`9be64d4e5e41d2d6cca26c7c347f055ddd053d78893979153b0dab158e821dda`.
The minimal recovery image has RTC time but no authenticated clock bootstrap.
Future-issued proofs are rejected even inside their30s lifetime; a signed
checkpoint stored after the local clock is also rejected. No acceptance window
was widened and no unauthenticated time source was introduced.
SATA15 reproduces the same strict future-issued-proof failure as NVMe17.
Console `lindm-cloud-init-2867842716.json` has SHA-256
`f7ae0b99bedb7f5d3c45094d71342fbc5cfbfd1c447d222dfe3a8898a0c13130`;
root probe `lindm-cloud-init-3515380366.json` has SHA-256
`6970d94b80bb0fb76286b600d4144c1c069510c9e9c338857ef7489bf9f69585`.
Both final recovery attempts have zero host swap-out delta and over50GiB available
memory. Their retained authenticated refusals—not the later lab wait timeout—are
the product diagnosis. Recovery needs an authenticated time bootstrap consistent
with the signed proof/grant/receipt contract before sanitize can be qualified.

The unified private build is based on
`01495afab18b08dcec438f973ce43728156c235c`, including the checked refresh-backlog
patch (`68921325a97af3b7fd594ef93fcdc8c4198a795f1b2075b640b346add0463a8b`).
`isolated-source-01495af-01.patch` has SHA-256
`174defbd6ca0ad20cf7f45ad8df338782c5c7fa80729c191e1226224c00c8d4c`;
matching binaries use explicit `-X lindm/internal/agent/buildinfo.Version=0.1.0`.
The alarm/target-refresh correction is patch03, SHA-256
`fa2707087334e5830104900d11281e5b500301b1cc61c08982cee5feb5d449a8`;
the signed console correction is patch04, SHA-256
`c31391f9a91de2a3e1ada2a77ab2e9c5f4a51b66af1c9ba78c6b3e1cbb824c86`.
The protected archive-root correction is patch05, SHA-256
`3bd9da1ce45e5af0c07ce37e56125cf737bc534f255321236f6d9e1ba03c803a`.
The executable-interpreter correction is patch06, SHA-256
`165f871a482ea01cdc36ad2205f7c2936c3d050d1f9c04829d638ce24bacfcd8`.
The public recovery-route correction is patch07, SHA-256
`2810782ac9f5875738c87ca86348a7eb554c552dab904378f299c1d2ec33b8b2`.
The mandatory current-trust correction is patch08, SHA-256
`26b4e3938a84a48b7d3df59334adb5b5d4f58504ce04a923591fd4207be1a863`.
The authenticated proof-diagnostic correction is patch09, SHA-256
`1275f1b3aee139e2e374deb8789cc16d19aa4222660cfa8d5a735008819da42a`.
The NVMe boot-local path correction is patch10, SHA-256
`9e604e9b1fe69be75539e9cd996a473b63431c0c208d575957a1192478fe8bf3`.
The signed receipt-clock diagnostic is patch11, SHA-256
`773109ec0702261b2fbc16b4fcf88c69f21f9c874fbf6d9e7c3e046991153e23`.
Adjacent JSON files bind binary and embedded-console digests and exercised checks.

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
converged to `OUTCOME_UNKNOWN`. That overall historical record remains **failed**:
TPM bind admission expected `2.0` instead of the collector's canonical `2`.
After the server fix and regression, separately scoped
`-scenario encryption -encryption-phase tpm` **passed** on Ubuntu24:
`ubuntu24-tpm-01.json`, SHA-256
`f2972ce70ea7b2a9fce28d5d774bbfc748739cecd8b99a45801ed1c16b178a32`
in the same directory. It proves actual successful TPM bind, server/host
systemd-tpm2 token agreement, unattended cold boot without a prompt, PCR7 policy
mismatch rejection, and cold recovery with a two-human-revealed escrow key.
Together the two records cover all five Ubuntu encryption scenarios, not one
uninterrupted full-lane pass.

Fedora44 full encryption run `fedora44-encryption-01.json` in the same directory
is **failed**, SHA-256
`29fd5d3f15eb25d1f3442612368427da02ae59b81caabc97b309806b05637a55`.
It proves native server/host inventory agreement, KEK custody/audited two-human
reveal, first revealed-key cold boot, committed rotation and retired-slot absence.
The retired-key cold boot did not satisfy the explicit serial rejection oracle;
the lane stopped before authorization denials, crash recovery and TPM binding.
The serial oracle now also accepts explicit cryptsetup or
[systemd 259](https://github.com/systemd/systemd/blob/v259/src/cryptsetup/cryptsetup.c)
incorrect-passphrase diagnostics after submitting the chosen key, without
requiring a repeated prompt; timeouts remain failures. Fragmented-message
regressions passed. This is not yet a demonstrated cause of the native failure:
that historical record masked the underlying boot error, which is now preserved.

**Fedora44 scenarios 1–5 subsequently passed in one full run**:
`$HOME/.cache/lindm-encryptionqual-20261010/fedora44-encryption-11.json`,
SHA-256 `33ae1246cc71ec97a83e7b7ccf319103d0fc46513cd089760155285ad9eb71a5`,
in 1240.93 seconds. This supersedes the open Fedora qualification status above,
without rewriting failed historical records. Native observations include:

- Server/host LUKS2 inventory, slots/tokens, TPM2 and Secure Boot agreement.
- Actual KEK custody, audited two-human reveal and eight authorization denials,
  including missing reason, dedicated permission and real five-minute step-up expiry.
- Revealed-key cold boot, committed rotation, explicit retired-key rejection and
  replacement-key cold boot.
- Hard-crash rotation retaining owner/old/new slots `[0,1,2]`, old/new recovery
  boots, and root/server `OUTCOME_UNKNOWN`.
- TPM bind and host token agreement, unattended cold boot without a prompt,
  PCR7 mismatch rejection, and separately revealed recovery-key cold boot.

The lab fix routes Fedora's initramfs `systemd-cryptsetup@` normal diagnostics to
the serial console using a disposable-clone service drop-in included by real
`dracut --force --include`. Fedora otherwise journals the exact rejection without
necessarily repeating its serial prompt. No product security gate or rejection
criterion was relaxed. Exact cryptsetup/systemd wrong-passphrase recognition has
fragmented-message regressions. Upstream reference:
systemd v259.5 commit `b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a`,
`src/cryptsetup/cryptsetup.c` (the `-EPERM` passphrase rejection branch).

Run11 source base is `9138d17f8ff6c3673f82cea1590c36c33fca2d22`,
private diff SHA-256
`f43c9fb98032fb8146c8b76f47804e4e56757d0755ee280afa7e41ac747a71b4`;
adjacent `fedora44-encryption-11-source.json` SHA-256
`7df54c6bbce104c0393508aceab452629e451a854d326ddf3baae51053aeb726`.
Its temporary masked deadline diagnostic was not exercised on this passing run
and has been removed from maintained code. The run began during host contention
and completed after other lanes stopped; no start/failure host samples existed
in that binary. The newly maintained host sampler's regression passes, but a
fresh full run exercising that sampler is not claimed. This is QEMU emulation,
not physical TPM/media certification.

Fedora continuation records retain failures, never overwrite them. Runs 03 and
07–10 ended in boot/readiness deadlines during the subsequently identified host
contention window; these are **not product-failure or rejection proofs**. The owner
observed 56/62 GiB swap occupancy and reduced local guests to encryption plus wipe.
Runs 08–10 prove the key was submitted, the cryptsetup unit failed, and dracut
could not find the root mapping, but not the unit's exact authentication error.
The maintained runner now records host load, available-memory KiB, total/free swap
KiB and cumulative `pswpin`/`pswpout` page counters at preflight and failure.
Differences show run-time swap activity rather than historical occupancy alone;
host observation errors remain explicit and cannot turn a failed run into a pass.

All following files are under `$HOME/.cache/lindm-encryptionqual-20261010/`:

| Record                        | SHA-256                                                            | Boundary                                                                                               |
| ----------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `fedora44-encryption-02.json` | `ceb11685c9c27d1281976106da000a331352f9289bcc4c954e1388254e29f9cf` | Shared inventory edit temporarily omitted collector definitions; no guest proof.                       |
| `fedora44-encryption-03.json` | `033f07c0e60de159a048a1deaa2e4096facc7070dac99f51bd3e49997e0c76d0` | Pre-action deadline, contention-window result; no enrolled action proof.                               |
| `fedora44-encryption-04.json` | `bc2d7c8bd531c0b83be4d4de23f86c964351baab5982a1193cbc3e638a12890b` | Shared generated handler lacked implementation during package compilation.                             |
| `fedora44-encryption-05.json` | `60e0fe3f47fcc02ac2a1840df94c92dd881115fcfcd8d1370ee1c9ca7d17dbf4` | Private fixture symlink correctly rejected by custody.                                                 |
| `fedora44-encryption-06.json` | `0018be1b884e3b806596aa6a5f35096a546e2a9b9d54364e02478d453d6dfbed` | Private fixture copy retained original directory binding; correctly refused.                           |
| `fedora44-encryption-07.json` | `d2e0c6fc44189d0878d7dc7de262a2ed491c1ef2758cf94191b1a255f92434d1` | Pinned `fa2bd15183a8376e01179cb8ec68302d777e6d96`; retired-key deadline after earlier positive proofs. |
| `fedora44-encryption-08.json` | `3bdca92440ffe4da1dd5fc2cfe3969abddb99902922c11b30c3c4d6279d9f8a2` | Masked late serial diagnosis: missing root mapper and dracut emergency shell.                          |
| `fedora44-encryption-09.json` | `d1f09edb77287c4da95f8eee4e5b3167a54e80dffe5cc3569b2e9e7b42817f64` | Masked early serial diagnosis: submitted key and failed cryptsetup unit.                               |
| `fedora44-encryption-10.json` | `edc93c0d1ae9eeefab61534162c8d477601dd5870ef436ea87757f68d7cb3fd7` | Kernel log-target change did not expose cryptsetup service journal on serial.                          |

Runs 08–10 use base `9138d17f8ff6c3673f82cea1590c36c33fca2d22`;
adjacent `-source.json` and `.patch` files bind each private diagnostic diff.
Private copied fixture credentials were removed; continuations use separate
`-repo` fixture and pinned `-build-repo` source roots.

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
