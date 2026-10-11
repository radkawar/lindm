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
optional within its tier ([tiers](#platform-support-tiers)). NixOS and Fedora Atomic
are design-only until their own management model is specified; mutable-provider
behavior never qualifies them. The table allocates qualification work; it does not
declare support.

### Platform support tiers

The owner set these tiers on 2026-10-11. **Tier 1** is desktop-first and requires
full parity with Ubuntu 24.04. **Tier 2** gets the same capability contract
through its own rolling model. Every cell still needs its own native evidence. The
older family/branch allocation [below](#branch-allocation) still sets
architectures and editions. Server-only legacy branches (RHEL/Rocky/Alma 8, SUSE
enterprise, Leap) are outside these tiers until the owner places them. The table is
generated from the platform registry (`internal/platform`); aarch64 rows are server
editions, and desktop editions qualify on x86_64.

<!-- BEGIN GENERATED platform-tiers -->

| Tier   | Distribution        | Releases                        | Desktop edition                | Architectures   | Platform page                             |
| ------ | ------------------- | ------------------------------- | ------------------------------ | --------------- | ----------------------------------------- |
| 1      | Ubuntu              | 22.04 LTS, 24.04 LTS, 26.04 LTS | GNOME                          | x86_64, aarch64 | [ubuntu](platforms/ubuntu.md)             |
| 1      | Debian              | 12, 13                          | GNOME/KDE                      | x86_64, aarch64 | [debian](platforms/debian.md)             |
| 1      | Fedora              | 43, 44                          | Workstation GNOME; KDE edition | x86_64, aarch64 | [fedora](platforms/fedora.md)             |
| 1      | RHEL                | 9, 10                           | GNOME                          | x86_64, aarch64 | [rhel](platforms/rhel.md)                 |
| 1      | Rocky Linux         | 9, 10                           | GNOME                          | x86_64, aarch64 | [alma-rocky](platforms/alma-rocky.md)     |
| 1      | AlmaLinux           | 9, 10                           | GNOME                          | x86_64, aarch64 | [alma-rocky](platforms/alma-rocky.md)     |
| 1      | Linux Mint          | 22.3                            | Cinnamon                       | x86_64          | [mint](platforms/mint.md)                 |
| 1      | Pop!\_OS            | 24.04 LTS                       | COSMIC                         | x86_64          | [popos](platforms/popos.md)               |
| 2      | Arch Linux          | rolling                         | owner-chosen per record        | x86_64          | [arch](platforms/arch.md)                 |
| 2      | Omarchy             | 4.0.4                           | Hyprland                       | x86_64          | [omarchy](platforms/omarchy.md)           |
| 2      | openSUSE Tumbleweed | pinned snapshot                 | KDE Plasma/GNOME               | x86_64, aarch64 | [opensuse](platforms/opensuse.md)         |
| Future | Fedora Atomic       | Silverblue/Kinoite              | —                              | —               | [atomic-nixos](platforms/atomic-nixos.md) |
| Future | NixOS               | any                             | —                              | —               | [atomic-nixos](platforms/atomic-nixos.md) |

<!-- END GENERATED platform-tiers -->

NixOS and Fedora Atomic manage the system declaratively or as images. They stay
**design-only** until a separate management model is specified; see the
[product specification](product-specification.md#supported-os-tiers). No mutable
DEB/RPM evidence counts toward them.

#### Tier capability matrix

Generated by `lab matrix report` from [`lab/ledger.json`](../lab/ledger.json), the
cell table [`lab/matrix.json`](../lab/matrix.json), the platform registry and the
pinned image manifests; the workflow is in
[engineering](engineering.md#lab-qualification-matrix). A cell shows one state
when every registry architecture agrees and `architecture state` pairs otherwise:

- `pass` / `fail`: the latest ledger entry's lane verdict, linked to the section
  narrating its records. A parenthesized scope names the recorded subset. This is
  VM evidence for that branch, architecture and pinned image only, not
  qualification. There are **no qualified cells**.
- `—`: the lane can run but nothing is recorded.
- `gated`: the registry gates a capability the lane needs; the
  [platform pages](platforms/README.md) state the reason.
- `no lane`: no maintained lab lane drives the capability.
- `no image`: no pinned manifest of the needed kind for that architecture.

Resources covers the registry resource capabilities; per-kind state is in
[resource-kind coverage](#resource-kind-coverage). Wipe/loss/lock merges the
former Wipe and Lock/quarantine columns; the former Config `service` subset is
the dispatch lane's systemd service evidence.

<!-- BEGIN GENERATED lab-matrix -->

| Release             | Inventory                                   | Enroll from console                                                                                                          | Lifecycle                                                     | Dispatch                     | Resources                                                                 | Encryption                                                                                                                           | Wipe/loss/lock                                 | Recovery sanitize                             | Self-update                         | Assistance                                                                                                                             | Advisories | OS update                     | Release upgrade |
| ------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------- | --------------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------- | --------------- |
| Ubuntu 22.04 LTS    | x86_64 [pass][r1]; aarch64 —                | no lane                                                                                                                      | x86_64 —; aarch64 [pass][r2]                                  | x86_64 —; aarch64 [pass][r2] | —                                                                         | —                                                                                                                                    | —                                              | gated                                         | x86_64 no lane; aarch64 [pass][r2]  | —                                                                                                                                      | no lane    | gated                         | gated           |
| Ubuntu 24.04 LTS    | x86_64 [pass][r3]; aarch64 [pass (TCG)][r3] | x86_64 —; aarch64 [pass (Bare VM; exact console clipboard; signed own-server APT; real console Enrolled; owned cleanup)][r4] | pass                                                          | pass                         | x86_64 [pass (seven kinds, no firewall)][r5]; aarch64 [pass (subset)][r6] | x86_64 [pass (TPM scenario)][r7]; aarch64 [pass (full encryption; product TPM bind; unattended cold boot; Secure Boot enforced)][r8] | x86_64 [pass (selected phases)][r7]; aarch64 — | —                                             | x86_64 [pass][r9]; aarch64 no lane  | x86_64 [pass (GNOME)][r10]; aarch64 [pass (GNOME Wayland assistance; all five scenarios; split controller/dgx20; Secure Boot on)][r11] | no lane    | x86_64 —; aarch64 [pass][r12] | [pass][r12]     |
| Ubuntu 26.04 LTS    | [pass][r12]                                 | no lane                                                                                                                      | x86_64 [pass][r12]; aarch64 [pass (control-plane trust)][r12] | [pass][r12]                  | [pass (eight kinds)][r12]                                                 | x86_64 [pass][r12]; aarch64 —                                                                                                        | x86_64 [pass][r12]; aarch64 —                  | x86_64 [pass (measured GRUB)][r12]; aarch64 — | x86_64 [pass][r12]; aarch64 no lane | x86_64 [pass (GNOME)][r12]; aarch64 —                                                                                                  | no lane    | [pass][r12]                   | gated           |
| Debian 12           | x86_64 —; aarch64 [pass][r1]                | no lane                                                                                                                      | x86_64 —; aarch64 [pass][r1]                                  | x86_64 —; aarch64 [pass][r1] | —                                                                         | no image                                                                                                                             | no image                                       | gated                                         | x86_64 no lane; aarch64 [pass][r2]  | no image                                                                                                                               | no lane    | gated                         | gated           |
| Debian 13           | x86_64 —; aarch64 [pass][r1]                | no lane                                                                                                                      | x86_64 —; aarch64 [pass][r1]                                  | x86_64 —; aarch64 [pass][r1] | —                                                                         | no image                                                                                                                             | no image                                       | no image                                      | x86_64 no lane; aarch64 [pass][r2]  | no image                                                                                                                               | no lane    | gated                         | gated           |
| Fedora 43           | x86_64 [pass][r13]; aarch64 no image        | no lane                                                                                                                      | x86_64 —; aarch64 no image                                    | x86_64 —; aarch64 no image   | no lane                                                                   | gated                                                                                                                                | gated                                          | gated                                         | no lane                             | gated                                                                                                                                  | no lane    | gated                         | gated           |
| Fedora 44           | x86_64 [pass][r3]; aarch64 [pass][r1]       | x86_64 —; aarch64 [pass (Bare VM; exact console clipboard; signed own-server RPM; real console Enrolled; owned cleanup)][r4] | x86_64 [pass][r1]; aarch64 —                                  | x86_64 —; aarch64 [pass][r6] | x86_64 —; aarch64 [pass (subset)][r6]                                     | x86_64 [pass][r7]; aarch64 [pass (Secure Boot off)][r14]                                                                             | x86_64 [pass (selected phases)][r7]; aarch64 — | —                                             | x86_64 [pass][r9]; aarch64 no lane  | x86_64 [pass (GNOME)][r10]; aarch64 [pass (GNOME, Secure Boot off)][r15]                                                               | no lane    | —                             | gated           |
| RHEL 9              | x86_64 [pass][r13]; aarch64 —               | no lane                                                                                                                      | x86_64 [pass][r1]; aarch64 —                                  | x86_64 [pass][r1]; aarch64 — | x86_64 —; aarch64 [pass (eight kinds)][r5]                                | no image                                                                                                                             | no image                                       | no image                                      | x86_64 —; aarch64 no lane           | gated                                                                                                                                  | no lane    | —                             | gated           |
| RHEL 10             | —                                           | no lane                                                                                                                      | x86_64 [pass][r1]; aarch64 —                                  | x86_64 [pass][r1]; aarch64 — | —                                                                         | no image                                                                                                                             | no image                                       | no image                                      | x86_64 —; aarch64 no lane           | gated                                                                                                                                  | no lane    | —                             | gated           |
| Rocky Linux 9       | [pass][r1]                                  | no lane                                                                                                                      | x86_64 —; aarch64 [pass][r1]                                  | x86_64 —; aarch64 [pass][r1] | —                                                                         | —                                                                                                                                    | —                                              | —                                             | x86_64 no lane; aarch64 [pass][r2]  | —                                                                                                                                      | no lane    | gated                         | gated           |
| Rocky Linux 10      | [pass][r1]                                  | no lane                                                                                                                      | —                                                             | —                            | —                                                                         | —                                                                                                                                    | —                                              | —                                             | x86_64 no lane; aarch64 [pass][r2]  | —                                                                                                                                      | no lane    | gated                         | gated           |
| AlmaLinux 9         | [pass][r1]                                  | no lane                                                                                                                      | —                                                             | [pass][r1]                   | x86_64 —; aarch64 [pass (eight kinds)][r5]                                | —                                                                                                                                    | —                                              | —                                             | x86_64 no lane; aarch64 [pass][r2]  | —                                                                                                                                      | no lane    | gated                         | gated           |
| AlmaLinux 10        | [pass][r1]                                  | no lane                                                                                                                      | [pass][r1]                                                    | [pass][r1]                   | x86_64 —; aarch64 [pass (all kinds)][r5]                                  | —                                                                                                                                    | —                                              | —                                             | x86_64 no lane; aarch64 [pass][r2]  | —                                                                                                                                      | no lane    | gated                         | gated           |
| Linux Mint 22.3     | —                                           | no lane                                                                                                                      | —                                                             | —                            | —                                                                         | —                                                                                                                                    | —                                              | —                                             | —                                   | gated                                                                                                                                  | no lane    | gated                         | gated           |
| Pop!\_OS 24.04 LTS  | —                                           | no lane                                                                                                                      | —                                                             | —                            | —                                                                         | —                                                                                                                                    | —                                              | —                                             | —                                   | —                                                                                                                                      | no lane    | gated                         | gated           |
| Arch Linux          | [pass][r1]                                  | no lane                                                                                                                      | [pass][r1]                                                    | [pass][r1]                   | gated                                                                     | gated                                                                                                                                | gated                                          | gated                                         | no lane                             | gated                                                                                                                                  | no lane    | gated                         | gated           |
| Omarchy 4.0.4       | —                                           | no lane                                                                                                                      | —                                                             | —                            | gated                                                                     | —                                                                                                                                    | —                                              | gated                                         | —                                   | gated                                                                                                                                  | gated      | gated                         | gated           |
| openSUSE Tumbleweed | x86_64 —; aarch64 [pass][r1]                | no lane                                                                                                                      | x86_64 —; aarch64 [pass][r1]                                  | x86_64 —; aarch64 [pass][r1] | gated                                                                     | gated                                                                                                                                | gated                                          | gated                                         | no lane                             | gated                                                                                                                                  | no lane    | gated                         | gated           |

[r1]: #1-launch-platform-qualification
[r2]: #tier-1-parity-records-2026-10-11
[r3]: #inventory-hardware-observations-2026-10-10
[r4]: #bare-machine-console-enrollment-2026-10-11
[r5]: #all-resource-kinds-in-one-connected-lane
[r6]: #generic-resource-executor-cutover-phase-2
[r7]: #encryption-and-imperative-action-evidence-l10-l13-l15
[r8]: #ubuntu-2404-aarch64-encryption-and-tpm
[r9]: #3-acceptance-scenario-families
[r10]: #built-in-graphical-remote-assistance-l09-l12
[r11]: #routed-split-topology-assistance
[r12]: #ubuntu-26041-parity-records-2026-10-11
[r13]: #branch-allocation
[r14]: #fedora-44-aarch64-encryption-and-tpm
[r15]: #fedora-44-aarch64-gnome-assistance

<!-- END GENERATED lab-matrix -->

Record lane results with `lab matrix run`, or `lab matrix import` for evidence
produced outside it, and regenerate this table in the same change. Desktop,
physical, air-gapped and other-architecture evidence each stays a separate claim.

### Tier 1 parity records (2026-10-11)

Native aarch64 KVM records in `~/.cache/lindm-debianel-20261011/`. The guests used
UEFI with AAVMF `2024.02-2ubuntu0.10`, Secure Boot disabled/SetupMode, virtio-blk,
no TPM or desktop, explicit user egress and isolated local password/WebAuthn
authority. Every record below passed.

| Record                                     | Host  | Lane and result                                                                                                                                                                                             | SHA-256                                                            |
| ------------------------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu2204-arm64-dgx20-lifecycle-01.json` | dgx20 | Ubuntu 22.04 signed 0.8.0→0.8.1 automatic-trust lifecycle with control-plane trust; five 602-package publications, denied attempt6 retained sequence5, epoch 1→3, final revocation and missing-journal hold | `81a9cd1b2679792a16f7501e4d7287150306c38ca44f92359942e3c809c64f10` |
| `ubuntu2204-arm64-dgx21-dispatch-01.json`  | dgx21 | Ubuntu 22.04 nine native dispatch scenarios with real periodic intervals and final revoked denial; supersession integration-only                                                                            | `0552aa6a866df6157cc4daf51d514b998b62065200332ed1651991caa5516dd1` |
| `ubuntu2204-arm64-dgx20-updates-01.json`   | dgx20 | Ubuntu 22.04 APT self-update; 602 packages                                                                                                                                                                  | `82f6b42fe52730e2b241d1c68a98a2e45017d293e50c25ebaf8c0529fdefe997` |
| `debian12-arm64-dgx21-updates-01.json`     | dgx21 | Debian 12 APT self-update; 362 packages                                                                                                                                                                     | `5191beac519d037d59000cc91ebe708b38cc506f9522112c4bcedb4295a5b00a` |
| `debian13-arm64-dgx20-updates-01.json`     | dgx20 | Debian 13 APT self-update; 354 packages                                                                                                                                                                     | `3ea705e345f9dba67552097e5e4987b4d1a296e929ba76bbfbbf605e8e2210af` |
| `rocky9-arm64-dgx20-updates-01.json`       | dgx20 | Rocky Linux 9.8 DNF self-update, SELinux Enforcing; 420 packages                                                                                                                                            | `9b4e2fef4b644d3c8a496f01d6fe18e687376dd15e891a2b8647079b69f91e19` |
| `rocky10-arm64-dgx20-updates-01.json`      | dgx20 | Rocky Linux 10.2 DNF self-update, SELinux Enforcing; 442 packages                                                                                                                                           | `cf1a27bc3a60a80a0d3ad869eb94b2b0be0a276ff592e9a25792bb62e2a26b6f` |
| `alma9-arm64-dgx21-updates-01.json`        | dgx21 | AlmaLinux 9.8 DNF self-update, SELinux Enforcing; 386 packages                                                                                                                                              | `842ee9401a8bf842604c71e861fa50c67129f773c78609c906a743b62084e17b` |
| `alma10-arm64-dgx20-updates-01.json`       | dgx20 | AlmaLinux 10.2 DNF self-update, SELinux Enforcing; 381 packages                                                                                                                                             | `c994f4a2a0ec95fc253ea3640ac676942ec10efbcb313dc07b1a81162fe8c9e9` |

Each self-update record passed all eight steps:

- the six signed negative/hold phases;
- an apt-get/dnf unpack frozen inside the admitted helper cgroup, then an owned QMP reset and a boot-ID change;
- the boot helper completing exact `0.2.0`.

After those steps, device and enrollment identity were retained, the session epoch advanced, fresh inventory advanced its sequence, and a signed downgrade was refused.

Ubuntu 22.04 uses the signed release `jammy-release-20261004` arm64 cloud image (`lab/images/ubuntu-jammy-arm64.json`).

All lanes ran through the remote scheduler as
`lab vm lifecycle|dispatch|updates -host dgxNN -arch arm64 -accelerator kvm -repo WT -manifest M -cache C -allow-network -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd -firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 -record R`.
The lanes added these flags:

- **Lifecycle:** `-first-build`/`-second-build` (signed arm64 0.8.0/0.8.1 DEBs `a805b0a4…`/`66ddab3e…`), `-apt-repository`, `-rejections`, `-public-key`, `-fingerprint 079A7418F86006FC29A111C3336A2C07625A898B` and `-control-plane-trust=true`.
- **Dispatch:** `-local-authority`.

Source base was `5231542`, with private diff `57f4c858…` (lifecycle/dispatch) or `264815db…` (updates).

`vm updates` previously had a fixed hardware contract and could not boot an aarch64 guest, which needs pinned EFI firmware. It now takes the shared hardware flags and is routed as a hardware-capable lane. It refuses an unbootable or non-virtio-blk machine before building packages. The registry admits the lane per architecture through `Lab.LaneArchitectures`. Regressions: `TestUpdateLaneArchitectures`, `TestUpdateHardwareResolvedBeforePackageBuild` and `TestVMUpdatesAcceptsRoutedHardwareFlags`.

### Ubuntu 26.04.1 parity records (2026-10-11)

Every Ubuntu 24.04 lane re-run on Ubuntu 26.04.1 (Resolute). Inputs:
[`ubuntu-resolute-amd64.json`](../lab/images/ubuntu-resolute-amd64.json) and
[`ubuntu-resolute-arm64.json`](../lab/images/ubuntu-resolute-arm64.json)
(release-20260927, the current cloud build after the 26.04.1 point release, signer
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, SHA-256 `88006518…32b2`/`63a93bd5…22e7`)
and the official desktop ISO
[`ubuntu-resolute-desktop-encrypted-amd64.json`](../lab/images/ubuntu-resolute-desktop-encrypted-amd64.json)
(`ubuntu-26.04.1-desktop-amd64.iso`, SHA-256 `601e30fb…1bda1f`, signer
`843938DF228D22F7B3742BC0D94AA3F0EFE21092`). x86_64 ran on local KVM (SeaBIOS
virtio-blk for cloud lanes; OVMF `2024.02-2ubuntu0.10` Secure Boot and swtpm 0.7.3 for
desktop and recovery lanes); aarch64 on dgx20/dgx21 KVM with AAVMF
`qemu-efi-aarch64 2024.02-2ubuntu0.10`, Secure Boot off. All records are under
`~/.cache/lindm-ubuntu2604-20261011/`; every record sits beside its `.cmd`/log, source
snapshot diff and `SHA256SUMS` for the built `lab`/`lindmd`/packages. Native deltas and
product behaviour are on the [Ubuntu page](platforms/ubuntu.md#ubuntu-26041-resolute-raccoon).
This is VM evidence only; there are no qualified cells.

Passing records:

| Cell                                                   | Arch    | Record                                                                  | SHA-256                                                            |
| ------------------------------------------------------ | ------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Inventory, 678/678 dpkg records                        | x86_64  | `advisories/ubuntu2604-amd64-local-inspect-01.json`                     | `678ef76e9a6b6e459e97260e9b6c97d547688044eab8c8786e907bf834031080` |
| Inventory, 675/675 dpkg records                        | aarch64 | `advisories/ubuntu2604-arm64-dgx20-inspect-01.json`                     | `711509471c3946c757d46238eccbbe509194f1ae87b0521b5c17314d554b27ca` |
| Control-plane trust lifecycle (5×679 packages)         | x86_64  | `cloudlanes/ubuntu2604-amd64-local-trust-01.json`                       | `120a76146b8a165edbdf521dda9f41fdad8af20de52a12c83259193eb97282c8` |
| Control-plane trust lifecycle (5×676 packages)         | aarch64 | `cloudlanes/ubuntu2604-arm64-dgx20-trust-01.json`                       | `9fa7e7aaaaf20aa9af3bf4014976433324089a8e99dd776541ea0a794513275f` |
| Signed-service lifecycle, isolated local authority     | x86_64  | `cloudlanes/ubuntu2604-amd64-local-service-01.json`                     | `9c3a1ee1ff2ff08f017e69c658c3336eaf62bcea14eacd218dfc51addbbea676` |
| Signed-service lifecycle, isolated local authority     | aarch64 | `cloudlanes/ubuntu2604-arm64-dgx20-service-01.json`                     | `2ff0873c28b68c445eba81ca69c3b4b82eaa765a2dad37eb9fff57ca612f9adb` |
| Dispatch, nine scenarios + two-human revocation        | x86_64  | `cloudlanes/ubuntu2604-amd64-local-dispatch-approval-02.json`           | `775819ce10b4d60cbc2da3f0abac84e713c7d54a2582fd5f8c81b0058d81449a` |
| Dispatch, nine scenarios + two-human revocation        | aarch64 | `cloudlanes/ubuntu2604-arm64-dgx21-dispatch-01.json`                    | `fb35f91f1d7e87c43f4e0d5f6c061e72d87ee4fe883b9553e7401d4ba61769c6` |
| Power: restart, refresh, shutdown                      | x86_64  | `cloudlanes/ubuntu2604-amd64-local-power-01.json`                       | `c07e1463caef9dfab7a16ce17a47436af9cb26e1e8480d9ecce3de74b87331af` |
| Power: restart, refresh, shutdown                      | aarch64 | `cloudlanes/ubuntu2604-arm64-dgx21-power-01.json`                       | `c88137ff981ed830732b4f0abf79523b78b8abe214a2e55e6ba9d0a1af918d08` |
| Resources, eight kinds incl. two-guest firewall, 72/72 | x86_64  | `resources/ubuntu2604-amd64-local-allkinds-03.json`                     | `d557520ece7bbaef160c27c4d7b2c38ba2b3ecf1a53ff3af3e8e346a8a7d6e96` |
| Resources, eight kinds incl. two-guest firewall, 72/72 | aarch64 | `resources/ubuntu2604-arm64-dgx21-allkinds-03.json`                     | `b04d326a6ee59f310462ed7a49bc464bb493e8665526a945e2d55e542a34e9d2` |
| Packages 10/10, files 9/9                              | aarch64 | `resources/ubuntu2604-arm64-dgx20-pkgfile-02.json`                      | `41569fce07fddff5618e8a7bbc5f13c05c110e8ee57b64e34a156848217e93ed` |
| Groups 7, users 11, sysctl 8, definitions 10           | aarch64 | `resources/ubuntu2604-arm64-dgx20-host-02.json`                         | `8a13fc45b1fd42253d559b1f1979039fa844e41d566f23048d65078a1df5c258` |
| Password policy 4/4                                    | aarch64 | `resources/ubuntu2604-arm64-dgx20-password-02.json`                     | `c09ddd2802b6649b34728af259b5159e6f50770a09ef65c798ba898ef16e5ea7` |
| Firewall with active UFW, 13/13                        | aarch64 | `resources/ubuntu2604-arm64-dgx21-firewall-02.json`                     | `2228260c525666b3db7562dae88ee0426bda780b15033a279e98b7848ed9fd4d` |
| Secret password 4/4, managed local admin 7/7           | x86_64  | `resources/ubuntu2604-amd64-local-secrets-02.json`                      | `ecc4409a501b6fe389010158b74d770bc515a79cda3a8f7f3df0d82cd583da3c` |
| Secret password 4/4, managed local admin 7/7           | aarch64 | `resources/ubuntu2604-arm64-dgx20-secrets-03.json`                      | `8ed66fc4c6e7018e496caa836cba336011628bc6918a8218884296b72376b66d` |
| Encryption compliance (24 scenarios)                   | x86_64  | `desktop-golden/ubuntu2604-amd64-local-compliance-03.json`              | `f27ca9a81fc6783b23a1c9e9fd0de3f73f589e5a5bda0167375a0239b3ad2d0f` |
| Encrypted desktop golden, stock dracut, GNOME          | x86_64  | `desktop-golden/ubuntu2604-amd64-local-encrypted-gnome-03.json`         | `f154468592ad3a16947260bc8c271d4e181c53f6b43ea55a2b2a7d6509b50b13` |
| Encrypted desktop golden, TPM-capable boot, GNOME      | x86_64  | `desktop-golden/ubuntu2604-amd64-local-encrypted-gnome-tpmboot-03.json` | `0d6c5b871bed3b3a13b69b0e27f9eedeaeaaadaa7719006279235b3ad345e967` |
| Encryption scenarios 1–5 in one run                    | x86_64  | `desktop-golden/ubuntu2604-amd64-local-encryption-04.json`              | `0dd4f878a2a4a80c52f73a120c111dd505ad1235ca17dc2b89abe9b3d35c0ff5` |
| Encryption scenario 5 (`-encryption-phase tpm`)        | x86_64  | `desktop-golden/ubuntu2604-amd64-local-tpm-03.json`                     | `d02c2566f627d9da1a5359ec1f65d16266307b164420a81795c374c468a7bee3` |
| Live-root erase                                        | x86_64  | `desktop-golden/ubuntu2604-amd64-local-live-erase-03.json`              | `dad47c6c12a56306308d91bad69216d8465039bb79ea22619288be76d2631c56` |
| Live-root report loss                                  | x86_64  | `desktop-golden/ubuntu2604-amd64-local-live-report-loss-03.json`        | `15374a0220cf236b490ed0702327dbdb73a03e7d31d14c2491f5c1aca32f7af8` |
| Lock/quarantine, GDM GNOME 50 Wayland                  | x86_64  | `desktop-golden/ubuntu2604-amd64-local-lock-quarantine-03.json`         | `fd9dcf3bea65db6861b0c58c153ff95b357a5d19a061adc2e816add42c375903` |
| Recovery sanitize NVMe, measured GRUB                  | x86_64  | `cloudlanes/ubuntu2604-amd64-local-recovery-nvme-grub-03.json`          | `702855ad402c39015bdb7e08c594737b3342d9ff094edd33af9624b9e046e57f` |
| Recovery sanitize SATA, measured GRUB                  | x86_64  | `cloudlanes/ubuntu2604-amd64-local-recovery-sata-grub-03.json`          | `edbbe480f94cbe895024b0b010fa097dbd06d889f7573650a196bbffee1c2901` |
| Self-update, eight steps                               | x86_64  | `cloudlanes/ubuntu2604-amd64-local-updates-01.json`                     | `1fd2f9902631797c9610ef46b5426e0293f4471329f1ddb10e9870c925b41a1d` |
| Remote assistance, five scenarios, GNOME 50 Wayland    | x86_64  | `assistance/ubuntu2604-assistance-02/assistance.json`                   | `35d6795606154d9ab53129b73ee6aef3650814c9448c7b29b256ad131ef7006c` |
| OS patch policy, 11 scenarios                          | aarch64 | `ospatch/ubuntu2604-arm64-dgx21-osupdate-06.json`                       | `2d598b2fa1e66d0eeca4ba059090013ac0d6dc65c80c263dee85e56fee8b857f` |
| OS patch policy, 11 scenarios                          | aarch64 | `ospatch/ubuntu2604-arm64-dgx20-osupdate-05.json`                       | `b42d0e5e2bad82c626a979d55d14e2d126dd129895984ffb44d85c25ccc1d187` |
| OS patch policy, 11 scenarios                          | x86_64  | `ospatch/ubuntu2604-amd64-local-osupdate-10.json`                       | `b7bd30df35337d34b0dc7281ce086fb5d9f6fef6a5c8fec887148fcb775fff2f` |
| OS patch policy regression on 24.04, 11 scenarios      | aarch64 | `ospatch/ubuntu2404-arm64-dgx21-osupdate-04.json`                       | `78ea16792fdca06a8bb7ff7880a4b9ce1cb347099f7718c3180ba9fbef8ba8de` |
| Advisory publication, Ubuntu OSV `all.zip`, 26.04      | x86_64  | `advisories/ubuntu2604-amd64-local-advisory-publish-01.json`            | `55705114fab3f28399622a1cf9746ebcb077b2d9c2b0a7a25650630d4227b304` |
| Advisory publication, Ubuntu OSV `all.zip`, 26.04      | aarch64 | `advisories/ubuntu2604-arm64-local-advisory-publish-01.json`            | `32b78285caf9368280782ef93fa24fc1db16daa16ba2d737197f067bf390ac7b` |
| Release upgrade 24.04 → 26.04.1                        | aarch64 | `release-upgrade/ubuntu2604-arm64-dgx21-release-upgrade-03.json`        | `f4e6baf3e0ad93fcc80666c4cbecda11c6cf0bc0a6fa0e856fccae07c2a4b741` |
| Release upgrade 24.04 → 26.04.1, landed code           | aarch64 | `release-upgrade/ubuntu2604-arm64-dgx20-release-upgrade-04.json`        | `c05eddec3f5a24d82bd89ce8a4595db158afebe4142bc30d75b9ce8d69e6a179` |
| Release upgrade 24.04 → 26.04.1, landed code           | x86_64  | `release-upgrade/ubuntu2604-amd64-local-release-upgrade-05.json`        | `f196191229ad055118bf9d87f19cc46f60b30d165f3833aa71b042c4214ad44a` |

Commands follow the 24.04 templates with the 26.04 manifests (cloud lanes: `lab vm
inspect|lifecycle|dispatch|resources|updates -host local|dgxNN`, lifecycle with
`-control-plane-trust -lindmd` or `-service-execution -local-authority`, dispatch with
`-local-authority [-power-actions]`, resources with `-phase connected -local-authority
-allow-network -kinds …`). Desktop lanes use
`-manifest lab/images/ubuntu-resolute-desktop-encrypted-amd64.json
-recovery-manifest lab/images/ubuntu-resolute-amd64.json -golden-cache … -firmware-code
/usr/share/OVMF/OVMF_CODE_4M.secboot.fd -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.ms.fd
-firmware-package ovmf -firmware-version 2024.02-2ubuntu0.10 -secure-boot`
(`lab vm encrypted -desktop gnome [-tpm-boot]`; `lab vm device-actions -scenario
encryption [-encryption-phase tpm]|compliance|wipe -wipe-phase
live-erase|live-report-loss|lock-quarantine|recovery-nvme|recovery-sata
[-recovery-boot-mode measured-grub]`; `lab vm assistance -require-cached-golden`).
Hosts whose `/boot/vmlinuz-*` is root-only need `SUPERMIN_KERNEL`/`SUPERMIN_MODULES`
for the out-of-band header read. The OS patch lane is `lab vm resources -phase
connected -kinds os-update -allow-network -local-authority`; the release-upgrade
lane is `lab vm resources -phase release-upgrade -local-authority -allow-network`
with the 24.04 manifest. Advisory publication used `lindmd advisories-refresh` on an
isolated owned database per architecture with feed `{ubuntu, "26.04", amd64|arm64,
…/Ubuntu/all.zip, OSV_ZIP}`, source SHA-256
`c45c2791452b55990d08ae1ba4962a712081d6e0134bc5c5c6707d09adf50aba`: 529,408 claims,
0 rejected, complete scoped coverage, 321.8 s/103,416 KiB (amd64) and 462.9 s/104,744
KiB (arm64), no swaps. Device matching on real 26.04 inventories is regression-tested by
`TestAdvisoriesMatchRecordedNativeInventory/ubuntu-resolute-{amd64,arm64}` (retained
PackageBatch fixtures, vendor notice USN-8861-1: three openssl findings per
architecture) and `TestUbuntuResoluteCanonicalRecords`.

Failed attempts, kept and root-caused:

| Record                                                                                        | SHA-256                                                               | Root cause and fix                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `advisories/ubuntu2604-arm64-dgx21-inspect-03.json`                                           | `c7ab875ac44dc72d23b1097c60dff021214075d12d0d26a8294188aa40f2a0fb`    | Boot `degraded`: the cloud fixture's `systemctl mask --now` made systemd 259 fail the masked apt timers. Fixture now stops then masks (`-04`/`-05` show only `systemd-networkd-wait-online`, a restricted-slirp property; `-allownet-05` settles `running`). Inspect now records `failed_units` (`TestInspectReadinessRecordsFailedUnits`).                  |
| `cloudlanes/ubuntu2604-amd64-local-dispatch-approval-01.json`                                 | `aa4a20afcb576012d5e22518299e67f5c45d044ef452c6f6f29102c0a9f562f9`    | All scenarios passed; cleanup `DROP DATABASE` exceeded its bound under shared-PostgreSQL checkpoint contention (environmental). Rerun `-02` passed.                                                                                                                                                                                                          |
| `cloudlanes/ubuntu2604-amd64-local-recovery-nvme-01.json`                                     | `40421b5976da284069d9cdcad1b2962d73e7fb484726629f9a9ed27c789ac73e`    | Native refusal in owned-UKI mode: `device_action_esp_insufficient`, needed 50,653,240, available 13,998,592 on the stock 105 MiB ESP.                                                                                                                                                                                                                        |
| `cloudlanes/ubuntu2604-amd64-local-recovery-{nvme,sata}-uki-02.json`                          | `e93ff280…e99e` / `05667b71…b3a8`                                     | Same refusal with a dracut `--hostonly` ordinary UKI (registry `OwnedBootHostonly`, not landed): 42,247,680 bytes free; NVMe needs 50,395,136 and SATA 46,651,904. The signed recovery initramfs grew from 24.4 to 33.0 MB since the 24.04 pass, mostly the static agent (39.2→57.0 MB). Closing the gap needs a cross-distribution recovery-image decision. |
| `cloudlanes/ubuntu2604-amd64-local-recovery-{nvme,sata}-grub-01.json`                         | `2d93127f…f2ae` / `81451d6c…7595`                                     | `grub_trailing_measurement`: Linux 7.0 EFI-stub PCR 9 tag events after GRUB's. Parser accepts them in order, bound to the initrd digest (FedoraGaps `48300b6`).                                                                                                                                                                                              |
| `cloudlanes/ubuntu2604-amd64-local-recovery-{nvme,sata}-grub-02.json`                         | `b8565bc1…71f1` / `d6350a8e…c7b6c7`                                   | Staging derived ext4 `/boot`'s UUID through the vfat-only ESP parser (`boot_filesystem_uuid_unavailable`); fixed on main (`bootFilesystemUUID`).                                                                                                                                                                                                             |
| `resources/ubuntu2604-arm64-dgx21-secrets-01.json`                                            | `5ed8586f6bf0fabe44af5455f1f573db4243c5b0b99231c0e69412aaace3d43c`    | Lab UID collision of the secret account with fixture `rlabforeign` (24003); now 24006, `TestProviderCreatedLabAccountsAvoidFixtureUIDs`.                                                                                                                                                                                                                     |
| `resources/ubuntu2604-amd64-local-secrets-01.json`                                            | `c286d36176dac41527d2f11d06ef66b299b0731beb58e01f0b16de3bf8876212`    | `getent` absence misread after the nativeexec move (`unsafe local account state: NSS lookup`); fixed in `4d9c358` (`TestNSSAbsenceThroughNativeexec`).                                                                                                                                                                                                       |
| `resources/ubuntu2604-arm64-dgx20-{pkgfile,host,password}-01.json`, `…dgx21-firewall-01.json` | `eebc5afb…ecd9`, `61b66311…07ab`, `4105e542…8f72`, `5884f39f…c787dc6` | Run without `-allow-network`; the fixture's archive install exited 100. Operator error.                                                                                                                                                                                                                                                                      |
| `desktop-golden/ubuntu2604-amd64-local-encrypted-gnome-tpmboot-01.json`                       | `5db0a3ec13cb364d47c38f3c74c1cfd97a8419d5d28993c31d8c457b95ad2c9a`    | The scheduler started the 3 h lane deadline before slot admission. Now it starts after admission (`TestRunAdmittedStartsLaneDeadlineAfterAdmission`).                                                                                                                                                                                                        |
| `desktop-golden/ubuntu2604-amd64-local-encrypted-gnome-02.json`                               | `2561e869b6f6d42d1151583f7afa16705aab44b9b3004ab4578b364ad66d9733`    | Header read needed `SUPERMIN_KERNEL`/`SUPERMIN_MODULES` on a root-only-`/boot` host (operator prerequisite).                                                                                                                                                                                                                                                 |
| `desktop-golden/ubuntu2604-amd64-local-encrypted-gnome-tpmboot-02.json`                       | `d6ba1cef2e8cb06248bf24d360a9af93b710f02fb43125657abf8c0835aef157`    | dracut `tpm2-tss` needs `tpm2`, absent on the desktop media; the TPM recipe installs `tpm2-tools` (`af7971a`).                                                                                                                                                                                                                                               |
| `desktop-golden/ubuntu2604-amd64-local-encryption-03.json`                                    | `3b0ab6287b3c479076f8e16ccfc560df50d0ebe70348b8881ff3bc9cb15bda3b`    | Retired-key oracle: systemd 259 `systemd-cryptsetup` reports the rejection only in the journal; registry `CryptsetupConsole` (`12e47e6`). `-04` passed.                                                                                                                                                                                                      |
| `assistance/ubuntu2604-assistance-01/assistance.json`                                         | `09b8957108ee02ea921ae78d8dff0efbe872b20f66293ac6a5213184b2942eb4`    | GNOME 50's `gnome-initial-setup-upgrade-login.service` welcome window confused the portal locator; registry first-login marker (`TestDesktopFirstLoginMarkersMatchUpgradeUnitConditions`).                                                                                                                                                                   |
| `ospatch/ubuntu2604-arm64-dgx21-osupdate-01.json`                                             | `8edc985991ce1c66265b65e1a1068a996f8d11020526c84e887daa508a95f8de`    | Guest killed by another lane's pattern `pkill` on dgx21; rerun.                                                                                                                                                                                                                                                                                              |
| `ospatch/ubuntu2604-arm64-dgx20-osupdate-{02,03}.json`                                        | `a6ff5be9…c1a1` / `3fe5ed53…30d0`                                     | SSH wall oracle: systemd 259 built `-UTMP` leaves the SSH logind `TTY` empty ([LP 2168583](https://bugs.launchpad.net/bugs/2168583)). The lane now tests native wall on a `systemd-run --pty -p PAMName=login` session and asserts `notified_sessions` counts graphical recipients only.                                                                     |
| `ospatch/ubuntu2604-arm64-dgx20-osupdate-04.json`                                             | `87f64e3c08f3aebdee5fc5badc54613ad7dea4cf085d4e99af6166bef9536f8f`    | systemd 259 OSC terminal-title output preceded the fixture's readiness line; metadata now starts on a fresh line.                                                                                                                                                                                                                                            |
| `ospatch/ubuntu2604-amd64-local-osupdate-{07,08,09}.json`                                     | `7f35289e…6c87` / `87f5a3c2…0cbf` / `d6db963a…97e9`                   | Lane invocation prerequisites, no policy scenario ran: private worktree passed as fixture `-repo`; unstamped `lindmd`; server release `0.26.4` vs the lane's `0.1.0` guest agent (`agent_release_unsupported`, correct refusal). `-10` passed.                                                                                                               |
| `release-upgrade/ubuntu2604-arm64-dgx21-release-upgrade-01.json`                              | `968e212919c97603695e2fd3ac7c984a7960aba8a674de40247b4b0bf981d9ae`    | Product: a retry while the upgrader held dpkg ended `FAILED/PRECONDITION` → never re-dispatched. Now `NATIVE_BUSY` → `BLOCKED`/`native_package_manager_busy` and re-dispatch (`resource_hold_integration_test.go`, `apt_lock_linux_test.go`). Lane oracle corrected for effect-free start grants.                                                            |
| `release-upgrade/ubuntu2604-arm64-dgx20-release-upgrade-02.json`                              | `108b6aadf96b3e07653cb37df8f1a8215c42e2a0db3453bea1df1d836eaf214a`    | Lane ordering: inventory oracle ran during the retried package change; it now waits for reconvergence.                                                                                                                                                                                                                                                       |

Capability boundaries: the aarch64 desktop cells that 24.04 records (encryption,
GNOME assistance) are not yet recorded for 26.04; the installer's core-boot TPM FDE variant is not a lindm
capability; `Ubuntu:Pro:26.04:LTS` advisories are an unconfigured product; the
release-upgrade lane covers cloud images, not desktop or encrypted-root upgrades.

### Branch allocation

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

DNF5 configuration qualification adds a separate real Fedora 44 Cloud 44-1.7
aarch64 capture on dgx20 KVM, under its four-slot native lease admission. The
signed image is pinned in `lab/images/fedora-44-aarch64.json`; exact commands,
firmware, package versions, helper digest and fixture digests are in
`internal/agent/inventory/testdata/dnf5-fedora44/provenance.json`. No packages were
installed. DNF5, libdnf5 and python3-libdnf5 are `5.4.1.0-1.fc44`; python3-dnf4
is also installed, so import availability is not manager selection.
Supported bindings report effective releasever `44`, no explicit release lock,
and successful `fedora`, `fedora-cisco-openh264`, `updates` configurations with
signature checks and Fedora44 ARM key paths. Metadata-free native CLI JSON agrees;
URL userinfo, queries and fragments are omitted with a redaction flag.

Reproduce the opt-in fixture lane with
`go test -tags=integration,dnfcapture -c ./internal/vmlab`, the manifest/output
environment variables documented in `vm_dnf_integration_test.go`, and the exact
executing host/EFI pins. The ordinary integration suite does not require these
capture inputs. Full dnf/inventory/vmlab race suites and frontend typecheck passed.
The subsequent full Fedora44 aarch64 `lab vm inspect` **passed**, independently
matching all 420 native RPM records and every current native detail. Repositories
and effective releasever are `SUCCESS`, with all three enabled configurations
matching independent metadata-free CLI evidence. Under
`~/.cache/lindm-dnf5-20261010/`, `fedora44-inspect-readiness.json` has SHA-256
`24d20334344f8229c4fc975af52d53e0df93165f1d37d2d1c21f36512a4ae1af`;
private raw `fedora44-native-readiness.json` has SHA-256
`e63e99a41be9a332d26a6b22a7f4e67f833026973bae49d211d21790b57799ba`.
The executed guest agent SHA-256 is
`c19a492fd8949b6e4231d4925f4210d616319cadc39cbd85f74b1494c83ae8be`.
This is dgx20 native aarch64 KVM with QEMU 8.2.2 and pinned AAVMF
`2024.02-2ubuntu0.10`, virtio storage, UEFI SetupMode, Secure Boot disabled and
no TPM—not physical hardware or desktop certification.

Earlier failed gates were fixed rather than excused: `vm inspect` now invokes the
agent as root like the production executor; standalone `inspect` retains caller
privilege. ARM CPU model is successful `virt-8.2` with source `smbios_type4`;
captured native MIDR `0x41/0xd85` is the lower-priority Cortex-X925 evidence.
The bounded executor projects CPU evidence with existing boot/freshness fences.
Captured manager/unspecified/local and user/tty/remote sessions have no seats,
and now carry schema-validated per-session `NOT_APPLICABLE`; a missing local
graphical seat still fails. CPU/session fixtures and provenance are under
`internal/agent/inventory/testdata/{cpu,sessions}-fedora44-aarch64`.
The independent storage oracle now preserves `/` among Btrfs `MOUNTPOINTS`
instead of mistaking a later `/var` mount for the whole topology.

The same final native lane also **passed RHEL9.8 x86_64**, independently matching
all 490 RPM records. DNF4 repository/CPE/effective releasever observations are
`SUCCESS`: effective releasever is `9`, explicit lock is absent, and enabled
repositories are truthfully empty on this unregistered image. Record
`rhel98-inspect-readiness.json` has SHA-256
`43933f4c4059439c502bdb461f2ec1a9b2ac5fe5c8aa21a14ceba094cdcb3000`;
private raw `rhel98-native-readiness.json` has SHA-256
`570a91b99cf307db437f5bc59499991c99175e245e9511fa8b5b61837ac40043`.
Executed x86_64 agent SHA-256 is
`c01aa4cf516941574890ca3948cd93002b45105d2af69871cf53dc83aedfd1da`;
the final local `lab-readiness` SHA-256 is
`c7f4a2778633da207518c3db88cc951a4ced45feac2637ac7d3a7de3678b1535`.
This RHEL run used local KVM, SeaBIOS, virtio storage and no TPM.

Both final records include native startup proof: systemd `degraded` is settled
startup, not all-services-health, and NetworkManager startup is `complete`.
RHEL's proof spans `14:16:45.573515705Z`–`14:16:48.942977329Z` on 2026-10-10;
Fedora's spans `14:19:09.706719760Z`–`14:19:09.720151061Z`.
Earlier RHEL attempts straddled an IPv6 router advertisement and correctly gave
no verdict. Bounded `systemctl is-system-running --wait` plus native
`nm-online -s -q` completed before the final before/agent/after samples;
no network exception or re-sampling fallback was needed. Local admission stayed
at maximum three guests; no owner's demo VM was stopped and no lease bypassed.
Successful records publish only after owned guest cleanup.

Current dnf/inventory/executor/transport/spool/device/vmlab/agent race suites and
web typecheck passed; the later readiness and multi-mount changes also passed the
vmlab race suite. These are inventory/configuration results, not DNF5 package
transaction, entitlement, desktop, physical-machine or whole-family certification.

| Family / branch                           | Build priority       | Native host acceptance                                                | Architecture scope                      |
| ----------------------------------------- | -------------------- | --------------------------------------------------------------------- | --------------------------------------- |
| Ubuntu 24.04 and 26.04 LTS                | 1 (major releases)   | Official GNOME Desktop and Server/minimal; Kubuntu/KDE separately     | x86_64 desktop/server; aarch64 server   |
| Fedora 43 and 44 while upstream-supported | 1 (major releases)   | Workstation GNOME and KDE editions; Server/minimal                    | x86_64 desktop/server; aarch64 server   |
| RHEL 9 and 10, supported minor            | 1 (major releases)   | Vendor GNOME-capable and minimal/server installations                 | x86_64; aarch64 server on vendor images |
| Rocky Linux 9 and 10, current minor       | 2                    | Separate derivative lifecycle, not RHEL evidence                      | x86_64; aarch64 server                  |
| AlmaLinux 9 and 10, current minor         | 2                    | Separate derivative lifecycle, not Rocky evidence                     | x86_64; aarch64 server                  |
| Debian 13                                 | 2                    | GNOME/KDE and minimal separately                                      | x86_64 desktop/server; aarch64 server   |
| openSUSE Leap 16.0                        | 2                    | GNOME/KDE and headless separately                                     | x86_64                                  |
| Ubuntu 22.04 LTS; Debian 12 LTS           | 3 (legacy)           | Separate branch/content/runtime evidence                              | x86_64; aarch64 server                  |
| RHEL 8, Rocky 8, AlmaLinux 8              | 3 (legacy)           | Independent vendor rows and maintained security content               | x86_64                                  |
| SLES 15 SP7 and 16; SLED 15 SP7           | 3 (SUSE enterprise)  | Each vendor product/desktop/server installation separately            | x86_64                                  |
| Arch Linux; openSUSE Tumbleweed           | Tier 2 (rolling)     | Separate pinned snapshots, whole-system update and rollback semantics | x86_64                                  |
| Omarchy on pinned Arch                    | Tier 2 (rolling)     | Omarchy installer, Hyprland session; not Arch evidence                | x86_64                                  |
| Linux Mint current                        | Tier 1 (desktop)     | Cinnamon edition; not Ubuntu evidence                                 | x86_64                                  |
| Pop!\_OS current LTS                      | Tier 1 (desktop)     | COSMIC edition and System76 installer; not Ubuntu evidence            | x86_64                                  |
| Fedora Silverblue and Kinoite             | Future (atomic)      | Design-only; needs a specified deployment/layering/rollback model     | x86_64                                  |
| NixOS stable 26.05 and successor          | Future (declarative) | Design-only; needs a specified configuration/generation model         | x86_64                                  |

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

| Image                                          | Authenticated acquisition                                                                                                                  | Independent native observation                                                                                                | Packaged lifecycle / dispatch                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rocky 9.8 GenericCloud Base 20260525.0         | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 422 RPM records, explicit UEFI/Secure Boot disabled                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rocky 10.2 GenericCloud Base 20260525.0        | Vendor detached BSD SHA256 CHECKSUM verified and cache reverified offline                                                                  | Passed, 443 RPM records, explicit UEFI/Secure Boot disabled                                                                   | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| AlmaLinux 9.8 GenericCloud 20261005            | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Passed, 387 RPM records                                                                                                       | Earlier lifecycle failed signed service after enrollment/upgrade. After removing the dbus-broker v28 argument-filter optimization, independent connected dispatch passed all 10 scenarios with SELinux Enforcing; packaged lifecycle rerun remains required                                                                                                                                                      |
| AlmaLinux 10.2 GenericCloud 20260817.0         | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Passed 2026-10-10 under UEFI, 380 RPM records (`alma10-x86_64-local-inspect.json`, below)                                     | Passed 2026-10-10: signed 0.7.0→0.7.1 automatic-trust lifecycle (five 382-package publications) and nine native dispatch scenarios; SELinux Enforcing (records below)                                                                                                                                                                                                                                            |
| Ubuntu 22.04 release 20261004                  | Ubuntu signed SHA256SUMS verified and cache reverified offline                                                                             | Passed, 597 dpkg records                                                                                                      | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rocky 8.10 GenericCloud Base 20240528.0        | Pinned manifest uses aggregate CHECKSUM.sig; 2.06 GB image download incomplete and cancelled at handoff, so actual bytes not authenticated | Not yet recorded                                                                                                              | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| AlmaLinux 8.10 GenericCloud 20260928           | Vendor detached CHECKSUM verified and cache reverified offline                                                                             | Passed 2026-10-10 under UEFI, 434 RPM records, after the systemd 239 readiness fix                                            | Passed 2026-10-10: signed automatic-trust lifecycle (five 436-package publications) and nine native dispatch scenarios; SELinux Enforcing (records below)                                                                                                                                                                                                                                                        |
| openSUSE Leap 16.0 Minimal-VM Cloud Build18.75 | Vendor checksum signature verified; fixed vendor-listed mirror avoids cross-origin redirect relaxation                                     | Earlier BIOS exit and UEFI 63-byte exit were the ndb `Packages.db` gap (fixed). 2026-10-10 UEFI rerun passed, 378 RPM records | Passed 2026-10-10: signed zypper 0.7.0→0.7.1 automatic-trust lifecycle (five 380-package publications) and nine native dispatch scenarios (records below)                                                                                                                                                                                                                                                        |
| openSUSE Tumbleweed Cloud Snapshot20261007     | Vendor checksum signature verified and cache reverified offline; fixed vendor-listed mirror avoids cross-origin redirect relaxation        | Not yet recorded                                                                                                              | Not yet recorded                                                                                                                                                                                                                                                                                                                                                                                                 |
| Debian 13.7.0 netinst                          | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Passed after privileged source-marker correction: 355 dpkg records, explicit UEFI/Secure Boot disabled                        | Historical 0.5.0→0.5.1 signed-service lane reached reinstall/spool recovery/denied-collection preservation (356 packages), then failed final approver authentication. Post-fix 0.6.0→0.6.1 automatic-trust run was **aborted: host contention** after enrolled/upgraded/rebooted publications (356 packages each), before final revocation. Neither a full pass nor a new distro failure; dispatch remains unrun |
| Debian 12.15.0 netinst                         | Debian CD signed SHA512SUMS verified, both image digests and exact size checked, cache reverified offline                                  | Not executed                                                                                                                  | Not executed                                                                                                                                                                                                                                                                                                                                                                                                     |

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

Native ARM continuation on the DGX Sparks uses independently pinned arm64/aarch64
vendor images, not cross-architecture inference. Debian 13 inspection passed on
`dgx20` KVM after correcting two missing laboratory observations: per-interface
IPv4/IPv6 default routes and active-session properties. The agent already emitted
these fields; the old independent oracle omitted them and correctly failed strict
comparison. The replacement oracle uses iproute2 netlink JSON and `loginctl`
properties, independently of the production proc-table and `busctl` parsers.
Shared-tree `go build ./...`, default and integration-tagged golangci lint on
`internal/labhost` and `internal/vmlab`, scoped golangci formatting, both packages'
race tests, and touched Markdown Prettier/markdownlint passed after these fixes.
The vmlab race result was cached; no new full-repository integration claim is made.

The corrected record in `~/.cache/lindm-mutabledistros3-20261010/` is
`debian13-arm64-dgx20-inspect-complete-oracle.json`, SHA-256
`a67af59b3846199900abff8744dd078c36ccc0e1de0b4ad579632c54ade98f23`.
It matched 353 dpkg identities and all asserted native fields, using agent
`494c6168c452abd0b45205d7f478f4d952097977346e2c191504af1300a9c49d`.
Source `d303cecb69bc041328438538a2e3bbf084ac06fb` plus private binary-diff SHA-256
`7bd66a46565181c187518e4b61dd5e1dae3a1d405ffb98ba60aed18e18f1e59c`
binds the independently rebuilt remote runner. This is QEMU 8.2.2, native aarch64
KVM, package-pinned AAVMF `2024.02-2ubuntu0.10`, Secure Boot disabled/SetupMode true,
virtio-blk, no TPM/desktop, and explicit user egress. This inspection record is
separate from the subsequent packaged lifecycle proof below.

The Debian 13 ARM packaged 0.7.0→0.7.1 automatic-trust lifecycle subsequently
**passed**, including actual independent final revocation after the approver fix.
Record `debian13-arm64-dgx20-lifecycle-stagingfix.json` in the same directory has
SHA-256 `be19db1bcf1197a534d6425d8944d3e68173e3cd9245dd0c9abac452abce8c05`.
Device `14e3a441-0a41-47f6-9e73-5a21a6b55373`, generation
`b9603ce7-fb9b-48df-991f-24ffb88ba1ce`, matched 354 native packages at all five
enrollment/upgrade/reboot/reinstall/spool-recovery publications; denied collection
preserved sequence 5 at attempt 6. Unsigned/tampered/wrong-signer rejection,
lost issuance, retained identity, spool corruption, authority rotation/rollback
denial/restart retention, final device revocation and missing-journal hold passed.
Epoch advanced 1→3. Total command time was 1,886.95 seconds; recorded remote lane
time excluding staging was 1,723.65 seconds. Native dispatch is a separate lane.

Its first attempt exposed another lab defect before package installation:
remote staging prefixed the artifact basename, but authenticated APT pool
validation correctly required the original name. Staging now keeps original
basenames in distinct numbered directories, with a real local-rsync relocation
regression. The passing lane retains source `d303cec` plus private diff
`8c30afa7e3e809009ec39cc777f8130efdf0d076101035ff8ac5f6d24eab3263`;
controller runner SHA-256 is
`80dd80799d2c5a9f95f4e39bb79a13687bae25b5cc84e273902ee4072d2c69aa`.
Both signed package versions were built from unchanged `d303cec` product sources;
the delta affects only lab oracles/staging and their tests.

All eight ARM image inputs (Debian 12/13, Rocky 9.8/10.2, AlmaLinux 8.10/9.8/10.2
and Leap 16.0) passed authenticated acquisition and offline cache reverification.
`arm64-acquisition.json`, SHA-256
`1c7b1bfe9711e92d513c768a72cfddc430bdc3dc3dac601e52c2885651d0d5fb`,
records their individual signatures, image hashes and exact sizes. Acquisition
does not qualify the remaining native lifecycle/dispatch cells.

Additional completed native ARM records in the same directory use source `d303cec`
and the exact `8c30afa7…` lab-only delta above, one `dgx20` KVM guest at a time:

| Distro / lane            | Observed result                                                                                                                                                                                                                                    | Record / SHA-256                                                                                           |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Debian 13 dispatch       | Passed nine native scenarios; periodic compliant recheck and drift remediation used real five-minute intervals, ±90-second guest clocks and final revoked-device denial. Unstarted supersession remains integration-only, not a tenth native claim | `debian13-arm64-dgx20-dispatch.json` / `0973b1cf434265359808e6553f4c0766a29042c03e788ebe29996e7cf18376a0`  |
| Debian 12 inspect        | Passed 361 native package identities and independent detail comparison                                                                                                                                                                             | `debian12-arm64-dgx20-inspect.json` / `5b872dedd2a611d7f6847b15cdacad6a0a941dd0d12c99c21ff6df7bea62bcc2`   |
| Debian 12 lifecycle      | Passed complete signed 0.7.0→0.7.1 automatic-trust lifecycle; five 362-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation and missing-journal hold                                                               | `debian12-arm64-dgx20-lifecycle.json` / `1bda2586f58dee2764b8ca69e20cf99883412ad01e9414d540d5579d0af8d95a` |
| Debian 12 dispatch       | Passed the same nine native scenarios with real periodic intervals and final revoked-device denial; unstarted supersession explicitly integration-only                                                                                             | `debian12-arm64-dgx20-dispatch.json` / `f29b8cdf4d4342c66e3928cc2d9ff5416fb1b92f243601e01682319376c7a8b0`  |
| Rocky 9.8 inspect        | Passed 418 native RPM identities and independent detail comparison                                                                                                                                                                                 | `rocky9-arm64-dgx20-inspect.json` / `e8b1d77d1c81b02ae833afc8cd7849d37557371b019f5726a264b9159f6bf3db`     |
| Rocky 9.8 lifecycle      | Passed full signed 0.7.0→0.7.1 lifecycle/automatic trust; five 420-package publications, denied attempt6 retained sequence5, final revocation/hold; SELinux Enforcing                                                                              | `rocky9-arm64-dgx20-lifecycle.json` / `c7b95fddeef7c28d396901993e920989c0970a56810de7b3f114ee345ad0c5d0`   |
| Rocky 9.8 dispatch       | Passed nine native scenarios, real periodic recheck/remediation and final revocation; SELinux Enforcing; supersession integration-only                                                                                                             | `rocky9-arm64-dgx20-dispatch.json` / `bb17111467ecef3bb47d0fb2fc898a49415c411dc0fd15e2c819f2e8b7830ed4`    |
| Rocky 10.2 inspect       | Passed 440 native RPM identities and independent detail comparison                                                                                                                                                                                 | `rocky10-arm64-dgx20-inspect.json` / `8e82dfa7570d14b8e30b8da2f77cd3b48d63650519b11d9897827cd117743049`    |
| Rocky 10.2 lifecycle     | Passed full signed 0.7.0→0.7.1 lifecycle/automatic trust; five 442-package publications, denied attempt6 retained sequence5, final revocation/hold; SELinux Enforcing                                                                              | `rocky10-arm64-dgx20-lifecycle.json` / `c4713821b59c9938a44b81fec68c5df7d6e1ad922e0641c7690a835c2de04df9`  |
| Rocky 10.2 dispatch      | Passed nine native scenarios, real periodic recheck/remediation and final revocation; SELinux Enforcing; supersession integration-only                                                                                                             | `rocky10-arm64-dgx20-dispatch.json` / `34bd45508a999bc54cc861b8d5d9f8d31db8305b99396345a802953f47a192bc`   |
| AlmaLinux 9.8 inspect    | Passed 384 native RPM identities and independent detail comparison                                                                                                                                                                                 | `alma9-arm64-dgx20-inspect.json` / `4b27eebefe3cf6c4f0987f076c8e3d8cb36d8c3c0c83980b17b5d562fad3f525`      |
| AlmaLinux 9.8 lifecycle  | Passed full signed 0.7.0→0.7.1 lifecycle/automatic trust; five 386-package publications, denied attempt6 retained sequence5, final revocation/hold; SELinux Enforcing                                                                              | `alma9-arm64-dgx20-lifecycle.json` / `3c76a258e81a63333f9e0937331ba2f70b0508392480505c77a77aad21d8827a`    |
| AlmaLinux 9.8 dispatch   | Passed nine native scenarios, real periodic recheck/remediation and final revocation; SELinux Enforcing; supersession integration-only                                                                                                             | `alma9-arm64-dgx20-dispatch.json` / `8df0e0271385e3220bce78f9dcae62fa5cb9a2cfbd05ea2b694f8f3e7a4cb665`     |
| AlmaLinux 10.2 inspect   | Passed 379 native RPM identities and independent detail comparison                                                                                                                                                                                 | `alma10-arm64-dgx20-inspect.json` / `50fa3dd6a71b1b0d963a36a57dfcfe35cf30695ad26e286199e2d84980c4e1f6`     |
| AlmaLinux 10.2 lifecycle | Passed full signed lifecycle/automatic trust; five 381-package publications, denied attempt6 retained sequence5, final revocation/hold; SELinux Enforcing                                                                                          | `alma10-arm64-dgx20-lifecycle.json` / `5a8056cbeb509530f9f6aa053a775c7310055fbb36baf773d6b3d8559ee94498`   |
| AlmaLinux 10.2 dispatch  | Passed nine native scenarios, real periodic recheck/remediation and final revocation; SELinux Enforcing; supersession integration-only                                                                                                             | `alma10-arm64-dgx20-dispatch.json` / `822336a8bcf022589772ea04a31247555b67dcf62146e989f7b0be8cc8e05830`    |

The following ARM records additionally carry the product/lab fixes described
below, with the lane-recorded source diff SHA-256 over `d303cec` shown per distro:

| Distro / lane               | Observed result                                                                                                                                                     | Record / SHA-256                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| AlmaLinux 8.10 inspect      | Passed 430 native RPM identities and independent detail comparison, including legacy-lsblk storage and systemd 239 sessions                                         | `alma8-arm64-dgx20-inspect-el8fix.json` / `9e314b95621a350cb0c6c76029abfed18250f61dc3128442d705e9f08c816567`     |
| AlmaLinux 8.10 lifecycle    | Passed full signed lifecycle/automatic trust; five 432-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold; SELinux Enforcing | `alma8-arm64-dgx20-lifecycle-el8fix.json` / `f336e9018b6682531f402db6e33b62bd42657cdb240bdad21eeb4f29481e400c`   |
| AlmaLinux 8.10 dispatch     | Passed nine native scenarios, real periodic recheck/remediation and final revocation; SELinux Enforcing; supersession integration-only                              | `alma8-arm64-dgx20-dispatch-el8fix.json` / `1e645149636351a18613562e197da23babd58602c364477686fb93952b88ad88`    |
| Leap 16.0 inspect (dgx21)   | Passed 376 native RPM identities and independent detail comparison                                                                                                  | `leap16-arm64-dgx21-inspect-diskfix.json` / `69b00b31f66d1255af30af2f2ffa3f584de1747ecc72d9c1366d64b2197fee9b`   |
| Leap 16.0 lifecycle (dgx21) | Passed signed zypper 0.7.0→0.7.1 automatic-trust lifecycle; five 378-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold      | `leap16-arm64-dgx21-lifecycle-diskfix.json` / `8f5056bf5a095b46eead2a4cb89d6988008de18437cd5aa8f62a71c52e0ba87d` |
| Leap 16.0 dispatch (dgx21)  | Passed nine native scenarios with real periodic intervals and final revoked denial; lane records SELinux `not applicable`; supersession integration-only            | `leap16-arm64-dgx21-dispatch-diskfix.json` / `29d037b83bcb7ca9c51c647a5175c4072542a7633e830c67e5d52274192a4b57`  |

Fixes, each with a deterministic regression, found by these lanes (2026-10-10):

- Leap 16 rpm uses the ndb backend (`Index.db`/`Packages.db` only). The agent did
  not recognise that database, reported package collection `UNAVAILABLE` and
  `inspect` exited 1 with the earlier unexplained 63 stderr bytes. `Packages.db`
  is now an RPM database marker.
- Leap's 1.5 GiB Minimal-VM disk left ~8 MB on `/`; the first signed RPM install
  failed (`needs 27MB more space`). Lab overlays now have a 10 GiB floor
  (larger bases unchanged); kiwi-repart grows the root, as on a resized cloud disk.
- EL8 util-linux 2.32.1 `lsblk` rejects `FSVER`/`PTTYPE`/`PTUUID`/`MOUNTPOINTS`.
  Agent and oracle use a legacy column set only after that native failure and a
  `lsblk --version` below 2.37; uncollected identity fields remain `UNAVAILABLE`.
- The native runner killed a tool that had already closed stdout (lsblk does so
  before exiting), turning its exit 1 into `INVALID_OUTPUT`; drained tools are now
  waited for, so the native failure is reported.
- EL8 systemd 239 `busctl` has no `--json`. Only after a busctl failure and a
  `busctl --version` below 240 the agent parses busctl's fixed text format through
  the same logind validation.

Leap's source diff is
`5e45a68b40197dea0ee85e0fd6a932e67572b608cff94dad1d04b7ff4ee8fdf7` (lab delta,
ndb, disk floor; RPMs carry only the ndb product change); AlmaLinux 8.10's is
`e10d895312dfb0bc99b139f6222ac07087ec7698321bc1d7b6df6e2ff0233de8` (lab delta,
ndb, all EL8 fixes, disk floor; RPMs rebuilt from it). Both use isolated local
password/WebAuthn authority, QEMU 8.2.2, AAVMF `2024.02-2ubuntu0.10`, Secure Boot
disabled/SetupMode, virtio-blk, no TPM/desktop and explicit user egress. Unlike
the earlier one-guest-at-a-time records, AlmaLinux 10.2 dispatch and the
AlmaLinux 8.10 lanes overlapped on `dgx20` (at most two leased guests of four)
while Leap ran on `dgx21`, under the normal lease/memory admission.

Debian 12 lifecycle device `ef1dbc74-a7ed-4a68-8857-b6f6d5962280` retained
generation `dbd9e3b5-aaa8-4963-8def-578c49ac1150`; its recorded remote lane lasted
1,768.12 seconds. Debian 13/12 dispatch devices are respectively
`740a50d1-c462-4861-8f2b-0caaf9f9447e` and
`027db59b-a2f6-4289-8d3c-7692221ac284`; each remote lane lasted about 932 seconds.
Their identically built native DEB SHA-256 is
`773b35160f722e83ed9621d9440cc274de146cb90dab35db010acacd2cd91cf7`,
remote lab `6f6188bf73dfaed9d2e61b3d9d89b4f34ef779597468756865c8c2aa019dea26`,
and server `aa63607622525c5037fca78f4ddd00f06798727b394af3892b88d8d9d0c282bb`.
Each lane uses isolated real local password/WebAuthn authority. These ARM passes
do not retroactively pass the aborted Debian x86_64 lane.

Arch cannot be substituted on these ARM hosts: [Arch's architecture policy](https://wiki.archlinux.org/title/Frequently_asked_questions#What_architectures_does_Arch_support?)
supports x86_64 and identifies Arch Linux ARM as a separate derivative. The pinned
official arch-boxes release publishes no aarch64 input. Tumbleweed's official
[ARM64 installer directory](https://download.opensuse.org/ports/aarch64/tumbleweed/iso/)
publishes signed Snapshot20261007 DVD/NET media, but its advertised ARM Cloud/KVM
checksum links return 404 and no matching native QCOW2 was found. That prerequisite
is now met by the maintained installer-to-golden workflow described below and in
`docs/engineering.md`; the x86_64 Tumbleweed cloud-image cell remains pending.

MutableDistros5 (2026-10-10) closed the remaining ARM gaps and the Leap 16.0,
AlmaLinux 10.2 and AlmaLinux 8.10 x86_64 cells.
Records are under `~/.cache/lindm-mutabledistros5-20261010/`; the source is
`4d74dcf` plus a lab-only delta (`md5-source-tw2.patch`
`3a9bca0585cb3aaba93e79b6f91d0e79767c5dbceb74ba847e70c3f4c3e4a987`; plus the
dispatch SELinux observation in `md5-source-v3.patch`
`7b6b0d5a2096370f28f5280ba84b6f841d4a1d6a2c60bb03679df74c39bb17b4`, used for the
v3 dispatches and the AlmaLinux 10.2 x86_64 lifecycle/dispatch; AlmaLinux 8.10
x86_64 adds the systemd 239 readiness fix, `md5-source-v4.patch`
`326ff7a2a1b103bdf843ae927a1a3215306197c95439eb10128c1fad02775ad9`). Rocky 8.10
instead reused the exact AlmaLinux 8.10 EL8 pin (`e10d8953…`, RPMs
`5e6043f9…`/`ac143d42…`). ARM uses AAVMF and x86_64 uses OVMF
`2024.02-2ubuntu0.10`, both with Secure Boot disabled, plus virtio-blk, no
TPM/desktop and isolated local password/WebAuthn authority.

| Distro / lane                         | Observed result                                                                                                                                      | Record / SHA-256                                                                                            |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Rocky 8.10 aarch64 inspect            | Passed 450 native RPM identities, legacy-lsblk storage and systemd 239 sessions                                                                      | `rocky8-arm64-dgx21-inspect.json` / `a78440395d110ccea326f59a3d1d111d66a4cab354a8f6d13f7f8cd6ff8c9ea8`      |
| Rocky 8.10 aarch64 lifecycle          | Passed full signed lifecycle; five 452-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold; SELinux Enforcing  | `rocky8-arm64-dgx21-lifecycle.json` / `e550555f5f8624edcc55276ad4bb282e1324492f2945bf4b13017e36e8e15e18`    |
| Rocky 8.10 aarch64 dispatch           | Passed nine native scenarios, real periodic recheck/remediation and revoked denial; SELinux Enforcing; supersession integration-only                 | `rocky8-arm64-dgx21-dispatch.json` / `6a7f8f8a1423fe5cda697e8342e86ca488e9700370cf88ddcfdeaa82c1f4bda2`     |
| Tumbleweed 20261007 aarch64 inspect   | Installer-built golden from the signed DVD; passed 830 native RPM identities                                                                         | `tw-arm64-dgx21-inspect-v2.json` / `76e793fdd477764a4b8c96afab993daa106ec99218e4ab880fde16d7921c2866`       |
| Tumbleweed 20261007 aarch64 lifecycle | Passed signed zypper 0.7.0→0.7.1 automatic trust; five 832-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold | `tw-arm64-dgx21-lifecycle-v2.json` / `d29350054997675adcb50bcd72deafa176456ec79b55877f595858eb04d7f37b`     |
| Tumbleweed 20261007 aarch64 dispatch  | Passed nine native scenarios with real periodic intervals and revoked denial; SELinux Enforcing (kernel-observed); supersession integration-only     | `tw-arm64-dgx21-dispatch-v3.json` / `ba180b62dde4cdf26a5117f8fcc29f55157f7c6a970b93c60cea09e7aa166308`      |
| Leap 16.0 aarch64 dispatch rerun      | Passed nine native scenarios on dgx20; SELinux Enforcing, replacing the earlier `not applicable` label                                               | `leap16-arm64-dgx20-dispatch-v3.json` / `17289eba4f96fdb1605c590578c572ad3cd037cbceaa3b925e7867fa2be9ba43`  |
| Leap 16.0 x86_64 inspect              | Passed 378 native RPM identities under UEFI after the ndb fix                                                                                        | `leap16-x86_64-local-inspect.json` / `dadb6bc9d37fd93dcaa6eecefc31913c37467738c1c68523904e2f567b2ea2cc`     |
| Leap 16.0 x86_64 lifecycle            | Passed signed zypper automatic trust; five 380-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold             | `leap16-x86_64-local-lifecycle.json` / `06c36ca389fc455a92f09f8fd87f2010252e508303061d1c0dd7570d2ef8e752`   |
| Leap 16.0 x86_64 dispatch             | Passed nine native scenarios; SELinux Enforcing (kernel-observed rerun). The first pass `4c0b3341…` predates the observation                         | `leap16-x86_64-local-dispatch-v3.json` / `d30cd1220e1573cbc0a5437ee76d5ea1a1c470309323a0c261fe71d2db3ebb55` |
| AlmaLinux 10.2 x86_64 inspect         | Passed 380 native RPM identities under UEFI                                                                                                          | `alma10-x86_64-local-inspect.json` / `76575dcfc770c61da3d0c570f697c77c7fbea2d59845f79f2e0c7bfaf2bfc9bb`     |
| AlmaLinux 10.2 x86_64 lifecycle       | Passed signed automatic trust; five 382-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold; SELinux Enforcing | `alma10-x86_64-local-lifecycle.json` / `0aaf17e8edcb8c4c9a51ec97bb285af804fea82ba19b6c9864a6f43941c2a060`   |
| AlmaLinux 10.2 x86_64 dispatch        | Passed nine native scenarios and revoked denial; SELinux Enforcing; supersession integration-only                                                    | `alma10-x86_64-local-dispatch.json` / `20be65dafef62626575e71eeabb5b3b133009cd1e163ad4af51b695248d70df8`    |
| AlmaLinux 8.10 x86_64 inspect         | Passed 434 native RPM identities under UEFI; readiness `degraded` after polling systemd 239                                                          | `alma8-x86_64-local-inspect.json` / `c33350a7dc4f74c6174cbd2fedd73777da8e31c6b7ccaca93087f0097c429f3d`      |
| AlmaLinux 8.10 x86_64 lifecycle       | Passed signed automatic trust; five 436-package publications, denied attempt6 retained sequence5, epoch1→3, final revocation/hold; SELinux Enforcing | `alma8-x86_64-local-lifecycle.json` / `4ea01b9bf89e9a9610a45b229c65e99ff9cd104b08546d472020957b9ff0f769`    |
| AlmaLinux 8.10 x86_64 dispatch        | Passed nine native scenarios and revoked denial; SELinux Enforcing; supersession integration-only                                                    | `alma8-x86_64-local-dispatch.json` / `f3e10b1dd10eaf438415199911d7234b8c67941e91245d3b480ed1511acfdf5c`     |

Defects fixed with deterministic regressions in these lanes: the vendor ARM DVD's
hybrid MBR made `xorriso` replay fail, so the remaster declares the vendor FAT image
as the UEFI El Torito entry. The AutoYaST profile failed the DVD's yast2-schema,
and `final_halt` rebooted the guest into the installer. The solver picked
MicroOS's cloud-init configuration. The dispatch lane recorded SELinux
`not applicable` for zypper guests that actually enforce it. One lifecycle failed
with `unable to authenticate` right after the reboot. Tumbleweed starts sshd in
parallel with `systemd-user-sessions`, and pam_nologin rejects logins until
`/run/nologin` is removed. A delayed-user-sessions guest reproduced "Access denied …
by PAM account configuration", and the golden now orders sshd after that unit. The
lab keeps treating authentication failure as terminal. AlmaLinux 8.10 x86_64
inspection first failed `native system startup is not settled`, because systemd 239
ignores `is-system-running --wait` (support arrived in v240). After a transient
answer from systemd older than 240, the readiness gate now polls within its
existing deadline.

Arch x86_64 (arch-boxes `20261001.604814`, Archive `2026-10-02`) then passed all
three lanes locally (KVM, SeaBIOS 1.16.3, virtio-blk, no TPM/desktop, user
egress, isolated local password/WebAuthn authority) once the lab's control-plane
publication comparison accepted Arch's honest `UNAVAILABLE` OS version, as
inspection already did. The two earlier 18-minute `get device failed` timeouts
were that lab mismatch, hidden because the expiring wait reported only the query
its own deadline interrupted; both lab defects have regressions. Source is
`d303cec` plus the lab delta and the 2026-10-10 fixes (private diff
`254f4c223519c8739fa2a6ae82c30e735d739b30093022cb7ad6ee9171e6f82e`), with signed
pacman 0.7.0/0.7.1 packages and repositories built from it:

| Arch x86_64 lane | Observed result                                                                                                                                                                                                | Record / SHA-256                                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Inspect          | 184 native pacman identities and independent detail comparison                                                                                                                                                 | `arch-x86_64-local-inspect-md4b.json` / `ee1f077485d4312db0c6784df20e88263261bb169f3d17aef5df8ce753be4c54`   |
| Lifecycle        | Signed pacman automatic-trust lifecycle; five 185-package publications, denied attempt6 retained sequence5, epoch1→3, lost issuance, purge identity, spool recovery, final revocation and missing-journal hold | `arch-x86_64-local-lifecycle-md4b.json` / `6b2d89456a907f971abb6921e8562f60484a4b3c9f8d32145a4fed739e0fa8fe` |
| Dispatch         | Nine native scenarios with real periodic intervals, ±90-second clocks and revoked denial; supersession integration-only                                                                                        | `arch-x86_64-local-dispatch-md4b.json` / `e6ae926e7293f5d58ce9e3a6731096bc931e9fe48dafc066d6cb0f8f6ddb2029`  |

These records sit in `~/.cache/lindm-mutabledistros3-20261010/`. They do not
cover Arch whole-system upgrade/rollback, desktop, encryption, air-gap or physical
gates, and Arch Linux ARM inherits nothing.

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
outside disposable VM state. Regressions were added; the following rerun now
also proves that native registration identity/receipt path.

RHEL 9.8 **automatic control-plane trust lifecycle passed** after owner-approved
resumption at local capacity2 using lease admission (`-host local`).
`ROOT/rhel98-trust-receipts.json`, SHA-256
`2cef05970f214a51f6a8573abf478a11cd228cc922b0f1371e94286f547e2ed2`,
device `29f1e6ce-1dd8-4503-a83a-d5e5a6756747`, generation
`dec2bec9-0b70-402d-8374-7d49d8f34c35`. Same-tree0.7.0→0.7.1,
five492-package publications, deniedattempt6 retained snapshot5, epoch1→3.
Automatic root/delegate rotation and revocation, quorum/delegation/epoch rollback
denials, exact retry after server restart, unchanged TLS identity, no probe
service effects, reboot/reinstall retention, spool recovery, final revocation and
missing-journal hold all passed. SELinux remained Enforcing; user-egress explicit.
All five Red Hat registration/cleanup outcomes were true. Public run name
`lindm-lab-efca32db41200c2bf17160fd488a1f4c`, consumer UUID
`7bf1b0d8-305f-4128-9250-b682b4ff3100`; retained receipt
`ROOT/lindm-lab-efca32db41200c2bf17160fd488a1f4c.redhat-registration.jsonl`,
SHA-256 `467e273741cfc6cc93fea9ff29cc68c0f4e8d42154baeeae1b76f434548c00b6`.

Exact build inputs are in `ROOT/receipt-lanes-build.json`, SHA-256
`43613f3f92bac84e38f838206d69eb7384158e4760ca786064d3dbed305fbb37`:
base01495af plus the cleanup/receipt source patch above, no fixture copies;
lab `3c5a1420054120e184c7595326f458eaaf338b3fbf76eeaef1d140acabdf23e9`,
server `fcdac2c7a22eca5f049f5aee1ea2ab6f09ec6321120797390474cafbc32bff04`,
RPM0.7.0 `84e0ad4de6aa1ca1a170febd247334e6951076b324e1ca4235213ef2831c0b2b`,
RPM0.7.1 `c93c53ccd362e5d683a01b5eb4266609ff9d09a44cef1400b79f3625c2c53ad7`.
The lifecycle uses `-control-plane-trust`, explicit RHEL `-allow-network` and
protected token-file, real shared `-repo`, and `-work-dir ROOT` for durable public
receipts. Continuation commands and custody notes are in
`local://platformlanes2-handoff.md`.

RHEL 9.8 **connected dispatch also passed**: `ROOT/rhel98-dispatch-receipts.json`,
SHA-256 `7c6d4d0f715184ad4eb9b788f8815da69d874f6270d6f18d305fd89915fe5b62`,
device `016b4c08-88aa-4135-b3cd-2343f0ccf16d`, generation
`0c0d1af5-2066-4685-af43-e7f91eed743a`. Same receipt-aware lab/server/source
custody, with real fixture `-repo` and private pinned `-build-repo`.
Native signed RPM SHA-256
`7de0e6ebebd4d5ba2611195280dfe144ab06acb88234c591f8a8b3e823b475fa`.
Nine native scenarios passed, including actual300s periodic compliance/drift
repair, open-action server restart, no drift without a grant, ±90s guest clocks
and revoked-device denial. Unstarted supersession remains explicitly
integration-only, not natively exercised. SELinux Enforcing and explicit
user-egress; all five Red Hat registration/cleanup outcomes true.
Public name `lindm-lab-6bc174ee8d92d6ad6ad30150b5f93b10`, consumer UUID
`55e55c27-373b-491c-99c3-35b210b32b5d`; retained corresponding JSONL receipt
SHA-256 `508cadd411756ad464a7e045a742c47a1e2fe9b0e9a80adde3a3e7e68aa79103`.

RHEL 10.2 **automatic control-plane trust lifecycle passed** with the same
0.7.0→0.7.1 artifacts and exact receipt-aware build provenance:
`ROOT/rhel102-trust-receipts.json`, SHA-256
`af60d409e6d367680655235e2a1e829448428aacca4fb2f57cbff0297d717723`,
device `1e2031ec-d7e4-41eb-8ce8-5a9da971426b`, generation
`14750bb9-08fb-4921-b8fa-634c7afdb84e`. Five530-package publications,
epoch1→3, denied collection retaining snapshot5 at attempt6, and the full
automatic authority/rollback/restart/retention/recovery/revocation/hold checks
above all passed. SELinux Enforcing unchanged; explicit user-egress; all5
registration and cleanup outcomes true. Public run
`lindm-lab-606fcf750e0afb81e804ebe06d387152`, consumer UUID
`5a20105a-218b-46bd-9840-439ac327f8f6`, retained corresponding JSONL receipt
SHA-256 `b07c451be5b0595380fac8678b68be8454b984c63d239a31acb5db03426e0298`.

RHEL 10.2 **connected dispatch passed**: `ROOT/rhel102-dispatch-receipts.json`,
SHA-256 `0c8b04c278095080fbe43e9b388805c02fe5b74e3c34943de1d1527ad1f29783`,
device `a5a490c8-37b8-44f3-ba51-a7d28434f95f`, generation
`80a0be61-3135-4510-94ed-e1fc855bd3f0`. Same pinned receipt-aware lab/server;
native RPM SHA-256
`61fd17aacc6455b16fac5b7f7e8e1595c9e458fb8c3203982daaf4dfadc8adc3`.
All nine native dispatch scenarios above passed; supersession remains
integration-only. SELinux Enforcing, user-egress explicit, all5 Red Hat outcomes.
Public run `lindm-lab-de5d9553b77cf49e1ab68c74524dddbe`, consumer UUID
`8618a771-fa06-4c5b-8549-58c169dfb986`, corresponding retained JSONL SHA-256
`3be7607fe1dcaf19725d2cfa7511f6d4c1d2f8ea56f7b795b76548874aaf0e26`.
Fedora43 **signed-service lifecycle passed** after the shared-schema prerequisite
correction below: `ROOT/fedora43-service-refreshed.json`, SHA-256
`0ba24f41374f177eef632a3905f0bd9563d6f8aa1d11bc914d3eccca35d21667`,
device `a0a090a5-eeed-43c7-b4b6-730f8ed0befd`, generation
`b9413ea5-0e18-438f-ac47-1e86ef0cc97f`. Same receipt-aware pinned
01495af lab/server and 0.7.0→0.7.1 RPM pair above; SELinux remained Enforcing,
restricted-user networking, x86_64 KVM/SeaBIOS/virtio-blk. Five 432-package
publications, epoch1→3, signed effects and retained history, upgrade/reboot/
reinstall, spool/lost-issuance recovery, artifact rejection, revocation and
missing-journal hold passed.

Fedora43 **automatic control-plane trust passed**:
`ROOT/fedora43-trust-receipts.json`, SHA-256
`111ca61db75624529310d9622d5cbc417c924070260b9915af76e6e3a582a3e6`,
device `ba01d7b7-1042-4968-b8de-3b3d2cc6c6a4`, generation
`42e63e47-a1a3-4910-b59a-3168d12ab192`. Same pinned lab/server and RPM pair;
SELinux Enforcing unchanged, restricted-user networking, five 432-package
publications and epoch1→3. Automatic root/delegate rotation and revocation,
quorum/delegation/epoch-rollback denial, exact restart retry, unchanged TLS,
verified no-service-effects witness, reboot/reinstall trust retention and final
recovery/revocation/hold checks passed. Connected dispatch remains separate.

Fedora43 **connected dispatch passed**:
`ROOT/fedora43-dispatch-receipts.json`, SHA-256
`2a03eddaa60af6f1a921a24f9b3c73a678487e44a932d8e76c1c63c262db0e7b`,
device `80622c4c-727d-4530-8f1d-467a997059e1`, generation
`a4f6a110-9d3b-45ff-ae42-fc86f20357e0`. Same receipt-aware lab/server and
build source; RPM SHA-256
`1346b0f3640a25a0b6df5e2808fc2bf918a75f260385b0563190fb640021cfac`,
signer `F5899883EB2A02895EBFAF72F0557B3D2F8ADD1C`.
SELinux Enforcing, restricted-user networking; nine native scenarios cover
active/enabled, periodic 300-second compliant checks without a start grant,
drift repair, inactive/disabled, open-action server restart, no drift effects
without authorization, ±90-second clocks and revoked-device denial.
Unstarted supersession remains integration-only, not native coverage.
All requested Ubuntu26, Fedora43, RHEL9.8 and RHEL10.2 lifecycle/trust/dispatch
continuation lanes are now recorded passes within their stated native scope.

Fedora43's first signed-service continuation failed on a **laboratory schema
prerequisite**, before initial publication: both installed guest units were
active and native DNF queries succeeded, but the shared development database
lacked `device_agent_update_reports` required by the pinned server. PostgreSQL
reported that exact missing relation 1,098 times. Device
`75e1bd80-2b8f-4cf2-a122-68ab85f897af`, generation
`f1854979-da4c-41ca-ab67-ccf113a06f13`; disposition record
`ROOT/fedora43-service-shared-schema-failure.json`, SHA-256
`926c6a14e0be040189b8f62c4a0871b1f338d3da10970fc74141007b9c8168b6`;
private guest diagnostic `ROOT/lindm-cloud-init-3700555002.json`, SHA-256
`b7c626be4e1ba4dcd96bd1a904696cfc4eb785bc892b10befe3c0460df40bb79`.
The owner authorized maintained `go run ./cmd/dev recreate-database
-confirm-delete`, which completed successfully and refreshed only `lindm`,
preserving the live demo's separate `lindm_authority_*` database. This is not
a Fedora defect or a native-lane pass; no product retry/suppression was added.

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
have their own evidence. `Na` marks the 2026-10-10 aarch64 Debian 12/13, Leap 16.0
and Tumbleweed 20261007 records (inventory, packaged lifecycle, connected service
dispatch); Leap's cell also has the same x86_64 lanes, and Arch's
`N` now includes the same x86_64 lanes. The generic-executor resource cells (files,
accounts, sysctl, timers/drop-ins, password policy, packages) are aarch64 records
listed under [the executor cutover](#generic-resource-executor-cutover-phase-2).
`N98a` and `N102a` mark registered RHEL 9.8 and 10.2 aarch64 connected records
([EL 9](#host-resource-providers-on-el-9) and
[EL 10](#host-resource-providers-on-el-10) host providers).
Rocky/AlmaLinux ARM records are derivative rows, not RHEL evidence, and nothing
here covers desktop workflows.
Exact builds and observed limits are in the
[evidence ledger](implementation-plan.md#2-evidence-ledger).

| Resource kind                                     | Code | Ubuntu LTS | Fedora   | RHEL        | Debian/SUSE  | Arch/Tumbleweed | Atomic product | NixOS product |
| ------------------------------------------------- | ---- | ---------- | -------- | ----------- | ------------ | --------------- | -------------- | ------------- |
| Host and native package inventory                 | I    | N24, N26   | N43, N44 | S           | Na Deb, Leap | N Arch; Na TW   | S              | S             |
| Systemd service state                             | I    | N24        | N44      | S           | Na Deb, Leap | N Arch; Na TW   | S*             | S*            |
| Device local accounts/groups                      | I    | N24        | N44      | N98a, N102a | S            | S               | S*             | S*            |
| Sudo policy                                       | S    | S          | S        | S           | S            | S               | S*             | S*            |
| SSH configuration                                 | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Session/password settings                         | I    | N24        | N44      | N98a, N102a | S            | S               | S*             | S*            |
| Managed files                                     | I    | N24        | N44      | N98a, N102a | S            | S               | S*             | S*            |
| Kernel sysctl                                     | I    | N24        | N44      | N98a, N102a | S            | S               | S*             | S*            |
| Systemd timers and drop-ins                       | I    | N24        | N44      | N98a, N102a | S            | S               | S*             | S*            |
| Firewall                                          | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Time synchronization                              | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Trust stores                                      | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Wi-Fi/Ethernet                                    | S    | S          | S        | S           | S            | S               | S*             | S*            |
| VPN                                               | S    | S          | S        | S           | S            | S               | S*             | S*            |
| DNS/proxy                                         | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Native repositories/packages                      | I    | N24        | N44      | S           | S            | S               | S*             | S*            |
| OS/security-update lifecycle                      | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Device/user certificates and directory client     | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Recovery escrow, lock/quarantine and sanitization | S    | S          | S        | S           | S            | S               | S*             | S*            |
| Atomic OS deployment/boot/rollback                | S    | —          | —        | —           | —            | —               | S              | —             |
| Declarative system generation/activation          | S    | —          | —        | —           | —            | —               | —              | S             |

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

#### Typed kernel-module blocklist

`lab vm resources -phase connected -kinds modules` is the disposable installed-agent
lane for the closed managed-file template. Its separate `module_blocklist` evidence
does not upgrade the existing generic-file cell. Ten scenarios cover already-loaded
USB storage drivers (explicit pending restart and effect-free re-observation),
actual blocked `modprobe` after reboot, idempotency, owned-file drift,
initramfs-only drift, ownership-safe release, and a built-in driver (effectful
and effect-free not-applicable findings, never successful blocking) with release.
Every scenario retains server-accepted signed evidence and an independent native
record with SHA256. This is VM evidence, not physical USB-device qualification.
Drift receipts additionally require an actual effect grant and a pre-effect file
hash change or stale embedded stanza, so a successful no-op cannot count as repair.

Native qualification on 2026-10-11 passed **10/10 scenarios on each platform**:
installed signed packages, real server assignment/start authority, native root
helper effects and independent guest oracles. Evidence root:
`~/.cache/lindm-evidence/org-kernel-modules/`.

| Platform and kernel                                                         | Native receipt         | SHA256                                                             |
| --------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------ |
| Ubuntu 24.04 arm64, `6.8.0-142-generic`, dgx20 KVM                          | `ubuntu-arm64-07.json` | `fba9e750f27d23697dc63ac405ca74e6a121c2eb54ea077305cbc6f4f1b37b65` |
| Fedora 44 aarch64, `6.19.10-300.fc44.aarch64`, dgx21 KVM, SELinux enforcing | `fedora-arm64-07.json` | `f68b0cadc1336fa64a33d1ccae9f2c89166698d9ee75bc880e86abd306cbb709` |

Pinned source media are `ubuntu-noble-20260926-arm64` SHA256
`1d6bffe64b848468ac97f821d369a4846d983de1800ccf6b5ec8853e85cefc55`
and `fedora-cloud-44-1.7-aarch64` SHA256
`55c60a3b80d3616a08705afd0459e75fe9f03c54aba7a46e4002a41a72fa0d5b`.
Both receipts bind lab SHA256
`acbcfd2f970fa463b23bdf5bc963b232073039f39f15f1a6b446b0806eb3a082`
and server SHA256
`d9453f48d14d508a24448a59333978d042bbe64ae4df0ddd8bf61f6da038570b`;
installed DEB/RPM SHA256 respectively
`0b93edc1ee0d7b237171e990fb5f1cede87053b6ce733c45e4ebc791f2132e07`
and `f08af45b5162135ef0b754c3c601c142fb7fa2c06b566323867281f29c9206e5`.
UEFI is EDK II `2024.02-2ubuntu0.10`, observable Secure Boot disabled/setup mode,
no TPM, virtio-blk; this is arm64 virtual-machine qualification, not x86 or physical
USB qualification. The initial Ubuntu receipt independently records absent
vendor state before permitted creation. Both observe real built-in `kvm` as
not applicable, not blocked compliance. Fedora's initramfs-only drift fixture
renames within the same parent and asserts device/inode/birth-time continuity;
it does not copy across btrfs subvolumes or bypass custody checks.

Earlier `*-03` through `*-06` failure receipts remain retained, not counted as
passes: unobservable firmware selection, missing initial Ubuntu tool state,
generic dracut omission, kmod empty-option whitespace, an assumed absent built-in,
and cross-subvolume fixture replacement were corrected without relaxing gates.
Native rebuild command failure and interrupted/unknown release retain regression
coverage and the safety limitations below; these successful VM receipts do not
claim fault-injection qualification.

The provider recognizes only registry-declared tooling: Ubuntu 24.04
`update-initramfs` and Fedora 44 `dracut`. It checks every installed kernel image
present under the registry path and streams newc archives, including early
microcode and gzip/zstd compression. Unsupported compression, missing native
tools, missing boot images and failed reads fail closed. A profile cannot unload
an active driver, block a built-in driver, prevent a privileged operator from
using `insmod`/`modprobe --ignore-install`, or prove bootloader selection of an
image. Local root remains outside the anti-tamper boundary. Initramfs rebuild
failures and helper-loss uncertainty are distinct from successful enforcement.
The resident executor retains `ProtectKernelModules=yes`. Only the closed
template's helper can read module metadata: its module tree is read-only,
`CAP_SYS_MODULE` remains absent and all `@module` syscalls are denied.
Ubuntu's absent vendor state directory requires a writable `/var/lib` parent for
that effect helper's lifetime; creation is performed only by the permitted native
command, and later invocations narrow to the existing state directory. Fedora
uses fixed `--include` source/target arguments while the stanza exists, including
generic dracut images; removal release uses the base rebuild command.
Archive names reject interior NULs and noncanonical paths; a bounded symlink
model rejects aliases into the protected subtree across concatenated archives.
Release cannot relinquish ownership on a zero-exit updater alone: stale boot
images retain the existing unknown-outcome safety hold.

Console review: `make -o acceptance-build ui-review` passed **172/172** against the
already-built reviewed artifacts. Report
`~/.cache/lindm-org-gaps-20261011/kernel-ui-final/report.json`, SHA256
`9902416d7a31476a9a34558ee7b2c4af4a4035913aa5e4b5cd292dda77d06cf3`;
contact sheet `kernel-ui-final/index.html` under the same root. The maintained
scenario uses the real setting-type control and module textarea. Keyboard
inspection resets focus before recording unfocused styles; it retains every
indicator assertion rather than masking an already-focused textarea.

Full screenshots under `kernel-ui-final/screenshots/`:

| `profiles-new-block-kernel-modules-` suffix | SHA256                                                             |
| ------------------------------------------- | ------------------------------------------------------------------ |
| `light-desktop-full.png`                    | `76bccffd300ab37ed635bb1070b7edb6403cddb75c25229a16ccdbff67ed137b` |
| `dark-desktop-full.png`                     | `d4f7b25e9c4aedf1de9476b5ba289fde65e7be7caaf39b8682d58b86d45680a0` |
| `light-mobile-full.png`                     | `ef7c5488e689fab314d3b133f46612a2678bfd2393da288c94e1728be5c0c9ea` |
| `dark-mobile-full.png`                      | `8ea5a77094f7dde67d54cba6959c03221719269d6e5fe46dbab4812464fa7359` |

Before captures are `ui-before/screenshots/profiles-new-{light,dark}-{desktop,mobile}-full.png`
under the same evidence root (baseline `c0a4b2ed`). Its report SHA256 is
`e5cef739767edf1e88a83198d7d41e1c2baf1da8f0c161d1b7ce02c23ce42655`;
164/168 was **not** a green gate: four preexisting audit-copy findings failed,
while the profile captures passed. Assistant visual review of all four final
task captures found readable module bounds and restart/built-in consequences,
one-setting flow and no overflow. Design checklist: decision, evidence,
restraint, safety and craft pass for this task; editing **needs owner decision**.
Automated and assistant visual review are not owner design approval; preexisting
duplicated profile title/copy remains outside this slice.

#### Generic resource executor cutover (Phase 2)

The agent now accepts only the generic signed resource intent, challenge, start
grant and attestation; the service-specialized wire, journal tables and provider
dispatch are removed. Systemd service is the first provider on that path. The
journal schema is version 2 and is not migrated: an agent that finds an older
service-only journal enters `RECOVERY_HOLD`, and pre-cutover lab or demo devices
are re-provisioned rather than upgraded in place.

The post-cutover Ubuntu 24.04 connected dispatch lane **passed** on aarch64 (`dgx20`
KVM, AAVMF `2024.02-2ubuntu0.10`, image `ubuntu-noble-20260926-arm64`): all nine
native scenarios, including periodic compliant recheck and drift remediation,
server restart with an open action, ±90-second guest clocks and revoked-device
denial; unstarted supersession remains integration-only. Record
`$HOME/.cache/lindm-resourceproviders3-20261010/ubuntu24-arm64-dgx20-dispatch-cutover.json`,
SHA-256 `3ac9d2ae57b887ff7e583364af4c35cd7b45b2f4f6aee1d6bc1e2d2219a53ab6`
(lindmd `19f773e85ed6757b4b931bcc52ac76052332677ea5ce2b0b589368d6926a16b2`).
This is not x86_64, desktop or physical evidence.

Each nonservice kind is dispatched only when the server's per-kind qualification
table ([`QualifiedResourceKinds`](../internal/device/dispatch/resource_rows.go)) lists it
with the ownership operations its native Ubuntu 24.04 and Fedora 44 records
exercised; any other kind, adoption or release behavior remains a visible
unsupported disposition. Per-kind records follow.

The Fedora 44 aarch64 connected dispatch lane for systemd services also
**passed** after the cutover (`dgx21` KVM, image `fedora-cloud-44-1.7-aarch64`,
SELinux enforcing, all ten scenarios):
`$HOME/.cache/lindm-resourceproviders3-20261010/fedora44-arm64-dgx21-dispatch-q1.json`,
SHA-256 `beee7a24c81859e5d29d17db4a204d2489edc61b7cf52a8a5b7999a0830f914c`.

Per-kind records were produced by `lab vm resources -phase connected` on aarch64
cloud-image guests (`ubuntu-noble-20260926-arm64` on `dgx20`,
`fedora-cloud-44-1.7-aarch64` on `dgx21`, KVM, AAVMF `2024.02-2ubuntu0.10`)
from a clean source tree whose server qualification table listed every candidate
kind; the landed tree differs from it only in that table and in lab-only
failure diagnostics. Every scenario runs through the real server
assignment, signed intent/challenge/start grant, the protected executor and an
independent native oracle. All records are under
`$HOME/.cache/lindm-resourceproviders3-20261010/`:

| Kind (ownership exercised)                                                                                                                                      | Ubuntu 24.04 record       | Fedora 44 record          | Not exercised                                                                        |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------- | ------------------------------------------------------------------------------------ |
| Native package (create, restore; exact version, absence, dependency retention, pin drift, wrong signer, unavailable version, interrupted effect without replay) | `pkgfile-q2`              | `pkgfile-q2`              | Any-version; repositories other than one signed fixture (EL DNF4: own section below) |
| Managed file (create, approved adoption, restore; POSIX ACL refusal)                                                                                            | `pkgfile-q2`, `files-hk3` | `pkgfile-q2`, `files-hk3` | Desired ACLs (no such field); filesystems other than ext4/btrfs                      |
| Local group (create, approved adoption, restore)                                                                                                                | `host-q2`, `host-hk3`     | `host-q2`, `host-hk3`     | —                                                                                    |
| Local user (create, approved adoption, restore; UID collision and reused identity refused)                                                                      | `host-q2`, `host-hk3`     | `host-q2`, `host-hk3`     | Released-UID reuse by another name (hash delivery: `secrets-q5`/`secrets-q6`)        |
| Sysctl (approved adoption, restore; reboot persistence, `net.ipv4.ip_forward`)                                                                                  | `host-q2`, `host-hk3`     | `host-q2`, `host-hk3`     | Runtime-only values across a reboot; non-host network namespaces                     |
| Systemd timer and drop-in (create, restore; interval and calendar timers firing)                                                                                | `host-q2`, `host-hk3`     | `host-q2`, `host-hk3`     | Missed calendar catch-up (`Persistent=no`), timers across reboot                     |
| Password policy (approved adoption, restore)                                                                                                                    | `password-q2`             | `password-q2`             | History, aging, faillock lockout, interactive PAM password change                    |

Record files are `<distro>-arm64-<host>-resources-<run>.json` (`ubuntu24-arm64-dgx20-…`,
`fedora44-arm64-dgx21-…`) with these SHA-256 digests:

| Record                                            | SHA-256                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu24-arm64-dgx20-resources-pkgfile-q2.json`  | `b24781df252af2b5b5950f1641d1e512c1201f1c4dd958db12c522de13498ddb` |
| `ubuntu24-arm64-dgx20-resources-host-q2.json`     | `3911110c0e15d6cc39cc4839b29978aef5d4090e58570df64c759f1e903711db` |
| `ubuntu24-arm64-dgx20-resources-password-q2.json` | `8ae48b2095a87053b5d2623bb776e3bfb3f7fd4c05c2a4ae0dd8308a8760b062` |
| `fedora44-arm64-dgx21-resources-pkgfile-q2.json`  | `245ff01db65edb63146d6830cf22a5215c60c5ac41503bbd3354430f63fde8e5` |
| `fedora44-arm64-dgx21-resources-host-q2.json`     | `4691d08fdca15fe9801821882fae10a661a83019f47098ec46320e88f6c145c5` |
| `fedora44-arm64-dgx21-resources-password-q2.json` | `7ac9079e55219f71bad7ef193e5c6f988af606f683e7081556dde099be451e6f` |

The `hk3` records extend those kinds. They were produced by the same lane from
one immutable source snapshot (worktree `rc-lane-hk3`, base commit `efa78922`,
tar digest `1edf6228…c377`), which already contained the APPROVED_ADOPTION
qualification for local users and groups and the two product fixes below. They
are under `$HOME/.cache/lindm-resourcecoverage-20261011/hostkinds/` (Ubuntu on
`ubuntu-noble-20260926-arm64`, Fedora on `fedora-cloud-44-1.7-aarch64` with
SELinux enforcing):

| Record                                | SHA-256                                                            |
| ------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu24-arm64-dgx21-host-hk3.json`  | `021d5881d79e95cf39bff56167dcd39d8eeb153336d53a61d7a8c4baacd7829d` |
| `fedora44-arm64-dgx21-host-hk3.json`  | `269528e3a2c8ce54b18afb30a7038fbb19636d13a724232e95ad8cc0da882f67` |
| `ubuntu24-arm64-dgx20-files-hk3.json` | `ffee7580b34ad05d1e0363a3036f0d0514cfb264262b6db0ea8c78a6c2950f53` |
| `fedora44-arm64-dgx20-files-hk3.json` | `17269737762148f2621d3b9aabda7288b2443f29d729fd99cc138ca3c8d9e067` |

- Accounts: adoption of an existing group (GID change, additive member) and of
  an existing user with a real random `$6$` hash (shell, lock, maximum age);
  each release restores the recorded baseline byte for byte (passwd and group
  lines, shadow aging fields, gshadow digest, memberships, home). The record
  holds only the SHA-256 of the shadow hash, which stays equal under the lock.
  Refusals (`hashed-password-refused` as `UNSUPPORTED`, `uid-collision-refused`
  and `owned-identity-reuse-refused` as `PRECONDITION`) are device-signed
  failures that never started; the account database digests are identical
  before, after the refusal and after the clear's release. `hashed-password-refused`
  predates secret delivery; delivered hashes are now qualified by the
  `secrets-q5`/`secrets-q6` records, and the lane no longer runs that refusal.
- Sysctl: `reboot-persists` is a real guest reboot (changed boot ID,
  `systemd-sysctl` success) followed by a device observation without a start
  grant that reports reboot persistence; `release-after-reboot-restores-prior`
  then restores the pre-management value and removes the stanza.
  `net.ipv4.ip_forward` is set, repeated and released in the host namespace.
- Timers: an interval timer ran the inert target twice (distinct systemd
  `INVOCATION_ID`s); after switching to a UTC calendar minute, the target ran
  once at that minute and not between the switch and it.
- Files: an access-ACL file is not adopted and a file is not created under a
  default-ACL directory; `getfacl`, mode, content, inode change times and the
  directory are identical before, after the refusal and after the clear.

Product fixes these runs found: a POSIX ACL refused by the shared native file
boundary was retried forever as an internal error instead of a signed refusal
(the executor now classifies `nativefile` refusals); and release after a
reboot was refused as drift because a live sysctl value's identity is
boot-scoped (it now stays owned across a boot only while the owned stanza is
unchanged and effective).

Encryption compliance (create, restore; read-only finding, never a storage
effect) passed `lab vm device-actions -scenario compliance` on x86_64 encrypted
installer goldens with Secure Boot and swtpm: a LUKS2 root without escrow is
`DRIFTED`, after a real escrow rotation it is `CONVERGED`, and release leaves the
independent keyslot evidence unchanged. Records:
`ubuntu24-amd64-compliance-03.json` SHA-256
`892c630c71790b98a9bf494c25197304dac923966cdc3fef6b3e7d7d1e5ef640` and
`fedora44-amd64-compliance-10.json` SHA-256
`33449d9662b9904037ae07bffaf1bfa4d239860abbdd18ff5b0654fd4c0fe55e` (same
directory). TPM-binding requirements and physical storage are not exercised.

All six resource records share lindmd `ff346ccfdb61e11e…` built by the lab from that clean tree;
the Fedora package lane first upgrades the guest to the maintained DNF5
5.4.6.0 release update.

Native findings fixed before these records: systemd `RestrictSUIDSGID=` makes
`openat2` fail with `ENOSYS`, so protected path walks open one `O_NOFOLLOW`
component at a time; Fedora's SELinux refuses a bind mount of a `/proc/sys` file,
so a sysctl runtime change gets writable `/proc/sys` in its one-use helper and the
sysctl identity no longer includes the per-mount-namespace procfs inode;
`matchpathcon -m` takes a file class, not a mode; btrfs compression and
copy-on-write flags are allocation details; a created account acquires a newly
managed field against its last applied state, not its absent baseline; an
inactive timer reports an empty invocation ID; releasing a drop-in whose
directory the ledger created needs the unit root writable; and a converged
password policy plans no effect. Fedora additionally needed: RPM 6 removed the
`HDRID` query tag and reports signatures by key fingerprint; the approved key must
be in system RPM trust; DNF5 before 5.4.6.0 refuses to store a transaction from
a read-only `/usr`; `NoNewPrivileges=` breaks RPM's SELinux scriptlet transition
(exit 127); and DNF's single shared versionlock file is not another package's pin.

##### Secret-delivered password hash and managed local-admin password

`lab vm resources -phase connected -kinds secret-password,local-admin
-allow-network` qualifies both paths on the same cloud-image guest.
`ConfigureServiceDispatchWithEscrow` gives the isolated server fresh escrow
transport and wrapping keys with `reveal_approval_required`. The guest enables
sshd `PasswordAuthentication` with a `Match User` drop-in for each
disposable account only; `sshd -T -C` records the effective result for that
user and for others. Each login is a real `golang.org/x/crypto/ssh` password
authentication against the pinned host key. It records `id`, the logind
session (`Service=sshd`, `Remote=yes`) and sshd's `Accepted password` journal
line. A refusal must be sshd's `unable to authenticate`. Records never contain
passwords or hashes. The shadow oracle compares the expected hash in the guest
from stdin and prints only `hash-matches $6$`, `passwd -S` and `chage -l`.

- `secret-password` (local user `rlabsecret`, uid 24003, SHA-512 crypt from
  in-guest `openssl passwd -6 -stdin`), via `CreateSecret(PASSWORD_HASH)` and a
  pinned `SecretRef` in `HashedPasswordPolicy`. Steps: `create-hashed-password`
  (the shadow hash matches the delivered secret, then a password login),
  `repeat` (no start grant), `rotate-secret-version` (`RotateSecret` to
  version 2 and republish: the new password logs in and the version-1 password
  is refused) and `release-removes-user` (account absent, login refused).
- `local-admin` (`lindm-laps`, in sudo/wheel, allowlisted in root's
  `action_provider.local_admin_accounts`, with the `action-sandbox` drop-in).
  `SetLocalAdminPasswordPolicy` (interval 1 day, post-reveal delay 90 s) leads
  to a server-minted rotation reaching `CURRENT` with its action `SUCCEEDED`.
  A reveal with step-up but no approval is denied `permission_denied` /
  `approval_required`. A reveal with step-up and an exact second-human approval
  returns 26 base32 characters that log in over SSH. After the delay, a new
  `CURRENT` escrow with a different action supersedes the revealed one
  (`SUPERSEDED`) and the old password is refused. Revealing the new password
  logs in, and the policy is then removed. The 90 s delay keeps the post-reveal
  rotation from beating the login. The rotated password uses system PAM hashing
  (yescrypt on both distributions).

Both records passed on aarch64 KVM (AAVMF `2024.02-2ubuntu0.10`, user egress;
Fedora with SELinux enforcing)
from shared-tree revision `a98feef` with uncommitted diff SHA-256
`ec0a7302…20ac` (lindmd `cbf14fef48660d46…`, lab `90e5fdb44f48f8b8…`), under
`$HOME/.cache/lindm-secrets-20261011/`:

| Record                                                                 | SHA-256                                                            |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu24-arm64-dgx20-secrets-q5.json` (`ubuntu-noble-20260926-arm64`) | `a2a1a389308a2e2d40c82546d175a6056fe53b1bff3eb64a81d0f65e3f477efb` |
| `fedora44-arm64-dgx21-secrets-q6.json` (`fedora-cloud-44-1.7-aarch64`) | `0e034d6161cab751911bfc8c8b944a2ac93265af81ab8255215cba244a86e3cd` |

Not exercised here: a device without a registered encryption key (covered by
integration tests), `RevealSecret`, yescrypt and bcrypt `SecretRef` hashes,
x86_64, desktops and physical machines.

Regression coverage below the native lane: `internal/secretseal` checks the
RFC 9180 A.2.1 base-mode vector for the attested suite, a golden delivery
known-answer vector, rebinding refusal for every binding field, wrong-device,
tampered and truncated ciphertext; `internal/escrow` checks recovery,
local-admin and managed-secret domain separation, binding and wrong-KEK refusal.
Executor tests refuse digest mismatch, binding or action substitution,
another device's ciphertext and replayed re-sealed bytes, and scan every journal
and WAL file for plaintext; LAPS executor tests prove escrow before the native
set and no plaintext on disk. Real-PostgreSQL integration tests cover secret
create/rotate/reveal (idempotency, version conflict, unrestricted scope,
step-up, approval), delivery minting and its blocking/waiting reasons, key
registration, LAPS policy, minting, escrow ingest and reveal, and scan the
affected tables and audit rows for plaintext.

Console flows were exercised against two disposable `lab console` servers in
headless Chromium with a CDP virtual WebAuthn authenticator: secret creation
with client-side hash validation, the `SecretRef` view, rotation and a stale
expected-version conflict, reveal within the five-minute step-up window, the
30 s/blur/dismiss lifetime with no material in URL, storage, history, cookies or
the query cache, a `-reveal-approval` reveal approved by a second enrolled
administrator, the step-up refusal after five minutes, and the device
local-admin policy form, bounds and rotation request. Local-admin reveal in the
console needs real device escrow and was not exercised there; the API path is
covered by the native records above.

##### Firewall zone (create, restore, coexistence) — two-guest probe lane

`lab vm resources -phase connected -kinds firewall` boots the device and an
independent probe-peer guest from the same verified image; each holds its own
host slot. Their second NICs share a lane-private QEMU `dgram` Unix-socket L2
link (device `52:54:00:77:00:10`, peer `52:54:00:77:00:20`, static
`192.168.77.0/24` and `fd77::/64`); management and the controller's loopback
forward stay on the slirp NIC outside the zone boundary. The peer runs the
packaged `lindm-connectivity-probe.service` with a transport-CA TLS leaf and an
Ed25519 proof key; the device, the peer and the server's `connectivity_probes`
carry the same eight dual-stack INPUT TCP / OUTPUT UDP allow/deny targets, and
the device enables the packaged guard and restore units. A lab-owned
priority-100 table drops only the DENY tuples so the static deny experiments
stay meaningful after release. Before any zone exists the device activates its
distribution's own firewall manager: UFW (iptables-nft `ip filter`/`ip6 filter`)
on Ubuntu with SSH and the oracle ports allowed, firewalld (installed, default
zone `public`, `inet firewalld`) on Fedora with the oracle ports opened. Root
provisioning also enables the real quarantine action (management endpoints
`127.0.0.1` and `10.0.2.2`, DNS `10.0.2.3`, 300 s kernel timer) and installs its
`action-sandbox` drop-in. Every converged step carries fresh signed peer
receipts and the controller's DSSE confirmation; each oracle is the device's own
`nft -j list ruleset` plus TCP connections from the peer and UDP datagrams
received by an independent peer witness. Every zone oracle also digests each
foreign table with `nft -s -a list table` (stateless, with handles) and requires
it unchanged since the last native-manager baseline (provisioning, the deliberate
reload, the reboot).

| Scenario                                      | Native outcome                                                                                                                                                                                                                                                           |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `zone-create-converged`                       | Owned table at priority 10; peer reaches TCP 8080, 8081 filtered; UDP 5301 egress dropped (EPERM), 5300 received; native tables unchanged                                                                                                                                |
| `repeat-no-start-grant`                       | Verification-only action with fresh probes, no start grant                                                                                                                                                                                                               |
| `reconcile-rule-change`                       | Added TCP 8083 accept becomes reachable from the peer                                                                                                                                                                                                                    |
| `native-manager-reload-preserves-zone`        | `ufw reload` / `firewall-cmd --reload` recreates the native tables; the zone's `nft -a -j` digest is identical before and after; verification converges without a start grant                                                                                            |
| `real-quarantine-precedence`                  | Real signed quarantine (root and server `SUCCEEDED`): `lindm_q_<action>` at priority -10, peer TCP 8080/8081/8083 all filtered, UDP egress EPERM, explicit DNS to `10.0.2.3` answered, zone digest unchanged                                                             |
| `quarantine-withholds-then-resumes-reconcile` | A new revision during quarantine gets no server work for 30 polls (`device_quarantined` in the relay journal), zone digest unchanged; after the signed release the withheld verification converges and the zone behaves as before                                        |
| `external-rule-added-refused`                 | A rule added with `nft` to the zone's input chain: signed precondition refusal before any authority; the rule is retained                                                                                                                                                |
| `external-rule-removed-converged`             | Removing that rule restores the exact table; verification converges without a start grant                                                                                                                                                                                |
| `owned-rule-deleted-refused`                  | The owned IPv6 TCP 8080 accept deleted with `nft`: signed precondition refusal; the peer reaches 8080 over IPv4 only                                                                                                                                                     |
| `reboot-restore`                              | `lindm-firewall-restore.service` replays the committed zone (repairing the deleted rule), packets match, verification converges without a start grant                                                                                                                    |
| `helper-killed-after-kernel-batch`            | A lab watcher SIGKILLs `lindm-resource-<action>.service` within 15 ms of the batch removing 8083 (guard `APPLIED`, no confirmation); action `OUTCOME_UNKNOWN`; guard `ROLLED_BACK`; zone text and committed file identical; no trace or extra table; no replacement work |
| `outcome-unknown-resolved-by-observation`     | The next revision resolves ownership from that rollback; a new action with a start grant applies a new generation (guard `COMMITTED` for it) and 8083 becomes filtered                                                                                                   |
| `release-restores-absence`                    | Owned table removed; 8081 and UDP 5301 reachable again; every native table byte-identical (with handles) before and after                                                                                                                                                |

Records (lindmd `bfcb9e67ef0030627b84227682cda6820c4345f8513315f03ecaf3eea734791c`,
lab `98f4583feb631ebe51a02305b26347afbc4085c4b4037810fb7889bae9cd29df` as embedded in
the records; no instrumentation), under `$HOME/.cache/lindm-resourcecoverage-20261011/firewall/`:

| Record                            | SHA-256                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `ubuntu2404-arm64-dgx21-fw3.json` | `052ad3c85705fb57682e18de69022817751f72d9a5854340ad5af43ca2fdeedf` |
| `fedora44-arm64-dgx20-fw3.json`   | `0bb71257ea8d70a798509ae4fe4d7cbe86587590e1e352595c4c86c317245faa` |

The earlier six-scenario records (no native manager, a lab table at priority -10
imitating quarantine) remain under `$HOME/.cache/lindm-resourceproviders3-20261010/`:
`firewall-ubuntu2404-arm64-dgx20-q2.json`
`3a7e842c7b39a17f0bdf12448510a055566e0c9452d4b7249631da7582f51dda` and
`firewall-fedora44-arm64-dgx21-q2.json`
`bb335f97639707ea4f599e58cfd013f224b0d366b09d0970742f8043d846edef`.

Not exercised: FORWARD probes, partitions, generation-CAS races, approved
adoption; crash windows other than the helper SIGKILL between the kernel batch
and controller confirmation (guard arm, pending write, committed write, disarm,
executor or supervisor restart, missed confirmation); quarantine kernel-timer
expiry under a zone (it ends by the signed release); release of a drifted or
still-unresolved zone; x86_64.

Native findings fixed before these records: `/proc/1/ns/net` is ptrace-gated, so
every capability-bounded firewall helper, the guard and the restore unit failed
the host-namespace check with `EACCES`; it now compares the per-namespace
`/proc/<pid>/net/dev` entries. Kernels read back a boolean bitwise expression with
an explicit `NFTA_BITWISE_OP=0`; the normalizer dropped it but re-marshaled the
parent with its stale netlink length, so every applied table read back as
foreign (outcome unknown). An observation directory listing resolved entries
against a label instead of its path, so one retained observer blocked all later
observations. The native worker took the guard record lock non-blockingly and
failed when it met the supervisor's 100 ms recovery poll; it now waits within its
deadline. Fedora 44's nftables 1.1.6 prints a `typeof` set key as the typeof
expression, so every real quarantine there failed its read-back after the kernel
effect, ended `OUTCOME_UNKNOWN` and rolled itself back
(`fedora44-arm64-dgx20-fw1.json`,
`16dac74cf1c6442bd7147d94eb0c76ff636bf87591371d68fc14e5a64fd923e6`); the parser now
accepts both forms. A helper killed after its kernel batch left the ownership
ledger UNKNOWN forever, so after the guard's exact rollback the zone could never
be reconciled or released; the next signed plan now resolves it from the guard's
terminal record of that exact transaction (see
[engineering](engineering.md#dedicated-typed-firewall-zones)). Quarantine admits
loopback only from its `127.0.0.1` endpoint, so the systemd-resolved stub is
unreachable while quarantined and Ubuntu's `sudo` failed to resolve the hostname
(`ubuntu2404-arm64-dgx21-fw1.json`,
`6cab1d39ad80e16af52a52fefd36837e9114a4fe695e487be52707e5fca9ceac`); the lab adds
the Debian `127.0.1.1` hostname line. This product behavior is unchanged.

##### Native packages on EL (DNF4 Python API backend)

The connected package lane (`lab vm resources -phase connected -kinds packages`)
ran its ten scenarios unchanged from Ubuntu/Fedora — exact v1 with dependency and
readiness, wrong signing key refused, unavailable exact version refused, exact v2
upgrade, repeat without a start grant, owned absence, presence after absence,
release retaining the dependency, external pin drift refusing release, and an
interrupted running scriptlet that is never replayed — against the
[DNF4 backend](platforms/rhel.md#package-resources-dnf4). The DNF4 oracle
additionally requires the marked exact line in
`/etc/dnf/plugins/versionlock.list`, the native `dnf` CLI resolving the other
repository version without the versionlock plugin and refusing it with the
plugin (`--assumeno upgrade|downgrade`; the plugin ignores non-resolving `list`),
`matchpathcon -V` of the payload and a `%post` scriptlet that recorded its own
SELinux context `system_u:system_r:rpm_script_t:s0`. SELinux stayed Enforcing.
Records are under `$HOME/.cache/lindm-resourcecoverage-20261011/`:

| Platform (aarch64, KVM on Sparks)      | Record                                 | SHA-256                                                            |
| -------------------------------------- | -------------------------------------- | ------------------------------------------------------------------ |
| RHEL 9.8 (registered, user egress)     | `rhel98-arm64-dgx21-packages-a5.json`  | `3d0b520490e43c4536d4a17fb63745747017aa5ecbe2ba96bef590d1fea04474` |
| AlmaLinux 9.8                          | `alma98-arm64-dgx20-packages-a5b.json` | `28c47a472b0760385b029ac4f8206e929d8f27b410c3bd4aa07fe16c204e8101` |
| AlmaLinux 10.2                         | `alma102-arm64-dgx21-packages-a7.json` | `9f22874f333a6a90abd6b3030901fbfc9acc6d2937d8ad0211ef292298181d5d` |
| AlmaLinux 8.10 (**failed**, diagnosis) | `alma810-arm64-dgx20-packages-a7.json` | `ea08989820a1bf5365492a3c99fdcfcac34bce6fcf0527275f633948d6161893` |

The RHEL 9.8 image is the vendor `rhel-9.8-aarch64-kvm.qcow2` (SHA-256
`5f9d524f…f384`), acquired with the maintained `lab images redhat fetch -arch
aarch64` path (vendor-authenticated checksum; pinned manifest
[`rhel-9.8-aarch64.json`](../lab/images/rhel-9.8-aarch64.json)). The record's
`redhat` block reports registration, native identity, authenticated repository
metadata refresh, unregistration and owned activation-key deletion all true
(run `lindm-lab-5748e60219113773077ffef2d09b26cb`, consumer
`34fcdaed-b232-49cf-b6c8-796d964eea21`); `rpm-build`, `createrepo_c` and
`python3-dnf-plugin-versionlock` came from the entitled AppStream. An earlier
attempt interrupted from the controller left consumer
`9bec2250-893e-412e-8f52-b05775ca09ae` registered; the maintained
`lab images redhat cleanup` deleted it and a following inventory returned `[]`
(`rhel98-a3-orphan-cleanup.json`).

AlmaLinux 8.10 is a precise failure, not a pass: the fixture and DNF4 4.7.0 on
platform-python 3.6 are ready (the adapter's resolve/stage/check/apply also
completed in a scratch guest under equivalent unit sandboxes), but systemd 239
refuses the package helper's transient unit (`Cannot set property
ProtectKernelLogs`; `Type=exec` and `RestrictSUIDSGID=` are likewise newer than
239). EL8 package resources stay blocked until the helper sandbox has an
equivalent EL8 expression; the failure precedes any native effect.

Native findings fixed before these records: the DNF4 CLI exits 1 under the
executor's read-only `/var` even for `--version` (its RPM sack opens
`/var/log/hawkey.log` before `--setopt=logdir` applies), so DNF4 is identified
through the entrypoint interpreter's `dnf` module; EL ships `/usr/bin/dnf` as a
symlink to `dnf-3` whose shebang is `#!/usr/bin/python3.9` (EL9),
`#!/usr/libexec/platform-python` (EL8) or `#! /usr/bin/python3 -s` (EL10); libdnf
opens `history.sqlite` read-write, so read-only staging resolves against a private
snapshot; DNF4 refuses package downloads under `cacheonly`; and the fixture
toolchain oracle assumed `dnf5`.

##### Shared native runner, custody walk and provider registry

After every agent provider moved onto `nativeexec`, `custody.OpenRoot`/`ReadRoot`
and the per-kind `resourceprovider` registries, the all-kinds connected lane
(`lab vm resources -phase connected -kinds
packages,files,accounts,sysctl,definitions,password,firewall`) passed all 72
scenarios on each of Ubuntu 24.04 (`ubuntu-noble-arm64`, `dgx20`) and Fedora 44
(`fedora-cloud-44-1.7-aarch64`, `dgx21`), aarch64 KVM, from one snapshot of the
shared tree (`c44a02b` plus 78 uncommitted landed files including the exit-status
fix; source tar SHA-256 `060a334d…2b687`, lab `3ff63d0a…278eecfa`, lindmd
`be7d457c…7fca2c48`). The first run of the same lanes caught that fix: account
NSS absence and the LUKS wipe proof still
matched `os/exec` exit errors, so every account action timed out. Per-kind
scope limits are unchanged from the records above. Records are under
`$HOME/.cache/lindm-providerlayer-20261011/`:

| Record                         | SHA-256                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `ubuntu2404-arm64-res-s2.json` | `d7445376e31e944ea010d4dda936448395d9d2ee0f4a0414d1690feb019fa5a8` |
| `fedora44-arm64-res-s2.json`   | `50457a88ec627a8f9e48524e9c0deccee4712cf15d9bfd32a2882714a0844b71` |

##### Host resource providers on EL 9

The connected host lanes (`lab vm resources -phase connected -kinds
files,accounts,sysctl,definitions,password` and the two-guest `-kinds firewall`)
ran their Ubuntu/Fedora scenarios unchanged on RHEL 9.8 and AlmaLinux 9.8
aarch64 cloud guests with SELinux Enforcing, plus one EL scenario: password
policy is first assigned to the image's unmanaged pam-package stack and must be
refused before any effect (`unmanaged-pam-stack-refused`; byte-identical
`system-auth`/`password-auth`/`pwquality.conf` before, after refusal and after
clear), then the lane selects the vendor `sssd` authselect profile and qualifies
the managed path. All four records come from one source snapshot (revision
`efa78922`, working-diff SHA-256 `74246a3d…221e`, lindmd `5a430504…3a3054`, lab
`f230b937…`); RHEL used the vendor KVM image `5f9d524f…f384` and AlmaLinux the
GenericCloud image `15cf8257…`. Records are under
`$HOME/.cache/lindm-resourcecoverage-20261011/elhost/`:

| Record (aarch64, KVM on Sparks)                             | Kinds and scenarios                                                                                                   | SHA-256                                                            |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `rhel98-host-el12.json` (RHEL 9.8, registered, `dgx21`)     | files 9, groups 7, users 12, sysctl 8 (reboot, `net.ipv4.ip_forward`), timers/drop-ins 10 (firing), password policy 5 | `106fa76cecbc56c6f4112b074ff26c51162da63ab3ad8d6b033c45ea9d03d87c` |
| `alma98-host-el12.json` (AlmaLinux 9.8, `dgx20`)            | same 51 scenarios                                                                                                     | `48d057dd4cec6ebac735720c114a15d12247765651a5c7aa80f61763b0456565` |
| `rhel98-firewall-el12.json` (RHEL 9.8, registered, `dgx21`) | firewall zone 13, firewalld active                                                                                    | `aa140e905b1e26e3e7fa906b5c19fe425852c78541a4b73b36e4355d48009bf6` |
| `alma98-firewall-el12.json` (AlmaLinux 9.8, `dgx20`)        | firewall zone 13, firewalld active                                                                                    | `368328a10db6a79d051818b2eddacf6810deb987fee0cbc02b65d71e3cba6fab` |

Each RHEL record's `redhat` block reports registration, native identity,
authenticated repository metadata refresh, unregistration and owned
activation-key deletion all true (host: run
`lindm-lab-fdf3eacf3dd99a5eab1785e62cfed311`, consumer
`06377afb-0b75-4de4-ae39-78e2a080446b`; firewall: run
`lindm-lab-c4077aec1778e0ea71a8a1a18d609810`, consumer
`3819ddcb-1257-4fc0-8ca1-dea6bc44dbf6`); firewalld, nftables and the fixture
toolchain came from the entitled repositories. AlmaLinux records are derivative
evidence, not RHEL qualification.

Native findings fixed before these records (diagnostic records in the same
directory):

- EL 9 shadow-utils 4.9 labels `--prefix` account databases from the prefixed
  path (`var_run_t`); after `create-locked-home` `sudo` failed and the lane lost
  the guest (`alma98-host-el1c.json`,
  `edad1751529366a243eb369bc8c5bce66d1629fb698afca2ba373e190216bf2d`). EL 9 now
  chroots the tools into an account root with the host procfs, selinuxfs and
  read-only `/usr` ([RHEL quirks](platforms/rhel.md#host-resource-providers-el-9)).
- The definition provider required systemd 255 and could not parse EL's
  `252-67.el9_8…` manager version; EL 9's floor is 252.
- An admission refusal recorded before a native plan (here the unmanaged PAM
  stack, then its refused release) was counted as a historical effect, so every
  later claim of the same key failed `resource_ownership_unknown`
  (`alma98-defpw-el7.json`,
  `28284090cf2ae46fa19476f1a8f5dabd38ddd90eb732777570a41f7fe4255845`). A FAILED
  record without a start grant envelope and start time is now effect-free for
  ownership history regardless of its plan; anything started still blocks
  ([`historicalEffect`](../internal/agent/journal/resource_ownership_linux.go)).
- Boot zone restoration failed beside firewalld: a generation refusal
  (`ERESTART`) and repeated `NEWRULE` acknowledgments during module autoload
  were both reported as unknown outcomes (`alma98-firewall-el8.json`,
  `1927a5f6de095e900e25aee33bba8d57254af95fa09a14b832df7a1279443758`;
  `rhel98-firewall-el11.json`,
  `2b551ab0758f5c4a0f584ae84de2c7cf74a98a803fd8f00a455c80a2d449922c`). The
  provider now retries refused batches, accepts repeated object successes and
  replaces the socket after every batch; the race is not EL-specific.

Not exercised on EL 9: Rocky Linux, EL 8, x86_64, delivered password hashes
(the secret-password lane ran only on Ubuntu and Fedora), history/aging/faillock password dimensions and interactive
PAM password change, authselect profiles other than `sssd`, a host whose
authselect selection predates enrollment, file ACLs beyond the refusals, timers
across a reboot, FORWARD probes and the firewall crash windows listed in the
records' `unproven` fields.

##### Host resource providers on EL 10

The same host and firewall lanes ran on RHEL 10.2 (registered, vendor KVM image
`0e6b8758…0836`) and AlmaLinux 10.2 (GenericCloud `b1203c2e…`) aarch64 guests,
SELinux Enforcing, after the gates were extended to EL 10 and the password pins
to 10.2 ([RHEL EL 10 notes](platforms/rhel.md#host-resource-providers-el-10)).
Both images already select authselect `local`, so the EL 9 unmanaged-stack
scenario does not arise. Per-kind development records, under
`$HOME/.cache/lindm-resourcecoverage-20261011/el10host/`:

| Record                                                         | Kinds and scenarios                                                          | SHA-256                                                            |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `rhel102-host-el10b.json` (RHEL 10.2, registered, `dgx21`)     | files 9, groups 7, users 11, sysctl 8, timers/drop-ins 10, password policy 4 | `bf09e21403c32e5c02b00005c13791d8e1f7f141d2b3906da4aea79eaf21ce9b` |
| `alma102-host-el10a.json` (AlmaLinux 10.2, `dgx20`)            | the same 49 scenarios                                                        | `a6698fa0f1d1b7f5ec5c03e8d65f548d4013b84517bc1c302071d04f0e65f9aa` |
| `rhel102-firewall-el10b.json` (RHEL 10.2, registered, `dgx21`) | firewall zone 13, firewalld active                                           | `efa5c80e3355b3c17a7aab973f6c09fd757d65a5e093c6b26a16968e5464b58f` |
| `alma102-firewall-el10b.json` (AlmaLinux 10.2, `dgx20`)        | firewall zone 13, firewalld active                                           | `de056a9c6c233edb32eb2fd3d2044705b40e0e38788282a1dddb3cf32d89139b` |

Each RHEL record's `redhat` block reports all five registration and cleanup
outcomes true (host: run `lindm-lab-f57bd294ba353b74e1cfaa97fef40a02`, consumer
`70f4e063-d8eb-4ab0-be47-96c96d9bb78b`; firewall: run
`lindm-lab-c3485a05f5f1b43d1cffa60a4e8b4ff7`, consumer
`9d76a277-a42a-4bc2-9d57-d71ecaace69f`). An earlier RHEL 10.2 host run
(`rhel102-host-el10a.json`,
`4bda96e1d1c6506e3e72ea10123114f8a88f1842605dab19a5e91f973d90510e`) passed files,
accounts and the first three sysctl scenarios, then lost the SSH transport while
probing the boot ID after the guest reboot; the rerun passed.

After landing, both platforms passed every kind together in one connected lane
(`-kinds packages,files,accounts,sysctl,definitions,password,firewall`, eight
resource kinds, 72/72 scenarios, SELinux Enforcing), each run from an immutable
snapshot of the shared tree (revision `5231542c`), under
`$HOME/.cache/lindm-resourcecoverage-20261011/`:

| Platform                                | Record                                    | Snapshot (diff SHA-256, lindmd) | SHA-256                                                            |
| --------------------------------------- | ----------------------------------------- | ------------------------------- | ------------------------------------------------------------------ |
| RHEL 10.2 aarch64, registered (`dgx21`) | `rhel102-arm64-dgx21-allkinds-el10.json`  | `304635fb…`, `09b405e7…`        | `27ec51eec1fc302e51a84460661e1ba7c23168f626bf4f1f198d3e3dc6d76e31` |
| AlmaLinux 10.2 aarch64 (`dgx20`)        | `alma102-arm64-dgx20-allkinds-el10b.json` | `95d893ed…`, `87936177…`        | `30d7dc4375d145a1fdb59ad68da6454293cbaad7d25193abf60a9fb4ca6eeee1` |

The RHEL record's `redhat` block reports all five outcomes true (run
`lindm-lab-d22b4e7cdcec997192ca036fad27b658`, consumer
`8f1f9be4-aecf-450a-b8ce-ddbd699e2995`). The AlmaLinux record comes from the
later snapshot that also contains the reboot-probe retry below; its first
all-kinds run (`alma102-arm64-dgx20-allkinds-el10.json`,
`80a68642b25543bde0652476b32e1b19dc082df66a27d1cdf0881c8998a73893`) passed
everything except firewall `reboot-restore`, where the lab's boot-ID probe
reached the old boot's `sshd` as shutdown stopped it and the session ended
without an exit status (`ssh.ExitMissingError`, seen twice on EL 10). The lab
now retries that like any other transport loss of the old boot
([`waitGuestBootChange`](../internal/vmlab/vm_lifecycle_helpers_linux.go)).
A RHEL rerun from that snapshot lost the controller's SSH link to `dgx21`;
its remote lane left consumer `1e213dc5-a28c-4e09-9617-39e4175f50f7`
registered (`rhel102-arm64-dgx21-allkinds-el10b-aborted.json`,
`cfee5a320dd8f1964f9de49b71788fb720d1a869dc68687cdd6c651f225ceb12`, unregistered
false). After stopping only that run's guests, the maintained
`lab images redhat cleanup` deleted it and a second lab system
(`3e964495-3828-4dc3-973d-f50948133b48`) plus the one remaining lab activation key;
inventory before (`rhel102-el10b-orphan-inventory-before.json`,
`932ca819aae0b913ad2a1a962d209628271b10f4d28c5cc7767583d9bff7c6c9`), cleanup
(`rhel102-el10b-orphan-cleanup.json`,
`b8ccc97e07527301df6346159215b4f258a4a8a5f2fa17ce3fca48366ea1d01b`) and inventory
after, `[]` (`rhel102-el10b-orphan-inventory-after.json`,
`37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`).

No product defect beyond the gates surfaced on EL 10; the decisive native fact
is that shadow-utils 4.15 `--prefix` still writes the account databases with the
prefixed path's label (`var_lib_t`), checked in a scratch guest before enabling
the chroot account root.

Not exercised on EL 10: Rocky Linux, x86_64, history/aging/faillock password
dimensions and interactive PAM password change, authselect profiles other than
`local`, timers across a reboot, FORWARD probes and the firewall crash windows
listed in the records' `unproven` fields.

##### All resource kinds in one connected lane

`lab vm resources -phase connected -kinds
packages,files,accounts,sysctl,definitions,password,firewall` runs every kind's
scenarios in sequence on one enrolled guest (plus the firewall probe peer), from
an immutable snapshot of the landed shared tree, so the later kinds also run
after the sysctl lane's and firewall lane's real reboots. Records are under
`$HOME/.cache/lindm-resourcecoverage-20261011/`:

| Platform                                          | Record                                    | Scenarios passed   | SHA-256                                                            |
| ------------------------------------------------- | ----------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| RHEL 9.8 aarch64, registered (dgx21)              | `rhel98-arm64-dgx21-allkinds-g3.json`     | 73/73, eight kinds | `0ef046228e7cb999c3fb6dd2d43b27236a0b0a081cd5eca86f23b21a029c21f4` |
| AlmaLinux 9.8 aarch64 (dgx20)                     | `alma98-arm64-dgx20-allkinds-g3.json`     | 73/73, eight kinds | `38bd4629131f2433869bcd190de19e3d211129f471c8b415fbaebe41e593f1c0` |
| Ubuntu 24.04 x86_64 (local; firewall not in lane) | `ubuntu2404-amd64-local-allkinds-g1.json` | 59/59, seven kinds | `0f31861443b7e7256f7d262c59933a7c013fd042106cc1859926899bcb545fc7` |
| Ubuntu 24.04 x86_64 (local), firewall only        | `ubuntu2404-amd64-local-firewall-g5.json` | 13/13, firewall    | `ae3766950c7a4d3115c294c7387efc0aca888b0fc19d28611bb24d6664484d7c` |

The RHEL record's Red Hat block reports all five registration and cleanup
outcomes true (run `lindm-lab-25119be2e02e805e01bcee0b5dc201b7`, consumer
`466b472d-2f13-4ff1-bffd-00062e12d493`); SELinux stayed Enforcing on both EL
guests. Both EL records share lindmd
`be646a1f69c4fb6bcf71fa210fe52f7cf6c2b41006fb59794296d068d3f49cc2`. The
AlmaLinux record was copied from the retained remote run directory
(`dgx20:/home/r/lindm-lab/runs/run-biS1hilutM/records/record`) after the
controller's SSH session to dgx20 dropped at the end of the lane; the remote
lane had completed and written it, but its `lab_host` provenance block is
therefore absent. The Ubuntu x86_64 all-kinds lane ran the seven host-local
kinds; the firewall kind, which needs a second x86_64 guest for its probe peer,
ran separately from a snapshot of shared revision `681e7ef` after first-come,
all-or-nothing lab admission landed (its first attempt held one local slot
while waiting for the second, the hold-and-wait deadlock described in
[engineering](engineering.md)). It passed all 13 firewall scenarios with UFW
active, including the real quarantine action, drift refusals, reboot restore
and the helper-killed crash boundary.

Two lane defects were found by these combined runs and fixed before the
records. First (`*-allkinds-f1.json`), the signed fixture repository was a
transient unit, so after the sysctl reboot the final package interruption
scenario could not stage (`connection refused`) and never reached its
interruption point. Second (`*-allkinds-g1.json`, `*-g1b.json`, and the
diagnostic `alma98-arm64-dgx20-allkinds-g2.json`), the now-persistent repository
unit was named `lindm-resource-repository.service`, which matched the firewall
crash watcher's `lindm-resource-*.service` helper glob: `systemctl kill` got two
unit names, killed neither, and the transaction succeeded instead of ending
`OUTCOME_UNKNOWN`. The repository is now `lindm-lab-resource-repository.service`,
and the watcher kills exactly one UUID-named effect helper or records why not.

##### OS update policy, patch now and patch status

`lab vm resources -phase connected -kinds os-update -allow-network -accelerator kvm
-local-authority` (RHEL adds `-redhat-token-file`) qualifies `os.update.v1`, the
`device.patch-now.v1` action, patch-status inventory and fleet patch
compliance. Every policy change goes through the real server assignment, signed
intent/challenge/start grant, protected executor and transient native helper.
Each guest uses the distribution's own signed repositories. The policy zone is
`Europe/Berlin` while guest clocks are UTC, so the timer calendar crosses a real
IANA conversion. Each record runs eleven scenarios, all passed:

| Scenario                             | Native proof                                                                                                                                                                                                                                                                             |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `competing-native-scheduler-refused` | APT: a later part sets `APT::Periodic::Unattended-Upgrade "1"`; RPM: an enabled `dnf-automatic.timer`/`dnf5-automatic.timer`. Signed failure before any effect; owned paths, loaded timer and native scheduler state byte-identical before, after refusal and after clear                |
| `policy-installs-window-timer`       | Owned files with mode/owner/digest, systemd's loaded `TimersCalendar` in the policy zone, `FragmentPath`, `ActiveState=active`, effective APT periodic `0`                                                                                                                               |
| `start-outside-window-skipped`       | Manual start before the window opens: package database digest unchanged; published patch status `last_run` `SKIPPED_OUTSIDE_WINDOW`                                                                                                                                                      |
| `window-deferral-holds-updates`      | The owned timer itself fires at the window start (`LastTriggerUSec`); with 7 deferral days the run is `DEFERRED` with deferred packages, the package database is unchanged                                                                                                               |
| `policy-reconciles-without-deferral` | Reconcile to deferral 0 and a new window                                                                                                                                                                                                                                                 |
| `window-installs-security-update`    | Timer-opened run installs the real pending security updates (package database changed); native reboot oracle set; logind `ScheduledShutdown` is `reboot` at completion + 5 min (±1 min) and equals the reported time; the policy notice reached a logged-in pty as a logind wall message |
| `scheduled-reboot-executes`          | A new boot ID after the scheduled time, native oracle cleared, fresh post-reboot patch status                                                                                                                                                                                            |
| `repeat-after-reboot`                | Same policy converges with no start grant                                                                                                                                                                                                                                                |
| `patch-now-all-updates`              | Signed patch-now (`ALL`, reboot `NEVER`) is `SUCCEEDED` with `patch_run_started`; patch status `last_run` carries the action ID, `SUCCEEDED`, no logind schedule (`policy_never` when a reboot is required); updated count agrees with the database diff                                 |
| `fleet-patch-compliance`             | `GetFleetSummary.patch_compliance` buckets sum to the active devices and place the device in the bucket its fresh status implies                                                                                                                                                         |
| `release-removes-policy`             | Signed release; owned objects, timer and native scheduler state byte-identical to the pre-lane baseline                                                                                                                                                                                  |

The server records come from signed `refresh_inventory` actions, which are part
of each scenario's evidence. All records are from source snapshot `s11`:
the feature rebased on `c44a02b` with native tools through `nativeexec`
(SIGTERM-only package transactions, credentialed notify child), commit
`656d4d5`, tree SHA-256 `3c2ddbba…1377`, lab `a80fb128…9889`, lindmd
`141c684d…beb4`. Records are under `$HOME/.cache/lindm-ospatch-20261011/`
(aarch64 on the Sparks with KVM and AAVMF):

| Record                                   | Image / SELinux                                | Facts                                                                                                                                     | SHA-256                                                            |
| ---------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu24-arm64-dgx20-osupdate-s11.json` | `ubuntu-noble-20260926-arm64`, AppArmor        | 29 pending security; 23 deferred; window installed 29 packages; reboot at +5 min executed; patch-now updated 3; fleet bucket `patched`    | `31fc2734ac310f230d143a324fd5b92d38d1c037984ee0375462024558ed55bd` |
| `fedora44-arm64-dgx20-osupdate-s11.json` | `fedora-cloud-44-1.7-aarch64`, Enforcing       | 71 pending security; 71 deferred; window installed 78; reboot executed; patch-now updated 120 (`policy_never`); fleet `reboot_required`   | `7b11840048a08037589a400bad54b0eb7b55ef12d858e8cae148b27899c65db5` |
| `rhel98-arm64-dgx21-osupdate-s11.json`   | `rhel-9.8-kvm-aarch64`, Enforcing, registered  | 105 pending security; 119 deferred; window installed 105; reboot executed; patch-now updated 24 (`policy_never`); fleet `reboot_required` | `819225c0ec2c1ce9ec9d0e5a0772857072a959819a4ef8311634f7f4b665772e` |
| `rhel102-arm64-dgx21-osupdate-s11.json`  | `rhel-10.2-kvm-aarch64`, Enforcing, registered | 117 pending security; 127 deferred; window installed 117; reboot executed; patch-now updated 53 (`policy_never`); fleet `reboot_required` | `fb3e576c856bee4910637689f3fcb886cff675a82bb4c6a59164f3c7282305b1` |

Red Hat receipts (registration, identity, entitled metadata refresh,
unregistration and activation-key deletion all true): RHEL 9.8 run
`lindm-lab-e13412e8d9165d718b63d1aeea5bb517`, consumer
`eb6add44-1caf-4e27-b1ae-c49dc2c63377`; RHEL 10.2 run
`lindm-lab-c1a2b9f74687cd9ee931ba5c8677dfbc`, consumer
`5a7ddb0a-a925-49bc-bac9-e55f9a190fce`. A read-only `lab images redhat
inventory` after the runs returned an empty list. The runner's deferred count is per
`name.arch` from `repoquery`, and the oracle counts `check-update` lines, so
the two counts need not be equal. Earlier passing `s8` records (pre-rebase)
for Ubuntu and both RHEL releases are superseded by these.

The x86_64 record is from snapshot `s13`: main `4fb7678` with the run-lock fix
below (landed as `b07301e`), tree SHA-256 `9a14f636…0779`, lab
`2e3a73e9…268b`, lindmd `42007996…163b`, a local KVM/OVMF guest admitted
through the FIFO lab queue. In this run no reconcile overlapped a window run,
so it proves the fix causes no regression. The race itself is proven by the
deterministic regressions:

| Record                                    | Image / SELinux                         | Facts                                                                                                                                   | SHA-256                                                            |
| ----------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `fedora44-x86_64-local-osupdate-s13.json` | `fedora-cloud-44-1.7-x86-64`, Enforcing | 71 pending security; 71 deferred; window installed 78; reboot executed; patch-now updated 127 (`policy_never`); fleet `reboot_required` | `f9f3701295a27eb3dcb96843ade841b399ed14ea038a6abc9ee84a42d380c8f0` |

Native findings, each fixed with a regression before these records:

- The helper's `NativeResourceTransactionRequest` kind allowlist lacked kind 15,
  so it refused the plan after the ownership effect began
  (`TestHelperAdmitsCreationAndReleaseRequests`).
- `/etc/os-release` is a symlink on all three distributions. The runner's
  `O_NOFOLLOW` read failed, so it now reads `/usr/lib/os-release`
  (`TestDetectReadsUsrLibOSReleaseBeforeTheEtcSymlink`).
- `dnf5 --cacheonly needs-restarting` loads filelists and failed cache-only. The
  oracle now disables repositories (`TestDNFRebootOracleDisablesEveryRepository`).
- Fedora's btrfs root assigns subvolume `st_dev` per boot. The owned-file
  identity digests changed across the policy reboot and blocked release, so
  release now compares boot-stable identity: bytes, mode/owner, label and inode
  (`TestOSUpdateDimensionsIgnoreBootDeviceNumbers`). The `s8` Fedora records end
  in `release_conflict` for this reason and are diagnostic only.
- Deferral is anchored to the window start in zone calendar days
  (`TestDeferralIsAnchoredToWindowStarts`, injected clock, DST weeks). The
  rendered timer passes the host's `systemd-analyze verify`, and its calendar
  elapses equal the runner gate's window starts
  (`TestRenderedUnitsPassSystemdVerify`, `TestTimerElapsesAreTheRunnerWindowStarts`).
- x86_64 Fedora 44 (`diag/fedora44-x86_64-local-osupdate-s12.json`, SHA-256
  `dec22973…93f4`): the server's periodic reconcile ran its helper while the
  window run's `dnf5` transaction was upgrading the system. The post-effect
  observation no longer matched, the ledger stayed `UNKNOWN` (fail-closed, no
  resolution path), and `repeat-after-reboot` timed out. A provider effect now
  takes the runner's lock without waiting before its ownership effect and holds
  it to completion; contention is `NATIVE_BUSY` with no effect
  (`TestApplyRefusesWhileAnUpdateRunHoldsTheLock`,
  `TestGrantedResourceRefusedBusyBeforeGateIsNativeBusy`).

Not proven by these records:

- Graphical desktop notification: the guests are headless. The notify helper is
  covered only by a real private `dbus-daemon` session test.
- A window ending during a running transaction, and DST on a real clock (unit
  tests only).
- Block-inhibitor deferral of the scheduled reboot.
- Physical hardware.
- Debian, AlmaLinux, Rocky and derivatives, which the registry gates.
- L07/P09 beyond one host's policy: package exclusions, advisory rings and canary
  pause, server availability budgets and release upgrades are not implemented by
  `os.update.v1`; the policy has no fields for them.

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

| Deployment                                                | Mandatory coverage                                                                                                                                           | Observed status                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native server package/systemd                             | L01 installation/permissions/restart; L14 migration/upgrade/backup/restore/rotation; L16 complete isolated install/upgrade/restore; single-host L18 capacity | Ubuntu24 x86_64 signed install, explicit migration, LOCAL bootstrap, TLS/401, confinement, restart, same-schema upgrade, backup/destroy/restore and retained-data purge passed; rotation/stale-restore/Ubuntu26/air-gap/capacity remain                                                                                         |
| OCI/Docker Compose single host                            | Same L01/L14/L16/single-host L18, with container volume ownership and image rollback independently observed                                                  | Docker 29.5.0 / Compose 5.1.3 boot, explicit migration, TLS and confinement passed; rollback/restore/capacity/rotation gates remain                                                                                                                                                                                             |
| Replicated API/workers + HA PostgreSQL + shared artifacts | L14 rolling upgrade/restore fences; L16 isolated HA topology; replicated L18 load/failover/queue fencing and artifact availability                           | Maintained `lab ha` passed 2026-10-11: replica crash mid-dispatch, synchronous-standby promotion and 0.1.0→0.1.1 rolling upgrade with zero duplicate or lost actions and single-leader jobs. Shared artifacts, worker-only processes, partitions, restore, replicated L18 load and 100k remain open                             |
| Built-in assistance relay                                 | Local TURN and no-relay/direct variants, certificate/credential rotation and bandwidth limits; L09/L12/L16 consent/termination/relay-only behavior           | Embedded relay-only TURN in `lindmd`: single-host relayed consent/view/control/termination passed on emulated Ubuntu24 and Fedora44 GNOME/Wayland ([remote assistance](#built-in-graphical-remote-assistance-l09-l12)); relay rotation, bandwidth limits, multi-host/NAT, TLS-TURN, replicated and air-gapped L16 not qualified |

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

`lab ha` (see [security/operations](security-and-operations.md#replicated-failover-laboratory))
is the maintained replicated-topology lane: two `lindmd` replicas behind pinned
HAProxy, a synchronous streaming PostgreSQL standby, simulated real-protocol
devices and a continuous accepted-work stream. It crashes a replica while
restarts are executing, promotes the standby, rolls N→N+1, then reconciles every
device effect journal with admin acceptance and server records. Evidence:
`artifacts/ha-failover-20261011.json`, SHA-256
`2e08c0ca74a23d7e7bc77a403b7b03cd68868d507bcab5e1df4b4d80d818390d`, passed: 279/279
accepted restarts and 24/24 assignments executed exactly once, 0 duplicates, 0
admin rejections, standby writable 384 ms after primary loss, both replicas on
0.1.1. The same lane against unchanged checkpoint `a98feef`
(`artifacts/ha-failover-baseline-a98feef-20261011.json`, SHA-256
`faf1ccf116a3d2a5f976fc5a7688a1eedd54dbc1e6a6a5450b44136fc7e6afd8`) failed: both
replicas exited on `integrations: delivery store unavailable` at primary loss.
Real-PostgreSQL `go test -race -tags=integration ./internal/jobs` covers single
leadership, takeover after a terminated coordination session, prompt handover on
shutdown, failure release and replicated restart. This is co-located laboratory
evidence with simulated device effects, not replicated capacity, a network-partition
or fencing proof, native-agent failover or physical multi-host HA.

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
`LINDM_TEST_DATABASE_URL_FILE` and isolated real Postgres schemas. It qualifies connector
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
The later [native KVM encryption and TPM record](#ubuntu-2404-aarch64-encryption-and-tpm)
qualifies a separate Ubuntu aarch64 tuple without rewriting this TCG failure.

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
uses real PostgreSQL isolated schemas through `LINDM_TEST_DATABASE_URL_FILE`, never the
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
using isolated `testdb` schemas and `LINDM_TEST_DATABASE_URL_FILE`. It exercises
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

Full Ubuntu OSV publication was measured separately on 2026-10-10 using the
maintained refresh command and owned demo database:
[`ubuntu-advisory-stream-cve2048-20261010.json`](../artifacts/ubuntu-advisory-stream-cve2048-20261010.json)
records 2,157,314 unique claims, four rejected malformed MinIO source records,
213.69-second atomic publication and 102,068 KiB peak RSS without swaps.
The six legitimate kernel notices formerly exceeding a 1,000-CVE bound now pass
the 2,048-CVE schema; the largest real USN fixture preserves all 1,416 CVEs.
This evidence is source publication, not authenticated console exposure or native
remediation. Current device findings and the new rejection-status UI remain
separate owner-session/restart gates. See [Ubuntu feed limits and evidence](platforms/ubuntu.md#advisory-feeds).
Durable generation cleanup is covered by isolated PostgreSQL cancellation,
concurrency, active-generation and expired-writer regressions; its forward
migration is not yet applied to the running demo.

Full RHEL 9 CSAF/VEX publication was measured on 2026-10-10 with the opt-in
`TestLiveRHEL9SignedArchivePublication` against both genuine signed 2026-10-04
archives, publishing through the production service into an isolated `testdb`
schema of the development database (never the demo): 1,892,833 unique of
1,894,410 emitted claims, one rejected source document (`CVE-2023-44487`'s
invalid `nginx:1.24` RPM name), 7 min 28 s refresh and 236,744 KiB peak RSS
without swaps under the progress watchdog (no fixed short deadline). Logs and
SHA-256 values are in [RHEL advisory feeds](platforms/rhel.md#advisory-feeds).
This is source publication only, not device findings, console exposure or
subscription entitlement evidence; coverage remains reported as partial.

## 3. Acceptance scenario families

Each family maps to product requirement IDs. Individual deterministic tests must
assert externally meaningful results, not merely process existence or successful RPC.

| ID                               | Scenarios and required result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Evidence surface                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L01                              | Fresh single-host server installation, first-owner binding, restart and invalid configuration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Actual installer/console/CLI; same pinned owner bootstrap is idempotent, replacement owner denied; persisted state recovered                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| L02                              | Real Keycloak/Entra/Okta/Google and SAML broker login, MFA/step-up, SCIM correlation, upstream disable/group removal during direct and brokered sessions without re-login, healthy broker with stale upstream, source outage, rename/recycled email                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Original-directory propagation and local enforcement measured separately; no freshness reset from broker imports, stale-claim resurrection, source ambiguity or permissions beyond bound                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| L03                              | Package enrollment, lost secret-issuance response, redaction/hash-only persistence, grant race, lost cert response, TPM/software key, renewal/revocation, cloned image and reinstall                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Retry never recovers a bearer secret or creates a second credential; distinct device generation, correct denial and no secret in database/audit/outbox                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| L04                              | Native hardware/OS/package collection, absent serial, package epochs, pagination/filters, delta duplicate/out-of-order ingestion, stale/offline device                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Guest truth compared with API/export; stale evidence never compliant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| L05                              | Profile preview/conflict/drift, trust bootstrap and quorum rotation, tampered/stale trust and plans, missing/corrupt executor journal, compromised network-process replay and restart during apply                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Actual state/revision, root-only replay fences and fail-closed recovery; unknown capability or trust never becomes privileged execution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| L06                              | Native package/image/generation and repository transactions, invalid signatures, dependencies/locks/interruption, device/person catalog entitlements and UID/account reuse                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Native package database or booted generation and application health; no partial Arch upgrade, mutable-image overwrite, unapproved source or cross-person install                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| L07                              | Patch/advisory rings, canary pause, maintenance window/DST, desktop deferral/deadline, server availability budget, kernel update and reboot inhibitor                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | New boot/kernel and workload health, not just agent reconnect; no reboot outside policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| L08                              | Agent install/upgrade/failed-upgrade recovery, purge/reinstall, journal migration, owner-safe config removal, supported OS upgrade or reinstall migration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Package/service/filesystem state and preserved/rotated identities as specified                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| L09                              | GNOME/KDE sessions, built-in support consent/indicator/local stop/input, self-service/notices, Wayland/X11 as claimed, UID reuse/shared-device/ownership transfer, suspend/resume and accessibility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Actual session evidence and isolated person binding; lock/logout/revocation terminates support; no tray or unattended-control dependency                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| L10                              | Network rollback, EAP-TLS/VPN, firewall, certificates/trust/SSSD, account controls, encryption escrow and person-certificate binding/deprovisioning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Real credential/network behavior and cold-boot recovery; no cross-person secret or competing native owner                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| L11                              | Compliance pass/fail/error/unknown/N/A, expiring exceptions, SCAP tailoring/content, distro backports/epochs, stale or conflicting advisories                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Native findings linked to content/version/freshness; no false healthy status                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| L12                              | CLI/UI parity, idempotency, webhooks retry/signature/dedup, export access, typed diagnostics, bounded scripts and consent-controlled remote support                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Receiver/user-visible outcomes, consent termination, redacted support bundle and action audit                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| L13                              | Approval separation, changed targets/authority, executor challenge replay/expiry/restart, restore epoch and actual lock/quarantine effects                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | No high-risk start without a fresh verified one-use grant; the bounded residual authorization window is measured                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| L14                              | Migration under traffic, DB/worker crash, both server installation modes, restore hold/epoch, revoked identity, key rotation/loss, audit/retention                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Usable restored system with fresh authority; no stale destructive replay or revived directory access                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| L15                              | Real TPM/Secure Boot/recovery, lock boundaries, authenticated recovery-media handoff, wrong target/expiry/power loss, off-target state, sanitize/reinstall and key-copy implications                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Physical signed evidence and separate verification/validation; lost state/report stays unknown rather than restarting wipe                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| L16                              | Full isolated management LAN with public egress blocked, local IdP/DNS/time/PKI, signed content import, expiry/replay/corruption and missed key rotation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Network capture/deny counters and successful offline lifecycle; no disabled integrity checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| L17                              | Cross-version contracts, generated code and two-clean-builder unsigned release-payload digest equality, TUF/freeze/rollback, native package/image trust, provenance/SBOM/licenses                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Both build manifests and comparisons plus actual installed release artifacts; signatures/attestations verified separately from deterministic payload equality                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| L17 release archive matrix       | Passed two isolated clean source/HOME/Go/npm cache builds of all three products × amd64/arm64 × DEB/RPM, plus server/CLI OCI; complete unsigned archive equality and separate native/DSSE verification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `artifacts/release-matrix-20261011.json` SHA-256 `dd92786edd9b97e2f8289b9d921ecb23c33edbdf42c5369199f8952117f8f668`; adjacent DSSE `270e32716f2e17609dd8abb73ebcfa1b34d764236606c08aa424ba1dbf9fde08`. Export includes dependency SBOMs, provenance and explicitly pinned OCI CA bytes. Development keys/CA, same host/toolchain; does not qualify native update transactions, independent builders, license approval or physical hardware.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| L08/L17 unattended native update | **Ubuntu24, Fedora44, RHEL 9.8 x86_64 and RHEL 10.2 x86_64 passed.** All prove six signed negative/hold phases, actual interrupted native unpack, boot-helper completion at 0.2.0, retained identity, fresh authenticated session/inventory and signed downgrade refusal. Fedora and RHEL SELinux remained enforcing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Under `~/.cache/lindm-updatequal-20261010/`: `ubuntu24-updates-05.json` SHA-256 `7716aa65b6d846dd935f2b087fa7a019563d33f124efda2e39ee81adc5da860c`; `fedora44-updates-06.json` SHA-256 `ae15ffd9663b050455c4e46a313038dd3dfaf7f88320d231908c0a665b0841e6`. Under `~/.cache/lindm-rhel-updates/`: `rhel98-updates-01.json` SHA-256 `3ec7e4fb8bba93205465e51d99756051c286958c28297fcd401903c9a132bbf4`; `rhel102-updates-01.json` SHA-256 `1b72058a9448d4dd960d71b26e755b4f463b1f9e02c5f5e27722592d3179365e` ([details](#rhel-encrypted-device-actions-and-self-update)). Distinct version stamps from one source per run, development signing custody and native QEMU resets; not historical-release, physical-power-loss or production-custody certification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| L16 offline bundle (2026-10-11)  | **Ubuntu24 amd64 and Fedora44 x86_64 passed `lab vm airgap`.** Each site server, its dedicated PostgreSQL, the QEMU guest and the lane shared a Docker `none` namespace (loopback only; no IPv4 routes, no non-`lo` IPv6 default; public IPv4/IPv6 `network is unreachable`, DNS refused); the restricted-slirp guest also failed public DNS/TCP. Bundle 1 (0.30.0) initialized the empty site before `serve`; the guest installed the agent only from `/offline/repositories` with the pinned station key, enrolled and held at the paused imported channel. Identical resubmission was a no-op; expired, same-size repository byte change, unsigned manifest edit and never-imported older sequence were rejected as `offline_bundle_expired`, `offline_bundle_corrupt`, signed-payload mismatch and `offline_bundle_replayed`. Bundle 3 (0.30.1) resumed its admitted sequence, staged targets v3 paused, advanced device findings to its signed acquisition time and, after audited `SetRollout`, the agent installed 0.30.1 with identity preserved and a fresh session. Fedora stayed SELinux Enforcing. | Under `~/.cache/lindm-airgap-20261011/`: `records/ubuntu-24.04-r2.json` SHA-256 `14773263f4ea519b5cc74d2c3eff6a78e530998a7c010c35d8041f126e8523a1`; `records/fedora-44-r1.json` SHA-256 `f7aa073c11240b3ba93cd069a36c1e114c4474576a855f107da508264a175f38` (`records/ubuntu-24.04-r1.json` `326ee77fb1c2c4a85d41e8e627e41ae37e2ff4d277b4d58ea650b8e629dded7a` passed before rejection reasons were recorded). `bundle.json` SHA-256: `b1` `271aef0883aef0122e01d1306f9dd9108cbba63da5ca5c1a4274d229c944b095`, `b2-replay` `ab3f7d2148e4d0bfcd7e5b8cd44f0b3f6b1ac4256c71d6b2de162cc2dfcdd18d`, `b3` `eba582965daebd5dc23a1b9dc64d94cb907e5bc84413515d4d7e606139f4f888`, `b5-expired` `083a69e67dd39702aee116aa5ee3331f5c4e9568d9bf63f43a11a6c840fd8e66`; `release.json` 0.30.0 `4ea6dbdbcc510ccf430fbbc6ae6b4f8257eae0602ba01f5117fe99549cf3d1a2`, 0.30.1 `877b84891ece386d495916b837761e07ec6ef24ae36abbfd15db2b72b5cfb07d`; site lindmd `e15e068ba0601dcfe3284fbba279586c52457738ff4cfb839f11a2c79cb0960a`. Development custody for package, attestation, TUF and bundle keys; local accounts; prebuilt site lindmd, not an install from the bundle's server packages; amd64 guests only (arm64 repositories built, not exercised); no site DNS/NTP/IdP topology, OCI image import, backup/restore or physical hardware. Ubuntu findings reached the lane's 20,000-row read bound (`truncated`). |
| L18                              | Single-host and replicated load/soak, reconnect storm, storage full, queue fairness and worker/DB failover                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Workload manifest and measured budgets from security/operations; accepted work preserved                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| L18 single-host launch gate      | Maintained `lab load`: real lindmd/disposable PostgreSQL, grants/mTLS, jittered sync/trust/work, full snapshots, signed service cycles; explicit CPU/pool/storage and iostat/QEMU evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Durable co-resident baselines and WAL-pressure failures are documented in security/operations. `artifacts/load-isolated-tmpfs.json` (SHA-256 `8efe8ec08315276197d527618050035deeb4b0147215195ce991ab4fd1e7c193`) passes only the completed non-durable 5,000-device plateau; 10,000 interrupted by parent scheduling directive. Dedicated tmpfs and NVMe fixture integration passes, not capacity qualification. Isolated durable ramp, two-hour soak and HA remain open.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

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
first transport error. Read-only status observers now reconnect with the
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
At that stage local starts were suspended under the owner's two-guest priority
cap, so the underlying APT error and native recovery paths were still unproven.
The subsequent instrumented runs below supersede that historical limitation.

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

After local slots reopened, instrumented Ubuntu run
`$HOME/.cache/lindm-updatequal-20261010/ubuntu24-updates-03.json` (SHA-256
`67136205668557c98ecef9d20f187a3108b4b47076ee4e701e22ec7e1ca25b1a`)
exposed a separate laboratory freshness race before reaching APT. The claimed
zero-percent observation finished at `10:52:13Z`, before initial inventory finished
at `10:52:14Z` and therefore before rollout mutation. Comparing only against the
older paused observation accepted a pre-mutation cycle; the replayed timestamp
had not been superseded at the guest. Healthy repeated `no_update` cycles then
continued until the rejection-oracle deadline, without SSH transport loss.
Independent diagnostic `lindm-cloud-init-112541792.json` (SHA-256
`0b88b9b7a96adb77d7dcc8e0d0aaefe74b5f6420ebbccff5ce63e618d42b8502`)
also identifies guest APT as `2.8.3`. The observer now fences on its first
post-mutation observation and requires a newer cycle start, rejecting both cached
and in-flight pre-mutation cycles. Focused encrypted-SSH race regressions passed,
including that boundary, before rebuilding the maintained lane. This run does not
claim a product rollback failure or a new native package failure.

The cycle-fenced Ubuntu run `ubuntu24-updates-04.json` (same evidence directory,
SHA-256 `9f6211d128eebbca6d5a504b547dfb262d97de25ada73ed215681519d208a5f8`)
passed all six signed negative phases and immediately exposed the actual native
APT `apply` error: `Internal Error, Pathname to install is not absolute
'lindm-agent_0.2.0_amd64.deb'` (exit 100). Bounded diagnostics retained that message
instead of a later SSH timeout. Diagnostic record `lindm-cloud-init-3380301119.json`
has SHA-256 `89b1093225038f6ae97ec93bad37379b4ce1777024945ab8af768cf2b259231a`.

APT `2.8.3` is observed in this guest. Its matching upstream tag is cloned read-only
at `~/dev/minor/clones/linux-flavour/apt-2.8.3`, commit
`01e6768bc131a5c50d3a705d00ff462395f9828e`.
[`apt-pkg/acquire-item.cc:3464–3506`](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-pkg/acquire-item.cc#L3464)
derives the canonical package/version/architecture archive basename and resolves
an existing private-cache file to its absolute pathname.
[`apt-private/private-install.cc:183–208`](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-private/private-install.cc#L183)
removes pending acquisition under `--no-download`. Our protected `agent.deb` lay
outside an empty separate `apt-cache`, leaving that install pathname unresolved.
Staging now writes the verified DEB directly under APT's canonical filename and
uses that same private transaction directory as its archive cache. No download,
source, no-remove, package-ownership, signature or network-isolation gate changed;
no copy, hardlink or symlink was added. Epoch/filename and retention regressions
passed. A real APT/dpkg integration regression also installed a script-free
epoch-version package into a disposable private root with no host package state,
hooks, cache or configured network sources, then checked native configured state,
payload bytes and retained archive. That fixture pass is not a guest self-update
or reboot-recovery qualification.

Ubuntu24 native qualification now **passes**:
`$HOME/.cache/lindm-updatequal-20261010/ubuntu24-updates-05.json`, SHA-256
`7716aa65b6d846dd935f2b087fa7a019563d33f124efda2e39ee81adc5da860c`.
The source snapshot is
`689714fe737b6cef2a8c2164f708f40dd40c93f05ee42c129b87521b060602f5`.
All six signed negative/hold phases passed, followed by actual unpack witness
`apt-get pid=7429 unpack=/usr/libexec/lindm/lindm-agent.dpkg-new bytes=39203473`,
owned QMP reset, boot-ID change
`98531dac-cdaf-440e-a2c8-8721fe4463c6` →
`5b325330-8188-450d-844b-746f11fbfdd0`, and exact `0.2.0` native helper recovery.
Device/enrollment identity was retained, authenticated session epoch advanced
`1 → 2`, fresh inventory sequence advanced `1 → 3` with 665 packages, and a fresh
signed downgrade catalog could not replace the installed agent. The lane completed
with `outcome: passed`, including owned resource cleanup. This is native KVM
guest evidence for distinct version stamps from one source snapshot, not historical
release compatibility, independent production custody or physical power-loss proof.

Fedora44 `fedora44-updates-02.json` (same evidence directory, SHA-256
`c79763559153ab4800185c840bca822170977e3f32026af49f8f1c78860c1940`) passed
all six signed negative phases under enforcing SELinux. Its next failure was a
lab observer race, not an observed DNF rejection: the unpack script statted RPM's
temporary file twice and the second read followed its atomic rename. Private
diagnostic `lindm-cloud-init-552405339.json` (SHA-256
`ebc0bf372b421b277668833f7f3561fff010fc5d9f8b89ca82e4fe03b456e05b`)
retains partial witness `dnf pid=6928 unpack=` and the actual `stat` ENOENT for
`/usr/libexec/lindm/lindm-agent;6aca1fa5`. The intermediate fix took one final
file-size snapshot after matching the real update-helper process; a vanished path
meant no witness, while other inspection errors remained visible. Deterministic
real-process/filesystem regression covered both boundaries. Later Fedora runs
below replace the sampled shell observer with a resident frozen-unpack witness.

Fedora03 (`fedora44-updates-03.json`, SHA-256
`e3024604058657bdb714a85b2f3da94f270f2fae6188398edbf3e4f3f9782fb5`) retained
all six negative phases but exposed a lab-induced service-start limit failure.
The four negative-fixture stop/start cycles consumed the network unit's
60-second/five-start budget before RPM's legitimate upgrade restart. Its journal
reports `Start request repeated too quickly` followed by native DNF apply exit 1,
not a still-running package-manager hang. Diagnostic
`lindm-cloud-init-3885517560.json` has SHA-256
`8cb7c5fa4af12bd819611c63e9814d5b5360063c22b5c5ef5331e1d029899c72`.
The lab now freezes/thaws that cgroup while publishing fault fixtures, leaving
product start-limit settings intact. This run also exposed a diagnostic gap after
executor replacement: with the network process failed, no transport poll triggered
helper reconciliation, so cached root status remained `applying`. Read-only status
now validates and projects durable helper failures without waiting for transport;
it cannot launch recovery, mutate authority or promote a helper success marker.
Focused race regressions cover disconnected failure projection, caller mutation,
invalid helper state and retained destructive-action interlocks.

Fedora04 (`fedora44-updates-04.json`, SHA-256
`edc0c931a96c073d127bda717b8b9ac1b44c7cc0c146660025a93c96f62c795d`) then
completed the native upgrade at `0.2.0` under enforcing SELinux, with no start-limit
failure. It correctly did **not** pass interruption qualification: SSH polling
missed RPM's short-lived temporary executable, so the observer returned the actual
`installed` state instead of inventing a reset witness. Diagnostic
`lindm-cloud-init-3522143806.json` has SHA-256
`cef32402c8390814f0052f3268a43b0ebc934aceddd3ab45284ed85f177a9fe1`.
The maintained lane now uses a resident inotify probe and freezes only the exact
admitted update-helper cgroup after a real partial write, rechecking the native
manager and nonempty regular file while the kernel reports `frozen 1`. Only then
does the host reset the owned guest. Ambiguous SSH loss never replays this fault
injection. Real-file rename/error and no-cgroup boundary tests, terminal-state
tests and the encrypted-SSH nonreplay regression passed before native execution.

The first resident-observer run, Fedora05, also completed the actual installation
without a frozen witness; `fedora44-updates-05.json` has SHA-256
`a39349985b8f0180b17817bc045521c04639d0be6e0a21d92bcc7f4924e42a06`.
Its diagnostic `lindm-cloud-init-3627174350.json` has SHA-256
`a502cbd46858ca5edbb9334c40fd6e1075d6dbfc8b17a8ed5555eb5d72cc311f`.
That observer assumed a cgroup path and did not retain why no witness was obtained;
wrong binding versus a missed write cannot be retrospectively distinguished.
The maintained probe now resolves systemd's actual `ControlGroup` for the exact
root-admitted transaction unit, validates the binding, and reports absent cgroups
or missing native managers rather than silently losing those observations.

Fedora44 native qualification **passes** in `fedora44-updates-06.json`, SHA-256
`ae15ffd9663b050455c4e46a313038dd3dfaf7f88320d231908c0a665b0841e6`.
Source snapshot SHA-256 is
`cf4a847f9417b857bad33b508a306d9bfc5a6bc69ca1fd071abe05680be0eded`;
lab binary SHA-256 is
`e75230ba8e43887221f1117cc2c40d208429e0064b77d30a854cb1662d4c0973`.
All six signed negative/hold phases passed under enforcing SELinux. The actual
kernel-frozen witness was `dnf pid=6707`, partial native executable
`/usr/libexec/lindm/lindm-agent;6aca29cf`, 35,356,672 bytes, in the admitted
`lindm-agent-update-b0606305-7744-4b76-a318-d3e47b47aab6.service` cgroup.
After owned QMP reset, boot ID changed from
`42d7b0d9-4e3f-4889-9093-85a9c4b484f4` to
`ac07a65d-034d-4968-95b1-0ed8fde33319`; the boot helper completed exact `0.2.0`.
Device/enrollment identity remained unchanged, session epoch advanced `1 → 3`,
fresh 429-package inventory advanced sequence `1 → 2`, and a fresh signed catalog
could not downgrade the installed agent. The 444.6-second lane passed including
cleanup. These records qualify the observed native QEMU tuples, not historical
release combinations, physical storage power-loss behavior or independent
production signing custody.

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

WWN-less encrypted GPT storage has an explicit signed `SERIAL_GPT_LUKS` basis.
Regression coverage includes virtio-blk selection, duplicate physical-disk serial
refusal even with differing GUIDs, changed/absent basis, WWN appearance or
disappearance, changed disk/container size, changed GPT/LUKS identity, unreadable
WWN evidence and pinned GPT header integrity. `WWN_SERIAL` remains preferred.
The native NVMe sanitize basis and authenticated `GetRecoveryTime` checks remain
independent; this encrypted-partition fallback grants neither sanitize authority
nor an exception to recovery-time validation. Selectability is not proof of an
encryption mutation, crypto-erasure, TPM binding or recovery qualification.
Focused race suites passed for actionprovider, inventory, executor, recovery,
recoveryboot, recoverycustody, device, trust and vmlab. Real-PostgreSQL race
selection `Test(ListDeviceStorageTargets|StorageAction|DeviceActionRecovery|RecoveryReadiness)`
passed, including API selectability and create/start basis-change refusal.
Buf lint, web typecheck and affected console ESLint passed.
The independent VM oracle now reads native pairs `PTTYPE`/`PTUUID`, initializes
GPT availability for every identity and inherits only a backing disk's GUID;
its focused storage-identity race regressions also passed.

Read-only baseline for enrolled Ubuntu 24.04 demo
`df29accb-d575-45a0-9c1e-0a1cab8f2cdc` retains native `lsblk -b -J -O` at
`/home/r/work/lindm-lab/console-encrypted-ubuntu-20261010/lsblk-native-baseline.json`.
Its virtio-blk disk has serial `lindm-demo-encrypted`, no WWN, size
25,769,803,776 bytes and GPT GUID `616f7698-4a4a-4c6c-8543-fc47d344c677`.
The LUKS partition is 22,493,003,776 bytes with UUID
`f393f8b5-f6bf-41a0-81fd-736cf10b6d9d`. This baseline is not a post-upgrade
selectability pass: that requires the coordinated signed-APT agent upgrade and
new server projection after the owner-approved bundled console restart. No
storage mutation is authorized by this read-only qualification.
Adjacent `native-sysfs-identity-baseline.json` independently confirms the disk's
block-level serial, absent WWID/device-WWID attributes and the partition's exact
kernel parent on `virtio2/block/vda`. No raw LUKS header was read for this check.
The integrated agent `0.1.2` package (including the transient read-only inventory
helper) is prepared under
`/home/r/.cache/lindm-targetidentity-package-20261010/`. DEB SHA-256:
`3585719b1c96949187d2a6c76e95977d781f528aeb44fad3e4e9e31e3daaebbf`;
agent payload SHA-256:
`f26caf943f5ceff7607c11aab0f75ccc411ae2ba325001c7c98791ed0a4d6ff2`.
`package-build.json` and `apt-publish.json` retain native build and repository
checks. Signed `InRelease` and package-index verification passed; an independent
`gpgv` check using the previously trusted demo key also passed with fingerprint
`F631DCC0574F0A49D747C00BAF987756B5A392C0`. This is prepared package evidence,
not an installed-upgrade or real-VM selectability claim.

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

The same lane **passed on Fedora 44** (encrypted GNOME golden
`fedora-server-encrypted-44-1.7-x86-64`, x86_64 KVM, OVMF `2024.02-2ubuntu0.10`
Secure Boot enforced, swtpm 0.7.3, virtio-scsi) with no product change:
`$HOME/.cache/lindm-fedoragaps-20261011/fedora44-lock-quarantine-01.json`,
SHA-256 `50985538321bb481f9baa94dbc9864564a204116ddf3e7494a89d350443428da`,
in 438 seconds. It proves the same lock, release, account-lock/expiry restore,
administrator-edit preservation, two quarantine/release cycles, timer expiry with
agent and executor stopped, and offline-start refusal on a real
`gdm-autologin` Wayland session. Lab and server SHA-256 are in the record;
agent package SHA-256
`6a787ce03842494d10f8f53662bdfcfed0388f74805390241e0eadf757e345b4`.

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
Those historical runs used a minimal recovery image with RTC time but no
authenticated clock bootstrap.
Future-issued proofs are rejected even inside their30s lifetime; a signed
checkpoint stored after the local clock is also rejected. No acceptance window
was widened and no unauthenticated time source was introduced.
SATA15 reproduces the same strict future-issued-proof failure as NVMe17.
Console `lindm-cloud-init-2867842716.json` has SHA-256
`f7ae0b99bedb7f5d3c45094d71342fbc5cfbfd1c447d222dfe3a8898a0c13130`;
root probe `lindm-cloud-init-3515380366.json` has SHA-256
`6970d94b80bb0fb76286b600d4144c1c069510c9e9c338857ef7489bf9f69585`.
Both historical recovery attempts have zero host swap-out delta and over50GiB
available memory. Their retained authenticated refusals—not the later lab wait
timeout—are the product diagnosis that motivated the authenticated-time work below.

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

Authenticated recovery-time continuation uses committed checkpoint
`d303cecb69bc041328438538a2e3bbf084ac06fb`, which includes the landed WipeQual3
changes above, plus private
`$HOME/.cache/lindm-recovery-time-20261010/recovery-time-source-d303cec-03.patch`
(SHA-256 `f578eaa6dfd6a99eaf85c95158e4d572f96dced9f2ac54549db455417b5631b7`).
Its adjacent JSON binds all changed sources and embedded-console inputs.
Stamped `lab-recovery-time` has SHA-256
`90a9efebc3fa8cb028f54de2e7576bf73ffed049e6d419eec8ab9af454a9be4d`;
`lindmd-recovery-time` has SHA-256
`b961ea969d43d73fcd3b0708b423e1e2142ab1248e019a9c921bf0c8f206bc92`.
No fixture, signing key or credential was copied into the private worktree.

The affected trust, recovery, transport, agent-command and device unit/race suites
passed, as did the real-PostgreSQL `TestRecoveryTime` and `TestDeviceActionRecovery`
integration/race selection, focused Buf lint, affected Go vet and stamped
whole-tree builds. Regressions cover replay/wrong nonce/request/boot/key/domain,
RTC skew decades in both directions without changing the host clock, full
round-trip uncertainty, expiry equality, monotonic rollback, HTTP/1.1 and HTTP/2
keepalive certificate revalidation, and unchanged/current trust delivery.
Independent review found and corrected learned-authority rollback and expiry
during final signature verification. Added regressions authenticate a newer
delegation before rejecting stale acquired trust, retain the same floor across
snapshot restoration, reject a higher-version root fork around the learned root,
and refuse expiry/suspend during the final post-checkpoint verification.
The corrected recovery race suite passed. These are protocol/runtime proofs,
not native sanitize or physical-media certification.

The first maintained WipeQual3 runner and handoff-command reruns covered
SATA and NVMe on Ubuntu 24.04 and Fedora 44, retaining every record beneath
`$HOME/.cache/lindm-recovery-time-20261010`. **None of these first four is a sanitize pass.**

| Native record                    | SHA-256                                                            | Retained outcome                                                                                                                                                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu-recovery-sata-01.json`   | `c1709f245ea60ce65aa7c0b1338f64aeda62758d493022242e65acdaf71156e3` | Fresh readiness accepts the 38,763,576-byte signed image, two humans approve, and original-device signed recovery boots. The server receives FAILED/PRECONDITION; the recovery console reports `device_action_precondition: target_identity_ambiguous` before a destructive start. |
| `ubuntu-recovery-nvme-01.json`   | `08b5a4a4ce09377ce1c1a77fb536df7653573466afbc4e006fc45ed9cc3a40d1` | The 39,508,024-byte signed image fits; native controller-serial/NSID identity, two-human approval and original-device handoff are retained. The server receives FAILED/PRECONDITION and the console reports the same `target_identity_ambiguous` pre-effect refusal.               |
| `fedora44-recovery-sata-01.json` | `cf62060f3e0012971dc521b1fde552325ced2476afbc8e8966be2dd823120999` | Signed refresh succeeds, then readiness refuses `device_action_esp_insufficient`: signed image 43,543,608 bytes, allocation-rounded requirement 43,544,576, vendor ESP available 14,888,960. No wipe approval/action is requested.                                                 |
| `fedora44-recovery-nvme-01.json` | `ce875a08d39cde14f6fef056dd67b7aa1f737d800054ba7fab5910f2afdcf512` | Signed refresh succeeds, then readiness refuses `device_action_esp_insufficient`: signed image 46,145,592 bytes, allocation-rounded requirement 46,147,584, vendor ESP available 14,888,960. No wipe approval/action is requested.                                                 |

For both Ubuntu runs, `actionprovider.openTarget` reaches its existing exact
WWN/serial/size matching guard and rejects because the native `lsblk` tree does
not provide exactly one matching node. The retained console does not distinguish
zero matches from multiple matches, so no narrower topology cause is claimed.
**[INFERENCE]** Reaching that native observation and authenticated failed result
means the mandatory signed-time bootstrap, scoped work acquisition and signed
BOOTED checkpoint completed; the prior `recovery_request_clock_ahead` is no longer
the reached blocker. No identity predicate was weakened to proceed.

Protected diagnostics were copied alongside the records, retaining mode 0600:

| Diagnostic                                                | SHA-256                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------ |
| Ubuntu SATA console `lindm-cloud-init-3413425091.json`    | `20397fae90e1f8252641af940b20650a7085e0368e2b39411ddd03b02bea1dd0` |
| Ubuntu SATA root probe `lindm-cloud-init-3597847071.json` | `9daa582ee767042c6e25ba2ddfcf9611ca8fe47245ee49772da72644a53523e9` |
| Ubuntu NVMe console `lindm-cloud-init-2616327059.json`    | `04492b06f65e3aef8b4778362cacffcb369d1dc4e84eed76e089120b7d921028` |
| Ubuntu NVMe root probe `lindm-cloud-init-3812067693.json` | `f05cb50f641aae4279a967e7ee93ce11dc48488f21c227a60ec5f5d415732a91` |
| Fedora SATA readiness `lindm-cloud-init-1152846659.json`  | `2586e76de60446b30d351b6b114823466a6ccb3730688b600e08669d85d14074` |
| Fedora NVMe readiness `lindm-cloud-init-3600537708.json`  | `a55220005a5ba294f6eea68c7fdc61b13ea6b223820cafcafc88fe4e7bc80c26` |

`retained-diagnoses.json` has SHA-256
`f1d98eba5cb2b4ace6dfbdfa2a18651a6801dc5dbe4d754d68ab15b6530a584f`.
All four runs used at most two local guests, recorded zero swap-out delta and at
least 56,834,268 KiB available memory at their retained host samples. All guests
exited; final `pgrep -c qemu-system` returned 0. The Fedora vendor ESP was not
enlarged, no validity window was extended, and no unauthenticated time source or
fallback sanitize method was introduced. The subsequent identity investigation
and explicit capacity-gate decision are recorded below.

The original resolver was then captured without changing its matching predicate.
The immutable diagnostic delta
`recovery-identity-diagnostic-delta.patch` has SHA-256
`f8924b9626d5a06dab2d25a26b5bc32a8392e7b5ec6302e8b98ed0421b85c101`;
`recovery-identity-diagnostic-source.json` binds it to source03 and the same runner
and has SHA-256
`20e9375ec942ee7b9fea607e4bc78da415fca90ce301dbe9ae2a747d0c3cd41b`.
Both actual recovery consoles reported seven candidates and **zero matches**,
not duplicate identities. The minimal initramfs has no populated udev database:
`lsblk` reports no WWN; SATA also has no serial, while NVMe exposes its
space-padded raw serial. Native sysfs still reports the exact approved identities.
SATA `/dev/sda` (`8:0`) has `device/wwid=naa.5000000000000001` and VPD page80
serial `lindm-lab-0`; the approval is `0x5000000000000001`,
`lindm-lab-0`, 3,758,096,384 bytes. NVMe's original target renumbered to
`/dev/nvme1n1` (`259:0`), with the exact approved namespace WWID
`nvme.1b36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001`
and `device/serial=lindm-lab-0`, again 3,758,096,384 bytes.
The off-target state disk has a different WWN, `lindm-lab-1` serial and
1,073,741,824-byte size; the identity-less seed is only 374,784 bytes. Neither
the seed nor an ESP partition matched the approved tuple.

| Retained diagnostic record or complete approved/candidate list | SHA-256                                                            |
| -------------------------------------------------------------- | ------------------------------------------------------------------ |
| `ubuntu-recovery-sata-diagnostic-02.json`                      | `def75968e75bac8b857321fa29fbeb287c6e367eccef554e1bd9af1aa7c7ba25` |
| `ubuntu-sata-approved-and-candidates-02.json`                  | `8223d76b60bf0fa87c6d0a051c6e63d78bedb21aabfed78ad30b4933361e72ef` |
| SATA console `lindm-cloud-init-3749473365.json`                | `f4b65b6cedd8e76547d6ca73aea28275483fbe1b5a730b703781b223b781d005` |
| `ubuntu-recovery-nvme-diagnostic-02.json`                      | `b3fb401a750f020edeeb604508a93153ff4f08304365f6f9dbc45297af233d61` |
| `ubuntu-nvme-approved-and-candidates-02.json`                  | `cb6d8e7a3cf753a83c354d3f70646ca6f361639d3b7dd63603fb5eaf1c301767` |
| NVMe console `lindm-cloud-init-256824549.json`                 | `74d1d153a8edae3661f5b359bbfc01ab512a3d97ed9f4a770c2618f12d3d327e` |

The corrected resolver reads native identity through validated kernel
major:minor sysfs paths, translates only the SCSI NAA/EUI representation, and
removes only native-backed trailing serial padding. It rejects conflicting
sources and still requires exactly one complete approved WWN/serial/size tuple;
sanitize cannot select a partition. It never chooses by path, serial alone or
the approval's expected value. Descriptor size and observed native identity are
rechecked after pinning/exclusive reopen. The independent frozen NVMe identity
basis, controller, namespace and method-scope checks are unchanged.
Regressions cover the captured missing-udev tuples, padding, duplicates,
renumbering/reordered candidates, changed or conflicting identity/size, malformed
VPD80/device numbers, whole-disk scope, branch-local inheritance and identity
change after pinning.

Source05, `recovery-time-source-d303cec-05.patch`, has SHA-256
`a249b98227efdd74daf76f1fbe36c5edafbb691d708f44ac30a74abf813f66de`;
its adjacent JSON binds all sources, checks and exact embedded-console archive.
Stamped runner `lab-recovery-identity` has SHA-256
`688bb13cf5ca0623126aa808855fe1910fcb41791636002dad880d0a1cc0e7d1`,
and server `lindmd-recovery-identity` has SHA-256
`a0b8a6f580c1147fa9c58f4bc32ecb1856061daa660d62a8d1f68ee77427795e`.
Affected actionprovider/recoveryboot/vmlab race suites, Go vet, stamped
whole-tree build, console build/TypeScript check, changed-console ESLint and
changed-document Markdown lint passed. Console bundling retained third-party
`use client` directive warnings; it did not fail or bypass the checks.

**Ubuntu 24.04 original-device recovery SATA and NVMe now pass natively** with
source05 and the authenticated-time bootstrap. Each retained record proves fresh
readiness, distinct requester/approver identities, the exact signed recovery UKI
booted on the original enrolled device, unchanged target identity and protected
off-target journal, successful server-verified scoped result, closed-image
poweroff and independent read-only samples of the stopped original disk.

| Passing native record          | SHA-256                                                            | Native result                                                                                                                                                                                                                                      |
| ------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu-recovery-sata-03.json` | `fa2b24daad9e76ca8069e4b80d79e464a07dc364115ad7e50f5cb9b3516a02ee` | Exact 3,758,096,384-byte rotational-emulation overwrite completed; 257 distributed zero-read samples verified. Signed image 38,780,984 bytes; unchanged ESP available 57,928,704.                                                                  |
| `ubuntu-recovery-nvme-03.json` | `9f076e650acb606477bc0a1e9257604d90405d55ec64cc48a3b19918b9ddab94` | Native NVMe user-data format completed with unchanged basis2 controller-serial/NSID1 scope, 3,758,096,384 bytes and LBA shift9; 257 cache-invalidated samples verified, with every formerly nonzero sample changed. Signed image 39,524,920 bytes. |

The exact signed recovery-image digests are
`43f49be9a65a32c8f11c8a3e46db99c9941dc48ac6962610fe3b3a1661bc806a`
(SATA) and
`748160f9a4cf3d8b043a739c00989cd1ca7b4d617b3087ed045245ce2fb203fa`
(NVMe). Both independent stopped-disk first/middle/last 4,096-byte samples hash
to the zero-block SHA-256
`ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7`.
These are QEMU/KVM controller and software-TPM qualification results, not ATA
secure erase, inaccessible/remapped-cell proof, organizational validation or
physical-media certification. No fallback method was substituted.

**Ubuntu 24.04 original-device recovery SATA and NVMe pass again with the Go
PID 1 recovery init (2026-10-11).** The signed image's `/init` is now the static
`lindm-agent`. BusyBox, the shell scripts, `udhcpc` and the in-image `sbverify`
with its `libcrypto` closure are gone, and Authenticode is checked in-process
(see [architecture](architecture.md#recovery-image-init-and-image-verification-security-review)).
Both runs used `-secure-boot` with the pinned OVMF Secure Boot code and
Microsoft-enrolled variable template, one local guest at a time through normal
lease admission. Stamped `lab-recovery-init` has SHA-256
`a4be2441d589741256bdc7eb5e9d95c544e30f3e4fb18023686282d3e06fce6c`,
and `lindmd-recovery-init` has SHA-256
`01089767ea589cf274c50e4fecb4f1cf7d03d7e111a375756c1d87c5378a0842`.
Records are under `$HOME/.cache/lindm-recovery-init/`.

| Passing native record          | SHA-256                                                            | Native result                                                                                                                                                                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu-recovery-sata-01.json` | `37b80116bac783b49c05226635f9f98453a8386fe43f62749b7e4d003450cdbb` | Overwrite of the exact 10,737,418,240-byte target, with 257 distributed zero-read samples, server `SUCCEEDED`. Signed image 43,412,024 bytes, SHA-256 `e8e035621d7e82f28618a588ed072a94fdd9beb56db345b0f8d4c7f8c2b72d7d`; ESP available 57,928,704.                  |
| `ubuntu-recovery-nvme-01.json` | `79b3e66cdceec026da68838083c9b4bd34d8dc4e5f52f8673e95bc7ffd68a201` | NVMe user-data format with unchanged controller/namespace scope, 257 cache-invalidated samples all changed, server `SUCCEEDED`. Signed image 46,149,176 bytes, SHA-256 `2031e3e8ed42de00f0f338923b4008bf9746dec32b99037ba957b79af7e5fd22`; ESP available 57,928,704. |

Independent stopped-disk first, middle and last samples all hash to the zero
block. The signed images are larger than the 2026-10-10 records (38,780,984 and
39,524,920 bytes), but the init is not the cause. The agent ingredient grew
from 39,203,057 to 55,430,584 bytes. An agent built from the unchanged base
tree with the same flags is already 55,062,209 bytes; the init and Authenticode
verifier add only 368,323 uncompressed bytes (195,646 gzip). This change
removes BusyBox (2,124,608 bytes, 1,107,188 gzip), the two init scripts,
`sbverify` with its 5,309,400-byte `libcrypto.so.3`, and `modules.dep`. The
SATA image now contains only: the agent as `init`, the signed init parameters,
configuration, three modules, `lsblk` and its nine-entry library/loader
closure. The records' component sizes give exact per-ingredient bytes and
SHA-256.

Fedora 44 under the **owned systemd-boot UKI fixture** is a capacity-refused
cell, not a sanitize pass. Read-only libguestfs extraction of the pinned cloud
image measured its unmodified vendor kernel
`/boot/vmlinuz-6.19.10-300.fc44.x86_64` at **18,479,464 bytes**, SHA-256
`4b37e4e542a62c580c751787848be6c99e6f908f6712c8c6da85516b8d541de2`.
The kernel alone exceeds the 14,888,960 available bytes that remain after the
fixture's own ordinary signed UKI and systemd-boot are written to the 100 MiB ESP
by 3,590,504 bytes, before the stub and initramfs. **Correction (2026-10-11):**
the stock, unconverted ESP has 82,089,984 bytes free (observed by `df` in the
measured-BLS records below and by read-only `guestfish statvfs` of the pinned
image: 40,083 free 2,048-byte clusters). The earlier "stock ESP too small"
wording described the converted fixture, not the vendor ESP. Stock Fedora still
cannot use the UKI path without enrolling a deployment key; it now uses measured
BLS recovery instead (below). Its retained configuration has
SHA-256 `1c0d2e478cdc33747fb3bdd9e332677c517b5791c8cbed0454d22e6e430042d5`
and already uses `CONFIG_KERNEL_ZSTD=y`; initramfs xz and zstd are supported but
cannot reduce this separate signed-kernel lower bound.
`fedora-vendor-kernel-capacity.json`, SHA-256
`71b98e75098a7fed49322457d7b644455117122ef39d97ff2e5b1e174c598eed`,
retains the source image digest and arithmetic.
No ordinary UKI was compacted or replaced, no vendor boot file deleted,
no ESP resized, and no unqualified alternate kernel introduced.
The console shows needed/available bytes and the separately qualified on-site
external-recovery-media alternative, with its boundary documented in the
[product capability notes](product-specification.md#original-device-sanitize-capability)
and [operations](security-and-operations.md#3-dangerous-actions).

The source05 Fedora reruns retain exact per-component byte counts and SHA-256
in `recovery_size_evidence`, including every helper/library/module and the actual
signed PE section sizes. Both refuse before any sanitize approval or action;
their `passed=false` records are retained as capability-gated cells, not relabeled
as successful erasure.

| Capacity-gated native record     | SHA-256                                                            | Signed image / rounded needed / available bytes |
| -------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------- |
| `fedora44-recovery-sata-02.json` | `90d08fb2c7ac139e520bdfd0087e62081fcbb2b25031510a5eca4cf6f26ca008` | 43,558,456 / 43,558,912 / 14,888,960            |
| `fedora44-recovery-nvme-02.json` | `39ee001297527b4d1e762b5a93160956e2b75f6c0ac203dc38f29663f16420cb` | 46,164,024 / 46,166,016 / 14,888,960            |

| Measured component                                | Fedora SATA bytes | Fedora NVMe bytes |
| ------------------------------------------------- | ----------------: | ----------------: |
| Unmodified signed kernel                          |        18,479,464 |        18,479,464 |
| EFI stub input (already included in UKI overhead) |           112,128 |           112,128 |
| Actual gzip initramfs                             |        24,962,758 |        27,568,297 |
| UKI overhead, alignment and signature             |           116,234 |           116,263 |
| Agent ingredient, uncompressed                    |        39,203,057 |        39,203,057 |
| Busybox ingredient, uncompressed                  |         1,440,888 |         1,440,888 |
| Method-required helpers, uncompressed             |           189,232 |         1,837,952 |
| Helper libraries/loader, uncompressed             |        11,847,992 |        15,049,608 |
| Exact required modules, uncompressed              |         1,068,606 |         2,179,236 |
| Firmware ingredients                              |                 0 |                 0 |

Only kernel + actual compressed initramfs + UKI overhead sum to the signed-image
size; uncompressed ingredient counts cannot be added as compressed contributions.
The closure already excludes unrelated firmware and method-irrelevant helpers
and modules, retaining signed module bytes unchanged. Kernel/stub/busybox/agent
digests and configuration/script/module metadata are in each record.
Retained Fedora SATA diagnostic `lindm-cloud-init-1539785054.json` has SHA-256
`cd6854af00a58315a42f7d50a5d03b145d93950ccbc5ff412a434e0e85870c73`;
NVMe diagnostic `lindm-cloud-init-1111728939.json` has SHA-256
`eb5b7f982bca327d20847ca06d670a57f9f201249de1aa1653862bac3c4ea431`.
Final summary `recovery-time-final-native-evidence.json` has SHA-256
`35b6c07f1b11291a972e0d48dd3072d8fe94cd8f0869692f4d808a852e25a7c8`.
The four final runs used at most two local guests, retained at least
55,606,804 KiB available memory and zero swap-out delta, and left zero guests.

#### Measured GRUB recovery on stock vendor boot chains

`RECOVERY_BOOT_MODE_MEASURED_GRUB` (see
[architecture](architecture.md#measured-grub-recovery-recovery_boot_mode_measured_grub))
keeps the vendor shim+GRUB chain, the vendor ESP and the vendor-signed kernel,
and proves the unsigned lindm initramfs only by a server-verified TPM quote. The
records below predate the pre-landing rename from `MEASURED_BLS`/`measured-bls`
(the BLS flavor, unchanged on the wire number) and the move of `grub-editenv`
out of the executor sandbox into its own transient unit:

```sh
lab vm device-actions -scenario wipe -wipe-phase recovery-sata \
  -recovery-boot-mode measured-grub -accelerator kvm \
  -manifest lab/images/fedora-44-encrypted-x86_64.json \
  -recovery-manifest lab/images/fedora-44-x86_64.json \
  -firmware-code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.ms.fd \
  -firmware-package ovmf -firmware-version 2024.02-2ubuntu0.10 -secure-boot \
  -record NEW.json   # plus the usual -repo/-lab/-lindmd/-cache inputs
```

`-wipe-phase recovery-nvme` selects the NVMe controller;
`-wipe-phase recovery-attestation-refusal` boots the SATA tuple without a TPM and
requires the capability refusal. Records are under
`$HOME/.cache/lindm-fedoragaps-20261011/`:

| Native record                     | SHA-256                                                            | Outcome                                                                                                                                                                                                                                                                                         |
| --------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fedoras44-measured-sata-01.json` | `18348b516d1419484d403614038122393596eafb08ac3c0a28dd7266b5892b0b` | **Failed.** Readiness, release pair and two-human approval succeeded, then every relay attempt got `resource_execution_rejected` from prepare. Cause: the absent UKI signer path resolved to the configuration directory, failing measured-mode validation. Fixed with a regression; no effect. |
| `fedora44-measured-sata-04.json`  | `5e05df3feabf4934117996e6d54c0fe31b0b287a3e8890b1cab8f37bdfeacaf0` | **Passed.** Overwrite of the exact 10,737,418,240-byte SATA target, 257 distributed zero samples, server `SUCCEEDED`, recovery powered off, three stopped-disk samples equal the zero-block digest.                                                                                             |
| `fedora44-measured-nvme-01.json`  | `2171c51da9beb72c4ea630077062fc22d6691a49c38cc9bcf0d9fb53938eb0bc` | **Passed.** Native NVMe user-data format with the approved basis2 controller-serial/NSID1 scope (QEMU 8.2.2, `lindm-lab-0`, 10,737,418,240 bytes, LBA shift 9), server `SUCCEEDED`, recovery powered off, three stopped-disk samples equal the zero-block digest.                               |
| `fedora44-measured-notpm-01.json` | `65d25e3578b26a5199850ba0bd52bd8fb816a8cc8cf6f1a22504c49d7f8a435c` | **Passed refusal.** TPM-less guest: device reason `recovery_readiness_tpm_attestation_unavailable`, server readiness and real two-human approval creation `failed_precondition`/`device_action_recovery_attestation_unavailable`; no action, BLS entry, initramfs or one-shot.                  |

The passing SATA record binds initramfs SHA-256
`0060bd8afcf6ecf3e38604f6f06af59ae0f4a4fb89a8d171d09d881d420cac55`
(30,023,469 bytes, offline target `recovery/<sha>.initrd`) to vendor kernel
`4b37e4e542a62c580c751787848be6c99e6f908f6712c8c6da85516b8d541de2`
(`recovery/<sha>.kernel`). Readiness reported GRUB 2.12, Secure Boot, btrfs
`/boot` with 9,225,383,936 bytes free and the measured kernel digest; the
unchanged vendor ESP had 82,089,984 bytes free. The start grant exists only after
`AuthorizeRecoveryStart` verified the quote, event-log replay and post-`linux`
GRUB sequence; the record proves that grant was issued, not a separate quote
transcript. The `sata-01` name typo is retained, not renamed. Records `02` and `03`
do not exist: `02` waited 60 minutes for a local slot and was stopped by its
controller deadline before a VM started, and `03` was cancelled while queued.
These are QEMU/swtpm results, not physical TPM, EK-certified attestation key or
physical media qualification; the initramfs used the busybox init.

**Measured GRUB after landing, Go PID 1 init (2026-10-11).** Three classes of defect
were found only by native lanes and fixed on main with regressions:

- The Linux EFI stub's tagged PCR 9 load-options and initrd events (`48300b6`,
  `fb76a81`). The load-options event is bound to GRUB's UTF-16LE command line,
  whose terminator differs between GRUB 2.12 and 2.14.
- gzip arm64 kernels, which GRUB measures decompressed (`3579b8d`).
- The grub.d `custom.cfg` flavor read the `/boot` UUID through the ESP-only
  parser (`54cc41f`).

Records are under `$HOME/.cache/lindm-fedoragaps-20261011/`:

| Native record                       | SHA-256                                                            | Outcome                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu24-mgrub-sata-x86-03.json`   | `e8acafca300e1c75edd5367533849e0df8a866408939003ba2ee2c5a311403cf` | **Passed.** Ubuntu 24.04 amd64 stock cloud image (`ubuntu-noble-20260926-amd64`, ext4 `/boot`, grub.d `custom.cfg` flavor) at `54cc41f`: overwrite of the exact SATA target, server `SUCCEEDED`, power-off, stopped-disk samples equal the zero block. Initramfs `4c4407b2…81d5` (29,002,464 bytes), vendor kernel `cd5fcfd2…2f2c`. |
| `ubuntu24-mgrub-nvme-x86-01.json`   | `2a2a0b85ca9e1e33628698b7989613aa867eeec89edfccfc4bf96270775defcc` | **Passed.** Same tuple with the NVMe controller: native NVMe user-data format with the approved scope, server `SUCCEEDED`, power-off, zero-block samples. Initramfs `6770184f…26fb` (31,740,292 bytes).                                                                                                                             |
| `ubuntu24-mgrub-nvme-arm64-04.json` | `554338b0d433b02e99fb178c71a285c00696b99706e5d93e9aefe43f7872ceda` | **Passed (additional arm64).** `dgx21` KVM, AAVMF Secure Boot with the Microsoft template, `ubuntu-noble-20260926-arm64`: GRUB measured the decompressed kernel `e989ab36…1914` and the EFI stub's load-options and initrd events; NVMe format, server `SUCCEEDED`, power-off, zero-block samples.                                  |
| `fedora44-mgrub-notpm-x86-01.json`  | `db46de61c270c3dff761473328d604f4a3c06758e99c454c1de42d090294fd2f` | **Passed refusal** with the Go PID 1 image at `48300b6`: device reason `recovery_readiness_tpm_attestation_unavailable`, server readiness and two-human approval `device_action_recovery_attestation_unavailable`, no action or staged boot files.                                                                                  |

The ordinary Ubuntu 24.04 arm64 event log is the parser fixture
`internal/measuredboot/testdata/ubuntu2404-arm64-stock.eventlog` (SHA-256
`3d218503b2c7862630fc518723020531bb48db626e46c13b5a3f6c8610d919af`). Ubuntu
26.04 amd64's log (`a0a884cb…8bc2`) came from Ubuntu2604's lane.

Not qualified:

- **Fedora 44 aarch64:** the stock cloud image never reaches SSH under AAVMF
  Secure Boot (`fedora44-mgrub-nvme-arm64-01.json`
  `67c5b1502dd4de63f2954d266ee354927dad7290615d3509b050d74c04e0c0b2`,
  `-02.json` `e03a74d147a28825ab7c585c665cf2295636b2142dea6c45fb3251fc00d27716`).
  The vendor aarch64 kernel has no Authenticode signature table, so shim rejects
  it ("bad shim signature") before lindm runs (DemoEnv.FedoraArmAssist evidence
  under `$HOME/.cache/lindm-assistqual-20261011/`). Measured GRUB requires
  Secure Boot, so the vendor chain makes this cell unsupported.
- **Ubuntu 22.04 arm64:** the lane stops at the release's existing
  RecoverySanitize gate (owned-boot fixture needs ukify) before any VM starts.
  No record was written.
- **Debian 12/13:** the lab has no Debian cloud recovery image; its goldens are
  netinst installs.
- **Fedora 44 x86_64 and RHEL 10.2 on the Go init (pending):** grub-editenv's
  unit failed natively, first at `54cc41f` (`fedora44-mgrub-sata-x86-03.json`
  `6abc8765e0ccbd415823da7d8173d3c2472789fa1541a52c1c5c789c576e2480`). The
  unit diagnostics added in `d26c5d6f` then showed exec status 203 on both
  releases (`fedora44-mgrub-sata-x86-04.json`
  `4de6bcb424c3c395e51732ed47321a622c0c3ad89073b2f38b5dee2e199e689d`,
  `rhel102-mgrub-sata-x86-03.json`
  `a471a3a5b2b92332b28a9a7be64c69ff3a0a8621156bb0aca37a41f1ca94db33`). Their
  targeted policy transitions the unit from `init_t` to `bootloader_t` on
  `bootloader_exec_t`, which `NoNewPrivileges` refuses; RHEL 9.8's older
  policy has no such transition. The unit now runs without `NoNewPrivileges`
  (still with an empty capability bounding set and every other confinement), so
  the vendor's confined `bootloader_t` domain applies.

RHEL 9.8 passed on the Go init at `d26c5d6f` with a real entitlement:
`rhel98-mgrub-sata-x86-03.json`
`29a5adf417bfcbc4893f9478fb8fc3e0fd8f387e0ac16bc48e847c5c10d891a2`. The tuple
was the stock `rhel-9.8-kvm-x86-64` image with separate XFS `/boot`, the BLS
flavor and the grub2-editenv unit with a read-only device. The lane overwrote
the SATA target, the server reported `SUCCEEDED`, the image powered off, and
the stopped-disk samples are zero blocks. Registration run
`lindm-lab-a1d0ef94c4e4c74dced9d310dfce7715`, consumer
`26174a33-3a9c-4b80-a802-f84f08819bcf`, was unregistered and its activation key
deleted before the action. The initramfs is `512e3442…8248` (30,479,356 bytes)
and the vendor kernel is `429e89b3…45fa`.

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

#### Ubuntu 24.04 aarch64 encryption and TPM

A full `vm device-actions -scenario encryption` run **passed** on `dgx20`
on 2026-10-11 in 2,251 seconds, with **Secure Boot enforced**:
`$HOME/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-encryption-01.json`,
SHA-256 `0dfcccf1cead839012e86b2f20981cff144ff45a35261cd801ecccb8062d7dac`.
This first invocation covers all five encryption scenarios without a phase
filter; no aarch64-specific product or harness fix was required.

The record binds clean source `7d10176af75e016879fb2081d0f311332ef8fffd`,
the signed `ubuntu-noble-encrypted-24.04.5-arm64` installer, native aarch64
KVM/QEMU 8.2.2, AAVMF `qemu-efi-aarch64=2024.02-2ubuntu0.10`,
virtio-scsi, a GNOME golden and swtpm 0.7.3. SecureBoot was true and SetupMode
false using the package-owned Microsoft-enrolled variables; no custom key
enrollment, replacement kernel or disabled verification was needed.
Native lab SHA-256:
`a8a416fbd9c905084f69d49f273a86011eaa64f6b5629b6cf838a1082e8f0fa5`;
server SHA-256:
`e44eeb7b3baeee9e3975f76b2d40618bf1058a1c8637a90c418aaf1f035b8e84`;
agent DEB SHA-256:
`8df1ea6596220ee6ce4378ba7f4996ffba5d3591d1c5da81889d560507b401d1`.

The product-action evidence proves:

- Signed escrow, actual KEK custody and audited two-human reveal, server/host
  LUKS2 inventory agreement, and a cold boot with the revealed recovery key.
- Committed rotation, independently absent retired slot, explicit rejection of
  the retired key at boot, and successful replacement-key cold boot.
- Hard-crash rotation at `AWAITING_ESCROW`, retained owner/old/new slots
  `[0,1,2]`, successful old/new recovery cold boots, and both executor and
  server converging to `OUTCOME_UNKNOWN`.
- Eight real denials: self-approval, changed digest, expired approval, revoked
  approver, missing reveal reason, missing dedicated permission, expired
  five-minute step-up, and offline start.
- Successful signed TPM bind, independently matched `systemd-tpm2` token,
  and unattended cold boot with `accepted=true`, `prompt_seen=false`.
- A separate signed bind against deliberately extended PCR7, refusal of
  unattended cold boot after firmware remeasurement, and successful prompted
  recovery using the separately escrowed, two-human-revealed key.

The native Spark invocation uses the same encrypted GNOME installer variant
as the Ubuntu aarch64 assistance lane, with the unbound TPM-capable dracut
stack. Device actions keep their isolated control plane on the selected lab
host by default; `-colocated` is an assistance-only flag.

```sh
artifacts/bin/lab vm device-actions -host dgx20 \
  -scenario encryption -architecture aarch64 \
  -manifest lab/images/ubuntu-noble-encrypted-arm64.json \
  -recovery-manifest lab/images/ubuntu-noble-arm64.json \
  -repo /home/r/dev/minor/lindm -build-repo "$WORKTREE" \
  -lab "$WORKTREE/artifacts/bin/lab" -lindmd "$WORKTREE/artifacts/bin/lindmd" \
  -cache .cache/lab/images \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.ms.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -secure-boot -record NEW_FILE
```

Rebuild the lab and server binaries before invoking the maintained FIFO
admission path. Use a fresh evidence path for each invocation. The package-owned
Microsoft-enrolled AAVMF template and `-secure-boot` require enforced Secure Boot;
the Fedora aarch64 SetupMode workaround is not part of this Ubuntu tuple.
This lane excludes wipe/recovery-sanitize, physical TPM/firmware/media,
stock-initramfs TPM unlock, Secure Boot off, and assistance after TPM-bound boot.

#### RHEL encrypted device actions and self-update

RHEL 9.8 and 10.2 x86_64 use the authenticated Binary DVDs acquired with
`lab images redhat fetch -edition dvd` (manifests
[`rhel-9.8-encrypted-x86_64.json`](../lab/images/rhel-9.8-encrypted-x86_64.json),
SHA-256 `c0dd53b7…1d2c80`, 15,540,420,608 bytes;
[`rhel-10.2-encrypted-x86_64.json`](../lab/images/rhel-10.2-encrypted-x86_64.json),
`e15cb333…2540a5`, 11,059,986,432 bytes; vendor-authenticated HTTPS checksum,
not an OpenPGP signature). Local KVM, QEMU 8.2.2, OVMF `2024.02-2ubuntu0.10`
`OVMF_CODE_4M.secboot.fd` + `OVMF_VARS_4M.ms.fd` (SecureBoot=1/SetupMode=0),
swtpm 0.7.3, GNOME Workstation golden with the TPM-capable dracut stack, SELinux
Enforcing. Records are under `$HOME/.cache/lindm-rhel-actions/`; goldens and the
first encryption run used private source patch `source-01.patch` (SHA-256
`42f9ee3845ad8adab51f3b7521e38cad9bc1cc7d441b8800e4ea2bd2ed8e5ac6`), runners
`lab-golden` `ba77bfe6…ccede0f9`, `lab-actions-01` `39330b8d…3e38b17e`,
`lab-actions-02` `45bc8005…b15b176cd` and `lindmd-actions-01` `05d19e4e…0fd0006c`,
all stamped `0.1.0`.

| Record                                  | SHA-256                                                            | Outcome                                                                                                                                                                                                                                       |
| --------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rhel98-golden-sb-gnome-tpm-01.json`    | `de5b835922938e0944899baac434ffc4ee5dfd899e5a0daa60550b898509f304` | **Golden passed.** Kickstart install, two prompted serial cold unlocks, LUKS2 root, TPM version 2, SecureBoot=1/SetupMode=0, guest/stopped-disk header agreement.                                                                             |
| `rhel102-golden-sb-gnome-tpm-01.json`   | `60bf3df529360497437be3490dd9edc5834c25ccca682f06bd71579d20f4ee7a` | **Golden passed** with the same observations.                                                                                                                                                                                                 |
| `rhel98-golden-nosb-gnome-tpm-01.json`  | `8383fc71fe253d6d5555e1860d2e9a3ec3f81d87c4b254fc0acc14bed8d6ec50` | Invocation error, not a product result: non-Secure-Boot `OVMF_CODE_4M.fd` omits the SecureBoot variable, which the posture gate correctly rejects as unavailable. The off tuple requires `OVMF_CODE_4M.secboot.fd` with unenrolled variables. |
| `rhel102-golden-nosb-gnome-tpm-01.json` | `16f33ced951ab658ae7849efebc633e6898ea54ec2b8952d42cacec31b7d2dd9` | Same invocation error.                                                                                                                                                                                                                        |
| `rhel98-golden-nosb-gnome-tpm-02.json`  | `2d6e8c2507c08231e4eb15c998e86d0f6a38543e6e6b18e0182d0c7047fe5346` | **Secure Boot off golden passed** with `OVMF_CODE_4M.secboot.fd` and unenrolled `OVMF_VARS_4M.fd`: SecureBoot=0/SetupMode=1 observed, two prompted cold unlocks, TPM version 2, header agreement.                                             |
| `rhel102-golden-nosb-gnome-tpm-02.json` | `e311ce49f82a3422cf248187bcc178e4efb2853de100ce84bdc617a7b55334e8` | **Secure Boot off golden passed** with the same observations.                                                                                                                                                                                 |
| `rhel98-encryption-01.json`             | `ea4b94f577d8d556c493eae7957eeabd277bfd5cf6dc606b58f7f00ed3fce20a` | **Scenarios 1–5 passed** in 1,378 s.                                                                                                                                                                                                          |
| `rhel102-encryption-01.json`            | `12fe79f67f981fc4315e9ce9185b24dc55c20f9838dc045f8f89883313d4cc0c` | **Scenarios 1–5 passed** in 1,378 s.                                                                                                                                                                                                          |
| `rhel98-live-erase-01.json`             | `3e524640895630e6a9554ccb0ab13872c5571b97a041d862ee7ad3934864bf8a` | **Live-root crypto-erase passed.**                                                                                                                                                                                                            |
| `rhel102-live-erase-01.json`            | `ddf2382aa528877307560d4116ef2a8eb95e53f86bb94d2748e181def65d39b8` | Failed before any action: the executor did not start after the data-disk cold boot (see below).                                                                                                                                               |
| `rhel102-live-erase-03.json`            | `b32dd234236b31877638b93c49ac9c12963a580cdb49a48b596c6257e1d2524a` | **Live-root crypto-erase passed** with the LUKS by-uuid sandbox fix (runner `lab-actions-05` `9a3ce445…5412f962`); two humans, pre-erase data recovery, server `SUCCEEDED` attested before power-off, both headers absent.                    |
| `rhel102-live-report-loss-03.json`      | `d6b24666a4d595264b7f7f92bca99af85721b7062fa530d6beea25f6ddc6fba4` | **Live-root report-loss passed**: result channel blocked, server `OUTCOME_UNKNOWN`, timer power-off, both headers absent.                                                                                                                     |
| `rhel98-recovery-sata-02.json`          | `222cb6376e4234124eb61e29d22cbc8a64bb92381bcd149cf6a0e4cf41f60f67` | Lab failure before any action: the registration probe upload needed the native guest directory, which did not exist yet. Fixed (staged then removed around registration).                                                                     |
| `rhel98-recovery-nvme-02.json`          | `68fee06938ed2801e41096a16b8ba1e4e8fb83a99770d5e9b591caa2c4690241` | Same probe-directory failure.                                                                                                                                                                                                                 |
| `rhel98-recovery-sata-03.json`          | `247207a1d8a26505cfc11c260a6153e63c23374d3e43f89593a8737caa6811d0` | Registration, entitled install, unregistration and key deletion succeeded; the owned ordinary UKI upload then failed (see below). No action.                                                                                                  |
| `rhel98-recovery-nvme-03.json`          | `f3eac0693af6213735ccd76c40284c7f2a6b1ff7b0260776be4f866b5c694a33` | Same owned ordinary UKI failure.                                                                                                                                                                                                              |
| `rhel98-recovery-sata-04.json`          | `0606531234893f924040cab24548d6b15f5ec826bd6f1feb3eb5fcdf18f4e2f0` | Transient: Red Hat SSO HTTPS authentication request failed before registration (nothing registered). Not a product result.                                                                                                                    |
| `rhel98-recovery-nvme-04.json`          | `55b79a7913b84d7692db9bca4cd4a831aed5c517df9e6e6f79a3696904d703b6` | Hostonly owned UKI built and booted; post-reboot `bootctl status` stderr refused (systemd's BLS `Unknown line` notices for grub keys, fixed in `89d5756c`). Registration cleaned up.                                                          |
| `rhel98-recovery-sata-05.json`          | `28403f9d59257d33140f7228f9a69406c79bccd7c476120fa3e2efda774c9665` | **SATA original-device recovery sanitize passed.**                                                                                                                                                                                            |
| `rhel98-recovery-nvme-05.json`          | `df07c739101599234fccff9415fe3ce86af1b25f01d7928ef932a013ea9853b2` | Two-human approval succeeded, then `CreateDeviceAction` refused `device_action_storage_target_mismatch`; no action. Under diagnosis (see below).                                                                                              |
| `rhel102-recovery-sata-04.json`         | `914c714b8ee81638ffccc51f7684e152bc2ee972c68062aba766c4b1f7a633d6` | **SATA original-device recovery sanitize passed.**                                                                                                                                                                                            |
| `rhel102-recovery-nvme-04.json`         | `38454aeaf3faf13e2ead17e5a09f510dffb8541c38616ec5e2bb9e6700bc5754` | **NVMe original-device recovery sanitize passed.**                                                                                                                                                                                            |
| `rhel98-live-report-loss-01.json`       | `4e33999ba1a32d1f635390630964a72e8a02375a411c83a1cf1fff06c4ca9753` | **Live-root report-loss passed.**                                                                                                                                                                                                             |
| `rhel102-live-report-loss-01.json`      | none (no record)                                                   | Not a product result: `context deadline exceeded` exactly 3 h after start with no record written, so the lane never returned a result; consistent with waiting for a local lease (inference). Ran on the pre-fix binary.                      |
| `rhel102-lock-quarantine-01.json`       | `5294527d651a9810d6ce61ab1598f07e862203440c4c30f08ddc953fb28199c8` | **Lock, release, account disable and quarantine passed** with a real GDM Wayland session.                                                                                                                                                     |
| `rhel98-lock-quarantine-01.json`        | `d94a7e23a6b44f4fa36501ae77e2b10b8f8ced3158f5c544ff6839c21932a377` | **Lock, release, account disable and quarantine passed** with a real GDM Wayland session.                                                                                                                                                     |

Both encryption records prove server/stopped-disk LUKS2 slot and token agreement,
real KEK custody with an audited two-human reveal, the eight authorization denials
(self approval, changed digest, expired and revoked approvals, missing reason,
dedicated permission, real step-up expiry, offline start), revealed-key cold boot,
committed rotation with retired-slot absence and serial rejection of the retired
key, replacement-key cold boot, a hard crash retaining slots `[0,1,2]` with
old/new recovery boots and root/server `OUTCOME_UNKNOWN`, and TPM2 binding with an
unattended cold boot (no prompt), PCR7-mismatch rejection and revealed-key
recovery. The 9.8 live erase proves two distinct humans, pre-erase data escrow
and recovery, native erasure with server `SUCCEEDED` attested before the forced
power-off, and both LUKS headers absent on independent stopped-disk inspection.
The 9.8 report-loss run blocked the result channel after approval: the server
stayed `OUTCOME_UNKNOWN` (never successful), the fixed timer powered the guest
off, and both headers were absent on stopped-disk inspection.
Both lock runs (9.8 and 10.2) log a password-enabled user into GDM (`gdm-autologin`,
Wayland); the signed lock sets logind `LockedHint` and GNOME ScreenSaver active,
and release removes only the owned restrictions without remotely unlocking the
desktop. Account disable locks the password and expires the account, release
restores the original shadow state, and an intervening administrator edit is
preserved. Quarantine blocks routed traffic while preserving the management
endpoints and DNS, is released explicitly, and expires with the executor stopped.

`rhel102-live-erase-01` root cause: the executor's sandbox drop-in bound the root
LUKS partition by kernel name (`/dev/sda3`). After the cold boot with the second
virtio-SCSI data disk, the kernel enumerated the data disk first and the root
became `sdb` (the boot journal mounts `/boot` from `sdb2`); systemd failed the
executor's mount namespace (`/dev/sda3: No such file or directory`, status
226/NAMESPACE) until the start limit. The retained diagnostic
`rhel102-live-erase-01-diagnostic.json` has SHA-256
`21a62780f4348211597cc42a79763250e8c2a18268741d08113909f0fec45c1d`. The
provisioning step now names LUKS targets by their approved
`/dev/disk/by-uuid/<luks_uuid>` alias, verified to be the identity-checked block
node (missing or diverging aliases fail closed), and `openTarget` opens that alias
only when the kernel name is absent, still requiring the same device number, size
and native identity. A deterministic regression covers matching, missing,
renumbered, wrong-type and non-LUKS cases; an independent review found no
blocking issue. The 9.8 pass predates this change and did not exercise it;
`rhel102-live-erase-03` exercises it natively.

The RHEL vendor KVM images used by original-device recovery have a 200 MiB vfat
ESP with 196,772 KiB (9.8) and 195,420 KiB (10.2) free, measured read-only from
the pinned images; the installer goldens have a 613,160 KiB ESP. Both DVDs, and
therefore entitled BaseOS/AppStream, publish `systemd-boot-unsigned`
(`252-67.el9_8.2` / `257-23.el10_2.1`) and `systemd-ukify`; neither publishes
busybox or sbsigntools. The recovery image no longer uses either (static
lindm-agent `/init`, in-process Authenticode; see the busybox-free recovery init
records above), so RHEL recovery sanitize awaits only its native qualification run.

The RHEL KVM images ship a generic (no-hostonly) initramfs of 240,001,314 bytes
(9.8) and 235,583,210 bytes (10.2), measured read-only from the pinned images. An
owned ordinary UKI embedding it exceeds the 200 MiB ESP. In `recovery-sata-03` and
`recovery-nvme-03` the signed UKI upload failed with a 42-byte stderr, consistent
with `cat: write error: No space left on device` on the guest's `/run` tmpfs
(inference; the message itself was not retained). The fixture now embeds a
`dracut --hostonly` image for the running kernel in the owned ordinary UKI
(registry `Lab.Guest.OwnedBootHostonly`); the installed initramfs is unchanged.
Each `-03` record retains the maintained registration's public run name,
consumer UUID, unregistration and activation-key deletion.

The three passing recovery records use runner `lab-actions-08` (SHA-256
`dd119538cc6c6bdd9703e94ba20e0651b5c5c2d389cb141f10f25a8536e5c493`) and
`lindmd-actions-08` (`dd2c74b960a1b94ce9aad9a4b1be2e278ea2dfea211e2d2cd2ddaa81715e619a`),
built from main with the Go PID 1 recovery init. Each proves fresh readiness on
the unchanged vendor ESP, distinct requester/approver, the signed recovery UKI
booted on the original device under Secure Boot (SecureBoot=1/SetupMode=0), a
server-verified scoped result `SUCCEEDED`, closed-image power-off, independent
stopped-disk samples all equal to the zero block, and the registration's
unregistration and activation-key deletion. SATA overwrote the exact
10,737,418,240-byte target with 257 zero-read samples; NVMe formatted user data
with unchanged controller-serial/NSID 1 scope and every formerly nonzero sample
changed.

| Release / bus | Signed image bytes | Rounded need / ESP available bytes | Kernel                         |
| ------------- | -----------------: | ---------------------------------: | ------------------------------ |
| 9.8 SATA      |         45,834,808 |           45,838,336 / 150,827,008 | `5.14.0-687.5.3.el9_8.x86_64`  |
| 10.2 SATA     |         47,172,664 |           47,173,632 / 139,493,376 | `6.12.0-211.7.3.el10_2.x86_64` |
| 10.2 NVMe     |         51,365,944 |           51,367,936 / 139,333,632 | `6.12.0-211.7.3.el10_2.x86_64` |

The available space is what remains of the 200 MiB vendor ESP after the owned
signed systemd-boot and hostonly ordinary UKI; the vendor ESP was not resized.

Self-update passed on unregistered vendor KVM images: `rhel98-updates-01.json` and
`rhel102-updates-01.json` under `$HOME/.cache/lindm-rhel-updates/` (hashes in the
L08/L17 row), lab binary `4928e0d1…f57c811`. Each passed all six signed
negative/hold phases, a kernel-frozen DNF4 unpack witness (`dnf pid=10461`,
32,768 bytes; `dnf pid=10791`, 229,376 bytes), an owned QMP reset with boot-ID
change and boot-helper completion at exact `0.2.0`, retained identity, session
epoch `1 → 2`, fresh inventory (492 and 530 packages) and signed downgrade
refusal, with SELinux asserted Enforcing. No product change was needed; the DNF4
CLI runs in the helper's own transient unit, outside the executor's read-only
`/var`.

#### Signed-action core regression lanes (2026-10-11)

Resource executions and device actions now share one signed-action core on the
executor and the server (architecture §resource dispatch). Two Ubuntu 24.04
aarch64 KVM lanes ran against source `deadcc1` with an empty applied diff. All
records and `source-provenance-and-results.json` (SHA-256
`998ad923c867a6919538d0d09e56dbc57bcbb9b537277e46941dc44170bcfc06`) are under
`$HOME/.cache/lindm-signedaction-20261011/`:

- Resource apply, `lab vm resources -phase connected -kinds files` on `dgx20`:
  **passed**, `ubuntu24-arm64-dgx20-files-03.json` (SHA-256
  `8e366825f0112c34f5de98ea064f9ad03b186b56c913ab9ce2545409c9d3ebd5`). All nine
  file scenarios ran through the real start grant and the attested result, and
  the native oracle observed the created file. Attempts `-01` and `-02` failed
  before enrollment because the guest could not resolve the Ubuntu mirror without
  `-allow-network`. Signed-action code was not involved.
- Device action, `lab vm device-actions -scenario wipe -wipe-phase lock-quarantine`
  on the encrypted GNOME/Wayland golden on `dgx21` (Secure Boot, swtpm):
  **native pass**, `ubuntu24-arm64-dgx21-lock-quarantine-01.json` (SHA-256
  `a68ce9f961639bb9efda595279e690ab6a6266af51765eccdffd2b0f2847d245`).

Unit characterization runs the same table against both kinds:
`TestSignedActionLifecycleCharacterization` on the executor and the integration
test `TestSignedActionServerCharacterization`. The table covers exact replay,
expiry by wall clock and by boottime, revocation, reboot, a different executor
incarnation, duplicate consumption, a foreign challenge, the self-update
interlock, the 30-second grant window, generation and session fences, late
nonces, mismatched attestation and ungranted start evidence.

### Built-in graphical remote assistance (L09, L12)

The maintained lane `lab vm assistance` boots a disposable clone of a cached
encrypted GNOME golden. It builds and installs the signed agent package, enrolls
the guest against an isolated `lindmd` with `ServerConfig.assistance` (the
embedded relay), and enables `AgentConfig.remote_assistance` in the executor
configuration. It then prepares GDM autologin for a password-enabled desktop user
and requires `lindm-session.service` to be active in that user's manager.

A real headless Chromium drives the real console. Local-user clicks are QMP
absolute-pointer input, located from QMP screendumps. The lane observes stable
hover feedback at the target before its single click; a QMP queue acknowledgment
alone is not proof that GNOME processed pointer motion. Every screenshot and
journal excerpt is SHA-256 bound in a read-only `assistance.json` and re-verified
before a pass.

```sh
lab vm assistance -host local \
  -manifest lab/images/ubuntu-noble-encrypted-amd64.json \
  -repo /path/to/initialized/fixture -build-repo . \
  -lab artifacts/bin/lab -lindmd artifacts/bin/lindmd \
  -cache .cache/lab/images -golden-cache .cache/lab/encrypted -require-cached-golden \
  -work-dir /tmp/short -firmware-code /usr/share/OVMF/OVMF_CODE_4M.ms.fd \
  -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.ms.fd -firmware-package ovmf \
  -firmware-version 2024.02-2ubuntu0.10 -secure-boot -evidence /new/absolute/dir
```

Use `-manifest lab/images/fedora-44-encrypted-x86_64.json` for Fedora. Keep
`-work-dir` short, because QMP and VNC Unix socket paths must stay under 108 bytes.
The lane runs five scenarios:

| Scenario      | Path                                                                                                                                                                                                 | Required outcome                                                                                                     |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| control       | CONTROL request → critical consent notification **Allow** → RemoteDesktop portal: enable **Allow Remote Interaction**, **Share** → console joins/answers → nonce typed in the viewer → operator Stop | `OPERATOR_STOPPED`; control granted; `lindm-input` channel; the guest terminal receives the nonce; gst capture stops |
| view          | VIEW request → Allow → ScreenCast portal Share → **Stop** on the in-progress notification                                                                                                            | `USER_STOPPED` (`local_stop`); offer has no `m=application`; no data channel or control button                       |
| decline       | **Decline** on the consent notification                                                                                                                                                              | `DECLINED` (`prompt_declined`); no consent audit row                                                                 |
| portal-cancel | Allow, then **Cancel** in the portal dialog                                                                                                                                                          | `DECLINED` (`portal_cancelled`)                                                                                      |
| lock          | Live VIEW session, then `loginctl lock-session`                                                                                                                                                      | `SESSION_LOCKED`                                                                                                     |

The live scenarios also require all of the following:

- At least 15 decoded frames in Chromium.
- A selected ICE pair that is relay/relay under `iceTransportPolicy=relay`.
- Binding to the GDM-autologin logind session.
- Recorded offer and answer DTLS fingerprints.
- A complete server state timeline.

Audit rows are read through `ListAuditEvents`. Every run must show `request`,
`prompt`, `consent`, `join`, `answer`, `start`, `stop` and `end` with the expected
`cause=` for each session.

Both runs below **passed** on 2026-10-11 from private worktree commit `0f5faf4`. Its
feature diff against the shared-tree overlay baseline is `feature.diff`, SHA-256
`f01d9ec17fcae3fdaf726bdb1536923123c4e15418e4e97cb2bf01165e68301b`. The lab binary
(`f200c953…0a4c2`) and `lindmd` (`1dedd43b…c4a1`) were rebuilt from that commit
with identical SHA-256, which `source-provenance.json` (SHA-256
`a6db87f0f13e17ec4136971a82a68467b0a5841c0a27cc36be79e107b004a32c`) records. All
files are under `$HOME/.cache/lindm-assistqual-20261011/`.

| Record                                   | SHA-256                                                            | Native tuple                                                                                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `ubuntu24-assistance-06/assistance.json` | `70d5bb4bb1e76775c6aa3e8dd29b278bdfec55aa7eccbc51a07cc01da63cf152` | Ubuntu 24.04.5, GNOME 46.0 Wayland, xdg-desktop-portal 1.18.4 / -gnome 46.2, GStreamer 1.24.2; device `be7732c4-42f6-423c-9826-2755d948b7b2` |
| `fedora44-assistance-03/assistance.json` | `6ea59f8908eb653f00e20d8c17843ce567d12f31f58f2909e410338fbf82e1be` | Fedora 44, GNOME 50.0 Wayland, xdg-desktop-portal 1.21.1 / -gnome 50.0, GStreamer 1.28.1; device `a59dc15a-4a9e-4cf2-be6c-a0e2dac6fc1a`      |

The common runtime was x86_64 KVM/QEMU 8.2.2 with virtio-gpu, OVMF
`2024.02-2ubuntu0.10` with Secure Boot enforced, swtpm and Chromium 156.0.8078.4.
On both distributions the RemoteDesktop dialog shows **Allow Remote Interaction**
off by default, so control is a second, separately visible local grant.

#### Native aarch64 Spark qualification and held demo

On 2026-10-11, the maintained SSH-native lane also passed on `dgx20` from
private commit `42ea7d9`, then passed again after the wire-name cutover rebase
at `73cdb53`, with `lab/images/ubuntu-noble-encrypted-arm64.json` and
`-console-turn-tcp`. Each run executed all five scenarios without automatic
retries. The records below are under the same
`$HOME/.cache/lindm-assistqual-20261011/` evidence root:

| Record                                           | SHA-256                                                            | Result                                                                                                                  |
| ------------------------------------------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `ubuntu24-aarch64-assistance-04/assistance.json` | `6669b3f6f6a1486cbaa9ef30d821a58626297e1f30c3f79fa122da6c9388d1d9` | PASS: control, view, decline, portal-cancel and lock; 35 screenshots and three journals SHA-256 bound in the record     |
| `ubuntu24-aarch64-assistance-05/assistance.json` | `8f8005297ae745a0ad1c2f05dbf74433d3f1a1fcef95ada1495b975d153e4099` | PASS after rebase: all five scenarios; 35 screenshots and three journals; device `6a227f77-e05e-4ae4-8af2-9815ffb751c2` |

The final run's native `lab` SHA-256 is
`945e1414070fad153dcf5dfb88dda748d819d2a12afeffe3a37af39c8950e3c6`;
`lindmd` is
`7124eab7dacde97c3d300ca349fc8af6ab5e008d9c1bba346e780afc48b2e50a`.
Reproduce with the usual binary/cache paths for your checkout:

```sh
lab vm assistance -host dgx20 -colocated \
  -manifest lab/images/ubuntu-noble-encrypted-arm64.json \
  -repo . -lab artifacts/bin/lab -lindmd artifacts/bin/lindmd \
  -cache .cache/lab/images -require-cached-golden -console-turn-tcp \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.ms.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -secure-boot \
  -evidence "$HOME/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-assistance-05"
```

Use a new evidence directory for another invocation; existing records are never
overwritten. RemoteRun cross-builds the native binaries from the selected source
checkout rather than sending the workstation's executables.

The tuple is native aarch64 KVM/QEMU 8.2.2, AAVMF
`qemu-efi-aarch64=2024.02-2ubuntu0.10` with Secure Boot enforced, swtpm 0.7.3,
virtio-gpu and Ubuntu 24.04.5 GNOME/Wayland. Guest packages were
`gnome-shell=46.0-0ubuntu6~24.04.15`,
`libmutter-14-0=mutter-common=46.2-1ubuntu0.24.04.18`,
`xdg-desktop-portal=1.18.4-1ubuntu2.24.04.3`,
`xdg-desktop-portal-gnome=46.2-0ubuntu1`,
`pipewire=1.0.5-1ubuntu3.3` and
`gstreamer1.0-plugins-good=1.24.2-1ubuntu1.8`.
The private operator Chromium was 156.0.8078.4 (Playwright 1.64.0, pinned Node
24.21.0). The Spark had no Node or Chromium on PATH initially; the maintained
prerequisite step installed them under its configured work directory, and `ldd`
and real browser launch succeeded with existing system libraries, without apt.

`lindmd`, its isolated PostgreSQL/trust fixture, the embedded TURN relay, QEMU,
QMP and Chromium all ran on the Spark. The three live scenarios selected
relay/relay ICE pairs with the console relay using TCP. Control received the
typed nonce through `lindm-input`; view had neither an application channel nor
a control button. The expected audited ends were `OPERATOR_STOPPED`,
`USER_STOPPED`, `DECLINED` (`prompt_declined`), `DECLINED` (`portal_cancelled`)
and `SESSION_LOCKED`. This remains virtual display evidence, not a physical
desktop or cross-host media-path qualification.

A pre-fix attempt, `ubuntu24-aarch64-assistance-02/assistance.json` (SHA-256
`c864cd1d736b6fe7f6909c16da3d51a73eade9696e1fdf8305abe46d7861ca2b`), failed
because the control prompt remained unaccepted after its recorded QMP click;
the helper journal contains a prompt but no Allow. The lane now requires stable
hover feedback at the target before sending its single click and retains a
screenshot if hover or the portal never appears. The failed attempt is retained,
not counted as a pass; no product consent, transport or capability gate was
relaxed.

The separate `ubuntu24-aarch64-held-03` demo used the arm64 manifest without
`-host`; auto-selection chose `dgx20`. It printed placeholder forwards
`ssh -L 39929:localhost:39929 -L 34370:localhost:34370 <user>@<this-host>`.
The printed remote `assistance-respond ... screenshot` command succeeded:
`guest-respond-20261011T102347.432Z-screenshot.png`, SHA-256
`79d772c17c204194da19fcbcc2a9795c108522e358c0b78f585f437488452cd2`.
Ctrl-C completed with exit 0, returned the screenshot without `owner-access`,
and removed the exact remote run directory; checks found both listeners gone.
The SSH process is isolated from terminal SIGINT so stdin closure can cancel
the worker and release its lease only after teardown. A transport error while
checking returned evidence retains the remote directory rather than treating
the error as an absent file. No Spark demo was left running.

#### Persistent named fixture regression

On 2026-10-11, `TestPersistentFixtureResumePreservesOwnerSession` passed with
`-race -tags=integration`, real PostgreSQL (`testdb`) and a freshly built
release-stamped `lindmd`, for both local and routed split fixtures. It creates
private state, rejects concurrent opens and live destruction, restarts only the
server for relay/authorization changes, closes and resumes the same database,
and exercises the original owner cookie without logging in again. The same
owner, lane owner and independent approver remain enrolled; TLS leaf,
admin/device addresses, TURN configuration and execution signing custody remain
unchanged. A busy saved admin port is refused instead of reallocated.
Explicit destroy removes both database and fixture state. The split case also
simulates interruption after database deletion, proving that repeated destroy
finishes filesystem cleanup without `FORCE` or a replacement database.

Evidence: `$HOME/.cache/lindm-persistent-demo-20261011/fixture-integration.log`,
SHA-256 `f4b772c5c58e3545cb94ff78dffc5e37b6a0a7fee2ec5638faac38962b214656`.
The two subtests completed in 23.78 seconds after exclusive integration admission.
This is fixture durability evidence, not VM or physical-host qualification.
Production `lindmd` already preserves PostgreSQL data across restart; only
disposable lab teardown intentionally drops its isolated database.

The real-server advisory regression also passed after making an unchanged
configuration a true no-op: existing feed publication timestamps and the
`lindmd` PID stay unchanged; changed configuration still refreshes and restarts
only the server. The production worker remains responsible for refreshes when
due, and held readiness still refuses unknown/stale device evaluations.
Evidence: `$HOME/.cache/lindm-persistent-demo-20261011/advisory-resume-integration.log`,
SHA-256 `2c1153be383aaadafb6f304bbf35f8013b0784179978a4511bcd940b7fb04f0f`.
This test uses a local TLS feed fixture, not a live-vendor qualification.

A subsequent real-server run also restored saved fixture creation options,
including CPU affinity, after reopening with empty caller options. Both local
and split subtests passed under the race detector. Evidence:
`~/.cache/lindm-persistent-demo-20261011/fixture-options-integration.log`,
SHA-256 `2e70230e57f8f15e5e1cad6af172061b9c4293b1b7fca6b1b3f4ebf17d3e0f4d`.

`TestPersistentAssistanceOperatorAccountsAcrossResume` also passed with real
PostgreSQL and `lindmd` under the race detector. It exercises the actual scenario
operator creation/retirement helpers twice across persistent controller and lane
restarts: unique account IDs and usernames, disabled cleanup even when the
scenario context is canceled, and unchanged human/controller/lane identities,
enabled state and account cardinality. Evidence:
`~/.cache/lindm-persistent-demo-20261011/operator-resume-integration.log`,
SHA-256 `9eb7493ee68e01ac680925af186c7c08fdb96fce6d8df3ee019e4acfac8e37bd`.

A later full integration run exposed a teardown timeout: this test's one-minute
cleanup context truncated the fixture's existing three-minute database-drop
budget. The observer connection closes before controller teardown; the independent
`testdb` pool remains on the shared database. The original terse error does not
establish a historical leaked connection or checkpoint wait. Routine cleanup now
honors the fixture's bound and retains its private root on failure, while failed
drops report a separately bounded activity snapshot without `FORCE`.

After the development credential rotation, the local/split owner-session tests
passed again (27.44/40.06 seconds), and the operator resume test passed in
19.67 seconds, all under the race detector. Captured output:
`~/.cache/lindm-persistfix/integration-initial.log`, SHA-256
`029f5a581fa23061c99f947cf7bd9304ba2b9af86710a218235bfa12b3cf419b`.
That first run also exposed an incorrect new test assumption: changing a database
connection limit takes a catalog tuple lock, not the intended database-object
lock. The corrected test uses an uncommitted rename, rolled back on connection close.

`TestPersistentDestroyReportsRemainingSessions` then passed against real
PostgreSQL and rebuilt `lindmd` in 13.86 seconds. It observes zero target clients
after controller close with the shared pool still open, identifies deliberately
retained target-client and cross-database object-lock sessions by PID and
application, preserves both the live blockers and private state on failure, then
successfully retries destroy after their connections close. Captured output:
`~/.cache/lindm-persistfix/cleanup-regression.log`, SHA-256
`2e4e79de34f87a2ca7bd4ed1e73100b50b20b066cd0c3f29d235ee89e9c960aa`.

Post-rebase architecture regressions cover the actual named VM resume path up to
control-plane validation without building a package or booting a VM, and the
split controller's native publication architecture selection. They pass for
`amd64`, `x86_64`, `arm64` and `aarch64`. These prevent dereferencing the absent
new package on resume and accidentally publishing an amd64 package for an arm64
guest. Evidence:
`~/.cache/lindm-persistent-demo-20261011/resume-architecture-regression.log`,
SHA-256 `723620b92dbf813bcff65cdf60de9fea3d4eaed36a3d7a9a723c7ae771d28802`.
The corrected merged source also passed independent static review, recorded in
`~/.cache/lindm-persistent-demo-20261011/merged-persistence-review.json`,
SHA-256 `7363a9b6473f154958dad011b46e71f0c074f9aa90fda96d02d117e5da0e7dfb`.

The merged split fixture integration additionally built real signed native
packages, reopened the same database with the original cookie, restored native
publication metadata and returned ready enrollment instructions. Its native
signer fingerprint stayed `5F131F501CEC1AB76346366E44B792EED0C89B0F`; explicit
destroy removed the database and state. The merged local subtest passed too.
Evidence: `~/.cache/lindm-persistent-demo-20261011/fixture-native-integration.log`,
SHA-256 `a6761e6a9e875c1c346b0b62badd74b8867e9b10044eff4ea32001bd84c4e236`.
The first native-enabled test attempt correctly refused a group-writable
`testing.TempDir` ancestor (Go creates its numbered child with 0777, under the
host's 0002 umask). The test now uses a short, private 0700 root and registers
exact-state cleanup before opening; packaging safety checks were not relaxed.

After the merged Spark lifecycle smoke, the combined repository gate passed:
`make check` (full web build/typecheck/lint, protobuf checks, default Go lint and
formatting, generated-doc check, all module race tests, npm audit and
`govulncheck`), `go build ./...`, and integration-tag lint for `cmd/lab`,
`internal/devlab`, `internal/labhost` and `internal/vmlab` (0 issues).
Npm reported no vulnerabilities; govulncheck reported no affected code, with one
uncalled required-module advisory. Full output:
`~/.cache/lindm-persistent-demo-20261011/final-gate.log`,
SHA-256 `4c3be3d50e97b2c51c0e085a1aa03ffeeb470bc5e51819762abd64f829a55a80`.

The advisory-config and repeated scenario-operator real-server regressions also
passed on the merged source, serialized under the host integration lock with
the race detector. Evidence:
`~/.cache/lindm-persistent-demo-20261011/merged-operator-advisory-integration.log`,
SHA-256 `1bfb796f9b0f7a7071cdec5e9e76d5a38e0a72307dab33371a0f3719e15f5992`.

#### Merged named split lifecycle and native repository acceptance

After rebasing onto native enrollment repository publication (`0261411`) and the
device-domain split, a fresh `persist-merged` demo passed on `dgx20`:
create → Ctrl-C → resume → Ctrl-C → explicit `-destroy`. The rebuilt server
included freshly generated web assets. Device
`019e1c44-9437-46aa-8b69-f5cbc0d39761` and generation
`12d56d0e-c5b3-4ca7-a4ca-353148eb9cc0` remained identical; published sequence
advanced from 1 to 2 without re-enrollment. All 33,509 findings and the exact
finding set survived. The original owner's browser cookie, account and session
remained valid without another login, and the owner-access file was unchanged.

Native enrollment readiness returned HTTP 200 and `ready=true` before and after
resume, with signed **arm64** APT and RPM publications. Every repository and
signing-custody file retained its SHA-256, mode and modification time; native
metadata was byte-for-byte unchanged. The retained signer fingerprint was
`357655DCBB6C5AB0FCD31C1DE8132A508A63A6B0`; packages were not republished.
The administrative origin remained `https://localhost:45875`, with TURN on
45947 and no product URL rewriting.

Both stops and explicit destruction exited 0. Exact-resource checks after
destroy found zero named databases, no controller or remote demo directory, no
owned process and no console/TURN listener. The receipt contains 32 hashed
evidence artifacts, including settled before/after owner screenshots:
`~/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-held-persistent-merged-03/smoke.json`,
SHA-256 `a8a07488b5e501c4891e8e3855e45f864a4c098bcc57633a7468b086ce425c47`.
The final `owner-after.png` SHA-256 is
`0b767a1e6a31cdef4ed32bdce2ae886d1a1dcd08035f5825b1003bb029333afe`.

The receipt discloses earlier interrupted setup: an already-created evidence
directory was refused before VM start; an import-cycle correction initially
failed the build; an architecture mapping initially published amd64 instead of
arm64. The initialized state was explicitly destroyed and the successful run
created afresh after these corrections. A manual readiness request missing its
CSRF header was correctly refused before the authenticated request succeeded.
This proves held-demo persistence on native aarch64 KVM, not a new
remote-control scenario qualification or physical-device validation. Stable,
nonsecret sibling lock files intentionally remain after destruction.

#### Named split held lifecycle regression

On 2026-10-11, a native aarch64 KVM run on `dgx20` exercised
`lab vm assistance -hold -name persist-smoke`: create, Ctrl-C, resume, Ctrl-C,
then the maintained `-destroy` command. The same device
`48d367fb-1391-4413-b03e-e022617b87e4` and enrollment generation survived, without
re-enrollment. All 33,509 findings remained while stopped and after resume.
The same browser cookie and unrevoked owner session reloaded the same device
page, visibly authenticated as `console-owner`, without another login.
Console origin, TURN port and the original mode-0400 owner-access file remained
unchanged.

Both Ctrl-C stops exited successfully and retained the database and encrypted
disk. Explicit destruction exited successfully; exact-resource checks found no
named database, controller or remote demo directory, owned QEMU/swtpm/lab
process, controller `lindmd`, or console/TURN listener. Unrelated lab resources
were untouched; empty sibling synchronization lock files intentionally remain.

Evidence:
`~/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-held-persistent-03/smoke.json`,
SHA-256 `79394570a57ec1d129db7676a4dca2f14b845c6f70704cfc82cdc198a244f64c`.
Its artifact manifest includes the settled `owner-after-resume.png`, SHA-256
`e55d50ba3821cdf3a6421e089a10bcc670672139542ff3859e3e464fd056aba2`.
The earlier blank pre-stop screenshot is excluded from rendered-UI evidence.
An initial resume exposed repeated `useradd` (exit 9); the corrected path skips
one-time account/GDM provisioning and the subsequent resume passed. This
snapshot predates both native enrollment repository integration and the
unchanged-advisory fast path, so it does not claim those behaviors. This is
encrypted GNOME Wayland VM lifecycle evidence, not a five-scenario assistance
qualification or physical-device validation.

#### Routed split-topology assistance

SSH-native assistance now defaults to a workstation control plane; use
`-colocated` to reproduce the older host-local records above. The workstation
owns the isolated PostgreSQL database, `lindmd` and embedded TURN. The Spark
owns the encrypted KVM guest, QMP and operator Chromium. The controller address
is the source IPv4 route to the SSH host, or explicit `-controller-address IP`.
Its device TLS leaf is run-scoped, signed by the development transport CA and
covers that IP without modifying the shared certificate fixtures.

The guest's one-time enrollment uses the signed localhost console origin through
QEMU's host alias and the SSH reverse admin forward. Thereafter device mTLS and
TURN use the real controller LAN address through QEMU user NAT on the Spark.
The record reports `topology: split`, the routed device/TURN endpoints and the
guest's observed `ip route get` result.
Admin HTTPS and TURN TCP use
`-R 127.0.0.1:ADMIN:127.0.0.1:ADMIN -R 127.0.0.1:TURN:CONTROLLER_IP:TURN`.
The operator test driver filters only ICE server URLs to the forwarded
`turn:localhost:TURN?transport=tcp`, modeling a browser outside the controller
LAN. It preserves the console's own relay-only policy and requires both the
selected local relay candidate URL and `relayProtocol: tcp`. This filtering is
disclosed in the record's boundaries; it is not a product protocol change.

**Passed on 2026-10-11:** the full five-scenario lane on `dgx20`, recorded at
`$HOME/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-assistance-split-03/assistance.json`,
SHA-256 `4177c9d6d2b0a02c9cef0669079a5c1afd3c31f2d5277de168215db8b75e916e`.
This was native aarch64 KVM, Ubuntu 24.04 GNOME 46 Wayland, encrypted storage,
Secure Boot and emulated TPM 2.0, with Chromium 156.0.8078.4 on the Spark.
The guest reported `192.168.0.109 via 10.0.2.2 dev enp0s2 src 10.0.2.15`;
device mTLS reached `https://192.168.0.109:46643`, and the workstation TURN
listener was `192.168.0.109:43905`. Control, view and lock each selected relay/relay
candidates with local URL `turn:localhost:43905?transport=tcp` and relay protocol
`tcp`, decoding 16, 18 and 20 frames respectively. Control delivered the nonce to
the guest; view had no data channel or control permission. Decline, portal
cancel, operator stop, local stop and lock all produced their expected end
causes and audit records; capture stopped for the three live scenarios.

The record binds native lab SHA-256
`4ee2e7092b93588919c05bef31b56e4609736f2cef0645ca1c4fdcec641e073a` and controller
`lindmd` SHA-256 `f364f585726746fba528633b26e44126da637170bba1a3eff0b489530edf835b`.
Reproduce with the aarch64 command above, omitting `-host dgx20` for FIFO host
selection and omitting `-colocated`; choose a fresh evidence directory. The lane
reserves a controller address and ports per run, so these recorded ports are
evidence, not configuration defaults.

The owner's browser uses matching SSH local forwards to the workstation.
For `-hold`, only the workstation creates and stores the owner's console
enrollment in `owner-access` (0400); the remote lane uses its own pre-enrolled
account and never receives the owner's enrollment secret.
The banner waits for real online advisory publication and current device
evaluation, then reports finding counts. A private held marker transfers guest
desktop access and is consumed over SSH, excluded from returned evidence.

The separate split held smoke **passed** on 2026-10-11. Its observed report is
`$HOME/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-held-split-01/smoke.json`,
SHA-256 `cf90f58bf377330efac3ade07c37237ca36a02bd77d2517907aa6226e86b2a07`.
The workstation saw three established device connections from Spark
`192.168.0.20` to `192.168.0.109:45225`; device
`553e6656-36a5-450a-bec7-b37f6606062b` was active with a current presence timestamp
and published inventory. The console stayed at `https://localhost:38345`, with
TURN on `192.168.0.109:34025`.

The first real Ubuntu OSV refresh published 2,157,314 unique records (four
rejected), taking 5m14.943s; the banner waited for evaluation and reported 33,509
affected, zero accepted, zero unknown and zero clear findings. These are actual
finding counts, not a clean-device claim. The owner's access file was 0400 on
the workstation. The printed SSH `assistance-respond ... screenshot` command
succeeded; returned `guest-respond-20261011T115750.899Z-screenshot.png` has SHA-256
`1c72e45ee155d586b686aa40dae76f5f3e19edf36aec3631d38aef97e536d00d`.
Ctrl-C exited 0. Read-only checks found no owned controller process, no listener
on any of those three ports, no owned QEMU or remote run directory, and zero
matching `pg_database` rows (one before teardown). The unrelated owner's Spark
demo was not stopped or modified.

Retained non-passing attempts under the same evidence root:

- `ubuntu24-aarch64-assistance-split-01/assistance.json`, SHA-256
  `a68a962df642c99660552a8e6c9a18f57c9e91070a99cf24294513a53bdbc8a3`: explicitly
  interrupted during guest SSH readiness to apply the enrollment-origin review
  correction; not qualification.
- `ubuntu24-aarch64-assistance-split-02/assistance.json`, SHA-256
  `ebf40983a55acbcc41504b95e293b39a9ed199c5048abef88048c127721b06ee`: control
  passed, including the forwarded TCP candidate URL and typed nonce; view
  reached OFFERED but not ANSWERED/ACTIVE before its 90-second bound. Its guest
  portal and offer succeeded. The lane now preserves a final console screenshot
  on scenario failure; the earlier awaiting-consent screenshot did not show
  that negotiation failure. No bound or consent/media gate was relaxed. The
  instrumented `split-03` run passed; the earlier stall's root cause remains
  undetermined, and the passing record is not a claimed fix for that failure.

#### Fedora 44 aarch64 GNOME assistance

The maintained colocated lane **passed all five scenarios** on `dgx21` on
2026-10-11 from clean source revision `54ad9413490d01b0225eda89db6111ac222eddb6`.
The record is under `$HOME/.cache/lindm-assistqual-20261011/`:

| Record                                           | SHA-256                                                            | Scope                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| `fedora44-aarch64-assistance-03/assistance.json` | `4298e63a70a0b2b1d745714be7dc944381b3ae71f5e17756e024205e136f1d72` | PASS: control, view, decline, portal-cancel and lock; Secure Boot **not enforced** |

This is native aarch64 KVM/QEMU 8.2.2, AAVMF
`qemu-efi-aarch64=2024.02-2ubuntu0.10`, `AAVMF_CODE.secboot.fd` with the
package-owned **unenrolled** `AAVMF_VARS.fd`, UEFI SetupMode, swtpm 0.7.3,
virtio-scsi and a 1280×800 virtio-gpu display. The signed installer manifest is
`fedora-server-encrypted-44-1.7-aarch64`. Guest packages were GNOME Shell and
Mutter `50.0-1.fc44`, portal `1.21.1-1.fc44`, portal-gnome `50.0-1.fc44`,
PipeWire/pipewire-gstreamer `1.6.2-1.fc44` and
gstreamer1-plugins-good `1.28.1-1.fc44`, all aarch64. The operator used Chromium
156.0.8078.4. Native lab SHA-256:
`78b806411e7774c261741cd41b1838aa72497cc3b2bd956093f0bd5c27a641a7`;
server SHA-256:
`7d189b3570c1f8620e8d71de8b3d052a1fed67192ff4208bbdf9ceb95248598f`.

The 35 screenshots and three journals are SHA-256 bound in the record.
The three live sessions decoded 17, 15 and 23 frames and selected relay/relay
ICE pairs, with the console relay using TCP. Control received the typed nonce
through `lindm-input`; view had no application channel or control button.
Audited ends were `operator_stopped`, `user_stopped` (`local_stop`),
`declined` (`prompt_declined`), `declined` (`portal_cancelled`) and
`session_locked` (`logind_lock`). The desktop helper started automatically
in the genuine GDM-autologin Wayland session. GNOME 50 dialog geometry and the
aarch64 GStreamer/PipeWire path needed no product or lane changes; no clicks,
scenarios or mutations were retried to obtain the pass.

```sh
artifacts/bin/lab vm assistance -colocated -host dgx21 \
  -manifest lab/images/fedora-44-encrypted-aarch64.json \
  -repo /home/r/dev/minor/lindm -build-repo "$WORKTREE" \
  -lab "$WORKTREE/artifacts/bin/lab" -lindmd "$WORKTREE/artifacts/bin/lindmd" \
  -cache .cache/lab/images -console-turn-tcp \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -evidence "$HOME/.cache/lindm-assistqual-20261011/fedora44-aarch64-assistance-03"
```

Use a new evidence directory for reproduction. Secure Boot is intentionally
not requested: the owner approved this separate non-Secure-Boot tuple after
diagnosing the enforced attempt. With `AAVMF_VARS.ms.fd` and `-secure-boot`,
firmware loaded Microsoft's signed shim and Fedora's signed GRUB, but GRUB
rejected the DVD kernel with `shim_lock_verifier_write:192:bad shim signature`.
The pristine, manifest-verified DVD's `/images/pxeboot/vmlinuz` (SHA-256
`e55a5f9a9177267f58d1e957f58e6b294a4552cfe7cdf72174e686edd6b474da`)
has **no PE signature table**; `objdump -p` reports a zero Security Directory.
This is an unsigned vendor kernel, not a missing Microsoft CA in AAVMF.
No keys were hand-enrolled, kernel replaced or capability gate weakened.

The initial enforced assistance attempt timed out at the installer; its record
was printed but lost by the then-current SSH evidence-copy omission, already
fixed by `ad1f0c5`. It is not counted as a pass. The maintained
`vm encrypted -desktop gnome -tpm-boot -installer-log FILE` diagnostic was
explicitly interrupted after capturing the reproducible boot rejection.
Retained evidence under the same root:

| Evidence                                        | SHA-256                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| `fedora44-aarch64-encrypted-diagnostic-02.json` | `6a3135ccd2ea6deb2dcc5430a8469aa306f6f7ec8893d14098461033287640b8` |
| `fedora44-aarch64-installer-secureboot-02.log`  | `a3f9327961aec74fa25f6c376429d14f284242a7342b897d1ba9796e5cbe92b8` |
| `fedora44-aarch64-vendor-pe-signatures.txt`     | `de5d305bcc9c28496f17b34d66ec017eca0b2cfbb2b1dc875166af4b6e884cdf` |

The assistance record proves encrypted passphrase boot with a TPM-capable
initramfs and attached software TPM, **not TPM binding or unattended unlock**.
Physical displays/TPMs, enforced Secure Boot, split/routed media, KDE and X11
remain outside this record.

#### Fedora 44 aarch64 encryption and TPM

A separate full `vm device-actions -scenario encryption` record **passed** on
the same `dgx21` native KVM/AAVMF/virtio-scsi/swtpm2 GNOME golden, with **Secure
Boot not enforced**, in 1,832 seconds on 2026-10-11:
`$HOME/.cache/lindm-assistqual-20261011/fedora44-aarch64-encryption-04.json`,
SHA-256 `b7b2c01b354bffb65beb0317b5c51d9865fcd12bd2af2e93590ee8d8a5ccfc6f`.
The record binds clean source `54ad9413490d01b0225eda89db6111ac222eddb6`,
the same native lab/server hashes as the assistance run, and agent RPM
`3c165932ad9ea52c193c3cb93d7c048270c8cb0d0851cafbf153ef5f02f4eca5`.

This is product-action proof, not native setup substituting for the API:

- Real signed escrow/reveal and KEK custody, independently matched LUKS2
  inventory and stopped-disk headers, then a boot with the revealed key.
- Committed rotation removed the retired slot; the retired key was rejected
  at boot and its revealed replacement booted successfully.
- Interrupted rotation at `AWAITING_ESCROW` preserved both keys across cold
  boots and recovered to `OUTCOME_UNKNOWN` in both executor and server.
- Self-approval, changed digest, expired approval, revoked approver, missing
  reveal reason/permission/recent step-up and offline start were denied.
- The signed TPM bind action succeeded, inventory contained `systemd-tpm2`,
  and an independent cold boot unlocked without a passphrase prompt.
- A separately bound deliberately mismatched PCR7 policy refused unattended
  boot; a server-revealed recovery key then booted successfully.

Reproduce with the assistance command's repository, binaries, image cache and
package-owned firmware pins, but invoke `vm device-actions -scenario encryption`
without `-colocated`, `-console-turn-tcp` or `-evidence`; add
`-recovery-manifest lab/images/fedora-44-aarch64.json -record NEW_FILE`.
Keep `AAVMF_VARS.fd` and omit `-secure-boot`. The
[unsigned installer kernel](#fedora-44-aarch64-gnome-assistance) still prevents
enforced-Secure-Boot qualification. PCR7 binding in SetupMode does not establish
an authenticated boot chain. Physical TPMs, wipe/recovery-sanitize and
assistance after TPM-bound boot are not combined claims of these separate runs.

#### Qualification boundaries

An earlier Ubuntu run exposed a product race. GNOME 46 closes the portal session
itself on lock, before logind sets `LockedHint`, so the session ended
`PORTAL_CLOSED`. The executor now holds a helper-reported portal closure for five
seconds, and a lock or logout seen in that window records `SESSION_LOCKED` or
`SESSION_ENDED`. `TestAssistanceBrokerPortalCloseSettlesBehindLock` covers both
outcomes.

These runs do not qualify any of the following:

- A human at a physical display, KDE, X11, older GNOME releases, multi-user or
  shared seats, or suspend/resume.
- Accessibility, or logout and helper-loss paths. Those are covered by broker race
  tests only.
- Network interruption, public-Internet NAT traversal, TURN-over-TLS, bandwidth,
  latency or video quality. Only the routed LAN split path described above is
  qualified across separate lab and controller hosts.
- Air-gapped L16 operation, browsers other than Chromium, or replicated `lindmd`.

The older co-located guests reached the relay through QEMU user networking at
host loopback; the split guest used QEMU user NAT and the routed LAN. GNOME idle
lock was disabled in the lab session.

#### Commercial assistance capability qualification

The [capability contract](product-specification.md#remote-assistance-capabilities)
extends the already recorded view/control baseline. All rows below are **not run**;
neither upstream source inspection nor the earlier assistance records qualify them.
Each future record must identify the code commit, OS/architecture, session type,
portal frontend/backend and compositor versions, scenario outcomes and SHA-256-bound
artifacts. A capability refusal is not a capability pass.

Source research on 2026-10-11, not native qualification:
`$HOME/.cache/lindm-assistance-roadmap-20261011/portal-source-evidence.json`,
SHA-256 `6dcb3eb799e340e0db171538854a32efae98de5513c64e78221ac1876730e307`,
records 63 source-file digests and immutable citations. Clones are under
`$HOME/dev/minor/clones/linux-flavour/<project>-<version>`.

| Source                   | Inspected tag | Commit                                     |
| ------------------------ | ------------- | ------------------------------------------ |
| xdg-desktop-portal       | 1.18.4        | `11c8a96b147aeae70e3f770313f93b367d53fedd` |
| xdg-desktop-portal       | 1.21.1        | `ced43a7c1c61083fac012a7c7991482ed9798fa3` |
| xdg-desktop-portal-gnome | 46.2          | `72d01648ab872c8d849c298fdd9f4d33b5eb820d` |
| xdg-desktop-portal-gnome | 50.0          | `c9a231d3a0c77b6b14f998653b7323858d559dd7` |
| mutter                   | 46.0          | `c4753689e3413cd9332d885dd0297b3b7d9ba9ca` |
| mutter                   | 50.0          | `e25c42e63234a9e3480567ab46ecf20fcefdf938` |

Both source stacks implement Clipboard v1 and multiple selected monitors on an
existing RemoteDesktop session. GNOME 46 has a MIME `(as)`/`as` forwarding quirk;
GNOME 50 normalizes it. See the
[source findings and citations](architecture.md#inspected-gnome-portal-sources).
The old native records omit Mutter packages; inspected Mutter tags are not proof
of exact installed distro builds. New qualification must collect those versions,
distro patch correspondence and the actual Clipboard wire/grant behavior.

| Capability / maintained scenario requirement | Ubuntu 24.04 x86_64, GNOME 46 Wayland                | Fedora 44 x86_64, GNOME 50 Wayland                   | Required independent evidence                                                                                                                                                                                                     |
| -------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clipboard text round-trip                    | Not run; portal source/runtime gate required         | Not run; portal source/runtime gate required         | Fresh nonce copied in each direction into the actual opposite clipboard, policy/consent denial, bounds, withdrawal and session-end refusal                                                                                        |
| Special keys and keyboard layouts            | Not run                                              | Not run                                              | Guest-observed shortcut effect, differing US/non-US layouts, modifier release and no stuck keys                                                                                                                                   |
| Full screen and scaling                      | Not run                                              | Not run                                              | Browser full screen, fit/actual size and correct guest input coordinates without expanding capture authority                                                                                                                      |
| Monitor selection                            | Not run                                              | Not run                                              | Two-head virtio-gpu guest, distinct per-head markers, granted stream selection, pointer mapping and hot-unplug refusal                                                                                                            |
| Operator-to-user notifications               | Not run                                              | Not run                                              | Guest screenshot visibly containing message nonce and correct operator identity; wrong-session denial                                                                                                                             |
| File transfer, admin-to-user                 | Not run                                              | Not run                                              | Downloads file independently hashed, visible completion notification, locally accepted with all remote input paused, no overwrite/execute/traversal/symlink escape; size/type and cancellation tests; independent security review |
| File transfer, user-to-admin                 | Not run                                              | Not run                                              | Actual portal FileChooser selection/cancel with remote input paused, operator cannot approve/select, descriptor-bound regular file and received SHA-256; no arbitrary remote path; permission/size/type rejection                 |
| Reconnect after reboot                       | Not run                                              | Not run                                              | Real reboot, ended old grant, new device epoch/session and fresh consent; expiry/revocation and no pre-consent media/input                                                                                                        |
| Reconnect after logout                       | Not run                                              | Not run                                              | Real logout/login, changed-user isolation, fresh consent and rejected stale session/credentials                                                                                                                                   |
| Recording                                    | Not run                                              | Not run                                              | Visible recording disclosure, playable known screen changes, encrypted-at-rest evidence, retrieval denial, retention deletion, storage failure and termination boundary                                                           |
| Unattended access                            | Not run; implementation requires parent confirmation | Not run; implementation requires parent confirmation | Native persistent-grant capability, local opt-in, independent approval, banner/stop, expiry/revocation and lock/login-screen denial                                                                                               |
| Elevation-prompt guidance                    | Not run                                              | Not run                                              | Real polkit prompt with employee-only typing and remote input paused; no credential collection or bypass                                                                                                                          |
| Pointer/annotation                           | Not run                                              | Not run                                              | Native overlay permission, actual guest-visible marks, stream/scaling alignment, local input unaffected and clear/stop                                                                                                            |
| Audio                                        | Not run                                              | Not run                                              | Separate source consent, known tone received, microphone distinction, local mute and stop/revocation                                                                                                                              |
| KDE Plasma qualification                     | Not run; parent confirmation required                | Not run; parent confirmation required                | Pinned Plasma/KWin/portal-kde versions and independent consent/input/notification/lock plus each supported Tier 1/2 scenario                                                                                                      |
| X11 qualification                            | Not run                                              | Not run                                              | Explicit portal-backed capture/input and local stop, no silent X11 fallback, UID/seat/lock/logout isolation                                                                                                                       |

Other architectures, Ubuntu 26.04, Fedora 43, derivatives and physical hardware
remain **not run** for these added capabilities unless a later exact-platform
record explicitly qualifies them. Old view/control evidence remains valid only
for the scenarios it actually exercised.

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

### Bare-machine console enrollment (2026-10-11)

The initial `lab vm enroll-from-console` observer installed the agent and local
identity on fresh Ubuntu 24.04 and Fedora 44 arm64 cloud guests on `dgx20`, but
**did not qualify enrollment**: it destroyed each guest before the first server
check-in. Neither guest had an agent, identity or enrollment configuration before
the command. After guest
readiness, Chromium signed into the production console with the existing local
owner and native virtual passkey, selected the exact registry OS, clicked **Copy
install command**, and handed the clipboard bytes unchanged to the guest's shell.
The recorded command digest equals the browser-capture digest in each record.
No separately reconstructed install command, preinstalled agent, skipped TLS
verification or externally hosted agent repository was used.

Authenticated inspection subsequently found both devices **Waiting to enroll**,
with no recorded contact. `initial-device-state.json`, SHA-256
`55cf64a46fd02049ce7021153284d2a253189ed13ca38987c41f0aec8273278c`,
records those real console observations. The initial records below are retained
as incomplete evidence, with failed matrix verdicts, not end-to-end passes.
The corrected observer must confirm the exact device's server-side **Enrolled**
state through the authenticated console while the guest is still alive.

Private records and redacted screenshots are under
`$HOME/.cache/lindm-self-hosted-install-20261011/`:

| Guest               | Initial lane record   | Record SHA-256                                                     | Local device identity                  |
| ------------------- | --------------------- | ------------------------------------------------------------------ | -------------------------------------- |
| Ubuntu 24.04, arm64 | `ubuntu-console.json` | `4a5e0a390eb8544314d35c73ea355827c07ebb7d62317baed7480a025c5f0c5d` | `d0d9e735-42b7-48d5-b7e2-30893f574626` |
| Fedora 44, aarch64  | `fedora-console.json` | `f9f22009886975f8794d2ff5581e1f4338998869b4a94690d8009d5b62c40b3f` | `71daa436-fc77-47a2-8a35-02653df1fcdc` |

Both commands installed the same agent payload, SHA-256
`0924f146d572f77967e7c90457057224bdd0766ffc961061e4ef9ee120ba4da5`,
from the customer's own `lindmd` origin. Ubuntu used the signed APT InRelease,
architecture-specific Packages index and deb822 `Signed-By` source; Fedora used
signed RPM metadata and packages with both signature checks enabled. The DEB
digest is `2d4ef89b79b919a2cc0372a717c396bd0d30297745eff0a90f6c5832c9e2d588`;
the signed RPM digest is
`2583beeb079f408792a43836dc10ce525961b332b2995665e10a4169fe46cca1`.
The publication record `publication-final.json` has SHA-256
`e9d36593f4efff32304813f861cc92700db506c60ca15999f5e003988b3cce0f`.
The public signed repository bytes are retained in the evidence directory's
`repo/`; private signing custody is not part of that evidence.

The native runner and production server were built from
`b5371c876b48a9eecdae167a7eea39119c36027a`, with the recorded source delta
`native-source-delta.patch` (SHA-256
`fb545444690aaf4ca46d0bcf2e1fc960ca825019868aad162dc5f7d7ff8f486c`).
`native-build.json` binds the exact binaries and has SHA-256
`91463f1cabb7e001ae0e32bc3ef6cd811531e864d723f5c52a276b6b7c88a602`.
The runner executed on `dgx20` with its normal five-slot admission namespace and
owned cleanup completed. SSH reverse forwards preserved the configured HTTPS
admin/device origins; the copied command still authenticated the server CA,
package signer and execution root. This was QEMU 8.2.2 on native aarch64 KVM,
package-pinned AAVMF `2024.02-2ubuntu0.10`, UEFI SetupMode with Secure Boot disabled,
virtio-blk, no TPM or desktop, and explicit user egress. It is not physical,
Secure Boot, full lifecycle or complete release-acceptance qualification.

`ubuntu-screenshots/` and `fedora-screenshots/` contain the copied-command dialog
and Settings repository readiness in light/dark desktop/mobile variants. For
example, `chromium-grant-grant-apt-light-desktop.png` and
`chromium-grant-grant-dnf-dark-mobile.png` show the corresponding OS selection.
Editable and command regions are deliberately masked; no enrollment code,
password, passkey state or copied script belongs in published screenshots.
The matrix cell is `enroll-from-console`; its browser configuration is private and
the [engineering runbook](engineering.md#bare-machine-enrollment-from-the-console)
describes the fixture and maintained command.

**Corrected end-to-end runs passed** on both fresh arm64 guests. The maintained
SSH-native runner now invokes the real console a second time before teardown,
signs in with the same owner's updated virtual passkey, and waits for the exact
installed device's lifecycle badge to become **Enrolled** after its real check-in.
That read-only confirmation is mandatory; a local identity alone cannot publish
a passing record. The native installation command is unchanged.

| Guest               | Final lane record               | Record SHA-256                                                     | Server-confirmed enrolled device       |
| ------------------- | ------------------------------- | ------------------------------------------------------------------ | -------------------------------------- |
| Ubuntu 24.04, arm64 | `ubuntu-console-qualified.json` | `f635617984f558831883501a018f2f88d3cc256db30ef7adf7b3bec15f710e51` | `f35e8a28-28b7-4115-b4e5-1d47b309c614` |
| Fedora 44, aarch64  | `fedora-console-qualified.json` | `51ece6fc1c1a4da9d730f930fc2a8a18f9b26e63542089d9ef221d2df8c99bd4` | `e7bdd37d-4f22-42c2-aa80-37928cd08fec` |

Each final record includes `pristine: true`, `owned_cleanup_complete: true`,
matching `command_sha256`/`browser_capture.command_sha256`, and
`console_enrollment.lifecycle: "Enrolled"` bound to that device ID.
Both installed the exact payload
`ef9ff5476f835796bb90972306ca88022e2e73b5952bf5315e8dea3e65f85995`.
The signed native publication record `publication-qualified.json` has SHA-256
`8235db40db7453a0e985ca2af14f9f89f069ae50a1176bb70b33e96f0c0ea477`;
DEB digest `c3f83d6e488cadc93e2674eee1229059228b4f9cf1e30015df3f80a633b3f5fd`,
signed RPM digest `39b742406947c769ca02eebb01cec23775895aab72285adbb2d32eeb0bc61657`.
The served repository bytes are retained under `qualified-repo/`.

Source is `ca1e8d72bf559c9ef3105a41cd081a5559ca0e47` plus
`qualified-source-delta.patch`, SHA-256
`30ca483ce55c981a4c12579015d3235c22c9d0d361ea07c8b3b64dda08585c65`.
`qualified-build.json` binds local runner/server binaries and publication, with
SHA-256 `ece3ad9f2658033e7798163886013bd2f105bba457c6f191f22f5f6730e6e1a1`.
Both lane records carry `lab_host` provenance for `dgx20`, SSH transport and native
runtime. The normal remote adapter cross-builds the guest observer, provisions
the pinned user-owned Chromium runtime, preserves both HTTPS origins through
reverse forwards, privately returns the updated passkey counter, relocates every
nested screenshot reference to its returned local copy, and removes its owned
remote run. Firmware/hardware boundaries remain those stated above.

Final dialog/Settings captures are in `ubuntu-qualified-screenshots/` and
`fedora-qualified-screenshots/`, including light/dark desktop/mobile variants.
Each directory also contains
`chromium-enrollment-status-confirm_enrolled_device.png`, showing the real
**Enrolled** badge, observed OS/architecture, hostname, current contact and
inventory on that device. The dialog variants now use viewport screenshots,
with advanced credential details collapsed and sensitive command areas masked.

The final maintained visual gate
`make ui-review UI_REVIEW_REPO=/home/r/dev/minor/lindm
UI_REVIEW_EVIDENCE=/home/r/.cache/lindm-self-hosted-install-20261011/ui-review-03`
passed **168 of 168 captures**, with zero findings. It used the actual unpublished
demo fixture for configuration remedies and a separate real signed APT/RPM
publication for enabled OS selection, clipboard equality and trust disclosure.
`ui-review-03/report.json` has SHA-256
`552acce9f851f01f73605e60171929aeba31080765b52604b4a0a2866b071f08`;
the contact sheet `ui-review-03/index.html` has SHA-256
`5f21901adf3acfef1b6bbdddc2431902b54f2387381508b9f81ac2b23ff43a4f`.
The earlier `ui-review-02` reported scrolled Settings rows occluded by the sticky
header as overlaps. The review now restores its initial viewport after disclosure
interaction before applying unchanged layout, accessibility and copy checks;
no tolerance or overlap rule was weakened.

Required design review: **decision—pass** (choose the target OS, copy one install
and enroll command); **evidence—pass** (real signed publications, both native
clipboard lanes and exact server-side Enrolled state); **restraint—pass** (one
primary installation action, technical trust/credential detail disclosed on
demand); **safety—pass** (single-use secret masking, protected stdin/file delivery,
CA/signer/root verification and explicit setup gates); **craft—pass** (light/dark
desktop/mobile review and bounded command field); **human editing—pass** (the
initial full-height command field was reduced, advanced details collapsed in the
default capture, and misleading full-page mobile captures replaced by viewport
captures). Before-edit captures are in `owner-screenshots/`, after-edit native
captures in the two `*-qualified-screenshots/` directories and the final contact
sheet. There are no recorded unresolved owner annotations for this slice;
automated green does not constitute owner design approval.

### Customer-journey release acceptance

`make acceptance` runs the maintained `lab acceptance` command, not a composition
of previously successful bespoke scenario records. It owns an isolated real
local-auth server/database and fresh browser accounts. `make check-web` runs the
same owner enrollment, fresh sign-in and one-time-code/provisioning-token UI journey
without claiming native or vendor-feed qualification. Both commands fail on an
unqualified browser engine; an unsupported virtual authenticator is not a pass,
except for the WebKit upstream prerequisite below.
Install the recorded browser prerequisites with `make browser-baseline`.

For independent native/UI diagnosis while a vendor feed defect is being repaired,
`lab acceptance -skip-feeds` runs the same stock guests and browser assignment
journey without advisory refresh or exposure qualification. Its record is labelled
`diagnostic-skip-feeds-NOT-A-RELEASE-PASS`, `passed` is false and the command exits
unsuccessfully even if every exercised native assertion passes. It cannot replace
the mandatory full default run or silently reuse an older feed publication.

The pinned Playwright Chromium lane uses its native CDP virtual authenticator.
Firefox uses pinned Firefox/geckodriver and W3C WebDriver virtual authenticators.
WebKitGTK uses the packaged WebKitWebDriver/MiniBrowser under Xvfb. Its exact
package version and capabilities are recorded. When that build answers the
virtual-authenticator command with WebDriver `unknown command`, the passkey phase
is recorded as `passkeyPhase.reason: unqualified_upstream_prerequisite` and does
not fail the release gate. This is release policy for an upstream gap, not a
passkey qualification. The WebKit Origin/Referrer regression step remains
mandatory and must pass first; any other WebKit authenticator failure still fails.
No JavaScript replacement for `navigator.credentials`, forged session, intercepted
RPC or authenticated-cookie import counts as a login.

The maintained runner interface is `node web/acceptance/run.mjs PRIVATE_CONFIG`.
Its private JSON specifies `mode` (`enroll`, `grant` or `native`), `engine`, `origin`,
`username`, `password`, `enrollmentSecret` for enrollment, `credentialPath`,
`resultPath`, `evidenceDirectory` and a bounded `timeoutMs`. Native mode also
specifies `deviceId`, `profileRevisionId`, `storageActions` and `requireNoWWN`.
The grant-only mode authenticates the existing browser owner and issues a fresh
single-use code after the native guest has its lease and installed package; queue
time cannot consume that code's short lifetime.
Only the owned disposable fixture permits certificate-error tolerance; this does
not change the real browser origin, Referrer-Policy or server CSRF enforcement.
Raw browser results and generated customer commands contain secrets and must not
be copied into the public report. `lab acceptance` performs that separation.

Both modes publish real signed amd64 APT and RPM agent repositories from the
checkout under test into the disposable server fixture. This satisfies the console's
install-command readiness prerequisite without weakening it or fabricating commands;
web-only mode still makes no native installation or vendor-feed claim.
The Origin diagnostic reads the HTTP status token without requiring a particular
administrator-facing sign-in error sentence. Select locators exclude closed popup
subtrees retained for exit transitions: Firefox otherwise finds an old option before
the next popup opens, whose disabled pointer events leave the credential dialog's
snippet textarea under the click. Waiting for the live option preserves native
browser clicks, without forced clicks or synthetic input.

The native gate boots the pinned Ubuntu 24.04 and Fedora 44 cloud images, then the
vendor-installer Ubuntu encrypted image, on virtio-blk without an invented WWN.
The encrypted guest has an swtpm TPM 2.0 so the escrow-rotation, encrypted-wipe
and TPM-bind target pickers are each observable; no TPM unlock is enrolled.
Only ordinary authenticated agent installation and documented enrollment commands
precede inventory collection. Stock background package units are not masked to
make this gate green. Each VM retains its host lease through owned teardown, runs
sequentially, and does not touch demonstration guests. After stock observations,
an owned harmless service unit supplies the independent native proof for a profile
assigned through the console.

Example (firmware values must match the installed package, never guessed):

```sh
make acceptance ACCEPTANCE_EVIDENCE="$HOME/acceptance-20261010" \
  ACCEPTANCE_FLAGS="-firmware-code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  -firmware-package ovmf -firmware-version INSTALLED_VERSION"
```

Use Secure-Boot-capable code with unenrolled variables for the off tuple:
SecureBoot=0/SetupMode=1 must be observed. The generic `OVMF_CODE_4M.fd`
may omit the variable entirely, which is unavailable, not proof of disabled
enforcement; the encrypted posture gate correctly rejects that prerequisite.

The gate refreshes the complete Ubuntu OSV export, Fedora repository updateinfo
and paired Red Hat CSAF archives through the production parser/publication path.
Fedora updateinfo is not mislabeled as CSAF. The digest-addressed cache revalidates
with the live vendor before reuse and rehashes cached bytes; offline bytes alone
never establish current coverage. Defaults are a 2 GiB aggregate input budget and
15-minute refresh budget, in addition to production per-source limits. Malformed
upstream records remain explicit rejections, never cleaned fixtures. A device
whose exposure remains unknown fails the known-exposure assertion.

`acceptance.json` and engine/native screenshots are written in a new private
evidence directory on success and failure. Browser credentials, enrollment
secrets and authenticator state live in a separate temporary private directory
removed at teardown; ordinary evidence never includes them. Browser failures do
not suppress independent feed checks. The report distinguishes web-only from
release mode and records cleanup, exact source digests and native outcomes.
This is VM evidence, not physical-disk or hardware-authenticator qualification.

The first full maintained run on 2026-10-10 failed honestly after 2786.6 seconds:
`~/.cache/lindm-acceptance-20261010-01/acceptance.json`, SHA-256
`5ef007bd0cc52698432d4add4bcce2bfbc13754d70a78ebcaa605250543ba252`.
Owned fixture/guest cleanup completed. Chromium 156.0.8078.4 completed enrollment,
two real sign-ins, grant issuance and provisioning-token issuance. WebKitGTK
2.52.6 returned `unknown command` for native virtual-authenticator creation and
its page lacked the required WebAuthn capability; its password phase did not
reach a POST and is unqualified, not an Origin-policy pass. Firefox 157.0.1
remained waiting for its native authenticator during enrollment.

The same run published the real 777,941,722-byte Ubuntu export (2,157,214 claims,
10 explicit rejections in that build) and Fedora's 4,301 claims. It rejected the
real signed Red Hat archive at `rhsa-2006_0661.json`; later parser changes require
a new run. Native failures exposed harness defects before product qualification:
the initial 15-minute grant expired while queued for a host lease, and the harmless
probe name incorrectly used the protected `lindm-` service prefix. Fresh UI grant
issuance after guest readiness and an admissible probe name correct those paths.
Fedora's successful provisioning additionally exposed a genuine not-applicable
seat field on a native `manager`/`unspecified` logind session; its exception must
remain capability-guarded. Encrypted first-boot posture failed before agent
enrollment; subsequent diagnostics identify the exact native prerequisite instead
of weakening the gate or silently adding a TPM. None of these failed native rows
qualifies inventory, storage selection, profile effects or known device exposure.

The corrected browser run
`~/.cache/lindm-acceptance-origin-20261010-02/acceptance.json` (SHA-256
`fac61c6f48c46c3420bccab821b64ef6d42fe22794e0b34af675e56afff2654a`)
passes the complete Chromium and Firefox journeys. Firefox's disposable native
profile selects its TestTokenManager instead of physical USB; it does not replace
the JavaScript credential API. WebKit additionally calls the actual loaded
console `beginLogin` client with a secret-free invalid body: the served document
has `Referrer-Policy: same-origin` and the real CSP, and the server returns 400,
not 403, after its Origin check. This catches the Safari `Origin: null` defect
class without claiming WebAuthn. The packaged WebKit build still lacks
`PublicKeyCredential` and native virtual-authenticator support, so its passkey
phase and the overall release gate remain explicitly unqualified.

The `-skip-feeds` diagnostic `~/acceptance-skipfeeds-20261010T150048Z` (not a
release pass) and three later full runs exposed and corrected further harness
defects: the session oracle ignored the not-applicable seat rule; the LUKS and
NVMe oracles probed without the inspected agent's root privilege; the snap oracle
treated `snap list`'s informational no-snaps stderr as a command failure; the
guest forwarded the device listener at its allocated port instead of the signed
bundle's `https://localhost:18445` device origin, so the agent never synchronized;
the profile picker read options before the popup mounted and per-guest profiles
shared one label; the fixture had no execution signing or admitted delegation, so
an accepted assignment never became device work; and the encrypted guest lacked
the TPM that makes the TPM-bind target observable. Inventory-timeout, health and
profile-effect failures now save private guest unit, journal, kernel and audit
diagnostics under the lab work directory.

The full run `~/acceptance-full-20261010T183751Z/acceptance.json` (SHA-256
`97d77ecb28dc17e2d9f4faee5cb335c4494f16f280c7b686e48df996c3eaee46`) **failed**.
Feed refresh, including Red Hat CSAF, completed in 570 s. Chromium and Firefox
passed. All three guests enrolled through UI-issued credentials, matched strict
native inventory and verified the console-assigned service profile natively. The
encrypted guest's escrow-rotation, encrypted-wipe and TPM-bind targets were
selectable. WebKit's missing virtual authenticator failed that run; it predates
the upstream-prerequisite policy above. Remaining product failures:
`ListDeviceFindings` exceeding its response deadline because the read path
re-evaluates against about 2.16 million Ubuntu records after a refresh; Fedora
exposure `package_architecture_uncovered` from `gpg-pubkey` rows with an empty
architecture; and Fedora's published storage `UNAVAILABLE` because the
executor's root inventory observation failed (`recovery_readiness_executor_unavailable`)
while the same root `inspect` collection succeeded.

The Fedora storage failure was reproduced on Fedora 44 Cloud 44-1.7 aarch64
under dgx20 KVM with SELinux Enforcing: `systemd-run --pipe` passed the executor's
pipes through dbus-broker, whose `dontaudit`ed `fifo_file write` denial reset the
connection ([Fedora quirk](platforms/fedora.md#agent-services-and-sandbox)).
Record `~/.cache/lindm-readiness-20261010/fedora44-arm64-dgx20-dispatch-repro1.json`
(SHA-256 `ac923c07d0180d40c87944be217a41f5774d0957005eda21d3ba52b81744ebf1`) holds
the executor journal line; `fedora44-arm64-dgx20-dispatch-probe2.json`
(`1ae232be4791fc483e7bc9fd2c4a527e7eb8348ed1c92399df77634869c1196a`) holds the
denial. The executor now starts the helper over PID 1's private socket. `lab vm
dispatch` now fails unless the first published host observation carries executor
root storage. From source `efa7892` plus diff
`8e56306ffad57d221eae6161f170cfd933fae85cd958369da9bd634daf21650c`, both arm64
dispatch lanes passed with storage `SUCCESS` (five devices), firmware `SUCCESS`,
`smbios_type4` CPU source and the executor's own readiness reason
`recovery_readiness_not_configured`: Fedora 44 Enforcing
`fedora44-arm64-dgx20-dispatch-final.json`
(`21e4134baa75aeb309148bebfec589bc47d77ba06e22782ac17602c554ae4eb0`) and Ubuntu
24.04 `ubuntu2404-arm64-dgx20-dispatch-final.json`
(`56dac71a1722617f2d196ef772b4a421a82a9f9f421a5612bbfb7bbd214c19a8`), with no
AppArmor denial.

Release acceptance `~/acceptance-full-20261010T195842Z` still failed Fedora 44
x86_64 storage. The private-socket call itself reset: sd-bus read the
descriptor-carrying start together with BEGIN
([Fedora quirk](platforms/fedora.md#agent-services-and-sandbox)). A local
Fedora 44 x86_64 stress run called `GetRecoveryReadiness` directly in bursts and
concurrently with `load_policy`, daemon-reload and `enable --now` plus agent
restart. Before the fix, 11 of 44 calls reset within 5 ms with no AVC, and one
more failed because readiness treated a daemon-reload `UnitRemoved` as final:
`fedora44-x86_64-local-dispatch-probe5e.json`
(`ca68d6cc4786d502af1c1a484b602d43fc75d35d6479657c18315cbb3def146a`). A single
handshake Ping replaced the reset with a 12 s stall in 8 of 36 calls
(`fedora44-x86_64-local-dispatch-stress-fixed.json`,
`6deaa16be8d8013695acd8a0d2dfbfed312702c3669562d8553e3a58a76c5b7b`). With repeated
Pings, all 44 calls succeeded in at most 168 ms
(`fedora44-x86_64-local-dispatch-stress-fixed2.json`,
`78cc22c8e1af8d54027c9e0881cc8cabf7a66b3cdb838923bb1eef645b149670`). From
`efa7892` plus diff `0b2e8f32e6f83de1031e974ca089b996afb447a0d407bc8abfe9b7d36b9bfd72`
(a later race-detector fix touched only the launcher test fixture), three
dispatch lanes passed with executor storage `SUCCESS`. Fedora 44 x86_64
Enforcing: `fedora44-x86_64-local-dispatch-final2.json`
(`1a4467bfac9d21dbfdd998a58554d7b49fcea8689a62141330ceb0e248666007`). Fedora 44
aarch64 Enforcing on dgx20: `fedora44-arm64-dgx20-dispatch-final2.json`
(`d1e639e439673253f733898f1aa73c57990841d07b3b33d478c79a7a5836f614`). Ubuntu
24.04 arm64 on dgx21: `ubuntu2404-arm64-dgx21-dispatch-final2.json`
(`44d0288f8062265299b5e46858f0f186bc24e94528bde2f0fd7154c502534cc1`). All records
are in `~/.cache/lindm-readiness-20261010/`.

Advisory exposure also failed in those runs. In `195842Z` the evaluator was gated
on the server's own (empty) feed list while the gate's fixture published the
feeds, so Ubuntu stayed `evaluation_pending`. In `~/acceptance-full-20261010T222202Z`
(Fedora fully passed, exposure `vendor_findings_present`) one 500-package window
of the real Ubuntu 24.04 inventory joined 79,359 candidate records from kernel
binaries and tripped the per-window row cap (`matching_capacity_exceeded`).
Matching now pages candidates by `(position, record id)`, the evaluator serves any
feed configured in the database, and the admission bound is 100,000 findings.
Offline against the same 2,157,314-record export, the 665-package acceptance
inventory evaluates to 28,821 findings in about 1.5 s, with 100 device reads under
5 ms each ([architecture](architecture.md#distro-advisory-findings)).

Release acceptance `~/acceptance-full-20261010T234632Z/acceptance.json`
(SHA-256 `e8c5db7df90e6943aca10cfcbe4a5d704bf465c470ce2b1b846a5beda67ab79c`)
**passed** in mode `release` in 1,318 s with owned cleanup complete. Feed refresh
(Ubuntu OSV 2,157,314, Red Hat CSAF 1,892,833, Fedora updateinfo 4,301 records)
took 592 s of its 900 s budget. Chromium, Firefox and WebKit passed. Stock
Ubuntu, Fedora 44 x86_64 and encrypted Ubuntu each passed inventory health
(Fedora storage now from the executor), the native profile effect and a known
exposure (`vendor_findings_present`). Server SHA-256
`8cc6249d4cda60e8341def8ef277ca267d0bc2be21292f0fd8dd405a0b6b038a`, lab SHA-256
`ae858d5a73e7dc0cd3e6519ca6a8eb8c551ace57eb854e377f706acfec9e00db`.

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
