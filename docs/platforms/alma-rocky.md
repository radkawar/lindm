# AlmaLinux and Rocky Linux

## Versions, architectures and qualification

AlmaLinux and Rocky Linux are independent qualification rows, not aliases for RHEL
or for one another. The launch targets are each vendor's 9 and 10 current minors
on x86_64 and aarch64 server, with separate legacy 8 rows. These are requirements,
not certified support. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative; a package architecture, acquired image or upstream compatibility
claim cannot qualify a native capability.

Exact image release, size, digest and signature provenance live in each
[`lab/images`](../../lab/images) manifest. For example,
[`almalinux-9.8-x86_64.json:2-18`](../../lab/images/almalinux-9.8-x86_64.json#L2-L18)
pins GenericCloud 9.8-20261005 and its detached checksum signature. Do not silently
replace the pinned image with the latest object behind a vendor directory.

## Packaging, signing, repositories, paths and LSM

Use native RPMs, independently verified against the configured package signer.
The builder signs then verifies before recording the release artifact
([`packaging/rpm.go:50-79`](../../internal/packaging/rpm.go#L50-L79)).
RPM config files use `%config(noreplace)` and package lifecycle scriptlets
([`rpm.go:83-112`](../../internal/packaging/rpm.go#L83-L112)).
Repository/package trust is explicit: package and local-package checks remain on,
and repository metadata signing is separately represented
([`publish.go:43-58`](../../internal/packaging/publish.go#L43-L58)).
A local dependency-satisfied RPM transaction does not establish connected vendor
repository or air-gap lifecycle support.

The binary is `/usr/libexec/lindm/lindm-agent`; configuration is
`/etc/lindm/executor.json` and `/etc/lindm/agent.json`, with separate state below
`/var/lib/lindm/executor` and `/var/lib/lindm/agent`. Keep vendor SELinux Enforcing.
AlmaLinux 9.8 x86_64 dispatch and the independent Rocky 9.8/10.2 ARM lifecycle
and dispatch records below retained Enforcing. AlmaLinux 10 inherits none of those
results. RHEL subscription-manager registration and Red Hat entitlement evidence
do not describe derivative repository access.

## Agent services and sandbox

The packaged root executor is AF_UNIX-only with strict filesystem protection,
private devices, no-new-privileges, no swap and no core dumps. The network agent
runs as `lindm` without capabilities and cannot access protected executor state.
Exact native action devices require the reviewed owned sandbox drop-in, not a
blanket device exception. Sources:
[`lindm-executor.service:10-61`](../../internal/packaging/assets/lindm-executor.service#L10-L61)
and [`lindm-agent.service:11-50`](../../internal/packaging/assets/lindm-agent.service#L11-L50).

AlmaLinux 9's **dbus-broker v28 argument-filter bug** is a real compatibility
boundary. `AddMatch` accepts `arg2='unit'` for systemd's `JobRemoved(uoss)` signal
but that match can silently lose the completion signal. The provider therefore
matches the authenticated manager's sender/path/interface/member and checks the
exact job and unit locally, rather than treating the lost signal as successful
execution or extending a timeout
([`serviceprovider/native_linux.go:271-281`](../../internal/agent/serviceprovider/native_linux.go#L271-L281)).
The wire regression documents simultaneous broad/argument-filtered native
observations ([`native_linux_test.go:71-75`](../../internal/agent/serviceprovider/native_linux_test.go#L71-L75)).
This correction is not permission to accept another job's result or to relax
sender authentication. Do not assume the same failure or success on Rocky solely
because its package family is RPM.

## Inventory and per-field quirks

The installed-package backend selects explicit `almalinux` or `rocky` identity,
requires an actual RPM database, and queries name, epoch, version, release,
architecture and modularity label. It does not select on `ID_LIKE` and rejects
OSTree/transactional markers
([`inventory/packages_linux.go:46-85`](../../internal/agent/inventory/packages_linux.go#L46-L85)).
Warnings or native failures do not become empty successful inventories
([`packages_linux.go:148-152`](../../internal/agent/inventory/packages_linux.go#L148-L152)).

The existing DNF4 configuration helper reads configured enabled repository IDs
and explicit releasever locks without plugins, metadata or network activity
([`platform_dnf.py:72-130`](../../internal/agent/inventory/platform_dnf.py#L72-L130)).
CPE is independent os-release evidence
([`platform_linux.go:41-64`](../../internal/agent/inventory/platform_linux.go#L41-L64)).
Missing configuration/API capability, absent lock, empty enabled repositories and
read failure must remain distinguishable. Derivative CPE/repository values must
not be relabeled as Red Hat EUS/E4S evidence.

## Updates

Agent self-update is not a generic package-management provider or a major-version
OS upgrade. Native agent update checks actual RPM identity and architecture,
and rejects immutable markers
([`update/native_linux.go:111-147`](../../internal/agent/update/native_linux.go#L111-L147)).
Fedora DNF5 update or package-resource evidence does not qualify these vendors'
DNF4 transaction behavior. Each derivative/minor needs its own signature rejection,
upgrade, reboot, removal/reinstall, recovery and interruption records.

## Encryption and recovery

Do not inherit Fedora or Ubuntu LUKS2, cryptsetup, TPM, Secure Boot or recovery
results. Qualify the actual derivative kernel/initramfs/systemd stack, exact
storage identity, enrolled firmware keys and both normal and recovery boots.
The packaged executor intentionally hides disks and TPMs until reviewed exact-node
provisioning ([`lindm-executor.service:21-30`](../../internal/packaging/assets/lindm-executor.service#L21-L30)).
[Verification](../verification.md#encryption-and-imperative-action-evidence-l10-l13-l15)
defines the required independent evidence; successful RPM installation or service
dispatch is not a recovery/erase result.

## Device actions

The AlmaLinux service result below covers signed systemd service dispatch, not
GNOME lock, account lock, quarantine, power actions, encryption or sanitize.
Keep server/minimal and desktop rows separate and follow each action's native
qualification record in [verification](../verification.md). An unavailable native
capability must remain unavailable, not a compatibility fallback to an unrelated
distribution or command.

## Advisory feeds

Fedora's updateinfo adapter explicitly refuses other distro identities
([`advisory/feed/rpm.go:51-59`](../../internal/advisory/feed/rpm.go#L51-L59)).
Red Hat CSAF applicability requires actual Red Hat CPE and corresponding native
repository/stream evidence
([`advisory/platform.go:11-72`](../../internal/advisory/platform.go#L11-L72)).
Therefore neither feed establishes AlmaLinux or Rocky coverage by compatibility
inference. Vendor-specific feed mapping and fresh complete coverage need their own
qualification; missing coverage is not zero exposure.

## Lab

Use each vendor's pinned manifest with maintained `lab images fetch`, offline
`lab images verify`, then native inspection/lifecycle/dispatch as documented in
[agent enrollment](../agent-enrollment.md) and [verification](../verification.md).
Retain image, architecture, firmware, SELinux, native versions, source and result
digests. The current independent status is:

| Vendor/image          | Observed evidence boundary                                                                                                                                                                         |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rocky 9.8 x86_64      | Native inspection matched 422 RPM records; no completed lifecycle/dispatch is claimed here.                                                                                                        |
| Rocky 10.2 x86_64     | Native inspection matched 443 RPM records; no completed lifecycle/dispatch is claimed here.                                                                                                        |
| AlmaLinux 9.8 x86_64  | Native inspection matched 387 RPM records. Earlier packaged lifecycle failed signed service; corrected connected dispatch passed independently. A full packaged lifecycle rerun is still required. |
| AlmaLinux 10.2 x86_64 | Authenticated acquisition is not a native inspection/lifecycle pass.                                                                                                                               |
| Legacy 8              | Consult each vendor's separate acquisition/native rows; do not inherit 9/10 results.                                                                                                               |
| Rocky 9.8 aarch64     | Passed inspect (418 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 420-package publications), and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                  |
| Rocky 10.2 aarch64    | Passed inspect (440 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 442-package publications), and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                  |
| AlmaLinux aarch64     | Signed acquisition/offline verification does not qualify native lifecycle; await each completed machine record independently of Rocky.                                                             |

The AlmaLinux corrected dispatch record is
`$HOME/.cache/lindm-alma-servicefix-20261010/alma9-dispatch-after.json`, SHA-256
`1879713374fba6153867c4a6eb24ad910ff9991a7299152cc15808b5f3b4cbd4`.
It proves nine native scenarios with SELinux Enforcing; the tenth listed scenario,
unstarted supersession, is explicitly integration-only. It does not rewrite the
historical failed packaged lifecycle.

The five aarch64 acquisitions (Rocky 9.8/10.2 and AlmaLinux 9.8/10.2/8.10) are
recorded in `$HOME/.cache/lindm-mutabledistros3-20261010/arm64-acquisition.json`,
SHA-256 `1c7b1bfe9711e92d513c768a72cfddc430bdc3dc3dac601e52c2885651d0d5fb`.
This is image authenticity/offline-cache evidence only, not an executed ARM pass.

Independent Rocky ARM passes use source `d303cecb69bc041328438538a2e3bbf084ac06fb`
plus lab-only diff `8c30afa7e3e809009ec39cc777f8130efdf0d076101035ff8ac5f6d24eab3263`.
The delta repairs missing native route/session truth and preserves signed package
basenames during remote staging; it does not alter product behavior or skip gates.
Runtime is native aarch64 KVM/QEMU 8.2.2, AAVMF `2024.02-2ubuntu0.10`, Secure Boot
disabled/SetupMode true, virtio-blk, no TPM/desktop and explicit user egress.
Both lifecycles passed signature rejection, enrollment, upgrade, changed-boot-ID
reboot, retained purge/reinstall identity, spool recovery, denied collection
preserving snapshot 5, independent final revocation and missing-journal hold.
Both dispatches passed periodic compliant recheck/drift remediation and revoked
denial; unstarted supersession remains integration-only. No x86_64, AlmaLinux,
air-gap, desktop or physical capability is inherited.

Records below are under `$HOME/.cache/lindm-mutabledistros3-20261010/`:

| Record                               | SHA-256                                                            |
| ------------------------------------ | ------------------------------------------------------------------ |
| `rocky9-arm64-dgx20-inspect.json`    | `e8b1d77d1c81b02ae833afc8cd7849d37557371b019f5726a264b9159f6bf3db` |
| `rocky9-arm64-dgx20-lifecycle.json`  | `c7b95fddeef7c28d396901993e920989c0970a56810de7b3f114ee345ad0c5d0` |
| `rocky9-arm64-dgx20-dispatch.json`   | `bb17111467ecef3bb47d0fb2fc898a49415c411dc0fd15e2c819f2e8b7830ed4` |
| `rocky10-arm64-dgx20-inspect.json`   | `8e82dfa7570d14b8e30b8da2f77cd3b48d63650519b11d9897827cd117743049` |
| `rocky10-arm64-dgx20-lifecycle.json` | `c4713821b59c9938a44b81fec68c5df7d6e1ad922e0641c7690a835c2de04df9` |
| `rocky10-arm64-dgx20-dispatch.json`  | `34bd45508a999bc54cc861b8d5d9f8d31db8305b99396345a802953f47a192bc` |

The original x86 records are under `$HOME/.cache/lindm-mutabledistros-20261010/`,
indexed by its `evidence-index.json`:

| Record                         | SHA-256                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `rocky9-inspect-uefi.json`     | `7920e3335d6c54fefdb90c124efb5253aa0bc8658e0cbc1704aefadc7b4b2307` |
| `rocky10-inspect-uefi.json`    | `55d62d0aadd2bf1dbf51e1c6636578b8982399678bdf037eeae3fa526221b365` |
| `alma9-inspect.json`           | `487aecbba8bc98572eee98b0918b6918e09b796b2cb231df2fd2926bc3c93f54` |
| `alma9-lifecycle-failure.json` | `ab55a20dd1642391bb8d315d1e5346e01778636ea440553a983cbd0ded489b2f` |

## Gaps

Rocky x86_64 and AlmaLinux still require the separate complete lifecycle cells
not passed above. Desktop, legacy, air-gap, actions and physical-machine evidence
remain exact-scope requirements. The dbus-broker fix closes a demonstrated AlmaLinux
signal-delivery issue, not the entire derivative matrix. Derivative advisory
coverage and generic package resources must not be inferred from RHEL/Fedora.
