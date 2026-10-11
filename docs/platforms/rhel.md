# Red Hat Enterprise Linux

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | RHEL 8                                                                                                                          | RHEL 9                                                                                    | RHEL 10                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                                                     | implemented                                                                               | implemented                                                                               |
| lifecycle         | gated: not implemented for RHEL 8                                                                                               | implemented                                                                               | implemented                                                                               |
| dispatch          | gated: not implemented for RHEL 8                                                                                               | implemented                                                                               | implemented                                                                               |
| packages          | gated: systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240 | implemented                                                                               | implemented                                                                               |
| accounts          | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                               | implemented                                                                               |
| sysctl            | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                               | implemented                                                                               |
| definitions       | gated: systemd 239 is below the definition provider floor 252                                                                   | implemented                                                                               | implemented                                                                               |
| password          | gated: not implemented for RHEL 8                                                                                               | implemented                                                                               | implemented                                                                               |
| firewall          | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                               | implemented                                                                               |
| encryption        | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| wipe              | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| report-loss       | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| lock              | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| recovery-sanitize | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| self-update       | gated: not implemented for RHEL 8                                                                                               | implemented                                                                               | implemented                                                                               |
| assistance        | gated: not implemented for RHEL 8                                                                                               | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: no maintained encrypted installer, native action prerequisites or graphical golden |
| advisories        | implemented                                                                                                                     | implemented                                                                               | implemented                                                                               |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                         | implemented                                                                               | implemented                                                                               |
| release-upgrade   | gated: release upgrade is not implemented                                                                                       | gated: release upgrade is not implemented                                                 | gated: release upgrade is not implemented                                                 |

<!-- END GENERATED platform-capabilities -->

RHEL 9 and 10 on a supported minor are launch qualification targets; RHEL 8 is a
separate legacy row. x86_64 and vendor-image aarch64 server results must remain
independent. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative and certifies no complete matrix cell. Rocky or AlmaLinux results
never substitute for RHEL entitlement, lifecycle or advisory applicability.

Pinned x86_64 inputs are
[`rhel-9.8-x86_64.json`](../../lab/images/rhel-9.8-x86_64.json) and
[`rhel-10.2-x86_64.json`](../../lab/images/rhel-10.2-x86_64.json).
RHEL 9.8 uses vendor-authenticated catalog SHA-256 provenance, not an OpenPGP cloud
image signature ([manifest:8-14](../../lab/images/rhel-9.8-x86_64.json#L8-L14)).
The vendor aarch64 KVM image is pinned as
[`rhel-9.8-aarch64.json`](../../lab/images/rhel-9.8-aarch64.json), acquired with
`lab images redhat fetch -version 9.8 -arch aarch64` (same authenticated catalog
checksum mode; the receipt schema now admits `x86_64` and `aarch64`). It runs on
the arm64 Sparks lab hosts and keeps independent results from x86_64.

## Packaging, signing, repositories, paths and LSM

The agent is a signed native RPM; building, signing and independent verification
precede publication ([`rpm.go:50-79`](../../internal/packaging/rpm.go#L50-L79)).
RPM configuration is `%config(noreplace)` and systemd lifecycle scriptlets are
part of the package ([`rpm.go:83-112`](../../internal/packaging/rpm.go#L83-L112)).
The installed binary is `/usr/libexec/lindm/lindm-agent`, with configuration under
`/etc/lindm` and distinct protected/network state under `/var/lib/lindm`.
Native RHEL service/trust/dispatch records below retained SELinux Enforcing;
permissive mode is not an equivalent qualification.

Image download, subscription registration and entitled repository access are three
different prerequisites. An offline API token is not a `subscription-manager`
activation key. The maintained lab creates a disposable registration credential,
sends it through bounded private input, records the actual consumer UUID, observes
identity and refreshes repository metadata
([`vm_redhat_linux.go:49-110`](../../internal/vmlab/vm_redhat_linux.go#L49-L110)).
The public run name and receipt survive guest teardown; native output and secrets
are suppressed ([`vm_redhat_linux.go:113-172`](../../internal/vmlab/vm_redhat_linux.go#L113-L172)).
Never publish token contents, activation credentials or temporary CDN URLs.

Use the documented `-redhat-token-file` and explicit `-allow-network` for a
registered connected lane. Restricted QEMU networking cannot reach the vendor:
`$HOME/.cache/lindm-platformlanes-20261009/rhel98-service-restricted-failure.json`,
SHA-256 `36bad86b993c56bd1ca9faa910e08b797456ed2237a7f2eb2f8336e158f21d78`,
records that prerequisite failure. A successful local RPM install with already
satisfied dependencies does not establish entitlement. Record registration,
identity, metadata refresh, unregister and activation-key deletion independently;
interrupted cleanup requires exact owned-consumer reconciliation, not broad tenant
deletion. Air-gap content authorization and mirrors require separate evidence.

## Agent services and sandbox

The root executor has AF_UNIX only, strict filesystem protection and private
devices. Action provisioning grants only reviewed target-specific exceptions;
network access belongs to the unprivileged `lindm` unit, which has no capabilities.
Sources: [`lindm-executor.service:10-61`](../../internal/packaging/assets/lindm-executor.service#L10-L61)
and [`lindm-agent.service:11-50`](../../internal/packaging/assets/lindm-agent.service#L11-L50).
Do not loosen SELinux or systemd protections to inherit another distro's result.

## Inventory and per-field quirks

RPM inventory preserves name, epoch, version, release, architecture and modularity
label. Selection requires exact OS identity and an existing native database, not
`ID_LIKE` ([`packages_linux.go:46-85`](../../internal/agent/inventory/packages_linux.go#L46-L85)).
RHEL's DNF4 configuration observer uses installed Python DNF4 APIs in isolated mode,
without plugins, metadata loading or network activity. The shared
[`dnf` helper](../../internal/agent/dnf/manager.go) identifies the installed native
manager and its version rather than deriving DNF4 from the distribution name.
The [configuration probe](../../internal/agent/inventory/platform_dnf.py) publishes
explicit releasever files in native precedence order, separately detected effective
releasever, and enabled repository IDs/configuration. Base URLs, metalink/mirrorlist,
package-signature checks and key locations preserve native settings; URL userinfo,
queries and fragments are removed with an explicit redaction marker. CPE remains
independent os-release evidence in the
[platform collector](../../internal/agent/inventory/platform_linux.go).

Unavailable release lock, successful empty repository list and collection failure
are different states. The unregistered RHEL captures in [verification](../verification.md)
had no configured lock and empty enabled repositories; these do not prove EUS/E4S
or entitled access. RHEL 9's lab CPU oracle uses portable `lscpu --json`, not the
newer `--hierarchic=never` option.

Current-schema RHEL9.8 x86_64 `lab vm inspect` passed all 490 native RPM records
with DNF4 repository/CPE/effective releasever observations `SUCCESS` (effective
major releasever `9`, no explicit lock, and zero enabled repositories on this
unregistered vendor image). See the `rhel98-inspect-readiness.json` record in
[verification](../verification.md); this is not entitlement or EUS/E4S evidence.
CPU model/source remain native procfs observations.

The fast Cloud image can finish SSH/cloud-init before NetworkManager finishes
IPv6 startup. Initial strict comparisons correctly returned no verdict when a
router advertisement added an address and default route between samples.
The maintained [readiness gate](../../internal/vmlab/vm_inspect_readiness_linux.go)
waits on systemd's startup-complete state and `nm-online -s -q`; the passing record
contains `degraded` (settled, not all-services-healthy) and NetworkManager
`complete`, with timestamps. No network field was removed or exempted.

## Updates

Distinguish agent self-update, package-resource transactions and vendor OS stream
upgrades. Native agent self-update verifies RPM name/version/architecture and
rejects immutable OS markers
([`update/native_linux.go:111-147`](../../internal/agent/update/native_linux.go#L111-L147)).
The RHEL service lifecycle records below prove their particular native agent
upgrade, not every package resource or an interrupted self-update campaign.

### Package resources (DNF4)

RHEL 9/10 package resources use their own DNF4 backend (`BACKEND_DNF4`), never
DNF5's stored/replayed transaction contract. The platform only selects which
generation is acceptable (`rhel`, `almalinux`, `rocky` → DNF4 4.7.0 or newer,
Fedora → DNF5); the installed manager must identify itself as that generation.
The DNF4 CLI cannot run under the executor's read-only `/var`: even `dnf
--version` builds an RPM database sack that opens `/var/log/hawkey.log` before
`--setopt=logdir` applies, and exits 1. DNF4 is therefore identified through the
`dnf` module imported by exactly the interpreter the native `/usr/bin/dnf`
entrypoint (a symlink to `dnf-3`) names, which also reports the native
versionlock plugin state
([`dnf4_linux.go`](../../internal/agent/packageprovider/dnf4_linux.go)).

Transactions use the fixed embedded
[DNF4 Python API adapter](../../internal/agent/packageprovider/dnf4_transaction.py),
run with `-I` under exactly the interpreter named by the native `/usr/bin/dnf`
shebang (`/usr/bin/python3.9` on EL9, `/usr/libexec/platform-python` on EL8).
It never reads ambient `dnf.conf`, drop-ins or repositories, and loads no plugin
except the native versionlock plugin. Staging is asynchronous like DNF5's:
`resolve` refreshes the approved repository (`repo_gpgcheck`) and declares exact
download sizes, `stage` re-resolves with non-expiring metadata, downloads into
the transaction directory and writes the same closed `transaction.json` shape the
Go provider already verifies (NEVRA, action, reason, repository, package path).
DNF4 refuses package downloads under `cacheonly`, so the stage phase pins
metadata expiry instead. The read-only staging sandbox cannot open
`/var/lib/dnf/history.sqlite` (libdnf's `Swdb` writes on open), so staging
resolves against a private consistent SQLite snapshot of it, which preserves
inherited install reasons. Before the signed start permit is consumed, a
`check` phase replays the staged bundle from local RPMs alone (`@commandline`
repository, dependencies chosen by the solver) and requires the identical
NEVRA/action/reason set; `apply` repeats that check after the lock is written
and runs the native RPM transaction.

Signatures are checked four times: every staged RPM against the approved key
only and against system RPM trust (`rpmkeys --checksig`, as for DNF5), by DNF's
`package_signature_check` in both stage and replay, and by RPM itself during the
transaction because the adapter sets `%_pkgverify_level all`. The approved key
must already be imported into system RPM trust.

Exact versions are persisted as an owned entry in the DNF4 versionlock plugin's
list `/etc/dnf/plugins/versionlock.list`: a `# lindm:<resource key>` comment
immediately followed by `name-epoch:version-release.arch`. Other lines are kept
byte for byte; an unmarked entry that can select the package (any NEVRA, NEVR,
NEV, NA or NAME reading, globs included) is an external pin that requires
adoption or is refused; a marker whose entry an operator replaced is orphaned
and never claims the following line. Because the list only has native effect
through the plugin, an exact version requires `python3-dnf-plugin-versionlock`
enabled with exactly that list (probed through the plugin's own configuration
at provider start); without it exact versions are `unsupported`. Staging sees
the candidate list through the read-only bind already used for DNF5; the list
is a packaged configuration file, so an empty rendering truncates rather than
deletes it.

Scriptlets run under RPM's SELinux plugin: the transient apply unit runs in
`unconfined_service_t`, which the targeted policy allows to transition into
`rpm_script_t` (`allow unconfined_service_t rpm_script_t:process transition`),
and the apply unit keeps `NoNewPrivileges=` off for that exec transition.

Qualified natively on registered RHEL 9.8 aarch64 (vendor KVM image acquired with
`lab images redhat fetch -arch aarch64`, maintained registration with explicit
user egress, all ten package scenarios, SELinux Enforcing, scriptlets observed in
`rpm_script_t`): see
[verification](../verification.md#native-packages-on-el-dnf4-python-api-backend).
Not exercised on RHEL: x86_64, RHEL 10, EUS/E4S streams, module streams,
`Weak Dependency` and obsoleting transactions (refused by policy, not exercised),
and the DNF4 path without the versionlock plugin (exact versions are refused).
All eight resource kinds (packages, files, groups, users, sysctl, timers and
drop-ins, password policy, firewall zone) also passed together in one connected
lane on registered RHEL 9.8 aarch64 (73/73 scenarios); see
[verification](../verification.md#all-resource-kinds-in-one-connected-lane).

## Host resource providers (EL 9)

Managed files, local groups and users, sysctl, systemd timers and drop-ins,
password policy and firewall zones use the same providers as Fedora. Their
platform gates accept `rhel` and `almalinux` only with an EL 9 or EL 10
`VERSION_ID` (EL 10 below); Rocky Linux and EL 8 are refused as unqualified. Password policy pins the
exact product (`rhel`/`almalinux` 9.8) and native releases observed there:
libpwquality 1.4.4, pam 1.5.1 (its `pam_pwhistory` reads
`/etc/security/pwhistory.conf`, `remember`, `enforce_for_root` and `file`) and
authselect 1.2.6 ([`version_linux.go`](../../internal/agent/passwordprovider/version_linux.go)).

Native quirks the providers handle:

- **Accounts.** EL 9's shadow-utils 4.9 takes the SELinux label of a rewritten
  `/etc/passwd`, `shadow`, `group` or `gshadow` from the `--prefix` path, so the
  private account root under `/var/lib/lindm` produced `var_run_t` databases:
  `sudo` then failed with "User not known to the underlying authentication
  module" and `sshd` could no longer read `passwd`. EL 9's `chage` also has no
  `--prefix`, and in a bare chroot it aborts (`avc_running` assertion) or reports
  "Permission denied". On EL 9 every shadow tool therefore chroots (`--root`)
  into an account root holding the exact host `/etc` bind, the private mail-spool
  scratch, the host procfs (non-recursive bind, with the `ProtectKernelTunables=`
  and `ProtectKernelLogs=` paths repeated read-only or inaccessible inside it),
  selinuxfs (already writable under `ProtectKernelTunables=`), a read-only `/usr`
  and the `/bin -> usr/bin` link, so the tools label the real `/etc` paths
  (`passwd_file_t`, `shadow_t`) and their own login-shell check sees the host
  shells ([`prefix_linux.go`](../../internal/agent/accountprovider/prefix_linux.go),
  [`resource_linux.go`](../../internal/agent/nativehelper/resource_linux.go)).
  Ubuntu and Fedora keep `--prefix`.
- **Timers and drop-ins.** EL 9 ships systemd 252 (its manager `Version` is
  `252-67.el9_8…`, without a dot); the provider's systemd floor is 252 on EL 9
  and 255 elsewhere.
- **Password policy.** The provider only manages authselect-owned stacks. The
  RHEL 9.8 KVM guest image (and AlmaLinux 9.8 GenericCloud) ship the pam
  package's own `system-auth`/`password-auth` with no authselect selection
  (`authselect check` exits 2, "No existing configuration detected"); a policy
  assigned there is refused as `unsupported` with no native change. An
  installer-provisioned host has a selection; the lane proves the refusal, then
  runs `authselect select sssd --force` (the vendor default, `pam_sss.so` from the
  installed `sssd-client`) and qualifies the managed path. EL 9 profiles live in
  `/usr/share/authselect/default` (`minimal`, `sssd`, `winbind`; there is no
  Fedora `local` profile) and authselect 1.2.6 has no `opt-out`.
- **Firewall zones.** Neither image installs firewalld or nftables; the lane
  installs both from the vendor repositories and keeps firewalld active. Boot
  restoration (`lindm-firewall-restore.service`) failed on both images in two
  ways the provider now handles
  ([`netlink_linux.go`](../../internal/agent/firewallprovider/netlink_linux.go)):
  firewalld, also ordered `Before=network-pre.target`, moved the nftables
  generation under the restore batch, and the kernel refused it (`ERESTART` on
  `BATCH_BEGIN`, surfaced by the netlink library as a receive error) before
  applying anything — the provider now re-observes and retries that batch (at
  most three attempts, only while lindm's own table is unchanged); and the EL 9
  5.14 kernel acknowledged a `NEWRULE` of the restore batch twice while modules
  autoloaded at boot — a repeated success for an object of the batch is now
  accepted (the applied table is verified by read-back as before) and the socket
  is replaced after every batch so late repeats cannot be read as replies to the
  next query. Both had been reported as an unknown outcome, which left the
  persisted zone `PENDING` and failed the unit.

Evidence and the unproven remainder are in
[verification](../verification.md#host-resource-providers-on-el-9).

## Host resource providers (EL 10)

The same providers and gates cover EL 10; password policy pins `rhel`/`almalinux`
10.2 with libpwquality 1.4.5, pam 1.6.1 and authselect 1.5.2. Native facts were
checked on the RHEL 10.2 KVM and AlmaLinux 10.2 GenericCloud aarch64 guests
(kernel 6.12, SELinux Enforcing, shadow-utils 4.15.0-11, systemd 257-23,
`yescrypt` password hashing):

- **Accounts.** shadow-utils 4.15 now offers `--prefix` for every tool including
  `chage`, but still labels the rewritten databases from the prefixed path
  (`var_lib_t` under `/var/lib/lindm`; `restorecon -n` wants `passwd_file_t` and
  `shadow_t`, and `chage -l` then fails with "cannot open /etc/passwd"). EL 10
  therefore uses the same chrooted account root as EL 9
  ([`ChrootAccountRoot`](../../internal/agent/accountprovider/prefix_linux.go));
  `groupadd`, `useradd`, `usermod` (shell, UID, lock, groups), `chage`,
  `userdel` and `groupdel` exit 0 there with correct labels. `/bin`, `/sbin` and
  `/lib64` are symlinks into `/usr`, as on EL 9.
- **Timers and drop-ins.** systemd 257 meets the general 255 floor; the EL 9
  exception (252) does not apply.
- **Password policy.** Unlike EL 9, both EL 10 images ship an authselect selection
  (`local`, no features; `authselect check` valid), so a policy is managed
  without the EL 9 profile step. EL 10 profiles are `local`, `sssd` and
  `winbind`; `local` offers `with-pwhistory` and `with-faillock`.
- **Firewall zones.** As on EL 9, neither image installs firewalld or nftables;
  the lane installs both and keeps firewalld active. The EL 9 boot-restoration
  fixes apply unchanged.

Evidence and the unproven remainder are in
[verification](../verification.md#host-resource-providers-on-el-10).

## OS update policy (EL 9 and EL 10)

RHEL 9 and 10 use DNF4 `dnf-automatic` (4.14 on EL 9, 4.20 on EL 10) under the
same lindm window timer, runner and release model as
[Ubuntu](ubuntu.md#os-update-policy-osupdatev1). AlmaLinux and Rocky are refused
as unsupported until their own records exist. Prerequisites are `dnf-automatic` and
`dnf-plugins-core` (for `dnf needs-restarting`). Updates come from the
registered system's entitled repositories, and the security classification is
the CDN updateinfo errata type. An unregistered host has no security metadata to
classify. The policy owns the policy file, the timer and its `timers.target`
drop-in; it does not touch the package's `%config` `/etc/dnf/automatic.conf`.
An enabled or active `dnf-automatic*.timer` is refused before any effect. Each run
writes `/run/lindm-os-update/automatic.conf` (`upgrade_type`, `random_sleep = 0`,
download and apply `yes`, `emit_via = stdio`, and `[base] excludepkgs` for
deferred `name.arch`, appended to `dnf.conf` excludes). It then runs
`dnf-automatic <conf> --installupdates`. The conf also sets `reboot = never`
(4.14 ignores the key); the reboot is always the lindm logind schedule. Listing uses
`dnf --cacheonly repoquery --upgrades --latest-limit 1 [--security]`. The reboot
oracle is `dnf -q --disablerepo=* needs-restarting -r`, which looks only at
installed core packages, as on [Fedora](fedora.md#os-update-policy-osupdatev1).
Records, the registration and consumer-UUID receipts, and SELinux state are in
[verification](../verification.md#os-update-policy-patch-now-and-patch-status).

## Encryption and recovery

No Fedora or Ubuntu LUKS2/TPM/recovery run certifies RHEL. Qualification requires
the RHEL kernel, cryptsetup/systemd/initramfs, firmware and actual target tuple,
plus independent recovery boots and signed action evidence. The default executor
hides disks and TPMs; action provisioning must preserve private-device isolation
and expose only exact approved nodes
([`lindm-executor.service:21-30`](../../internal/packaging/assets/lindm-executor.service#L21-L30)).
Use the capability-specific encryption/recovery cells in [verification](../verification.md),
not successful registration or RPM installation, to decide availability.

## Device actions

Signed service execution is not desktop lock, quarantine, restart, shutdown,
crypto-erase or sanitize evidence. Each requires its own authorization, native
effect and recovery/uncertainty record. Server/minimal and vendor GNOME-capable
installations remain separate qualification targets. Consult
[verification's action gates](../verification.md#encryption-and-imperative-action-evidence-l10-l13-l15)
before enabling an action on a RHEL device.

## Advisory feeds

RHEL uses vendor CSAF 2.0 security advisories and VEX, not Fedora updateinfo or a
version-string-only CVE join. Parsing checks publisher, final status, product tree
and supported relationships, retaining fixed, known affected, known not affected
and under-investigation distinctions
([normalization](../../internal/advisory/feed/redhat_claims.go),
[product policy](../../internal/advisory/feed/redhat.go)).
An individual advisory or legacy VEX is not complete coverage.
A Red Hat CSAF source must name a RHEL 8, 9 or 10
[registry release](../../internal/platform/registry.go) (major or exact minor);
the registry's per-stream fact, not the os-release ID string, makes hosts require
corroborated stream evidence and native module identity.
RPM `gpg-pubkey` signing-key rows without an architecture are keyring entries:
they neither match records nor make architecture coverage UNKNOWN
([Fedora advisory feeds](fedora.md#advisory-feeds)).
Product CPE applicability is established before applying advisory metadata policy,
so historical off-scope informational notices cannot poison a selected host feed.
Applicable final `csaf_informational_advisory` documents contribute no claims only
when their `vulnerabilities` property is absent, as required by
[CSAF 2.0 profile 3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).
The genuine RHEL 9 AppStream notice
[`RHSA-2023:6529`](../../internal/advisory/feed/testdata/redhat-rhsa-2023_6529.json)
is retained with [signed-archive provenance](../../internal/advisory/feed/testdata/redhat-rhsa-2023_6529-provenance.txt).
Informational notices containing even a null or empty vulnerability array are
refused; unsupported relevant categories, metadata and product trees still fail
the whole source rather than silently discarding potential claims.

VEX status references may identify declared products directly. A direct reference
is skipped only when its explicit, supported CPE syntax proves that the product
is outside the selected native RHEL scope; a missing relationship alone is not
proof of irrelevance. Missing product declarations, malformed or escaped CPEs,
unbound RPM products and relevant broad-platform statuses still fail rather than
inventing package-level fixes or clean assertions. The retained
[`CVE-2002-0059` VEX](../../internal/advisory/feed/testdata/redhat-cve-2002-0059.json)
with [vendor proofs and provenance](../../internal/advisory/feed/testdata/redhat-cve-2002-0059-provenance.txt)
demonstrates historical Red Hat Linux/Powertools direct fixes alongside four
authoritative RHEL 9 zlib binary/source not-affected relationships.
A valid nonnative product CPE can omit its version
([ANY under NISTIR 7695 URI binding](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)),
as the layered RHSSO
product does in the retained
[`CVE-2020-25649` VEX](../../internal/advisory/feed/testdata/redhat-cve-2020-25649.json)
and its [provenance](../../internal/advisory/feed/testdata/redhat-cve-2020-25649-provenance.txt).
This does not permit a native RHEL CPE with an absent/empty version to establish
off-scope status; that unresolved applicability remains a failure.

Production `REDHAT_CSAF` and paired `REDHAT_CSAF_ARCHIVES` refreshes stage original
bytes in private temporary files, require the vendor SHA-256 and pinned-root
detached signature before parsing, and preserve original-byte artifact digests.
Optional configured pins and transfer CRC32C checks remain additional integrity
checks, not substitutes for signatures
([acquisition](../../internal/advisory/feed/signed.go)).
An offline individual CSAF import can be digest-pinned but gains neither a
signature timestamp nor complete coverage; a lone compressed archive is refused
rather than treated as the authenticated paired distribution.

Each JSON document is capped at **128 MiB**, independently of the
512 MiB compressed-archive and **32 GiB expanded-archive** limits. The measured
2026-10-04 signed advisory distribution contains four documents above the former
32 MiB limit; its largest, `RHSA-2024:9315`, is 46,707,671 bytes with 594 distinct
CVEs ([cardinality evidence](../../artifacts/rpm-advisory-cve-cardinality-20261010.json)).
The retained [original compressed fixture](../../internal/advisory/feed/testdata/redhat-rhsa-2024_9315.json.gz)
exercises that document, not a reduced substitute.
The paired VEX distribution contains 69,859 JSON entries and expands to
21,371,545,600 bytes (19.904 GiB), so the former 16 GiB aggregate limit could not
consume it. Its largest member, `CVE-2026-33186`, is 107,532,378 bytes and
explicitly includes native RHEL 9 products
([complete VEX expansion/scope evidence](../../artifacts/rhel-vex-expansion-scope-20261010.json)).
The larger aggregate expansion allowance does not retain the archive in memory:
entry, token, product-index and normalized-stage bounds remain independent.

The [incremental parser](../../internal/advisory/feed/redhat_json.go) token-skips
unused fields and bounds each scalar at 64 KiB, JSON nesting at 64, branch nesting
at 12, branches and relationships at 250,000 each, and retained product metadata
text at 64 MiB. A first pass records the vulnerability-array position and builds
the bounded product index; a second pass retains one vulnerability at a time
(at most 250,000 status references and 64 MiB of reference text). Parent indices
preserve inherited architecture and constraints even when child branches precede
their parent metadata. Arbitrary JSON key order does not require retaining a
whole document or vulnerability as `RawMessage`.
The [advisory-distribution metadata measurement](../../artifacts/rhel-csaf-tree-bounds-20261010.json)
records maxima of 3,438 branch products, 8,618 relationships, 2,643,893 bytes of
product-tree string values and a 41,523-byte scalar, providing measured headroom
for these independent limits.
The [complete VEX reference census](../../artifacts/rhel-vex-reference-shapes-20261010.json)
records maxima of 42,967 branch products, 42,954 relationships and a 7,119-byte
scalar. It found no undeclared status references or relationship-edge targets;
among native-RHEL-9-potential documents, the additional direct-reference forms
are nonnative versionless products and AMQ versions such as `2026.Q3`. Uppercase
version text does not case-fold or otherwise rewrite native product identity.

Repeated declarations are not automatically conflicting identities. Identical
relationship edges/helpers and product helpers/inherited architecture/constraints
are deduplicated, ignoring opaque display-label differences. A conflicting ID
remains explicitly ambiguous; it rejects a document only when encountered in a
relevant status dependency. Exclusion requires every declared platform
alternative to be provably off-scope. Initial applicability considers the union
of duplicate CPE declarations, so neither first- nor last-declaration order can
hide native ambiguity. Scope proofs retain the eight-edge traversal bound and
memoize indexed references within one vulnerability.
The [selected original VEX duplicate census](../../artifacts/rhel-selected-vex-duplicate-identities-20261010.json)
records 618 identical relationship redeclarations in `CVE-2026-33186` and 2,194
in `CVE-2023-44487`; their conflicting product-helper declarations are outside
native RHEL 9.8 dependencies and do not invalidate independent native claims.
One product ID declared once per module build shipping the same NEVRA, whose
PURLs differ only in `rpmmod` version:context (for example
`postgresql:15:9020020240213145157:rhel9` and
`postgresql:15:9030020240209100638:rhel9`), is the same normalized component:
both PURLs must parse as native RPMs with identical name, EVR, architecture,
source flag and module name/stream, and the product CPE must match. Any
normalized difference remains a conflict. The genuine
[`CVE-2024-0985`](../../internal/advisory/feed/testdata/redhat-cve-2024-0985-provenance.txt)
member carries 117 such redeclarations.

[Disk-backed reconciliation](../../internal/advisory/feed/redhat_reconcile.go)
preserves the earliest native RPM fix, first-observation ties, architecture,
source/binary and module separation, and suppression of bare affected claims
across the complete source, including both archives. Its private SQLite stage
has a 2 GiB database limit and an 8 MiB page cache. Ordinary batches contain at
most 500 claims; each vendor document uses a single disk-spilling transaction
so rejection rolls back its entire prefix before another document is accepted.
The configured total-claim limit applies separately from document-byte limits;
the materialized compatibility APIs retain their 500,000-claim/128 MiB bounds,
but streaming publication does not accumulate the normalized export in memory.
Only fully parsed and reconciled sources reach generation-staging callbacks.
A signature, malformed JSON, byte/structure bound, storage, cancellation or
consumer failure invalidates the entire generation; no earlier document may
become a partially published source
([streaming acquisition](../../internal/advisory/feed/redhat_fetch.go)).
An applicable document with invalid vendor semantics is instead rejected as a
whole and exposed in bounded rejected-record metadata, never repaired. The
configured rejection threshold is enforced (zero requires no rejected records);
diagnostics are capped at 48 KiB. Unscoped rejection preserves uncertainty for
all packages whose claims were rolled back, preventing a clean-coverage claim.

Servicing stream matching requires corroborating native Red Hat CPE, enabled
BaseOS/repository IDs, architecture and release-lock observations. Mixed streams,
missing BaseOS or ambiguous EUS/E4S locks do not establish applicability
([`advisory/platform.go:11-72`](../../internal/advisory/platform.go#L11-L72)).
Do not infer entitlement from `VERSION_ID`, rewrite a MAIN.EUS internal identifier
as an EUS CPE, or treat a derivative as Red Hat. Current complete paired archive
coverage and freshness are governed by [verification](../verification.md).

Streaming refresh has no size-derived deadline. A progress watchdog aborts only
when no source document completes and no publication batch commits for
`progress_timeout_seconds` (default 300); `refresh_timeout_seconds` (default
7,200) is the overall ceiling, and the staging lease is renewed every minute.
The real signed 2026-10-04 archive pair (advisories SHA-256
`708b53ef…5354afc1ee`, VEX `fa61b885…b82182345`, signer
`77E79ABE93673533ED09EBE2DCE3823597F5EAC4`) was published on 2026-10-10 through
`TestLiveRHEL9SignedArchivePublication` into an isolated `testdb` schema
(release `9`, `standard`, x86_64; workstation NVMe, shared host): 1,894,410
emitted and 1,892,833 unique claims, one rejected document, 7 min 28 s refresh
(7:28 wall), 236,744 KiB peak RSS, no swaps. The sole rejection is the genuine
`CVE-2023-44487` `nginx:1.24` RPM name above. The preceding run, before
module-build redeclarations were recognized, rejected 38 additional module
documents (PostgreSQL, Node.js, MariaDB, PHP, Ruby and others) as conflicting
identities (1,892,498 unique claims, 7 min 3 s, 241,884 KiB); each now parses
without rejection. Coverage remains partial, so freshness is not advertised as
clean completeness. Run logs are under `~/.cache/lindm-rhel-publication-20261010/`
(final `lindm-rhel-live-20261010-2.log` SHA-256
`74a1313711e73f229847b6d226a20582ba7d5e8a99c1d269da4e24dba05cd8bd`).

RPM PURL package names and versions use single path-component percent decoding,
not form/query decoding: a literal `+` remains `+`, and `gnutls-c%2B%2B` identifies
the native package `gnutls-c++`. Invalid escapes, decoded separators and residual
double encoding are refused, never repaired. The genuine
[`RHSA-2022:6854` fixture](../../internal/advisory/feed/testdata/redhat-rhsa-2022_6854.json)
and its [provenance](../../internal/advisory/feed/testdata/redhat-rhsa-2022_6854-provenance.txt)
retain this identity boundary.

Component identity follows Red Hat's
[PURL matching logic](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/#purl-matching-logic)
and [RPM PURL conventions](https://redhatproductsecurity.github.io/security-data-guidelines/purl/#identifying-rpm-packages):
PURLs identify components, CPEs identify products, and opaque product IDs join
them through relationships. Display labels are not a second RPM NEVRA assertion
and cannot override the PURL name, epoch or version. The native namespace is
exactly `redhat`, not a prefix: `redhat/rhacm2` and `redhat/rhel9` remain distinct,
out-of-scope namespaces, never suffix-repaired into host package names.
This agrees with the reference
[PURL namespace parser](https://github.com/package-url/packageurl-go/blob/c88ed7b2a2305ec91a087dd6cb7168ca1f42cfe3/packageurl.go#L711-L735)
and [Clair's native-RPM filter](https://github.com/quay/claircore/blob/7da686f8454001747e3ca122fcaf1d3647f06018/rhel/vex/parser.go#L1273-L1288).

`known_affected` is an unfixed package/source claim for the matched native product,
even when a component PURL happens to include a version; it does not invent an
exact affected-version interval from that value. This matches the reference
[Clair known-affected normalization](https://github.com/quay/claircore/blob/7da686f8454001747e3ca122fcaf1d3647f06018/rhel/vex/parser.go#L779-L831).
The source's original PURL remains unchanged. `fixed` retains the exact PURL EVR,
and source-wide reconciliation still suppresses a bare affected claim when a
native fix exists. Versioned `known_not_affected` claims remain version-specific,
not blanket clean assertions.

Modules require the documented
[`rpmmod` qualifier](https://redhatproductsecurity.github.io/security-data-guidelines/purl/#identifying-rpm-modules)
or an independently declared module relationship. A colon in an RPM name is not
permission to invent a module. The signed-archive specimens
[`CVE-2021-27358`](../../internal/advisory/feed/testdata/redhat-cve-2021-27358-provenance.txt),
[`CVE-2026-103111`](../../internal/advisory/feed/testdata/redhat-cve-2026-103111-provenance.txt)
and [`CVE-2023-44487`](../../internal/advisory/feed/testdata/redhat-cve-2023-44487-provenance.txt)
respectively exercise nested-namespace exclusion without discarding independent
native binary claims, a bare display label with a versioned unfixed PURL, and a
genuinely invalid `nginx:1.24` RPM name without module metadata. The
[completed source interpretation census](../../artifacts/rhel-vex-purl-interpretation-20261010.json)
distinguishes 115 out-of-scope namespace entries and 290 valid display-label
differences from that one remaining invalid document; the latter is rejected
unscoped, not normalized to `nginx`.

## Lab

Use maintained image acquisition/offline verification and the registered native
lanes described in [agent enrollment](../agent-enrollment.md) and
[verification](../verification.md). Keep fixture and pinned source-build roots
separate; retain public registration receipts outside disposable VM state.

The following x86_64 KVM records are under
`$HOME/.cache/lindm-platformlanes-20261009/`; they retain SELinux Enforcing and
registered repository/cleanup evidence:

| Capability                          | Record                                  | SHA-256                                                            |
| ----------------------------------- | --------------------------------------- | ------------------------------------------------------------------ |
| RHEL 9.8 signed-service lifecycle   | `rhel98-service-egress-platform2.json`  | `6378848308eecfaad17e38ff76d7d0b275688f4f7618f6d7f3d618cedcd30ee8` |
| RHEL 10.2 signed-service lifecycle  | `rhel102-service-egress-platform2.json` | `3d0eebd689834efa9f7daf766a9bc8cdd29f994a3306360b9fda0a249751b78f` |
| RHEL 9.8 automatic trust lifecycle  | `rhel98-trust-receipts.json`            | `2cef05970f214a51f6a8573abf478a11cd228cc922b0f1371e94286f547e2ed2` |
| RHEL 10.2 automatic trust lifecycle | `rhel102-trust-receipts.json`           | `af60d409e6d367680655235e2a1e829448428aacca4fb2f57cbff0297d717723` |
| RHEL 9.8 connected dispatch         | `rhel98-dispatch-receipts.json`         | `7c6d4d0f715184ad4eb9b788f8815da69d874f6270d6f18d305fd89915fe5b62` |
| RHEL 10.2 connected dispatch        | `rhel102-dispatch-receipts.json`        | `0c8b04c278095080fbe43e9b388805c02fe5b74e3c34943de1d1527ad1f29783` |

Dispatch contains nine native scenarios; unstarted supersession is explicitly
integration-only, not a tenth native scenario. These records do not qualify aarch64,
physical hardware or disconnected vendor content.

## Gaps

RHEL 8, native aarch64, vendor desktop coverage, physical TPM/media, entitled
air-gap lifecycle and each unsupported resource/action remain independent work.
DNF4 repository observation is not package mutation qualification. Standard,
EUS and E4S applicability must retain exact content provenance and cannot be
borrowed from another vendor or minor release.
