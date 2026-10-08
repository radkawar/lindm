# Research and decision record

Research date: 2026-10-08. These are evidence-backed design inputs, not certification
of any implementation. Living vendor pages must be rechecked when images/dependencies
are pinned. Sources describe their own systems, not a guarantee that lindm supports
them. No Fleet code or documentation was copied into the product.

## 1. What "standardized Linux MDM" can mean

**Observed:** OMA DM defines a management protocol and objects. Linux exposes native
management interfaces for services, networking, packages, sessions and encryption.
SCAP standardizes security-content/evaluation formats. None of those facts supplies
a cross-distribution agent or uniform Linux workstation policy implementation.

**Inference:** the reviewed sources did not establish a universal distro-shipped Linux
MDM endpoint/policy namespace comparable to Apple MDM. This is not a proof that Linux
cannot implement OMA DM. Implementing SyncML ourselves would still require the same
agent, OS adapters, trust, recovery and certification work.

**Decision:** authenticated versioned protobuf RPC for our agent/control plane;
standards-based identity/update/content formats; typed native Linux providers for
execution. Describe the wire protocol honestly as lindm's, not an industry Linux MDM
standard. Avoid an OMA DM compatibility layer without a real interoperable client or
customer requirement.

| Source                                                                                                                                                                                                               | Evidence and design consequence                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| [OMA DM releases](https://www.openmobilealliance.org/release/DM/) and [management-object registry](https://www.openmobilealliance.org/omna/dm/dm_mo_registry.html)                                                   | Protocol/object standards exist; do not confuse protocol conformance with OS management functionality                                  |
| [systemd D-Bus](https://wiki.freedesktop.org/www/Software/systemd/dbus/)                                                                                                                                             | Typed service/job interface; a queued job is not observed application readiness                                                        |
| [NetworkManager API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html)                                                                                                           | Checkpoints support timed network rollback; do not apply NetworkManager policy to networkd/ifupdown-owned links                        |
| [Debian apt manual](https://manpages.debian.org/trixie/apt/apt.8.en.html)                                                                                                                                            | Prefer documented automation interfaces such as apt-get/apt-cache over parsing interactive apt output                                  |
| [DNF5 daemon API](https://dnf5.readthedocs.io/en/latest/dnf_daemon/dnf5daemon_dbus_api.8.html)                                                                                                                       | Optional typed package interface, not evidence of availability on DNF4/RHEL systems                                                    |
| [Zypper usage](https://en.opensuse.org/SDB:Zypper_usage)                                                                                                                                                             | Native noninteractive/XML interfaces can back a SUSE provider; preserve native solver/signatures                                       |
| [PackageKit backend contract](https://packagekit.freedesktop.org/gtk-doc/introduction-backends.html)                                                                                                                 | Backend roles differ; no assumption that PackageKit makes all package operations equivalent                                            |
| [NIST SCAP specifications](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications) and [XCCDF](https://csrc.nist.gov/Projects/security-content-automation-protocol/Specifications/xccdf) | Use versioned compliance content/results and explicit tailoring/applicability; not an enrollment or remediation wire protocol          |
| [logind API](https://wiki.freedesktop.org/www/Software/systemd/logind/)                                                                                                                                              | LockSession requests action by a session implementation; verify the visible lock rather than count RPC success                         |
| [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)                                                                                                              | Existing LUKS2 and TPM policy integration have compatibility/boot constraints; no universal live encryption promise                    |
| [cryptsetup FAQ](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ)                                                                                                                                           | Header backups/key copies matter to recovery and erase claims                                                                          |
| [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)                                                                                                                                               | Media sanitization requires method/scope/evidence and validation; not equivalent to deleting a device record or receiving no heartbeat |

NetworkManager is the first network provider; separately qualified networkd/Netplan
and other ownership paths are required wherever included by the supported server
images. Standardization means reuse and honest adapter boundaries, not forcing all
hosts onto a single network stack.

## 2. Commercial reference and Fleet lessons

[SimpleMDM's feature catalog](https://simplemdm.com/features/) provides the workflow
baseline: enrollment, configurations, device inventory/actions, software deployment,
self-service and automation. Apple Business Manager/APFS/Activation Lock semantics do
not transfer automatically to Linux. Console SSO, enrollment identity, and workstation
login are separate product capabilities.

Fleet was inspected read-only at `/home/r/dev/minor/clones/fleet`. These local paths
are audit references to the checkout inspected, not immutable upstream citations.

| Reference path and inspected lines                          | Finding / consequence                                                                                                                  |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/Get started/FAQ.md:73-95`                             | Broad Linux listing but GNOME/KDE and disk-encryption restrictions; support needs a per-feature matrix                                 |
| `docs/Contributing/mdm/disk-encryption.md:194-240,273-293`  | Preexisting LUKS2 escrow differs from vendor-owned TPM encryption; do not mutate another encryption manager's key slots                |
| `orbit/pkg/update/update.go:85-109,151-198,217-242,407-468` | TUF-related bootstrap/metadata/target validation is a useful conceptual reference, not a reason to copy updater code                   |
| `.github/workflows/e2e-agent.yml:340-430`                   | Ubuntu amd64/arm64 agent install/enroll/process/remove tests; this job explicitly does not check desktop in its windowless environment |
| `.github/workflows/test-packaging.yml:81-111`               | Installer generation is a distinct test from installed lifecycle behavior                                                              |
| `LICENSE:1-30` and `ee/LICENSE`                             | Root licensing distinguishes documentation, enterprise and other code; do not treat the entire repository as permissively licensed     |

The inspected job is not evidence of comprehensive Fleet test absence, and Fleet
marketing support is not certification for this product. Reuse concepts: separate
inventory/execution/update trust, staged agent updates, feature-specific eligibility
and observed results. Improve our evidence contract: real installer, boot/session,
interruption, server workload, air-gap and physical destructive gates.

## 3. Backend and security decisions

| Source                                                                                                                                            | Decision                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [Connect introduction](https://connectrpc.com/docs/introduction/)                                                                                 | Single protobuf schema with Go/browser clients and gRPC interoperability; use Go net/http without mandatory gateway                  |
| [sqlc documentation](https://docs.sqlc.dev/en/v1.31.1/index.html)                                                                                 | Generate typed Go from reviewed SQL; no ORM or handwritten query boilerplate layer                                                   |
| [PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html)                                                                      | Row locking/SKIP LOCKED can support competing durable workers; leases/fences/outbox remain our responsibility                        |
| [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) and [OAuth security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Code flow, PKCE, issuer/audience validation and tightly bound redirects; do not improvise authentication                             |
| [SCIM RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html)                                                                                      | Standards-based identity provisioning is separate from login; expose declared capabilities and atomic PATCH behavior                 |
| [TUF specification](https://theupdateframework.github.io/specification/latest/)                                                                   | Signed checksums alone are insufficient; root/delegation, freshness, rollback and threshold/key-rotation handling matter offline too |
| [Google Go style](https://google.github.io/styleguide/go/guide)                                                                                   | Clarity/simplicity/maintainability and standard tools; no linter alone confers production quality                                    |

Using open standards does not establish FIPS validation, SOC 2, ISO 27001, CIS
certification, NIST compliance or interoperability beyond what is actually tested.
Licensing of compliance benchmarks and vendor feeds must be reviewed separately.

## 4. Distro lifecycle sources

| Family          | Primary source                                                                                                                                                                        | Implication for qualification                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Ubuntu          | [Release cycle](https://ubuntu.com/about/release-cycle)                                                                                                                               | Distinguish LTS Main maintenance, ESM/Universe entitlements, flavors and Core; target 24.04/26.04 separately |
| Debian          | [Releases](https://www.debian.org/releases/)                                                                                                                                          | Stable 13 and older LTS have different support/content scopes; do not inherit support by package format      |
| Fedora          | [44 announcement](https://fedoramagazine.org/announcing-fedora-linux-44/) and [lifecycle](https://docs.fedoraproject.org/en-US/releases/lifecycle/)                                   | Moving release window; retain supported 43/44 candidates and re-evaluate before launch                       |
| RHEL            | [Lifecycle](https://access.redhat.com/support/policy/updates/errata)                                                                                                                  | Subscription, EUS and content-access rules differ from rebuilds; use actual licensed RHEL for certification  |
| Rocky Linux     | [Release notes](https://docs.rockylinux.org/latest/releases/)                                                                                                                         | Current minor and CPU baseline matter; qualify 9/10 independently                                            |
| AlmaLinux       | [Release notes](https://wiki.almalinux.org/release-notes/)                                                                                                                            | Separate releases/architectures/support rules; not an automatic Rocky test alias                             |
| openSUSE        | [Leap 16 release](https://news.opensuse.org/2025/10/01/next-chapter-opens-with-leap-release/) and [maintenance policy](https://news.opensuse.org/2025/09/03/leap-16-doubles-support/) | Leap 16 differs from EOL Leap 15.6, Tumbleweed and immutable variants                                        |
| SUSE enterprise | [Product lifecycle](https://www.suse.com/lifecycle/)                                                                                                                                  | SLES 15 SP7/16 and SLED are distinct products with distinct licensed images and installer paths              |

Pin exact release inputs during implementation. Do not fabricate digests for images
not yet acquired; qualification status remains planned until their evidence exists.

## 5. Test infrastructure sources

- [QEMU image tooling](https://www.qemu.org/docs/master/tools/qemu-img.html),
  [libvirt domain/TPM definitions](https://libvirt.org/formatdomain), and
  [libvirt snapshots](https://www.libvirt.org/formatsnapshot.html): immutable bases,
  per-run overlays and coherent firmware/TPM state.
- [cloud-init instance data](https://cloudinit.readthedocs.io/en/latest/topics/instancedata.html):
  fresh instance identity and repeatable fast image provisioning.
- [openQA](https://open.qa/docs/): existing installer/graphical testing rather than an
  ad hoc visual-test framework.
- [Ubuntu autoinstall](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html),
  [Debian preseed](https://www.debian.org/releases/stable/amd64/apb),
  [RHEL Kickstart](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/automatically_installing_rhel/kickstart-script-file-format-reference),
  [SLES 16 Agama](https://documentation.suse.com/sles/16.0/html/SLES-x86-64-agama-automated-installation/index.html):
  native installer automation, not proof that a cloud-image boot covers installation.

## 6. Review-confirmed additions and remaining prerequisites

The owner confirmed the full proposed core matrix plus SUSE enterprise, maintained
legacy branches and rolling/immutable Linux; both device/person entitlements;
Keycloak/Entra/Okta/Google; and built-in graphical assistance. These are now in the
contract, not undecided optional features.

Additional primary implementation references:

- [NixOS manual](https://nixos.org/manual/nixos/stable/) and
  [26.05 release](https://nixos.org/blog/announcements/2026/nixos-2605/): generations,
  closures, activation and boot/rollback are not ordinary package updates. Persistent
  application data is not automatically rolled back.
- [rpm-ostree administrator handbook](https://github.com/coreos/rpm-ostree/blob/main/docs/administrator-handbook.md):
  staged/booted deployments, layering and rollback need a dedicated provider.
- [Arch system maintenance](https://wiki.archlinux.org/title/System_maintenance):
  do not promise partial upgrades on a rolling distribution.
- [RemoteDesktop portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html):
  user-mediated grants, ScreenCast/PipeWire integration, EIS versus D-Bus input and
  session lifecycle. Presence/version must be qualified, not assumed on older images.
- [WebRTC overview RFC 8825](https://www.rfc-editor.org/rfc/rfc8825.html) and
  [coturn](https://github.com/coturn/coturn): reuse established transport/relay
  mechanisms; consent, identity binding and session authorization remain our job.

Remaining prerequisites before their gates: exact licensed image/repository snapshots;
actual identity-provider tenants/API permission and immutable-correlation configuration;
named sacrificial physical hardware; distribution/content licensing; owner-controlled
public namespace/signing custody; verified oldest-session portal feasibility; and
measured capacity/retention sizing. These are not permission to ship unsafe defaults,
stub integrations, or certify all versions of a rolling distribution.
