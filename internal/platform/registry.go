package platform

import (
	"fmt"
	"slices"
	"strings"
)

// New distribution facts go only into this table. A capability absent from
// Supports is gated; Gates states why when the default reason ("not
// implemented for <release>") is not the whole story.

var (
	agentCore = []Capability{Inventory, Lifecycle, Dispatch, SelfUpdate}
	// hostResources are the EL 9/10, Debian 12/13, Ubuntu and Fedora host providers.
	hostResources = []Capability{Packages, Accounts, Sysctl, Definitions, Firewall}
	// actionLanes have a maintained encrypted-installer recipe, native action
	// prerequisites and a graphical golden.
	actionLanes = []Capability{Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}
)

// RepositorySnapshotRecipes is the trust/source and explicit lane input set for
// maintained bounded repository captures. Other backends fail closed.
var RepositorySnapshotRecipes = map[string]RepositorySnapshotRecipe{
	"opensuse-tumbleweed": {
		Signer: "AD485664E901B867051AB15F35A2F86E29B700A4",
		Sources: map[string]string{
			"x86_64":  "https://download.opensuse.org/history/%s/tumbleweed/repo/oss/",
			"aarch64": "https://download.opensuse.org/ports/aarch64/tumbleweed/repo/oss/",
		},
		Packages: []string{
			"cloud-init", "cloud-init-config-suse", "openssh-server", "sudo",
			"cryptsetup", "tpm2.0-tools", "libtss2-esys0", "nftables", "python313",
			"libpwquality-tools", "libpwquality1", "pam", "pam_pwquality", "pam-config",
			"dracut", "udev", "patterns-gnome-gnome", "gnome-terminal",
			"xdg-desktop-portal-gnome", "pipewire", "gstreamer-plugin-pipewire",
			"gstreamer-plugins-good", "rpm-build", "rpm", "createrepo_c",
			"gpg2", "openssl", "attr", "acl", "curl", "firewalld", "zypper",
			"iproute2", "iputils", "bind-utils", "xdg-desktop-portal",
			"gnome-shell", "mutter", "sdbootutil",
			"patterns-base-base", "patterns-base-enhanced_base",
			"nvme-cli", "e2fsprogs", "kmod", "zstd",
		},
		ArchitecturePackages: map[string][]string{
			"aarch64": {"grub2-arm64-efi-bls"},
			"x86_64":  {"grub2-x86_64-efi-bls"},
		},
		SnapshotPackages: map[string]map[string][]string{
			"20261007": {"aarch64": {"kernel-default=7.2.9-1.1"}},
			"20261009": {"x86_64": {"kernel-default=7.2.9-1.1"}},
			// OS-update target: the later x86_64 closure a 20261009 golden upgrades to.
			"20261010": {"x86_64": {"kernel-default=7.2.9-1.1"}},
		},
		// YaST's en_US locale selection recommends it with the GNOME pattern;
		// the 20261007 aarch64 closure, solved without RequestedLocales, lacks it.
		DesktopTaboo: map[string]map[string][]string{
			"20261007": {"aarch64": {"openconnect-lang"}},
		},
	},
}

const (
	reasonNoActionRecipe = "no maintained encrypted installer, native action prerequisites or graphical golden"
	reasonNoPasswordPins = "libpwquality/PAM/manager versions not measured on this release"
	reasonOSPatch        = "OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release"
	reasonReleaseUpgrade = "release upgrade is not implemented"
	// Fedora signs only its x86_64 kernels for shim (vmlinuz PE security
	// directory: 43 x86_64 1896 bytes, 43 aarch64 empty).
	reasonFedoraARMUnsignedKernel = "the vendor aarch64 kernel has no Authenticode signature, so shim refuses it under the Secure Boot that original-device recovery requires"
	reasonDesignOnly              = "design-only: the declarative/image-based management model is not specified"
	reasonELHost                  = "EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10"
	reasonEL8Packages             = "systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240"
	// The release-upgrade lane drives ubuntu-release-upgrader's unattended
	// frontend; Debian documents a manual sources rewrite plus apt full-upgrade.
	reasonDebianUpgrade = "Debian has no unattended release upgrader (the documented path is a manual sources rewrite and apt full-upgrade); the lane drives only do-release-upgrade"
	// EL rebuild major upgrades go through the separate ELevate/Leapp tooling.
	reasonELMajorUpgrade = "EL major upgrades need ELevate/Leapp, for which lindm has no upgrader or lane"
	reasonNoEL11         = "no successor release: EL 11 is not released"
	// The APT runner renders Ubuntu's Allowed-Origins (origin:suite) list.
	reasonDebianOSUpdate = "the os-update runner selects Ubuntu origin:suite pairs; Debian's security suites (stable-security/oldstable-security) need codename/label Origins-Pattern selection, which is not implemented"
	reasonRockyOSV       = "Rocky's OSV export uses source-like package mappings without a complete binary universe"
	// popUnsignedBoot was measured with `sbverify --list` on the Pop!_OS 24.04
	// generic build 28 golden's ESP ("No signature table present").
	popUnsignedBoot = "Pop!_OS's installed systemd-boot (EFI/systemd/systemd-bootx64.efi and its EFI/BOOT/BOOTX64.EFI copy) carries no Authenticode signature, so the installed system cannot boot under Secure Boot"
	// Omarchy's ALPM pre-transaction hook (00-omarchy-update-guard.hook)
	// aborts any direct `pacman -Syu`; `omarchy update` owns the transaction.
	reasonOmarchyOSUpdate = "Omarchy 4.0.4's ALPM guard aborts direct pacman system upgrades (only `omarchy update` may run them), and its moving stable mirrors have no immutable snapshot for a pinned rolling update"
	// The owned systemd-boot recovery fixture needs systemd-ukify, sbsigntools
	// and busybox, absent from the authenticated Omarchy ISO's offline
	// repository; a partial install from rolling mirrors is not used.
	reasonOmarchyOwnedBoot = "owned-boot recovery fixture packages (systemd-ukify, sbsigntools, busybox) are not on the authenticated Omarchy ISO and partial pacman upgrades are unsupported"
)

func caps(groups ...[]Capability) []Capability { return slices.Concat(groups...) }

func gates(pairs ...string) map[Capability]string {
	m := map[Capability]string{OSUpdate: reasonOSPatch, ReleaseUpgrade: reasonReleaseUpgrade}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[Capability(pairs[i])] = pairs[i+1]
	}
	return m
}

// without drops the default gate of capabilities a row supports.
func without(m map[Capability]string, supported ...Capability) map[Capability]string {
	for _, c := range supported {
		delete(m, c)
	}
	return m
}

func actionGates(pairs ...string) map[Capability]string {
	m := gates(pairs...)
	for _, c := range actionLanes {
		if _, ok := m[c]; !ok {
			m[c] = reasonNoActionRecipe
		}
	}
	return m
}

func designOnly() map[Capability]string {
	m := make(map[Capability]string, len(Capabilities))
	for _, c := range Capabilities {
		m[c] = reasonDesignOnly
	}
	return m
}

// nixosGates keeps NixOS design-only and names the installation boundary:
// lindmd serves agents only as signed native APT/RPM/pacman repositories, and
// a NixOS module must not depend on a derivation hosted elsewhere.
func nixosGates() map[Capability]string {
	m := designOnly()
	m[Lifecycle] = "design-only: lindmd serves no NixOS installation artifact (no release-signed agent archive pinned through the console, no NixOS runtime for the agent's units, inventory or package backend); see the NixOS self-hosted design in atomic-nixos.md"
	return m
}

var (
	both       = []string{"x86_64", "aarch64"}
	x86        = []string{"x86_64"}
	debianLike = []string{"debian"}
	fedoraVar  = []string{"", "workstation", "server", "cloud", "container"}
	apt        = PackageTooling{Backend: BackendAPT}
	// update-notifier-common (jammy 3.192.54.8, noble 3.192.68.2, resolute
	// 3.207.2; listed in the 24.04.5 desktop and live-server manifests) ships
	// notify-reboot-required and its /etc/kernel/postinst.d symlink, which
	// write /var/run/reboot-required (/var/run is /run) and .pkgs when a
	// kernel, or a package whose maintainer script calls it, is installed.
	// Read from the noble 3.192.68.2 deb (SHA-256
	// 50c3303b52aaaaadcf11750e1a0afc905bdee0d6f75aa2f1febdd4416afe7fec).
	ubuntuRebootSignal = &RebootSignal{Marker: "/run/reboot-required", Package: "update-notifier-common",
		Writers: []string{"/usr/share/update-notifier/notify-reboot-required", "/etc/kernel/postinst.d/update-notifier"}}
	// DNF5 up to 5.4.2.1 treats --store as system-modifying and refuses a
	// read-only /usr (fixed in 5.4.3.0); 5.4.6.0 is the natively qualified
	// floor (docs/platforms/fedora.md, DNF5 floor). The Fedora 44 release
	// image carries 5.4.1.0 and no dnf5 plugins; os.update.v1 needs only dnf5
	// and rpm, so its first window run raises dnf5 above the floor.
	dnf5 = PackageTooling{Backend: BackendDNF5, Minimum: "5.4.6.0"}
	// DNF 4.7.0 is EL 8.10's; older DNF4 lacks the plugin selection, strict
	// remote-RPM and query APIs the DNF4 adapter relies on.
	dnf4 = PackageTooling{Backend: BackendDNF4, Minimum: "4.7.0"}
	// ALA 2026/10/02 pacman-7.1.0.r9.g54d9411-2, SHA256
	// 2092ec7a0391416e4a1757c455bc071d7b58a124cedc83f582cb7d37d52f211b:
	// packaged public headers and library filename identify this ABI.
	// Detached package signature verified against the Arch developer page's
	// primary fingerprint 02FD1C7A934E614545849F19A6234074498E9CEE.
	// Native runtime qualification remains a separate matrix receipt.
	pacman    = PackageTooling{Backend: BackendPacman, ALPM: ALPMABI{Path: "/usr/lib/libalpm.so.16.0.1", SONAME: "libalpm.so.16", Version: "16.0.1"}, ResourceDependencies: []string{"python"}}
	zypper    = PackageTooling{Backend: BackendZypper}
	gnomeGDM3 = Desktop{Name: "GNOME", DisplayManager: "gdm3", Lock: "GNOME Shell"}
	gnomeGDM  = Desktop{Name: "GNOME", DisplayManager: "gdm", Lock: "GNOME Shell"}
	ufw       = "nftables + ufw (inactive)"
	firewalld = "nftables + firewalld"
	nftables  = "nftables"
	// EL 9's systemd 252-67 carries the 255-era TPM2 code with the stale
	// encryption-session retry (rhel.md#tpm2-unseal-retry; Rocky 9.8 measured).
	elQuirks9  = Quirks{AccountChroot: true, SystemdFloor: 252, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB, TPM2UnsealRetry: TPM2UnsealRetryNextToken}
	elQuirks10 = Quirks{AccountChroot: true, SystemdFloor: 255, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB}
	// Stock shim+GRUB chains for measured original-device recovery.
	blsGRUB     = GRUBChain{Entries: GRUBBLS, Editenv: "/usr/bin/grub2-editenv", ConfigDirectory: "grub2", BootDirectory: "/boot"}
	debianGRUB  = GRUBChain{Entries: GRUBCustomConfig, Editenv: "/usr/bin/grub-editenv", ConfigDirectory: "grub", BootDirectory: "/boot"}
	el9Pins     = []PasswordPins{{Version: "9.8", Quality: "1.4.4", PAM: "1.5.1", Manager: "1.2.6"}}
	el10Pins    = []PasswordPins{{Version: "10.2", Quality: "1.4.5", PAM: "1.6.1", Manager: "1.5.2"}}
	osvFeed     = []Feed{FeedOSV}
	debianFeeds = []Feed{FeedOSV, FeedDebianTracker}
	redHatFeed  = []Feed{FeedRedHatCSAF}
	suseFeed    = []Feed{FeedSUSECSAF}
	// Debian's OSV export (DSA/DLA/DEBIAN-CVE) covers every Debian release;
	// records are selected by ecosystem. It is the primary (configured) feed.
	debianExports = map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 4 << 30}}
	almaExports   = map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 1 << 30}}
	rockyExports  = map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 1 << 30}}
	// Rocky Linux and AlmaLinux 9/10 lab lanes, on both architectures.
	elRebuildLanes = []LabLane{LaneResources, LaneUpdates, LaneServices, LaneAirgap, LaneAdvisories, LaneEnrollFromConsole}
	// Encrypted-installer and device-action lab recipes.
	dracutTPM      = []string{"systemd", "crypt", "tpm2-tss", "lvm"}
	dracutSplitTPM = []string{"systemd", "crypt", "tpm2-tss", "lvm", "systemd-cryptsetup"}
	ubuntuSession  = LabSession{
		Desktops:  map[string][]string{"gnome": {"ubuntu-desktop-minimal"}, "kde": {"kubuntu-desktop"}},
		GDMConfig: "/etc/gdm3/custom.conf", Name: "ubuntu", Terminal: []string{"gnome-terminal", "--"},
		UpgradePrompt: "/etc/update-manager/release-upgrades",
		Capture:       []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gstreamer1.0-pipewire", "gstreamer1.0-plugins-good", "gnome-shell", "mutter-common"},
	}
	// The 26.04 desktop ISO replaces gnome-terminal with Ptyxis and carries
	// Mutter ABI 18; keep both choices separate from the GNOME 46 recipe.
	ubuntuResoluteSession = LabSession{
		Desktops: ubuntuSession.Desktops, GDMConfig: ubuntuSession.GDMConfig, Name: ubuntuSession.Name,
		Terminal: []string{"ptyxis", "--new-window", "--"}, UpgradePrompt: ubuntuSession.UpgradePrompt,
		Capture: slices.Concat(ubuntuSession.Capture, []string{"libmutter-18-0"}),
		// GNOME's new --upgrade-user unit ignores gnome-initial-setup-done.
		FirstLoginMarkers: []string{"gnome-initial-setup/upgrade-26.04-done"},
	}
	ubuntuGuest = LabGuest{
		KernelConfig: "/boot/config-%s",
		Initrd:       "/boot/initrd.img-%s",
		Actions:      []string{"cryptsetup", "nftables", "iproute2", "iputils-ping", "tpm2-tools", "dnsutils", "curl"},
		OwnedBoot:    []string{"systemd-boot", "systemd-boot-efi", "systemd-ukify", "cryptsetup-bin", "dmsetup", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// resolute's dracut 110 + systemd 259 cryptsetup reports a rejected
	// recovery key only in the journal (noble's 255 printed it), so the lab
	// routes its diagnostics to the console like Debian 13 and Fedora/EL.
	ubuntuResoluteGuest = LabGuest{
		KernelConfig: ubuntuGuest.KernelConfig, Initrd: ubuntuGuest.Initrd, CryptsetupConsole: true,
		Actions: ubuntuGuest.Actions, OwnedBoot: ubuntuGuest.OwnedBoot, MeasuredBoot: ubuntuGuest.MeasuredBoot,
	}
	fedoraGraphical = []string{"base-graphical", "desktop-accessibility", "fonts", "guest-desktop-agents", "hardware-support", "input-methods", "networkmanager-submodules"}
	fedoraSession   = LabSession{
		Desktops:  map[string][]string{"gnome": slices.Concat(fedoraGraphical, []string{"gnome-desktop"}), "kde": slices.Concat(fedoraGraphical, []string{"kde-desktop"})},
		GDMConfig: "/etc/gdm/custom.conf", Name: "gnome", Terminal: []string{"ptyxis", "--new-window", "--"},
		Capture: []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "pipewire-gstreamer", "gstreamer1-plugins-good", "gnome-shell", "mutter"},
	}
	fedoraGuest = LabGuest{
		KernelConfig: "/boot/config-%s",
		Initrd:       "/boot/initramfs-%s.img", CryptsetupConsole: true,
		Actions:      []string{"cryptsetup", "nftables", "iproute", "iputils", "systemd-udev", "tpm2-tools", "bind-utils", "curl"},
		OwnedBoot:    []string{"systemd-boot-unsigned", "systemd-ukify", "cryptsetup", "device-mapper", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// Fedora signs only its x86_64 kernels for shim (see reasonFedoraARMUnsignedKernel).
	fedoraARMNoSecureBoot = map[string]string{"aarch64": "the vendor aarch64 kernel has no Authenticode signature, so shim refuses it"}
	// RHEL installs only from the vendor-authenticated Binary DVD (no Lab.Repository):
	// the Workstation environment, TPM user space and action prerequisites
	// become kickstart %packages. An unregistered installed system has no other
	// repository, so the action prerequisites also carry the recovery helpers.
	rhelSession = LabSession{
		Desktops: map[string][]string{"gnome": {"@^workstation-product-environment"}},
		// The aarch64 DVDs' comps have only Server with GUI and Server.
		ArchitectureDesktops: map[string]map[string][]string{"aarch64": {"gnome": {"@^graphical-server-environment"}}},
		GDMConfig:            "/etc/gdm/custom.conf", Name: "gnome",
	}
	rhelGuest = LabGuest{
		KernelConfig: "/boot/config-%s",
		Initrd:       "/boot/initramfs-%s.img", CryptsetupConsole: true, OwnedBootHostonly: true,
		Actions:      []string{"cryptsetup", "nftables", "iproute", "iputils", "systemd-udev", "tpm2-tools", "bind-utils", "curl", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		OwnedBoot:    []string{"systemd-boot-unsigned", "systemd-ukify", "cryptsetup", "device-mapper", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	rhelTPMPackages = []string{"tpm2-tools", "tpm2-tss"}
	// The signed EL 9.8/10.2 grubaa64.efi records no GRUB PCR 8/9 event (the
	// RHEL 9.8/10.2 aarch64 ordinary logs captured by recovery-sanitize have
	// no PCR 8 event at all), so measured recovery is refused at readiness;
	// aarch64 recovery runs the owned-boot UKI fixture with the host's ukify.
	elARMUnmeasuredGRUB = map[string]string{"aarch64": "the signed EL grubaa64.efi records no PCR 8/9 event, so measured-GRUB readiness refuses (recovery_readiness_measured_grub_required)"}
	// Provisioning installs only from lindmd's repository: the console
	// snippet skips its DNF prerequisites when rpm -q has them, so both the
	// unregistered KVM image (cloud-init) and the unregistered Binary DVD
	// install (Kickstart %post) enroll without Red Hat entitlement.
	rhelLanes = []LabLane{LaneResources, LaneUpdates, LaneServices, LaneAdvisories, LaneEnrollFromConsole, LaneProvisionCloudInit, LaneProvisionKickstart}
	// RHEL CSAF matching applies only to a corroborated servicing stream, which
	// the host proves with its entitled BaseOS repository ID (internal/advisory
	// rhelStream). The air-gap lane's guest has no route to Red Hat from boot,
	// and the lab has no disconnected Satellite, so evaluation stays
	// rhel_platform_stream_unavailable and never binds the bundle's feed.
	rhelLaneGates  = map[LabLane]LaneGate{LaneAirgap: {Reason: "air-gapped RHEL proves its CSAF servicing stream only through entitled BaseOS repositories (CDN registration or a disconnected Satellite), which the offline lab cannot provide"}}
	rhelCSAFExport = map[Feed]AdvisoryExport{FeedRedHatCSAF: {
		URL: "https://security.access.redhat.com/data/csaf/v2/", Format: "redhat-csaf-archives", MaxAgeSeconds: 604800, PlatformStream: "standard",
	}}
	// Rocky Linux and AlmaLinux 9.8/10.2 also install only from their vendor
	// DVD, but their unregistered systems keep the free vendor repositories,
	// so the lanes install action and owned-boot prerequisites with DNF. Only
	// "Server with GUI" carries GNOME on every pinned DVD: the aarch64 comps
	// have no workstation-product-environment (Anaconda stopped on it).
	elRebuildDesktops = map[string][]string{"gnome": {"@^graphical-server-environment"}}
	elRebuildCapture  = []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "pipewire-gstreamer", "gstreamer1-plugins-good", "gnome-shell", "mutter"}
	elRebuildSession9 = LabSession{
		Desktops: elRebuildDesktops, GDMConfig: "/etc/gdm/custom.conf", Name: "gnome",
		Terminal: []string{"gnome-terminal", "--"}, Capture: elRebuildCapture,
	}
	elRebuildSession10 = LabSession{
		Desktops: elRebuildDesktops, GDMConfig: "/etc/gdm/custom.conf", Name: "gnome",
		Terminal: []string{"ptyxis", "--new-window", "--"}, Capture: elRebuildCapture,
	}
	// Debian's netinst installs desktops as tasksel tasks; its gdm3 reads
	// daemon.conf (Ubuntu patches it to custom.conf).
	debianSession = LabSession{
		Desktops:  map[string][]string{"gnome": {"desktop", "gnome-desktop"}, "kde": {"desktop", "kde-desktop"}},
		GDMConfig: "/etc/gdm3/daemon.conf", Name: "gnome", Terminal: []string{"gnome-terminal", "--"},
		Capture: []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gstreamer1.0-pipewire", "gstreamer1.0-plugins-good", "gstreamer1.0-tools", "gnome-shell"},
	}
	debianGuest = LabGuest{
		KernelConfig: "/boot/config-%s",
		Initrd:       "/boot/initrd.img-%s",
		Actions:      []string{"cryptsetup", "nftables", "iproute2", "iputils-ping", "tpm2-tools", "bind9-dnsutils", "curl"},
		OwnedBoot:    []string{"systemd-boot", "systemd-boot-efi", "systemd-ukify", "cryptsetup-bin", "dmsetup", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// trixie's systemd 257 cryptsetup reports a rejected recovery key only in
	// the journal (bookworm's 252 prints it on the console), so the lab routes
	// its diagnostics to the console like Fedora/EL.
	debianTrixieGuest = LabGuest{
		KernelConfig: debianGuest.KernelConfig,
		Initrd:       debianGuest.Initrd, CryptsetupConsole: true,
		Actions: debianGuest.Actions, OwnedBoot: debianGuest.OwnedBoot, MeasuredBoot: debianGuest.MeasuredBoot,
	}
	// Debian's arm64 kernels build TPM CRB but not the TIS platform driver,
	// QEMU virt's only TPM device.
	debianArmNoTIS = []string{"aarch64"}
	// reasonNoUkify: the owned-boot recovery fixture builds its ordinary UKI
	// with the guest's ukify, which systemd 253 introduced.
	reasonNoUkify = "no systemd-ukify (systemd 253+) for the owned-boot recovery fixture's ordinary UKI"
	// Vendor unattended installer formats; each must also exist in the
	// release's installation media (see docs/agent-enrollment.md).
	cloudInitOnly        = []Provisioning{ProvisionCloudInit}
	cloudInitAutoinstall = []Provisioning{ProvisionCloudInit, ProvisionAutoinstall}
	cloudInitKickstart   = []Provisioning{ProvisionCloudInit, ProvisionKickstart}
	cloudInitAutoYaST    = []Provisioning{ProvisionCloudInit, ProvisionAutoYaST}
	// Remotely grantable provider facts (the "Capability policy facts" section
	// of docs/platforms/ubuntu.md, fedora.md, alma-rocky.md and debian.md
	// records how they were obtained).
	// Standard roots are vendor drop-in directories read by pam_motd and agetty.
	dropInRoots = []string{"/etc/issue.d", "/etc/motd.d"}
	// login.defs UID_MIN..UID_MAX-1 / GID_MIN..GID_MAX-1 (1000/60000) on
	// Ubuntu, Debian, Fedora and EL 9/10 (shadow-utils, login, login.defs).
	regularAccounts = AccountDefaults{HomeRootID: "f0047cfe-68c5-5850-a2b5-b9adc55d4f43", HomeRoot: "/home", MinUID: 1000, MaxUID: 59999, MinGID: 1000, MaxGID: 59999}
	// ubuntuArchive is the Ubuntu archive repository identity every Ubuntu row
	// binds (apt/<uuid>), on archive.ubuntu.com (amd64) or ports (arm64).
	ubuntuArchive = VendorRepository{
		RepositoryID: "8053e72a-44e8-53fc-9472-825c068cf9b5", DB: PackageDBDpkg,
		ArchiveURIs: map[string]string{"x86_64": "https://archive.ubuntu.com/ubuntu", "aarch64": "https://ports.ubuntu.com/ubuntu-ports"},
		Components:  []string{"main", "universe"}, KeyFile: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
	}
	// ubuntu-keyring 2023.11.28.1 (noble's only version, SHA256
	// 36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8 in the
	// signed noble main index), 3607 bytes; holds the 2012 and 2018 archive keys.
	// Every noble, noble-updates and noble-security InRelease on archive and
	// ports verifies with it (signer F6ECB3762474EDA9D21B7022871920D1991BC93C).
	nobleArchive = ubuntuSuites(ubuntuArchive, "7c640025-e320-5951-9086-6a67ea6572f7", "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31", "noble")
	// ubuntu-keyring 2021.03.26 (jammy's only version; none in -updates or
	// -security; SHA256 0d0e7ed6…520f in the signed jammy main indexes),
	// 7399 bytes: the 2012 and 2018 archive keys plus the 2012 CD image key.
	// Every jammy, jammy-updates and jammy-security InRelease on archive and
	// ports verifies with it (signer F6ECB3762474EDA9D21B7022871920D1991BC93C).
	jammyArchive = ubuntuSuites(ubuntuArchive, "d74a0281-9d25-5f2c-ac6b-9d4bfa1e8c2e", "1a4dd63e5c76728960a2edddae22e2e0fc53df8e8b87806deb971030ac704eb0", "jammy")
	// vendorRPMArchiveID is the RPM repository identity profiles bind for the
	// host's own distribution archive (rpm/<uuid>): Fedora's on Fedora, the
	// rebuild's own BaseOS/AppStream on Rocky Linux and AlmaLinux.
	vendorRPMArchiveID = "12e3a0eb-c710-58d9-bd79-a491c614754c"
	// fedora-gpg-keys 44-1 (release) and 44-2 (updates) ship identical
	// RPM-GPG-KEY-fedora-44-primary bytes (1672), fingerprint as published on
	// fedoraproject.org/security; both packages verify with it. The -x86_64 and
	// -aarch64 names are symlinks to this file.
	fedora44Archive = VendorRepository{
		RepositoryID: vendorRPMArchiveID, DB: PackageDBRPM,
		NativeRepositories: []VendorNativeRepository{
			{ID: "fedora", Metalinks: map[string]string{"x86_64": "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64", "aarch64": "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=aarch64"}},
			{ID: "updates", Metalinks: map[string]string{"x86_64": "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64", "aarch64": "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=aarch64"}},
		},
		KeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary", KeyArtifactID: "95fa021e-c28c-5534-b003-6ece85787e0c",
		KeySHA256:      []string{"93642aec521a1e5e96dd715f7ae0ec0850ebc9de09a94ce03cae5263f26cc18a"},
		RPMFingerprint: "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
		// releases/44 and updates/44 repodata have no repomd.xml.asc (HTTP 404
		// on 2026-10-12): metadata is authenticated through Fedora's HTTPS
		// MirrorManager metalink (owner decision, docs/security-and-operations.md).
		MetadataUnsigned: true, MetalinkHost: "mirrors.fedoraproject.org",
	}
	// EL rebuild archives (alma-rocky.md, "Capability policy facts"):
	// BaseOS and AppStream under the vendor RPM identity profiles bind for
	// the host's own distribution archive. Both vendors sign repomd.xml, so
	// the sources use HTTPS base URLs with signed metadata; no metalink pin.
	// The key file bytes were identical in every minor's -gpg-keys package.
	rocky9Archive = elArchive("https://dl.rockylinux.org/pub/rocky/9/%s/%s/os/", VendorRepository{
		KeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9", KeyArtifactID: "c8feefd2-7828-523a-aeff-a7f2e4dc5efe",
		KeySHA256: []string{"3a66e521e7a4abac9768d889c7cd60a8250f59512b275cf576c8a10ff34624c1"}, RPMFingerprint: "21CB256AE16FC54C6E652949702D426D350D275D",
	})
	// rocky-gpg-keys 10.2-1.2 appends a second, v6 post-quantum key block to
	// RPM-GPG-KEY-Rocky-10 (18586 bytes,
	// 7f517e9ca329b042228e9a35e74e1b260513ed9c786d5ebcc459e623855f2831). The
	// RSA-only file of 10.0-1.6 through 10.2-1.1 is accepted; the two-key
	// file is not, until a native run shows DNF and rpm accept it.
	rocky10Archive = elArchive("https://dl.rockylinux.org/pub/rocky/10/%s/%s/os/", VendorRepository{
		KeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10", KeyArtifactID: "191f7baf-7cbb-58f4-9925-9497bde260b0",
		KeySHA256: []string{"be8c4f070b696e64d8ce40e59a95a57e8b5c776f0015c2fd64e14b896622bdb4"}, RPMFingerprint: "FC226859C0860BF0DDB95B085B106C736FEDFC85",
	})
	alma9Archive = elArchive("https://repo.almalinux.org/almalinux/9/%s/%s/os/", VendorRepository{
		KeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9", KeyArtifactID: "7410d2c1-f135-57bd-a08d-a40d7aa2fd04",
		KeySHA256: []string{"387a8be6b70ecff4949d28778bf8abd06231654283b6e9515afc9305a1391458"}, RPMFingerprint: "BF18AC2876178908D6E71267D36CB86CB86B3716",
	})
	// AlmaLinux 10 also publishes an x86_64_v2 build whose packages the
	// x86_64 (x86-64-v3) tree must never replace.
	alma10Archive = elArchive("https://repo.almalinux.org/almalinux/10/%s/%s/os/", VendorRepository{
		KeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10", KeyArtifactID: "70b42e69-0f63-534e-8414-3a79c2ee2b2f",
		KeySHA256: []string{"de57c3c0a2dcde88ff5b894e74335f55a0ec074815f36d472270d937c16f077b"}, RPMFingerprint: "EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572",
		VariantMarkers: []string{"/etc/rpm/macros.x86_64_v2"},
	})
)

var registry = []*Release{
	{
		Key: "ubuntu-22.04", Name: "Ubuntu 22.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("22.04"), Codename: "jammy", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, RebootSignal: ubuntuRebootSignal, Systemd: 249, Provisioning: cloudInitAutoinstall,
		FDE: "LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut 051 + TSS2 libraries)", Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:22.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "jammy",
			Exports: map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 4 << 30}}},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "22.04", Quality: "1.4.4", PAM: "1.4.0", Manager: "1.4.0"}}, RecoveryGRUB: debianGRUB},
		VendorRepositories: []VendorRepository{jammyArchive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		// Jammy's dracut 051 has no tpm2-tss module: the initramfs carries the
		// TSS2 libraries systemd 249's cryptsetup dlopens and the TPM drivers.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneServices, LaneUpdates, LaneAirgap, LaneAdvisories, LaneEnrollFromConsole}, Installer: Subiquity, Session: ubuntuSession, Guest: ubuntuGuest, FirstBootAccount: true,
			OwnedBootUnavailable: reasonNoUkify,
			TPM: LabTPM{Modules: []string{"systemd", "crypt", "lvm"}, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0", "cryptsetup-initramfs-"},
				Items:   []string{"/usr/lib/%s/libtss2-esys.so.0", "/usr/lib/%s/libtss2-mu.so.0", "/usr/lib/%s/libtss2-rc.so.0", "/usr/lib/%s/libtss2-tctildr.so.0", "/usr/lib/%s/libtss2-tcti-device.so.0"},
				Drivers: []string{"tpm_tis", "tpm_crb"}}},
		// Recovery sanitize is measured GRUB only, on amd64: jammy's signed
		// grubaa64.efi embeds no tpm module (the amd64 build does), and the arm64
		// vmlinuz is gzip-compressed, so neither recovery boot exists there.
		Supports:          caps(agentCore, []Capability{Packages, Accounts, Sysctl, Firewall, Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		ArchitectureGates: map[string]map[Capability]string{"aarch64": {RecoverySanitize: "jammy's signed grubaa64.efi (grub-efi-arm64-signed 1.187.12+2.06-2ubuntu14.8) embeds no tpm module, so it records no PCR 8/9 event for measured recovery, and the gzip-compressed arm64 vmlinuz with systemd 249 (no ukify) cannot form the owned recovery UKI"}},
		// 249's verify has no --recursive-errors (systemd 250) and exits 0 on
		// a candidate setting it ignores as invalid. A modelled 22.04→24.04
		// do-release-upgrade completed natively, but owned resources then stayed
		// unconverged (see ubuntu.md#release-upgrade-2204--2404).
		Gates: without(gates(string(Definitions), "systemd 249 is below the definition provider floor 255",
			string(ReleaseUpgrade), "22.04→24.04 post-upgrade reconvergence is not implemented: after do-release-upgrade the owned sysctl fails its postcondition and the managed file is refused at admission"), OSUpdate),
	},
	{
		Key: "ubuntu-24.04", Name: "Ubuntu 24.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("24.04"), Codename: "noble", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, RebootSignal: ubuntuRebootSignal, Systemd: 255, UpgradeTo: "ubuntu-26.04", Provisioning: cloudInitAutoinstall,
		FDE: "LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME", Version: "GNOME 46", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: ufw,
		// Archive facts observed on every 24.04 pocket (archive, security,
		// ports and the Pop!_OS mirror) on 2026-10-11: Ubuntu Archive Automatic
		// Signing Key (2018). Ubuntu's OSV export assesses the release, -updates
		// and -security pockets; -backports and -proposed get no security support.
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:24.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "noble", CodenameRelease: true,
			Exports:       map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 4 << 30}},
			ArchiveOrigin: "Ubuntu", ArchiveSuites: []string{"noble", "noble-security", "noble-updates"}, ArchiveSigners: []string{"F6ECB3762474EDA9D21B7022871920D1991BC93C"}},
		// systemd 255.4-1ubuntu8.17 lacks upstream 1923e213165d (255.5): a
		// PCR_CHANGED unseal retry fails "Missing encryption session" (EINVAL),
		// and the signed kernel's Secure Boot IMA policy measures each initrd
		// module load into PCR 10 during the unlock (ubuntu.md#tpm2-unseal-race).
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate, SSHBannerUnit: "ssh.service", TPM2UnsealRetry: TPM2UnsealRetryNextToken,
			Password: []PasswordPins{{Version: "24.04", Quality: "1.4.5", PAM: "1.5.3", Manager: "1.5.3"}}, RecoveryGRUB: debianGRUB},
		ModuleBlocklist:    ModuleBlocklistTooling{Modprobe: "/usr/sbin/modprobe", InitramfsPattern: "/boot/initrd.img-%s", Rebuild: "/usr/sbin/update-initramfs", RebuildArgs: []string{"-u", "-k", "all"}, WritePaths: []string{"/boot"}, StateDirectory: "/var/lib/initramfs-tools"},
		VendorRepositories: []VendorRepository{nobleArchive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneServer, LaneAdvisories, LaneAcceptance, LaneEncryptedAcceptance, LaneEnrollFromConsole, LaneProvisionCloudInit, LaneProvisionAutoinstall},
			Installer: Subiquity, Session: withCapture(ubuntuSession, "libmutter-14-0"), Guest: ubuntuGuest,
			// The signed arm64 vmlinuz (linux-signed 6.8.0-142.142) is a gzip-compressed
			// Image that GRUB unpacks; systemd 255's stub cannot embed it in a UKI.
			OwnedBootUnavailableOn: map[string]string{"aarch64": "the arm64 vendor kernel is a gzip-compressed Image that systemd-stub cannot embed in the owned ordinary UKI"},
			TPM:                    LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0t64", "cryptsetup-initramfs-"}}},
		// ReleaseUpgrade: do-release-upgrade to UpgradeTo, `lab vm resources -phase release-upgrade`.
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, ReleaseUpgrade}, actionLanes),
		Gates:    without(gates(), OSUpdate, ReleaseUpgrade),
	},
	{
		Key: "ubuntu-26.04", Name: "Ubuntu 26.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("26.04"), Codename: "resolute", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, RebootSignal: ubuntuRebootSignal, Systemd: 259, Provisioning: cloudInitAutoinstall,
		Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:26.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "resolute",
			Exports: map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 4 << 30}}},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "26.04", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}}, RecoveryGRUB: debianGRUB},
		// The 26.04 desktop ISO carries dracut 110, systemd-cryptsetup and the
		// TSS2 libraries, but not tpm2-tools, whose tpm2 binary dracut's
		// tpm2-tss module requires.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneServices, LaneAdvisories, LaneEnrollFromConsole, LaneProvisionCloudInit, LaneProvisionAutoinstall},
			Installer: Subiquity, Session: ubuntuResoluteSession, Guest: ubuntuResoluteGuest, TPM: LabTPM{Modules: dracutSplitTPM, Packages: []string{"tpm2-tools"}}},
		// Recovery sanitize is qualified through measured GRUB (recovery-*-grub-03):
		// on the stock 105 MiB cloud ESP the owned UKI holds the vendor kernel plus
		// the non-hostonly dracut initrd (72 MB), so UKI mode is refused natively
		// (device_action_esp_insufficient), as on Fedora 44. The ESP is not resized
		// and no vendor file or kernel is substituted.
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate}, actionLanes),
		// No later Ubuntu LTS exists to upgrade to; 24.04 upgrades into this row.
		Gates: without(gates(string(ReleaseUpgrade), "no successor release: the next Ubuntu LTS is not released"), OSUpdate),
	},
	{
		Key: "debian-11", Name: "Debian 11", Distribution: "Debian", ID: "debian", Version: Exact("11"), Codename: "bullseye",
		Tier: TierOutside, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 247, Provisioning: cloudInitOnly,
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:11", PURLNamespace: "debian", PURLDistro: "bullseye"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Advisories}),
		Gates:    actionGates(string(Definitions), "systemd 247 is below the definition provider floor 255"),
	},
	{
		Key: "debian-12", Name: "Debian 12", Distribution: "Debian", ID: "debian", Version: Exact("12"), Codename: "bookworm",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 252, Provisioning: cloudInitOnly,
		FDE: "LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME/KDE", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: nftables,
		// Debian's OSV export qualifies purls with the codename (distro=bookworm).
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:12", PURLNamespace: "debian", PURLDistro: "bookworm", Exports: debianExports},
		// Debian 12's systemd 252 runs the timer/drop-in lane like EL 9's.
		Quirks: Quirks{SystemdFloor: 252, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "12", Quality: "1.4.5", PAM: "1.5.2", Manager: "1.5.2"}}, RecoveryGRUB: debianGRUB},
		// No vendor archive: AptRepository has one URI, but the security pocket
		// lives only under /debian-security (debian.md, "Capability policy facts").
		StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneServices, LaneAirgap, LaneAdvisories, LaneEnrollFromConsole}, Installer: DebianInstaller, Session: debianSession, Guest: debianGuest,
			OwnedBootUnavailable: reasonNoUkify,
			TPM:                  LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "tpm2-tools", "libtss2-tcti-device0", "cryptsetup-initramfs-"}, Unobservable: debianArmNoTIS}},
		// Recovery sanitize is measured GRUB only (systemd 252 has no ukify),
		// on amd64: bookworm's signed grubaa64.efi embeds no tpm module.
		Supports:          caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		ArchitectureGates: map[string]map[Capability]string{"aarch64": {RecoverySanitize: "bookworm's signed grubaa64.efi (grub-efi-arm64-signed 1+2.06+13+deb12u2) embeds no tpm module, so it records no PCR 8/9 event for measured recovery, and systemd 252 has no ukify for the owned recovery UKI"}},
		Gates:             gates(string(ReleaseUpgrade), reasonDebianUpgrade, string(OSUpdate), reasonDebianOSUpdate),
	},
	{
		Key: "debian-13", Name: "Debian 13", Distribution: "Debian", ID: "debian", Version: Exact("13"), Codename: "trixie",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 257, Provisioning: cloudInitOnly,
		FDE: "LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME/KDE", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: nftables,
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:13", PURLNamespace: "debian", PURLDistro: "trixie", Exports: debianExports},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "13", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}}, RecoveryGRUB: debianGRUB},
		StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		// trixie splits systemd-cryptsetup out of systemd and its dracut out of crypt.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneServices, LaneAirgap, LaneAdvisories, LaneEnrollFromConsole}, Installer: DebianInstaller, Session: debianSession, Guest: debianTrixieGuest,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: []string{"dracut", "tpm2-tools", "libtss2-tcti-device0t64", "systemd-cryptsetup", "cryptsetup-initramfs-"}, Unobservable: debianArmNoTIS}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}, actionLanes),
		Gates:    gates(string(ReleaseUpgrade), "no successor release: Debian 14 is not released", string(OSUpdate), reasonDebianOSUpdate),
	},
	{
		Key: "fedora-43", Name: "Fedora 43", Distribution: "Fedora", ID: "fedora", Version: Exact("43"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5, Systemd: 258, Provisioning: cloudInitKickstart,
		FDE: "LUKS2 (anaconda LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "Workstation GNOME; KDE edition", Version: "GNOME 49", DisplayManager: "gdm", Lock: "GNOME Shell"}, Firewall: firewalld,
		Advisory: Advisory{Feeds: []Feed{FeedRPMUpdateinfo}, Ecosystem: "Fedora 43",
			Exports: map[Feed]AdvisoryExport{FeedRPMUpdateinfo: {
				ArchitectureURLs: map[string]string{
					"x86_64":  "https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/x86_64/repodata/repomd.xml",
					"aarch64": "https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/aarch64/repodata/repomd.xml",
				},
				Format: "rpm-repomd", MaxAgeSeconds: 86400,
			}}},
		// shadow-utils 4.18.0 labels --prefix writes by the prefixed path: the
		// account helper's /etc/passwd, shadow, group and gshadow became
		// var_lib_t and PAM lost every local user. --root (chroot) writes them
		// at /etc paths; Fedora 44's 4.19.0 labels --prefix writes correctly.
		Quirks: Quirks{AccountChroot: true, SystemdFloor: 255, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB},
		// Fedora Cloud Base 43-1.6 (x86_64 and aarch64) ships / as root:root
		// 0775 (Fedora 44 1.7: 0755); `filesystem` packages it 0555.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneServices, LaneAdvisories, LaneEnrollFromConsole, LaneProvisionCloudInit, LaneProvisionKickstart},
			RootPermissionsRepair: []string{"rpm", "--restore", "filesystem"},
			// Encrypted goldens and provision-kickstart install from the signed Server DVD.
			Installer: Anaconda, Session: fedoraSession, Guest: fedoraGuest,
			Kickstart: "F43", Repository: "https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/%s/os/", RepositoryKey: "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-43-%s",
			TPM:                     LabTPM{Modules: dracutSplitTPM, Packages: []string{"systemd-udev", "tpm2-tools", "tpm2-tss"}},
			SecureBootUnavailableOn: fedoraARMNoSecureBoot},
		// Fedora 43 (release and updates) carries dnf5 5.2.18.0, below the
		// package provider's unprivileged-transaction floor (resources record
		// "native dnf5 5.4.6.0 or newer required"); os.update.v1 runs dnf5 itself.
		Supports: caps(agentCore, []Capability{Accounts, Sysctl, Definitions, Firewall, Advisories, OSUpdate}, actionLanes),
		Gates: without(gates(string(Password), reasonNoPasswordPins,
			string(Packages), "Fedora 43 ships dnf5 5.2.18.0; the package provider requires 5.4.6.0 to store a transaction without privileges"), OSUpdate),
		// kernel-core-6.17.1-300.fc43.aarch64's vmlinuz has no PE security
		// directory; the encrypted Secure Boot golden never reached SSH
		// (fedora-act43-arm-20261012T140712Z/recovery-sanitize-aarch64.json).
		ArchitectureGates: map[string]map[Capability]string{"aarch64": {RecoverySanitize: reasonFedoraARMUnsignedKernel}},
	},
	{
		Key: "fedora-44", Name: "Fedora 44", Distribution: "Fedora", ID: "fedora", Version: Exact("44"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5, Systemd: 259, Provisioning: cloudInitKickstart,
		FDE: "LUKS2 (anaconda LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "Workstation GNOME; KDE edition", Version: "GNOME 50", DisplayManager: "gdm", Lock: "GNOME Shell"}, Firewall: firewalld,
		Advisory: Advisory{Feeds: []Feed{FeedRPMUpdateinfo}, Ecosystem: "Fedora 44",
			Exports: map[Feed]AdvisoryExport{FeedRPMUpdateinfo: {
				ArchitectureURLs: map[string]string{
					"x86_64":  "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml",
					"aarch64": "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/aarch64/repodata/repomd.xml",
				},
				Format: "rpm-repomd", MaxAgeSeconds: 86400,
			}}},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerAuthselect, SSHBannerUnit: "sshd.service",
			Password: []PasswordPins{{Version: "44", Quality: "1.4.5", PAM: "1.7.2", Manager: "1.7.1"}}, RecoveryGRUB: blsGRUB},
		ModuleBlocklist:    ModuleBlocklistTooling{Modprobe: "/usr/sbin/modprobe", InitramfsPattern: "/boot/initramfs-%s.img", Rebuild: "/usr/bin/dracut", RebuildArgs: []string{"--regenerate-all", "--force"}, RebuildWithFileArgs: []string{"--regenerate-all", "--force", "--include", "/etc/modprobe.d/99-lindm-blocklist.conf", "/etc/modprobe.d/99-lindm-blocklist.conf"}, WritePaths: []string{"/boot"}},
		VendorRepositories: []VendorRepository{fedora44Archive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneAdvisories, LaneAcceptance, LaneEnrollFromConsole, LaneProvisionCloudInit, LaneProvisionKickstart},
			Installer: Anaconda, Session: fedoraSession, Guest: fedoraGuest,
			Kickstart: "F44", Repository: "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/%s/os/", RepositoryKey: "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-%s",
			TPM:                     LabTPM{Modules: dracutSplitTPM, Packages: []string{"systemd-udev", "tpm2-tools", "tpm2-tss"}},
			SecureBootUnavailableOn: fedoraARMNoSecureBoot},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate}, actionLanes),
		Gates:    without(gates(), OSUpdate),
		// Recovery needs Secure Boot (measured GRUB: PCR 7 SecureBoot=1; owned
		// UKI: signed recovery). Under AAVMF Secure Boot shim refuses Fedora's
		// unsigned aarch64 kernel (fedora44-mgrub-nvme-arm64-01/-02), and the
		// encrypted golden itself never reaches SSH
		// (fedora-recovery-arm-20261011T234650Z/recovery-nvme-aarch64.json).
		ArchitectureGates: map[string]map[Capability]string{"aarch64": {RecoverySanitize: reasonFedoraARMUnsignedKernel}},
	},
	{
		Key: "fedora-atomic", Name: "Fedora Atomic Silverblue/Kinoite", Distribution: "Fedora Atomic", ID: "fedora", Version: Any(),
		Variants: []string{"silverblue", "kinoite"},
		Tier:     TierFuture, Page: "atomic-nixos.md", Family: FamilyRedHat, Gates: designOnly(),
	},
	{
		Key: "rhel-8", Name: "RHEL 8", Distribution: "RHEL", ID: "rhel", Version: Major("8"),
		Tier: TierOutside, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 239, Provisioning: cloudInitKickstart,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:8", PURLNamespace: "redhat", PlatformStreams: true},
		Lab:      Lab{Lanes: []LabLane{LaneServices}, Entitlement: true},
		Supports: []Capability{Inventory, Advisories},
		Gates:    gates(string(Packages), reasonEL8Packages, string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost, string(Definitions), "systemd 239 is below the definition provider floor 252"),
	},
	{
		Key: "rhel-9", Name: "RHEL 9", Distribution: "RHEL", ID: "rhel", Version: Major("9"),
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:9", PURLNamespace: "redhat", PlatformStreams: true, Exports: rhelCSAFExport},
		Quirks:   withPins(elQuirks9, el9Pins),
		Lab: Lab{Lanes: rhelLanes, LaneGates: rhelLaneGates, Entitlement: true, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			Installer: Anaconda, Session: rhelSession, Guest: rhelGuest,
			RPMMedia: &LabRPMMedia{Repositories: []string{"BaseOS", "AppStream"}, Key: "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"},
			// EL 9's dracut 057 installs systemd-cryptsetup from crypt.
			TPM: LabTPM{Modules: dracutTPM, Packages: rhelTPMPackages}},
		// Native qualification of each action is per pinned minor in
		// verification.md (RHEL encrypted device actions); implemented
		// capabilities stay admitted so their qualification lanes can run.
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize}),
		Gates:    rhelGates(),
	},
	{
		Key: "rhel-10", Name: "RHEL 10", Distribution: "RHEL", ID: "rhel", Version: Major("10"),
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:10", PURLNamespace: "redhat", PlatformStreams: true, Exports: rhelCSAFExport},
		Quirks:   withPins(elQuirks10, el10Pins),
		Lab: Lab{Lanes: rhelLanes, LaneGates: rhelLaneGates, Entitlement: true, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			Installer: Anaconda, Session: rhelSession, Guest: rhelGuest,
			// dracut 107 ships the split 01systemd-cryptsetup module.
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: rhelTPMPackages}},
		// Native qualification per pinned minor: see the rhel-9 row.
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize}),
		Gates:    rhelGates(),
	},
	elRebuild("rocky-8", "Rocky Linux 8", "Rocky Linux", "rocky", "8", TierOutside, 239, "Rocky Linux:8", "rocky-linux", reasonRockyOSV),
	{
		Key: "rocky-9", Name: "Rocky Linux 9", Distribution: "Rocky Linux", ID: "rocky", Version: Major("9"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory:           Advisory{Feeds: osvFeed, Ecosystem: "Rocky Linux:9", PURLNamespace: "rocky-linux", PURLDistro: "rocky-linux-9", Partial: reasonRockyOSV, Exports: rockyExports},
		Quirks:             withPins(elQuirks9, el9Pins),
		VendorRepositories: []VendorRepository{rocky9Archive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: elRebuildLanes, Installer: Anaconda, Session: elRebuildSession9, Guest: rhelGuest, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			TPM: LabTPM{Modules: dracutTPM, Packages: rhelTPMPackages}},
		// Native qualification of each action is per pinned minor and
		// architecture in verification.md; implemented capabilities stay
		// admitted so their qualification lanes can run (see the rhel-9 row).
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    without(gates(string(ReleaseUpgrade), reasonELMajorUpgrade), OSUpdate),
	},
	{
		Key: "rocky-10", Name: "Rocky Linux 10", Distribution: "Rocky Linux", ID: "rocky", Version: Major("10"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory:           Advisory{Feeds: osvFeed, Ecosystem: "Rocky Linux:10", PURLNamespace: "rocky-linux", PURLDistro: "rocky-linux-10", Partial: reasonRockyOSV, Exports: rockyExports},
		Quirks:             withPins(elQuirks10, el10Pins),
		VendorRepositories: []VendorRepository{rocky10Archive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: elRebuildLanes, Installer: Anaconda, Session: elRebuildSession10, Guest: rhelGuest, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    without(gates(string(ReleaseUpgrade), reasonNoEL11), OSUpdate),
	},
	elRebuild("almalinux-8", "AlmaLinux 8", "AlmaLinux", "almalinux", "8", TierOutside, 239, "AlmaLinux:8", "almalinux", ""),
	{
		Key: "almalinux-9", Name: "AlmaLinux 9", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("9"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory:           Advisory{Feeds: osvFeed, Ecosystem: "AlmaLinux:9", PURLNamespace: "almalinux", PURLDistro: "almalinux-9", Exports: almaExports},
		Quirks:             withPins(elQuirks9, el9Pins),
		VendorRepositories: []VendorRepository{alma9Archive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: elRebuildLanes, Installer: Anaconda, Session: elRebuildSession9, Guest: rhelGuest, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			TPM: LabTPM{Modules: dracutTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    without(gates(string(ReleaseUpgrade), reasonELMajorUpgrade), OSUpdate),
	},
	{
		Key: "almalinux-10", Name: "AlmaLinux 10", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("10"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257, Provisioning: cloudInitKickstart,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory:           Advisory{Feeds: osvFeed, Ecosystem: "AlmaLinux:10", PURLNamespace: "almalinux", PURLDistro: "almalinux-10", Exports: almaExports},
		Quirks:             withPins(elQuirks10, el10Pins),
		VendorRepositories: []VendorRepository{alma10Archive}, StandardFileRoots: dropInRoots, Accounts: regularAccounts,
		Lab: Lab{Lanes: elRebuildLanes, Installer: Anaconda, Session: elRebuildSession10, Guest: rhelGuest, MeasuredGRUBUnavailableOn: elARMUnmeasuredGRUB,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    without(gates(string(ReleaseUpgrade), reasonNoEL11), OSUpdate),
	},
	{
		Key: "centos-stream-9", Name: "CentOS Stream 9", Distribution: "CentOS Stream", ID: "centos", Version: Exact("9"),
		Tier: TierOutside, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Provisioning: cloudInitKickstart,
		Supports: []Capability{Inventory}, Gates: gates(),
	},
	{
		Key: "centos-stream-10", Name: "CentOS Stream 10", Distribution: "CentOS Stream", ID: "centos", Version: Exact("10"),
		Tier: TierOutside, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Provisioning: cloudInitKickstart,
		Supports: []Capability{Inventory}, Gates: gates(),
	},
	{
		Key: "linuxmint-22.3", Name: "Linux Mint 22.3", Distribution: "Linux Mint", ID: "linuxmint", Version: Exact("22.3"),
		IDLike: []string{"ubuntu", "debian"}, Base: "ubuntu-24.04",
		Tier: Tier1, Page: "mint.md", Family: FamilyDebian, Architectures: x86,
		FDE: "LVM on LUKS (Ubiquity)", Desktop: Desktop{Name: "Cinnamon", DisplayManager: "lightdm", Lock: "cinnamon-screensaver (logind Lock; never sets LockedHint)"}, Firewall: ufw,
		// The ISO's Ubiquity runs noninteractively from a debconf preseed; the
		// installed root uses Ubuntu's initramfs-tools and archive package names.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, Installer: Ubiquity, Guest: ubuntuGuest,
			TPM: LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0t64", "cryptsetup-initramfs-"}},
			// The live media install Cinnamon itself; LightDM autologs into it.
			Session: LabSession{Desktops: map[string][]string{"cinnamon": nil}, Name: "cinnamon", Terminal: []string{"gnome-terminal", "--"},
				Capture: []string{"cinnamon", "cinnamon-screensaver", "lightdm", "xdg-desktop-portal", "xdg-desktop-portal-xapp", "xdg-desktop-portal-gtk", "pipewire", "gstreamer1.0-pipewire", "gstreamer1.0-plugins-good"}}},
		// packages.linuxmint.com publishes Release + Release.gpg with Origin
		// "linuxmint" (observed 2026-10-11).
		Advisory: Advisory{VendorOrigins: []string{"linuxmint"}, Partial: "vendor feed unavailable for Linux Mint packages"},
		// Mint installs Ubuntu's signed shim and GRUB packages (EFI/ubuntu on the
		// golden ESP); recovery readiness reads the os-release row's own quirk.
		Quirks:   Quirks{RecoveryGRUB: debianGRUB},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize}),
		Gates:    gates(string(Assistance), "portal_screencast_unavailable: xdg-desktop-portal-xapp/-gtk implement no ScreenCast or RemoteDesktop; lindm has no X11 capture path"),
	},
	{
		Key: "pop-24.04", Name: "Pop!_OS 24.04 LTS", Distribution: "Pop!_OS", ID: "pop", Version: Exact("24.04"),
		IDLike: []string{"ubuntu", "debian"}, Base: "ubuntu-24.04",
		Tier: Tier1, Page: "popos.md", Family: FamilyDebian, Architectures: x86,
		FDE: "LVM on LUKS (distinst)", Desktop: Desktop{Name: "COSMIC", DisplayManager: "cosmic-greeter", Lock: "cosmic-greeter (logind)"}, Firewall: ufw,
		// The ISO's distinst runs pop-installer's erase layout; the installed
		// root uses Pop's initramfs-tools and Ubuntu's archive package names.
		// COSMIC comes from the ISO itself (no packages). The shipped
		// cosmic.portal declares ScreenCast but no RemoteDesktop; the ISO lacks
		// gstreamer1.0-pipewire, which the agent package Recommends.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, Installer: Distinst, Guest: ubuntuGuest,
			Session: LabSession{Desktops: map[string][]string{"cosmic": nil}, Name: "cosmic", Terminal: []string{"cosmic-term", "-e"},
				Capture: []string{"cosmic-comp", "cosmic-greeter", "cosmic-notifications", "xdg-desktop-portal", "xdg-desktop-portal-cosmic", "pipewire", "gstreamer1.0-pipewire", "gstreamer1.0-plugins-good"}},
			TPM: LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0t64", "cryptsetup-initramfs-"}},
			// pop-system-updater c208318: UpdateSystem runs apt update and upgrade
			// through apt-get, holding dpkg's frontend lock (daemon/src/dbus/server.rs).
			Updater: LabUpdater{Unit: "com.system76.SystemUpdater.service",
				Trigger: "busctl call com.system76.SystemUpdater /com/system76/SystemUpdater com.system76.SystemUpdater UpdateSystem"},
			// pop-default-settings' pop-zram-config (pop-default-settings-zram.service)
			// runs `sysctl -w vm.swappiness=180` at every boot after systemd-sysctl.
			SysctlKey:             "vm.vfs_cache_pressure",
			SecureBootUnavailable: popUnsignedBoot},
		// apt.pop-os.org/release ("pop-os-release") and /proprietary
		// ("system76") use codename noble and the Pop!_OS key; its Ubuntu mirror
		// serves Ubuntu's own signed InRelease (observed 2026-10-11).
		Advisory: Advisory{VendorOrigins: []string{"pop-os-release", "system76"}, Partial: "vendor feed unavailable for Pop!_OS packages"},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, Assistance}),
		Gates:    gates(string(RecoverySanitize), "original-device recovery requires Secure Boot; "+popUnsignedBoot),
	},
	{
		Key: "arch", Name: "Arch Linux", Distribution: "Arch Linux", ID: "arch", Version: Absent(),
		Tier: Tier2, Page: "arch.md", Family: FamilyArch, Architectures: x86, Packages: pacman, Provisioning: cloudInitOnly,
		RollingUpdate:       &RollingUpdateTooling{ArchiveURL: "https://archive.archlinux.org/repos/", Repositories: []string{"core", "extra", "multilib"}},
		RequalificationDays: 14,
		Advisory: Advisory{Feeds: []Feed{FeedArchASA}, Ecosystem: "Arch Linux rolling", Partial: "tracker omits historical and non-repository packages", Exports: map[Feed]AdvisoryExport{
			FeedArchASA: {URL: "https://security.archlinux.org/issues/all.json", Format: "arch-json", MaxAgeSeconds: 86400},
		}},
		Quirks:  Quirks{SystemdFloor: 255, PAMManager: PAMManagerNative, RecoveryOwnerKey: true, NoPasswordMinAge: true, Password: []PasswordPins{{Version: "", Quality: "1.4.5-7", PAM: "1.7.3-1", Manager: "20260616-1"}}},
		FDE:     "LUKS2; systemd-cryptenroll with mkinitcpio sd-encrypt",
		Desktop: Desktop{Name: "GNOME Wayland (maintained); owner-chosen bootloader", DisplayManager: "gdm", Lock: "GNOME Shell"},
		Lab: Lab{
			Lanes:              []LabLane{LaneUpdates, LaneAirgap, LaneAdvisories, LaneResources, LaneServices, LaneEnrollFromConsole},
			ResourcePackages:   []string{"gnupg", "openssl", "python", "attr", "acl", "curl", "libarchive", "zstd", "pacman-contrib", "nftables", "firewalld", "libpwquality", "pam", "pambase"},
			Installer:          ArchISO,
			OfflineRTCWaitUnit: "systemd-time-wait-sync.service",
			// Archive 2026-10-09 (core.db 130,342 bytes vs 129,310 on the
			// images' 2026-10-02 pin) is the os-update policy's later target.
			OSUpdateTargets:   map[string]RollingTarget{"x86_64": {Date: "2026-10-09"}},
			InstallerPackages: []string{"base", "linux", "linux-firmware", "mkinitcpio", "cryptsetup", "systemd", "tpm2-tss", "tpm2-tools", "openssh", "sudo", "networkmanager", "grub", "dosfstools"},
			RecoveryEdition:   "systemd-boot-lab", RecoveryInstallerEdition: "systemd-boot-encrypted-lab",
			Session: LabSession{
				Desktops:  map[string][]string{"gnome": {"gnome-shell", "gdm", "gnome-session", "gnome-terminal", "xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gst-plugin-pipewire", "gst-plugins-good"}},
				GDMConfig: "/etc/gdm/custom.conf", Name: "gnome", Terminal: []string{"gnome-terminal", "--"},
				Capture: []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gst-plugin-pipewire", "gst-plugins-good", "gnome-shell", "mutter"},
			},
			Guest: LabGuest{
				KernelConfig: "/proc/config.gz", KernelConfigModule: "configs",
				Kernel: "/boot/vmlinuz-linux", Initrd: "/boot/initramfs-linux.img",
				Actions:      []string{"cryptsetup", "tpm2-tools", "tpm2-tss", "nftables", "iproute2", "iputils", "bind", "curl", "python", "libpwquality"},
				OwnedBoot:    []string{"systemd", "systemd-ukify", "cryptsetup", "device-mapper", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
				MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
			},
		},
		Supports: caps(agentCore, hostResources, []Capability{Advisories, Password, Encryption, Wipe, ReportLoss, Lock, Assistance, OSUpdate, RecoverySanitize}),
		Gates:    without(gates(string(ReleaseUpgrade), "rolling whole-system snapshot update; use os-update, not a numbered release upgrade"), OSUpdate),
	},
	{
		Key: "omarchy-4.0.4", Name: "Omarchy 4.0.4", Distribution: "Omarchy", ID: "omarchy", Version: Exact("4.0.4"),
		IDLike: []string{"arch"}, Base: "arch",
		Tier: Tier2, Page: "omarchy.md", Family: FamilyArch, Architectures: x86,
		Systemd: 261,
		FDE:     "LUKS2 on Btrfs (archinstall via the Omarchy ISO); mkinitcpio busybox encrypt hook, no TPM2 token unlock",
		Desktop: Desktop{Name: "Hyprland", Version: "Hyprland 0.56.2", DisplayManager: "sddm", Lock: "Quickshell WlSessionLock (Omarchy shell)",
			// omarchy404-lock-quarantine-01: LockedHint and
			// omarchy-hyprland-session-locked stayed unlocked after LockSessions.
			SessionLockUnsupported: "logind LockSessions has no effect on Omarchy's Quickshell session lock (omarchy-hyprland-session-locked stays unlocked)"},
		Firewall: "ufw (active)",
		// The ISO's offline repository supplies cloud-init and the action
		// prerequisites at the install snapshot; see vmlab omarchy installer.
		Lab: Lab{Lanes: []LabLane{LaneUpdates, LaneResources}, Installer: OmarchyCidata,
			// Arch's resource tools as shipped on the 4.0.4 ISO (no firewalld).
			ResourcePackages: []string{"gnupg", "openssl", "python", "attr", "acl", "curl", "libarchive", "zstd", "pacman-contrib", "nftables", "libpwquality", "pam", "pambase"},
			Guest:            LabGuest{Actions: []string{"cryptsetup", "nftables", "iproute2", "iputils", "tpm2-tools", "bind", "curl"}, FromInstaller: true},
			TPM:              LabTPM{Unsupported: "the vendor mkinitcpio busybox encrypt hook cannot unlock with systemd TPM2 tokens, and no lab TPM early-boot variant replaces the vendor boot path"},
			// The ISO always installs Hyprland; encrypted installs autologin
			// SDDM into omarchy.desktop (uwsm). xdg-terminal-exec selects foot.
			Session: LabSession{Desktops: map[string][]string{"hyprland": nil}, Name: "omarchy", Terminal: []string{"foot", "--"},
				Capture: []string{"hyprland", "xdg-desktop-portal", "xdg-desktop-portal-hyprland", "pipewire", "gst-plugin-pipewire", "gst-plugins-good", "quickshell"}}},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Sysctl, Definitions, Encryption, Wipe, ReportLoss, Lock}),
		Gates: gates(string(Advisories), "no vendor advisory feed; the Arch feed does not cover Omarchy packages",
			string(RecoverySanitize), reasonOmarchyOwnedBoot,
			string(Assistance), "session_lock_state_unreported: Omarchy's Quickshell WlSessionLock bypasses logind (no Lock listener, no LockedHint) and Hyprland screencopy keeps streaming a locked screen; CONTROL additionally lacks RemoteDesktop in xdg-desktop-portal-hyprland",
			string(Password), "Omarchy 4.0.4 ships pam 1.7.2-2 (Arch pins measured 1.7.3-1) and rewrites system-auth (pam_faillock deny=10); its own PAM stack has no measured password pins",
			string(Firewall), "the Arch firewall provider manages firewalld zones; Omarchy 4.0.4 runs ufw active by default and its ISO carries no firewalld",
			string(OSUpdate), reasonOmarchyOSUpdate),
	},
	{
		Key: "opensuse-tumbleweed", Name: "openSUSE Tumbleweed", Distribution: "openSUSE Tumbleweed", ID: "opensuse-tumbleweed", Version: Snapshot(),
		Tier: Tier2, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper, Provisioning: cloudInitAutoYaST,
		RollingUpdate:       &RollingUpdateTooling{ArchiveURL: "https://download.opensuse.org/history/", SnapshotCPEPrefix: "cpe:/o:opensuse:opensuse:"},
		RequalificationDays: 14,
		Advisory: Advisory{Feeds: []Feed{FeedSUSEOVAL, FeedSUSECSAF}, Ecosystem: "cpe:/o:opensuse:tumbleweed", PURLNamespace: "suse", OVALPlatform: "openSUSE Tumbleweed", OVALReleasePackage: "openSUSE-release", Partial: "vendor package assessments do not cover all rolling or third-party packages", Exports: map[Feed]AdvisoryExport{
			FeedSUSEOVAL: {URL: "https://ftp.suse.com/pub/projects/security/oval/opensuse.tumbleweed.xml.gz", Format: "suse-oval", MaxAgeSeconds: 604800, MaxArchiveBytes: 67108864},
		}},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamConfig, NoPasswordMinAge: true,
			RecoveryGRUB: GRUBChain{Entries: GRUBBLSLoaderEntryOneShot, ConfigDirectory: "EFI/opensuse", BootDirectory: "/boot/efi"},
			Password: []PasswordPins{
				{Version: "20261007", Quality: "1.4.5-5.7", PAM: "1.7.3-1.1", Manager: "2.14+git.20260216-1.4"},
				{Version: "20261009", Quality: "1.4.5-5.7", PAM: "1.7.3-1.1", Manager: "2.14+git.20260216-1.4"},
			}},
		FDE:     "LUKS2 (AutoYaST); systemd-cryptenroll with dracut",
		Desktop: Desktop{Name: "GNOME Wayland (maintained); KDE separately qualified", DisplayManager: "gdm", Lock: "GNOME Shell"},
		Lab: Lab{
			Lanes:            []LabLane{LaneUpdates, LaneAirgap, LaneAdvisories, LaneResources, LaneServices, LaneEnrollFromConsole, LaneProvisionAutoYaST},
			ResourcePackages: []string{"rpm-build", "rpm", "createrepo_c", "gpg2", "openssl", "python313", "attr", "acl", "curl", "nftables", "firewalld", "pam_pwquality", "libpwquality1", "libpwquality-tools", "pam", "pam-config"},
			Installer:        AutoYaST,
			// YaST's NetworkManager readiness check executes /bin/ip, while
			// NetworkManager only recommends iproute2. The offline bootstrap
			// deliberately disables recommends, so this is a required input.
			InstallerPackages: []string{"rpm", "zypper", "iproute2"},
			TPM:               LabTPM{Modules: dracutSplitTPM, Packages: []string{"dracut", "udev", "tpm2.0-tools", "libtss2-esys0"}},
			// The 2026-10-10 x86_64 closure (captured 2026-10-12, 2,075 files)
			// is later than the 20261009 goldens. The aarch64 ports repository
			// has published nothing after its 2026-10-07 snapshot (repomd
			// 990c58b8…, revision 2026-10-08T02:08Z), so aarch64 has no target.
			OSUpdateTargets: map[string]RollingTarget{"x86_64": {Date: "2026-10-10", ClosureSHA256: "1165cc188e357a44320f9dee48974af28f76f0c6dd454d22e6d875526ac6ad3a", RepomdSHA256: "f48382bb7f18b6762f1fcf342954413c5ed88edd33a6c9215c4d80dc86e1f0d2"}},
			Session: LabSession{
				Desktops:  map[string][]string{"gnome": {"patterns-gnome-gnome", "gnome-terminal", "xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gstreamer-plugin-pipewire", "gstreamer-plugins-good"}},
				GDMConfig: "/etc/gdm/custom.conf", GDMSysconfig: "/etc/sysconfig/displaymanager", Name: "gnome", Terminal: []string{"gnome-terminal", "--"},
				Capture: []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "gstreamer-plugin-pipewire", "gstreamer-plugins-good", "gnome-shell", "mutter"},
			},
			Guest: LabGuest{Initrd: "/boot/initrd-%s", KernelConfig: "/usr/lib/modules/%s/config",
				Actions:      []string{"cryptsetup", "udev", "tpm2.0-tools", "libtss2-esys0", "nftables", "iproute2", "iputils", "bind-utils", "curl", "python313", "libpwquality-tools"},
				MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd", "tpm2.0-tools", "udev"},
			},
		},
		Supports: caps(agentCore, hostResources, []Capability{Advisories, Password, Encryption, Wipe, ReportLoss, Lock, Assistance, OSUpdate, RecoverySanitize}),
		Gates:    without(gates(string(ReleaseUpgrade), "rolling whole-system snapshot update; use os-update, not a numbered release upgrade"), OSUpdate),
	},
	{
		Key: "opensuse-leap-16.0", Name: "openSUSE Leap 16.0", Distribution: "openSUSE Leap", ID: "opensuse-leap", Version: Exact("16.0"),
		// Leap 16.0 installs with Agama; its AutoYaST compatibility is not modelled.
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper, Provisioning: cloudInitOnly,
		Advisory: Advisory{Feeds: suseFeed, Ecosystem: "cpe:/o:opensuse:leap:16.0", PURLNamespace: "suse"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    gates(),
	},
	{
		Key: "sles-15", Name: "SLES 15", Distribution: "SLES", ID: "sles", Version: Major("15"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper, Provisioning: cloudInitAutoYaST,
		Advisory: Advisory{Feeds: suseFeed, Ecosystem: "cpe:/o:suse:sles:15:spN", PURLNamespace: "suse"},
		Supports: []Capability{Inventory, Advisories}, Gates: gates(),
	},
	{
		Key: "sled-15", Name: "SLED 15", Distribution: "SLED", ID: "sled", Version: Major("15"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: x86, Packages: zypper, Provisioning: []Provisioning{ProvisionAutoYaST},
		Supports: []Capability{Inventory},
		Gates:    gates(string(Advisories), "SLED is not mapped by the SUSE CSAF feed"),
	},
	{
		Key: "nixos", Name: "NixOS", Distribution: "NixOS", ID: "nixos", Version: Any(),
		Tier: TierFuture, Page: "atomic-nixos.md", Family: FamilyNix, Gates: nixosGates(), Provisioning: []Provisioning{ProvisionNixOS},
	},
}

func withPins(q Quirks, pins []PasswordPins) Quirks {
	q.Password = pins
	return q
}

func withCapture(session LabSession, packages ...string) LabSession {
	session.Capture = slices.Concat(session.Capture, packages)
	return session
}

// rhelGates gates the RHEL action lane without a maintained recipe. Gates mean
// "not implemented", never "not yet qualified": a gated capability also
// refuses its own qualification lane.
func rhelGates() map[Capability]string {
	return without(gates(string(Assistance), "no maintained RHEL assistance session recipe"), OSUpdate)
}

func elRebuild(key, name, distribution, id, major string, tier Tier, systemd int, ecosystem, purl, partial string) *Release {
	return &Release{
		Key: key, Name: name, Distribution: distribution, ID: id, Version: Major(major), Provisioning: cloudInitKickstart,
		Tier: tier, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: systemd,
		Desktop: gnomeGDM, Firewall: firewalld,
		Lab:      Lab{Lanes: []LabLane{LaneResources}},
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: ecosystem, PURLNamespace: purl, PURLDistro: purl + "-" + major, Partial: partial},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates: actionGates(string(Packages), reasonEL8Packages, string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost,
			string(Definitions), reasonELHost, string(Password), reasonELHost),
	}
}

// ubuntuSuites binds one Ubuntu release's keyring and its release, -updates
// and -security pockets to the shared Ubuntu archive identity.
func ubuntuSuites(archive VendorRepository, keyArtifactID, keySHA256, codename string) VendorRepository {
	archive.KeyArtifactID, archive.KeySHA256 = keyArtifactID, []string{keySHA256}
	archive.Suites = []string{codename, codename + "-updates", codename + "-security"}
	return archive
}

// elArchive completes an EL rebuild's signed BaseOS + AppStream archive;
// pattern takes the repository directory and the kernel architecture.
func elArchive(pattern string, key VendorRepository) VendorRepository {
	key.RepositoryID, key.DB = vendorRPMArchiveID, PackageDBRPM
	for _, id := range []string{"BaseOS", "AppStream"} {
		urls := map[string][]string{}
		for _, architecture := range both {
			urls[architecture] = []string{fmt.Sprintf(pattern, id, architecture)}
		}
		key.NativeRepositories = append(key.NativeRepositories, VendorNativeRepository{ID: strings.ToLower(id), BaseURLs: urls})
	}
	return key
}

func init() {
	for _, r := range registry {
		if r.Base == "" {
			continue
		}
		base, ok := Lookup(r.Base)
		if !ok || base.Base != "" {
			panic("platform: derivative " + r.Key + " names an unknown or derivative base")
		}
		r.base = base
	}
}
