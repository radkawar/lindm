package platform

import "slices"

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

const (
	reasonNoActionRecipe = "no maintained encrypted installer, native action prerequisites or graphical golden"
	reasonNoPasswordPins = "libpwquality/PAM/manager versions not measured on this release"
	reasonOSPatch        = "OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release"
	reasonReleaseUpgrade = "release upgrade is not implemented"
	reasonDesignOnly     = "design-only: the declarative/image-based management model is not specified"
	reasonELHost         = "EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10"
	reasonEL8Packages    = "systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240"
	reasonRockyOSV       = "Rocky's OSV export uses source-like package mappings without a complete binary universe"
	reasonPacmanHost     = "host resource providers have no pacman/Arch implementation or measured native quirks"
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

var (
	both       = []string{"x86_64", "aarch64"}
	x86        = []string{"x86_64"}
	debianLike = []string{"debian"}
	fedoraVar  = []string{"", "workstation", "server", "cloud", "container"}
	apt        = PackageTooling{Backend: BackendAPT}
	// DNF 5.4.6.0 is the first release that stores a transaction without
	// privileges; older releases refuse the staging sandbox's read-only /usr.
	dnf5 = PackageTooling{Backend: BackendDNF5, Minimum: "5.4.6.0"}
	// DNF 4.7.0 is EL 8.10's; older DNF4 lacks the plugin selection, strict
	// remote-RPM and query APIs the DNF4 adapter relies on.
	dnf4       = PackageTooling{Backend: BackendDNF4, Minimum: "4.7.0"}
	pacman     = PackageTooling{Backend: BackendPacman}
	zypper     = PackageTooling{Backend: BackendZypper}
	gnomeGDM3  = Desktop{Name: "GNOME", DisplayManager: "gdm3", Lock: "GNOME Shell"}
	gnomeGDM   = Desktop{Name: "GNOME", DisplayManager: "gdm", Lock: "GNOME Shell"}
	ufw        = "nftables + ufw (inactive)"
	firewalld  = "nftables + firewalld"
	nftables   = "nftables"
	elQuirks9  = Quirks{AccountChroot: true, SystemdFloor: 252, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB}
	elQuirks10 = Quirks{AccountChroot: true, SystemdFloor: 255, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB}
	// Stock shim+GRUB chains for measured original-device recovery.
	blsGRUB     = GRUBChain{Entries: GRUBBLS, Editenv: "/usr/bin/grub2-editenv", ConfigDirectory: "grub2"}
	debianGRUB  = GRUBChain{Entries: GRUBCustomConfig, Editenv: "/usr/bin/grub-editenv", ConfigDirectory: "grub"}
	el9Pins     = []PasswordPins{{Version: "9.8", Quality: "1.4.4", PAM: "1.5.1", Manager: "1.2.6"}}
	el10Pins    = []PasswordPins{{Version: "10.2", Quality: "1.4.5", PAM: "1.6.1", Manager: "1.5.2"}}
	osvFeed     = []Feed{FeedOSV}
	debianFeeds = []Feed{FeedOSV, FeedDebianTracker}
	redHatFeed  = []Feed{FeedRedHatCSAF}
	suseFeed    = []Feed{FeedSUSECSAF}
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
		Initrd:       "/boot/initrd.img-%s",
		Actions:      []string{"cryptsetup", "nftables", "iproute2", "iputils-ping", "tpm2-tools", "dnsutils", "curl"},
		OwnedBoot:    []string{"systemd-boot", "systemd-boot-efi", "systemd-ukify", "cryptsetup-bin", "dmsetup", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// resolute's dracut 110 + systemd 259 cryptsetup reports a rejected
	// recovery key only in the journal (noble's 255 printed it), so the lab
	// routes its diagnostics to the console like Debian 13 and Fedora/EL.
	ubuntuResoluteGuest = LabGuest{
		Initrd: ubuntuGuest.Initrd, CryptsetupConsole: true,
		Actions: ubuntuGuest.Actions, OwnedBoot: ubuntuGuest.OwnedBoot, MeasuredBoot: ubuntuGuest.MeasuredBoot,
	}
	fedoraGraphical = []string{"base-graphical", "desktop-accessibility", "fonts", "guest-desktop-agents", "hardware-support", "input-methods", "networkmanager-submodules"}
	fedoraSession   = LabSession{
		Desktops:  map[string][]string{"gnome": slices.Concat(fedoraGraphical, []string{"gnome-desktop"}), "kde": slices.Concat(fedoraGraphical, []string{"kde-desktop"})},
		GDMConfig: "/etc/gdm/custom.conf", Name: "gnome", Terminal: []string{"ptyxis", "--new-window", "--"},
		Capture: []string{"xdg-desktop-portal", "xdg-desktop-portal-gnome", "pipewire", "pipewire-gstreamer", "gstreamer1-plugins-good", "gnome-shell", "mutter"},
	}
	fedoraGuest = LabGuest{
		Initrd: "/boot/initramfs-%s.img", CryptsetupConsole: true,
		Actions:      []string{"cryptsetup", "nftables", "iproute", "iputils", "systemd-udev", "tpm2-tools", "bind-utils", "curl"},
		OwnedBoot:    []string{"systemd-boot-unsigned", "systemd-ukify", "cryptsetup", "device-mapper", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// RHEL installs only from the vendor-authenticated Binary DVD (no Lab.Repository):
	// the Workstation environment, TPM user space and action prerequisites
	// become kickstart %packages. An unregistered installed system has no other
	// repository, so the action prerequisites also carry the recovery helpers.
	rhelSession = LabSession{
		Desktops:  map[string][]string{"gnome": {"@^workstation-product-environment"}},
		GDMConfig: "/etc/gdm/custom.conf", Name: "gnome",
	}
	rhelGuest = LabGuest{
		Initrd: "/boot/initramfs-%s.img", CryptsetupConsole: true, OwnedBootHostonly: true,
		Actions:      []string{"cryptsetup", "nftables", "iproute", "iputils", "systemd-udev", "tpm2-tools", "bind-utils", "curl", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		OwnedBoot:    []string{"systemd-boot-unsigned", "systemd-ukify", "cryptsetup", "device-mapper", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	rhelTPMPackages = []string{"tpm2-tools", "tpm2-tss"}
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
		Initrd:       "/boot/initrd.img-%s",
		Actions:      []string{"cryptsetup", "nftables", "iproute2", "iputils-ping", "tpm2-tools", "bind9-dnsutils", "curl"},
		OwnedBoot:    []string{"systemd-boot", "systemd-boot-efi", "systemd-ukify", "cryptsetup-bin", "dmsetup", "nvme-cli", "e2fsprogs", "kmod", "zstd"},
		MeasuredBoot: []string{"nvme-cli", "e2fsprogs", "kmod", "zstd"},
	}
	// trixie's systemd 257 cryptsetup reports a rejected recovery key only in
	// the journal (bookworm's 252 prints it on the console), so the lab routes
	// its diagnostics to the console like Fedora/EL.
	debianTrixieGuest = LabGuest{
		Initrd: debianGuest.Initrd, CryptsetupConsole: true,
		Actions: debianGuest.Actions, OwnedBoot: debianGuest.OwnedBoot, MeasuredBoot: debianGuest.MeasuredBoot,
	}
	// Debian's arm64 kernels build TPM CRB but not the TIS platform driver,
	// QEMU virt's only TPM device.
	debianArmNoTIS = []string{"aarch64"}
	// reasonNoUkify: the owned-boot recovery fixture builds its ordinary UKI
	// with the guest's ukify, which systemd 253 introduced.
	reasonNoUkify = "no systemd-ukify (systemd 253+) for the owned-boot recovery fixture's ordinary UKI"
	// The native self-update lane (`lab vm updates`) is qualified per guest
	// architecture: x86_64 on the local host, aarch64 on the arm64 KVM hosts.
	// EL rows cite the 9.8/10.2 minors their records exercised.
	updatesX86 = map[LabLane][]string{LaneUpdates: x86}
	updatesARM = map[LabLane][]string{LaneUpdates: {"aarch64"}}
)

var registry = []*Release{
	{
		Key: "ubuntu-22.04", Name: "Ubuntu 22.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("22.04"), Codename: "jammy", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 249,
		FDE: "LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut 051 + TSS2 libraries)", Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:22.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "jammy"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "22.04", Quality: "1.4.4", PAM: "1.4.0", Manager: "1.4.0"}}, RecoveryGRUB: debianGRUB},
		// Jammy's dracut 051 has no tpm2-tss module: the initramfs carries the
		// TSS2 libraries systemd 249's cryptsetup dlopens and the TPM drivers.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneServices, LaneUpdates}, LaneArchitectures: updatesARM, Installer: Subiquity, Session: ubuntuSession, Guest: ubuntuGuest, FirstBootAccount: true,
			OwnedBootUnavailable: reasonNoUkify,
			TPM: LabTPM{Modules: []string{"systemd", "crypt", "lvm"}, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0", "cryptsetup-initramfs-"},
				Items:   []string{"/usr/lib/%s/libtss2-esys.so.0", "/usr/lib/%s/libtss2-mu.so.0", "/usr/lib/%s/libtss2-rc.so.0", "/usr/lib/%s/libtss2-tctildr.so.0", "/usr/lib/%s/libtss2-tcti-device.so.0"},
				Drivers: []string{"tpm_tis", "tpm_crb"}}},
		// Recovery sanitize is measured GRUB only (amd64; jammy's arm64 GRUB
		// records no PCR 8/9 measurements, so readiness refuses there).
		Supports: caps(agentCore, []Capability{Packages, Accounts, Sysctl, Firewall, Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		// 249's verify has no --recursive-errors (systemd 250) and exits 0 on
		// a candidate setting it ignores as invalid.
		Gates: gates(string(Definitions), "systemd 249 is below the definition provider floor 255"),
	},
	{
		Key: "ubuntu-24.04", Name: "Ubuntu 24.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("24.04"), Codename: "noble", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 255, UpgradeTo: "ubuntu-26.04",
		FDE: "LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME", Version: "GNOME 46", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: ufw,
		// Archive facts observed on every 24.04 pocket (archive, security,
		// ports and the Pop!_OS mirror) on 2026-10-11: Ubuntu Archive Automatic
		// Signing Key (2018). Ubuntu's OSV export assesses the release, -updates
		// and -security pockets; -backports and -proposed get no security support.
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:24.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "noble", CodenameRelease: true,
			Exports:       map[Feed]AdvisoryExport{FeedOSV: {URL: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: "osv-zip", MaxAgeSeconds: 86400, MaxArchiveBytes: 4 << 30}},
			ArchiveOrigin: "Ubuntu", ArchiveSuites: []string{"noble", "noble-security", "noble-updates"}, ArchiveSigners: []string{"F6ECB3762474EDA9D21B7022871920D1991BC93C"}},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate, SSHBannerUnit: "ssh.service",
			Password: []PasswordPins{{Version: "24.04", Quality: "1.4.5", PAM: "1.5.3", Manager: "1.5.3"}}, RecoveryGRUB: debianGRUB},
		ModuleBlocklist: ModuleBlocklistTooling{Modprobe: "/usr/sbin/modprobe", InitramfsPattern: "/boot/initrd.img-%s", Rebuild: "/usr/sbin/update-initramfs", RebuildArgs: []string{"-u", "-k", "all"}, WritePaths: []string{"/boot"}, StateDirectory: "/var/lib/initramfs-tools"},
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneServer, LaneAcceptance, LaneEncryptedAcceptance, LaneEnrollFromConsole},
			LaneArchitectures: updatesX86, Installer: Subiquity, Session: withCapture(ubuntuSession, "libmutter-14-0"), Guest: ubuntuGuest,
			TPM: LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0t64", "cryptsetup-initramfs-"}}},
		// ReleaseUpgrade: do-release-upgrade to UpgradeTo, `lab vm resources -phase release-upgrade`.
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate, ReleaseUpgrade}, actionLanes),
		Gates:    without(gates(), OSUpdate, ReleaseUpgrade),
	},
	{
		Key: "ubuntu-26.04", Name: "Ubuntu 26.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("26.04"), Codename: "resolute", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 259,
		Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Ubuntu:26.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "resolute"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "26.04", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}}, RecoveryGRUB: debianGRUB},
		// The 26.04 desktop ISO carries dracut 110, systemd-cryptsetup and the
		// TSS2 libraries, but not tpm2-tools, whose tpm2 binary dracut's
		// tpm2-tss module requires.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneServices, LaneEnrollFromConsole},
			LaneArchitectures: updatesX86, Installer: Subiquity, Session: ubuntuResoluteSession, Guest: ubuntuResoluteGuest, TPM: LabTPM{Modules: dracutSplitTPM, Packages: []string{"tpm2-tools"}}},
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
		Tier: TierOutside, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 247,
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:11", PURLNamespace: "debian", PURLDistro: "debian-11"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Advisories}),
		Gates:    actionGates(string(Definitions), "systemd 247 is below the definition provider floor 255"),
	},
	{
		Key: "debian-12", Name: "Debian 12", Distribution: "Debian", ID: "debian", Version: Exact("12"), Codename: "bookworm",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 252,
		FDE: "LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME/KDE", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: nftables,
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:12", PURLNamespace: "debian", PURLDistro: "debian-12"},
		// Debian 12's systemd 252 runs the timer/drop-in lane like EL 9's.
		Quirks: Quirks{SystemdFloor: 252, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "12", Quality: "1.4.5", PAM: "1.5.2", Manager: "1.5.2"}}, RecoveryGRUB: debianGRUB},
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: DebianInstaller, Session: debianSession, Guest: debianGuest,
			TPM: LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "tpm2-tools", "libtss2-tcti-device0", "cryptsetup-initramfs-"}, Unobservable: debianArmNoTIS}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, Assistance}),
		Gates:    gates(string(RecoverySanitize), reasonNoUkify),
	},
	{
		Key: "debian-13", Name: "Debian 13", Distribution: "Debian", ID: "debian", Version: Exact("13"), Codename: "trixie",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 257,
		FDE: "LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME/KDE", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: nftables,
		Advisory: Advisory{Feeds: debianFeeds, Ecosystem: "Debian:13", PURLNamespace: "debian", PURLDistro: "debian-13"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "13", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}}, RecoveryGRUB: debianGRUB},
		// trixie splits systemd-cryptsetup out of systemd and its dracut out of crypt.
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: DebianInstaller, Session: debianSession, Guest: debianTrixieGuest,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: []string{"dracut", "tpm2-tools", "libtss2-tcti-device0t64", "systemd-cryptsetup", "cryptsetup-initramfs-"}, Unobservable: debianArmNoTIS}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}, actionLanes),
		Gates:    gates(),
	},
	{
		Key: "fedora-43", Name: "Fedora 43", Distribution: "Fedora", ID: "fedora", Version: Exact("43"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5,
		Desktop: Desktop{Name: "Workstation GNOME; KDE edition", DisplayManager: "gdm", Lock: "GNOME Shell"}, Firewall: firewalld,
		Advisory: Advisory{Feeds: []Feed{FeedRPMUpdateinfo}, Ecosystem: "Fedora 43"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerAuthselect, RecoveryGRUB: blsGRUB},
		Lab:      Lab{Lanes: []LabLane{LaneServices}},
		Supports: caps(agentCore, hostResources, []Capability{Advisories}),
		Gates:    actionGates(string(Password), reasonNoPasswordPins),
	},
	{
		Key: "fedora-44", Name: "Fedora 44", Distribution: "Fedora", ID: "fedora", Version: Exact("44"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5, Systemd: 259,
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
		ModuleBlocklist: ModuleBlocklistTooling{Modprobe: "/usr/sbin/modprobe", InitramfsPattern: "/boot/initramfs-%s.img", Rebuild: "/usr/bin/dracut", RebuildArgs: []string{"--regenerate-all", "--force"}, RebuildWithFileArgs: []string{"--regenerate-all", "--force", "--include", "/etc/modprobe.d/99-lindm-blocklist.conf", "/etc/modprobe.d/99-lindm-blocklist.conf"}, WritePaths: []string{"/boot"}},
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneAcceptance, LaneEnrollFromConsole},
			LaneArchitectures: updatesX86, Installer: Anaconda, Session: fedoraSession, Guest: fedoraGuest,
			Kickstart: "F44", Repository: "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/%s/os/", RepositoryKey: "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-%s",
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: []string{"systemd-udev", "tpm2-tools", "tpm2-tss"}}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, OSUpdate}, actionLanes),
		Gates:    without(gates(), OSUpdate),
	},
	{
		Key: "fedora-atomic", Name: "Fedora Atomic Silverblue/Kinoite", Distribution: "Fedora Atomic", ID: "fedora", Version: Any(),
		Variants: []string{"silverblue", "kinoite"},
		Tier:     TierFuture, Page: "atomic-nixos.md", Family: FamilyRedHat, Gates: designOnly(),
	},
	{
		Key: "rhel-8", Name: "RHEL 8", Distribution: "RHEL", ID: "rhel", Version: Major("8"),
		Tier: TierOutside, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 239,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:8", PURLNamespace: "redhat", PlatformStreams: true},
		Lab:      Lab{Lanes: []LabLane{LaneServices}, Entitlement: true},
		Supports: []Capability{Inventory, Advisories},
		Gates:    gates(string(Packages), reasonEL8Packages, string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost, string(Definitions), "systemd 239 is below the definition provider floor 252"),
	},
	{
		Key: "rhel-9", Name: "RHEL 9", Distribution: "RHEL", ID: "rhel", Version: Major("9"),
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:9", PURLNamespace: "redhat", PlatformStreams: true,
			Exports: map[Feed]AdvisoryExport{FeedRedHatCSAF: {
				URL: "https://security.access.redhat.com/data/csaf/v2/", Format: "redhat-csaf-archives", MaxAgeSeconds: 604800, PlatformStream: "standard",
			}}},
		Quirks: withPins(elQuirks9, el9Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneServices}, LaneArchitectures: updatesX86, Entitlement: true,
			Installer: Anaconda, Session: rhelSession, Guest: rhelGuest,
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
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: redHatFeed, Ecosystem: "cpe:/o:redhat:enterprise_linux:10", PURLNamespace: "redhat", PlatformStreams: true},
		Quirks:   withPins(elQuirks10, el10Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates, LaneServices}, LaneArchitectures: updatesX86, Entitlement: true,
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
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Rocky Linux:9", PURLNamespace: "rocky-linux", PURLDistro: "rocky-linux-9", Partial: reasonRockyOSV},
		Quirks:   withPins(elQuirks9, el9Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: Anaconda, Session: elRebuildSession9, Guest: rhelGuest,
			TPM: LabTPM{Modules: dracutTPM, Packages: rhelTPMPackages}},
		// Native qualification of each action is per pinned minor and
		// architecture in verification.md; implemented capabilities stay
		// admitted so their qualification lanes can run (see the rhel-9 row).
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    gates(),
	},
	{
		Key: "rocky-10", Name: "Rocky Linux 10", Distribution: "Rocky Linux", ID: "rocky", Version: Major("10"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "Rocky Linux:10", PURLNamespace: "rocky-linux", PURLDistro: "rocky-linux-10", Partial: reasonRockyOSV},
		Quirks:   withPins(elQuirks10, el10Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: Anaconda, Session: elRebuildSession10, Guest: rhelGuest,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    gates(),
	},
	elRebuild("almalinux-8", "AlmaLinux 8", "AlmaLinux", "almalinux", "8", TierOutside, 239, "AlmaLinux:8", "almalinux", ""),
	{
		Key: "almalinux-9", Name: "AlmaLinux 9", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("9"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "AlmaLinux:9", PURLNamespace: "almalinux", PURLDistro: "almalinux-9"},
		Quirks:   withPins(elQuirks9, el9Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: Anaconda, Session: elRebuildSession9, Guest: rhelGuest,
			TPM: LabTPM{Modules: dracutTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    gates(),
	},
	{
		Key: "almalinux-10", Name: "AlmaLinux 10", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("10"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: "AlmaLinux:10", PURLNamespace: "almalinux", PURLDistro: "almalinux-10"},
		Quirks:   withPins(elQuirks10, el10Pins),
		Lab: Lab{Lanes: []LabLane{LaneResources, LaneUpdates}, LaneArchitectures: updatesARM, Installer: Anaconda, Session: elRebuildSession10, Guest: rhelGuest,
			TPM: LabTPM{Modules: dracutSplitTPM, Packages: rhelTPMPackages}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories, Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}),
		Gates:    gates(),
	},
	{
		Key: "centos-stream-9", Name: "CentOS Stream 9", Distribution: "CentOS Stream", ID: "centos", Version: Exact("9"),
		Tier: TierOutside, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4,
		Supports: []Capability{Inventory}, Gates: gates(),
	},
	{
		Key: "centos-stream-10", Name: "CentOS Stream 10", Distribution: "CentOS Stream", ID: "centos", Version: Exact("10"),
		Tier: TierOutside, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4,
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
			TPM: LabTPM{Modules: dracutTPM, Packages: []string{"dracut", "systemd", "tpm2-tools", "libtss2-tcti-device0t64", "cryptsetup-initramfs-"}}},
		// apt.pop-os.org/release ("pop-os-release") and /proprietary
		// ("system76") use codename noble and the Pop!_OS key; its Ubuntu mirror
		// serves Ubuntu's own signed InRelease (observed 2026-10-11).
		Advisory: Advisory{VendorOrigins: []string{"pop-os-release", "system76"}, Partial: "vendor feed unavailable for Pop!_OS packages"},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}, actionLanes),
		Gates:    gates(),
	},
	{
		Key: "arch", Name: "Arch Linux", Distribution: "Arch Linux", ID: "arch", Version: Absent(),
		Tier: Tier2, Page: "arch.md", Family: FamilyArch, Architectures: x86, Packages: pacman,
		Desktop:  Desktop{Name: "owner-chosen per record"},
		Advisory: Advisory{Feeds: []Feed{FeedArchASA}, Ecosystem: "Arch Linux rolling"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "omarchy-4.0.4", Name: "Omarchy 4.0.4", Distribution: "Omarchy", ID: "omarchy", Version: Exact("4.0.4"),
		IDLike: []string{"arch"}, Base: "arch",
		Tier: Tier2, Page: "omarchy.md", Family: FamilyArch, Architectures: x86,
		Systemd: 261,
		FDE:     "LUKS2 on Btrfs (archinstall via the Omarchy ISO); mkinitcpio busybox encrypt hook, no TPM2 token unlock",
		Desktop: Desktop{Name: "Hyprland", Version: "Hyprland 0.56.2", DisplayManager: "sddm", Lock: "Quickshell WlSessionLock (Omarchy shell)"}, Firewall: "ufw (active)",
		// The ISO's offline repository supplies cloud-init and the action
		// prerequisites at the install snapshot; see vmlab omarchy installer.
		Lab: Lab{Lanes: []LabLane{LaneUpdates}, Installer: OmarchyCidata,
			Guest: LabGuest{Actions: []string{"cryptsetup", "nftables", "iproute2", "iputils", "tpm2-tools", "bind", "curl"}},
			TPM:   LabTPM{Unsupported: "the vendor mkinitcpio busybox encrypt hook cannot unlock with systemd TPM2 tokens, and no lab TPM early-boot variant replaces the vendor boot path"},
			// The ISO always installs Hyprland; encrypted installs autologin
			// SDDM into omarchy.desktop (uwsm). xdg-terminal-exec selects foot.
			Session: LabSession{Desktops: map[string][]string{"hyprland": nil}, Name: "omarchy", Terminal: []string{"foot", "--"},
				Capture: []string{"hyprland", "xdg-desktop-portal", "xdg-desktop-portal-hyprland", "pipewire", "gst-plugin-pipewire", "gst-plugins-good", "quickshell"}}},
		Supports: caps(agentCore, []Capability{Encryption, Wipe, ReportLoss, Lock}),
		Gates: gates(string(Advisories), "no vendor advisory feed; the Arch feed does not cover Omarchy packages",
			string(RecoverySanitize), reasonOmarchyOwnedBoot,
			string(Assistance), "session_lock_state_unreported: Omarchy's Quickshell WlSessionLock bypasses logind (no Lock listener, no LockedHint) and Hyprland screencopy keeps streaming a locked screen; CONTROL additionally lacks RemoteDesktop in xdg-desktop-portal-hyprland",
			string(Packages), reasonPacmanHost, string(Accounts), reasonPacmanHost, string(Sysctl), reasonPacmanHost,
			string(Definitions), reasonPacmanHost, string(Firewall), reasonPacmanHost, string(Password), reasonPacmanHost),
	},
	{
		Key: "opensuse-tumbleweed", Name: "openSUSE Tumbleweed", Distribution: "openSUSE Tumbleweed", ID: "opensuse-tumbleweed", Version: Snapshot(),
		Tier: Tier2, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Desktop:  Desktop{Name: "KDE Plasma/GNOME"},
		Advisory: Advisory{Feeds: suseFeed, Ecosystem: "cpe:/o:opensuse:tumbleweed", PURLNamespace: "suse"},
		Lab:      Lab{Installer: AutoYaST},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "opensuse-leap-16.0", Name: "openSUSE Leap 16.0", Distribution: "openSUSE Leap", ID: "opensuse-leap", Version: Exact("16.0"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Advisory: Advisory{Feeds: suseFeed, Ecosystem: "cpe:/o:opensuse:leap:16.0", PURLNamespace: "suse"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    gates(),
	},
	{
		Key: "sles-15", Name: "SLES 15", Distribution: "SLES", ID: "sles", Version: Major("15"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Advisory: Advisory{Feeds: suseFeed, Ecosystem: "cpe:/o:suse:sles:15:spN", PURLNamespace: "suse"},
		Supports: []Capability{Inventory, Advisories}, Gates: gates(),
	},
	{
		Key: "sled-15", Name: "SLED 15", Distribution: "SLED", ID: "sled", Version: Major("15"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: x86, Packages: zypper,
		Supports: []Capability{Inventory},
		Gates:    gates(string(Advisories), "SLED is not mapped by the SUSE CSAF feed"),
	},
	{
		Key: "nixos", Name: "NixOS", Distribution: "NixOS", ID: "nixos", Version: Any(),
		Tier: TierFuture, Page: "atomic-nixos.md", Family: FamilyNix, Gates: designOnly(),
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
		Key: key, Name: name, Distribution: distribution, ID: id, Version: Major(major),
		Tier: tier, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: systemd,
		Desktop: gnomeGDM, Firewall: firewalld,
		Lab:      Lab{Lanes: []LabLane{LaneResources}},
		Advisory: Advisory{Feeds: osvFeed, Ecosystem: ecosystem, PURLNamespace: purl, PURLDistro: purl + "-" + major, Partial: partial},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates: actionGates(string(Packages), reasonEL8Packages, string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost,
			string(Definitions), reasonELHost, string(Password), reasonELHost),
	}
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
