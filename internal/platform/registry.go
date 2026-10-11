package platform

import "slices"

// New distribution facts go only into this table. A capability absent from
// Supports is gated; Gates states why when the default reason ("not
// implemented for <release>") is not the whole story.

var (
	agentCore = []Capability{Inventory, Lifecycle, Dispatch, SelfUpdate}
	// hostResources are the EL 9/10, Ubuntu and Fedora host providers.
	hostResources = []Capability{Packages, Accounts, Sysctl, Definitions, Firewall}
	// actionLanes have a maintained encrypted-installer recipe, native action
	// prerequisites and a graphical golden.
	actionLanes = []Capability{Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, Assistance}
)

const (
	reasonNoActionRecipe = "no maintained encrypted installer, native action prerequisites or graphical golden"
	reasonNoPasswordPins = "libpwquality/PAM/manager versions not measured on this release"
	reasonOSPatch        = "OS patch policy provider not landed"
	reasonReleaseUpgrade = "release upgrade is not implemented"
	reasonDesignOnly     = "design-only: the declarative/image-based management model is not specified"
	reasonELHost         = "EL host providers are qualified only on RHEL and AlmaLinux 9/10"
)

func caps(groups ...[]Capability) []Capability { return slices.Concat(groups...) }

func gates(pairs ...string) map[Capability]string {
	m := map[Capability]string{OSUpdate: reasonOSPatch, ReleaseUpgrade: reasonReleaseUpgrade}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[Capability(pairs[i])] = pairs[i+1]
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
	dnf5       = PackageTooling{Backend: BackendDNF5, Minimum: "5.4.6.0"}
	dnf4       = PackageTooling{Backend: BackendDNF4, Minimum: "4.7.0"}
	pacman     = PackageTooling{Backend: BackendPacman}
	zypper     = PackageTooling{Backend: BackendZypper}
	gnomeGDM3  = Desktop{Name: "GNOME", DisplayManager: "gdm3", Lock: "GNOME Shell"}
	gnomeGDM   = Desktop{Name: "GNOME", DisplayManager: "gdm", Lock: "GNOME Shell"}
	ufw        = "nftables + ufw (inactive)"
	firewalld  = "nftables + firewalld"
	nftables   = "nftables"
	elQuirks9  = Quirks{AccountChroot: true, SystemdFloor: 252, PAMManager: PAMManagerAuthselect}
	elQuirks10 = Quirks{AccountChroot: true, SystemdFloor: 255, PAMManager: PAMManagerAuthselect}
	el9Pins    = []PasswordPins{{Version: "9.8", Quality: "1.4.4", PAM: "1.5.1", Manager: "1.2.6"}}
	el10Pins   = []PasswordPins{{Version: "10.2", Quality: "1.4.5", PAM: "1.6.1", Manager: "1.5.2"}}
)

var registry = []*Release{
	{
		Key: "ubuntu-22.04", Name: "Ubuntu 22.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("22.04"), Codename: "jammy", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 249,
		Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Ubuntu:22.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "jammy"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Sysctl, Firewall, Advisories}),
		Gates:    actionGates(string(Definitions), "systemd 249 is below the definition provider floor 255", string(Password), reasonNoPasswordPins),
	},
	{
		Key: "ubuntu-24.04", Name: "Ubuntu 24.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("24.04"), Codename: "noble", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 255,
		FDE: "LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "GNOME", Version: "GNOME 46", DisplayManager: "gdm3", Lock: "GNOME Shell"}, Firewall: ufw,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Ubuntu:24.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "noble"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "24.04", Quality: "1.4.5", PAM: "1.5.3", Manager: "1.5.3"}}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}, actionLanes),
		Gates:    gates(),
	},
	{
		Key: "ubuntu-26.04", Name: "Ubuntu 26.04 LTS", Distribution: "Ubuntu", ID: "ubuntu", Version: Exact("26.04"), Codename: "resolute", IDLike: debianLike,
		Tier: Tier1, Page: "ubuntu.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 259,
		Desktop: gnomeGDM3, Firewall: ufw,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Ubuntu:26.04:LTS", PURLNamespace: "ubuntu", PURLDistro: "resolute"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate,
			Password: []PasswordPins{{Version: "26.04", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "debian-11", Name: "Debian 11", Distribution: "Debian", ID: "debian", Version: Exact("11"), Codename: "bullseye",
		Tier: TierOutside, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 247,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Debian:11", PURLNamespace: "debian", PURLDistro: "debian-11"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Advisories}),
		Gates:    actionGates(string(Definitions), "systemd 247 is below the definition provider floor 255"),
	},
	{
		Key: "debian-12", Name: "Debian 12", Distribution: "Debian", ID: "debian", Version: Exact("12"), Codename: "bookworm",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 252,
		Desktop: Desktop{Name: "GNOME/KDE"}, Firewall: nftables,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Debian:12", PURLNamespace: "debian", PURLDistro: "debian-12"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Advisories}),
		Gates:    actionGates(string(Definitions), "systemd 252 is below the definition provider floor 255", string(Password), reasonNoPasswordPins),
	},
	{
		Key: "debian-13", Name: "Debian 13", Distribution: "Debian", ID: "debian", Version: Exact("13"), Codename: "trixie",
		Tier: Tier1, Page: "debian.md", Family: FamilyDebian, Architectures: both, Packages: apt, Systemd: 257,
		Desktop: Desktop{Name: "GNOME/KDE"}, Firewall: nftables,
		Advisory: Advisory{Feed: "osv", Ecosystem: "Debian:13", PURLNamespace: "debian", PURLDistro: "debian-13"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerPamAuthUpdate},
		Supports: caps(agentCore, []Capability{Packages, Accounts, Definitions, Advisories}),
		Gates:    actionGates(string(Password), reasonNoPasswordPins),
	},
	{
		Key: "fedora-43", Name: "Fedora 43", Distribution: "Fedora", ID: "fedora", Version: Exact("43"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5,
		Desktop: Desktop{Name: "Workstation GNOME; KDE edition", DisplayManager: "gdm", Lock: "GNOME Shell"}, Firewall: firewalld,
		Advisory: Advisory{Feed: "rpm-updateinfo", Ecosystem: "Fedora 43 updates"},
		Quirks:   Quirks{SystemdFloor: 255, PAMManager: PAMManagerAuthselect},
		Supports: caps(agentCore, hostResources, []Capability{Advisories}),
		Gates:    actionGates(string(Password), reasonNoPasswordPins),
	},
	{
		Key: "fedora-44", Name: "Fedora 44", Distribution: "Fedora", ID: "fedora", Version: Exact("44"), Variants: fedoraVar,
		Tier: Tier1, Page: "fedora.md", Family: FamilyRedHat, Architectures: both, Packages: dnf5, Systemd: 259,
		FDE: "LUKS2 (anaconda LVM); TPM2 via systemd-cryptenroll (dracut)", Desktop: Desktop{Name: "Workstation GNOME; KDE edition", Version: "GNOME 50", DisplayManager: "gdm", Lock: "GNOME Shell"}, Firewall: firewalld,
		Advisory: Advisory{Feed: "rpm-updateinfo", Ecosystem: "Fedora 44 updates"},
		Quirks: Quirks{SystemdFloor: 255, PAMManager: PAMManagerAuthselect,
			Password: []PasswordPins{{Version: "44", Quality: "1.4.5", PAM: "1.7.2", Manager: "1.7.1"}}},
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}, actionLanes),
		Gates:    gates(),
	},
	{
		Key: "fedora-atomic", Name: "Fedora Atomic Silverblue/Kinoite", Distribution: "Fedora Atomic", ID: "fedora", Version: Any(),
		Variants: []string{"silverblue", "kinoite"},
		Tier:     TierFuture, Page: "atomic-nixos.md", Family: FamilyRedHat, Gates: designOnly(),
	},
	{
		Key: "rhel-8", Name: "RHEL 8", Distribution: "RHEL", ID: "rhel", Version: Major("8"),
		Tier: TierOutside, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 239,
		Advisory: Advisory{Feed: "redhat-csaf", Ecosystem: "cpe:/o:redhat:enterprise_linux:8", PURLNamespace: "redhat"},
		Supports: []Capability{Inventory, Packages, Advisories},
		Gates:    gates(string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost, string(Definitions), "systemd 239 is below the definition provider floor 252"),
	},
	{
		Key: "rhel-9", Name: "RHEL 9", Distribution: "RHEL", ID: "rhel", Version: Major("9"),
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feed: "redhat-csaf", Ecosystem: "cpe:/o:redhat:enterprise_linux:9", PURLNamespace: "redhat"},
		Quirks:   withPins(elQuirks9, el9Pins),
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "rhel-10", Name: "RHEL 10", Distribution: "RHEL", ID: "rhel", Version: Major("10"),
		Tier: Tier1, Page: "rhel.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feed: "redhat-csaf", Ecosystem: "cpe:/o:redhat:enterprise_linux:10", PURLNamespace: "redhat"},
		Quirks:   withPins(elQuirks10, el10Pins),
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}),
		Gates:    actionGates(),
	},
	elRebuild("rocky-8", "Rocky Linux 8", "Rocky Linux", "rocky", "8", TierOutside, 239, "Rocky Linux:8", "rocky-linux"),
	elRebuild("rocky-9", "Rocky Linux 9", "Rocky Linux", "rocky", "9", Tier1, 0, "Rocky Linux:9", "rocky-linux"),
	elRebuild("rocky-10", "Rocky Linux 10", "Rocky Linux", "rocky", "10", Tier1, 0, "Rocky Linux:10", "rocky-linux"),
	elRebuild("almalinux-8", "AlmaLinux 8", "AlmaLinux", "almalinux", "8", TierOutside, 239, "AlmaLinux:8", "almalinux"),
	{
		Key: "almalinux-9", Name: "AlmaLinux 9", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("9"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 252,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feed: "osv", Ecosystem: "AlmaLinux:9", PURLNamespace: "almalinux", PURLDistro: "almalinux-9"},
		Quirks:   withPins(elQuirks9, el9Pins),
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "almalinux-10", Name: "AlmaLinux 10", Distribution: "AlmaLinux", ID: "almalinux", Version: Major("10"),
		Tier: Tier1, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: 257,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feed: "osv", Ecosystem: "AlmaLinux:10", PURLNamespace: "almalinux", PURLDistro: "almalinux-10"},
		Quirks:   withPins(elQuirks10, el10Pins),
		Supports: caps(agentCore, hostResources, []Capability{Password, Advisories}),
		Gates:    actionGates(),
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
		FDE: "LVM on LUKS (Ubiquity)", Desktop: Desktop{Name: "Cinnamon", Lock: "cinnamon-screensaver"},
		Supports: caps(agentCore, hostResources, []Capability{Password}),
		Gates:    actionGates(string(Advisories), "no vendor advisory feed; the Ubuntu feed covers only verified Ubuntu-archive packages"),
	},
	{
		Key: "pop-24.04", Name: "Pop!_OS 24.04 LTS", Distribution: "Pop!_OS", ID: "pop", Version: Exact("24.04"),
		IDLike: []string{"ubuntu", "debian"}, Base: "ubuntu-24.04",
		Tier: Tier1, Page: "popos.md", Family: FamilyDebian, Architectures: x86,
		FDE: "LUKS (distinst)", Desktop: Desktop{Name: "COSMIC", DisplayManager: "cosmic-greeter", Lock: "cosmic-greeter (logind)"},
		Supports: caps(agentCore, hostResources, []Capability{Password}),
		Gates:    actionGates(string(Advisories), "no vendor advisory feed; the Ubuntu feed covers only verified Ubuntu-archive packages"),
	},
	{
		Key: "arch", Name: "Arch Linux", Distribution: "Arch Linux", ID: "arch", Version: Absent(),
		Tier: Tier2, Page: "arch.md", Family: FamilyArch, Architectures: x86, Packages: pacman,
		Desktop:  Desktop{Name: "owner-chosen per record"},
		Advisory: Advisory{Feed: "arch-asa", Ecosystem: "Arch Linux rolling"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "omarchy-4.0.4", Name: "Omarchy 4.0.4", Distribution: "Omarchy", ID: "omarchy", Version: Exact("4.0.4"),
		IDLike: []string{"arch"}, Base: "arch",
		Tier: Tier2, Page: "omarchy.md", Family: FamilyArch, Architectures: x86,
		FDE: "LUKS on Btrfs", Desktop: Desktop{Name: "Hyprland", Lock: "hyprlock"},
		Supports: agentCore,
		Gates:    actionGates(string(Advisories), "no vendor advisory feed; the Arch feed does not cover Omarchy packages"),
	},
	{
		Key: "opensuse-tumbleweed", Name: "openSUSE Tumbleweed", Distribution: "openSUSE Tumbleweed", ID: "opensuse-tumbleweed", Version: Snapshot(),
		Tier: Tier2, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Desktop:  Desktop{Name: "KDE Plasma/GNOME"},
		Advisory: Advisory{Feed: "suse-csaf", Ecosystem: "cpe:/o:opensuse:tumbleweed", PURLNamespace: "suse"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    actionGates(),
	},
	{
		Key: "opensuse-leap-16.0", Name: "openSUSE Leap 16.0", Distribution: "openSUSE Leap", ID: "opensuse-leap", Version: Exact("16.0"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Advisory: Advisory{Feed: "suse-csaf", Ecosystem: "cpe:/o:opensuse:leap:16.0", PURLNamespace: "suse"},
		Supports: caps(agentCore, []Capability{Advisories}),
		Gates:    gates(),
	},
	{
		Key: "sles-15", Name: "SLES 15", Distribution: "SLES", ID: "sles", Version: Major("15"),
		Tier: TierOutside, Page: "opensuse.md", Family: FamilySUSE, Architectures: both, Packages: zypper,
		Advisory: Advisory{Feed: "suse-csaf", Ecosystem: "cpe:/o:suse:sles:15:spN", PURLNamespace: "suse"},
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

func elRebuild(key, name, distribution, id, major string, tier Tier, systemd int, ecosystem, purl string) *Release {
	return &Release{
		Key: key, Name: name, Distribution: distribution, ID: id, Version: Major(major),
		Tier: tier, Page: "alma-rocky.md", Family: FamilyRedHat, Architectures: both, Packages: dnf4, Systemd: systemd,
		Desktop: gnomeGDM, Firewall: firewalld,
		Advisory: Advisory{Feed: "osv", Ecosystem: ecosystem, PURLNamespace: purl, PURLDistro: purl + "-" + major},
		Supports: caps(agentCore, []Capability{Packages, Advisories}),
		Gates: actionGates(string(Accounts), reasonELHost, string(Sysctl), reasonELHost, string(Firewall), reasonELHost,
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
