package platform

import (
	"fmt"
	"slices"
	"strings"
)

// Lab records the virtual-machine lab recipes maintained for a release. A lane
// absent from Lanes has no maintained fixture builder or oracle there.
type Lab struct {
	Lanes []LabLane
	// LaneArchitectures restricts a lane to the listed guest architectures
	// (x86_64, aarch64) on which it was natively qualified. A lane absent here
	// runs on every Release.Architectures entry.
	LaneArchitectures map[LabLane][]string
	// LaneGates records lanes the release genuinely cannot qualify, with the
	// concrete product or vendor reason (never "not yet run"). A lane gated
	// on an architecture is refused there and its matrix cells are gated.
	LaneGates map[LabLane]LaneGate
	// Entitlement: the guest's vendor repositories need a subscription token.
	Entitlement bool
	// Installer is the vendor installer the lab's encrypted and installed-image
	// recipes remaster; InstallerNone when the lab installs from cloud images.
	Installer Installer
	// InstallerPackages is the explicit base closure requested by a live
	// installer rather than a vendor's task or guided package selection.
	InstallerPackages []string
	// OfflineRTCWaitUnit is a lab-only network time wait disabled when a
	// disposable offline guest uses the QEMU host's UTC hardware clock.
	// It does not assert NTP synchronization or change production agents.
	OfflineRTCWaitUnit string
	// RootPermissionsRepair is the native remedy (argv) the lab runs at first
	// boot on a pinned cloud image that ships / writable by group or other,
	// which the agent's native tool custody refuses. Stock-image acceptance and
	// console enrollment keep the vendor mode and require the console's
	// unprotected-tool-path alert instead.
	RootPermissionsRepair []string
	// RecoveryEdition selects an explicit ordinary recovery baseline instead
	// of the normal cloud image. RecoveryInstallerEdition binds its matching
	// encrypted topology; an explicit incompatible owner choice is refused.
	RecoveryEdition, RecoveryInstallerEdition string
	// Kickstart is the Anaconda kickstart syntax version, e.g. "F44".
	// Repository and RepositoryKey are the immutable signed release tree and
	// its key file that the installed root adds packages from; %s is the
	// architecture.
	Kickstart, Repository, RepositoryKey string
	// RPMMedia describes offline repositories on the authenticated installer
	// DVD. It does not grant CDN entitlement or provide security updates.
	RPMMedia *LabRPMMedia
	// TPM is the encrypted installer's TPM2-unlocking initramfs recipe.
	TPM LabTPM
	// Session is the encrypted golden's graphical lab session.
	Session LabSession
	// Guest names the native guest facts of the device-action lanes.
	Guest LabGuest
	// ResourcePackages are the native tools for signed resource fixtures.
	ResourcePackages []string
	// FirstBootAccount: the installer hands the lab account to cloud-init,
	// which creates it on first boot, so installer late commands cannot own
	// files to it (Ubuntu 22.04's subiquity); the login key arrives through
	// the installer's own SSH identity instead.
	FirstBootAccount bool
	// OwnedBootUnavailable is why the lab's owned systemd-boot UKI recovery
	// fixture cannot run on this release. Recovery sanitize itself may still
	// be qualified through measured GRUB, which needs no ukify.
	OwnedBootUnavailable string
	// OwnedBootUnavailableOn holds such reasons for single guest architectures
	// (x86_64, aarch64) where the fixture works on the others.
	OwnedBootUnavailableOn map[string]string
	// MeasuredGRUBUnavailableOn holds, per guest architecture, why the
	// release's stock shim+GRUB chain cannot carry measured recovery (its
	// signed GRUB records no PCR 8/9 event, so readiness refuses with
	// recovery_readiness_measured_grub_required). Matrix recovery there uses
	// the owned-boot UKI fixture even though Quirks.RecoveryGRUB is declared.
	MeasuredGRUBUnavailableOn map[string]string
	// Updater is the vendor's own background package updater. The lab stops it
	// for stable package truth, and the resources lane drives it on purpose
	// to hold the native package lock while a package change arrives.
	Updater LabUpdater
	// SysctlKey replaces the resources lane's vm.swappiness when a vendor
	// boot service owns that key's live value (empty keeps vm.swappiness).
	SysctlKey string
	// SecureBootUnavailable is the measured reason the installed system cannot
	// boot under UEFI Secure Boot; lab matrix cells that require Secure Boot
	// are gated with it. Empty when Secure Boot is available.
	SecureBootUnavailable string
	// SecureBootUnavailableOn holds such reasons for single guest
	// architectures (x86_64, aarch64), e.g. a vendor kernel signed for shim
	// only on the others.
	SecureBootUnavailableOn map[string]string
	// OSUpdateTargets pins, per guest architecture (x86_64, aarch64), the
	// later rolling snapshot the os-update lane's whole-system policy installs.
	// Lane prerequisites are provisioned at the image's own snapshot, so a
	// policy targeting that same snapshot could never change a package.
	OSUpdateTargets map[string]RollingTarget
}

// RollingTarget is one immutable later repository snapshot: an Arch Linux
// Archive date, or a dated content-addressed closure (Tumbleweed) with its
// signed repomd digest, served by the lab like the image's own closure.
type RollingTarget struct {
	Date, ClosureSHA256, RepomdSHA256 string
}

// LabUpdater names a vendor updater service and the root command that makes
// it start a full package update through the native frontend.
type LabUpdater struct {
	Unit, Trigger string
}

// LabRPMMedia keeps vendor DVD layout and installed signing-key facts here.
type LabRPMMedia struct {
	Repositories []string
	Key          string
}

// LaneGate is why a lab lane cannot qualify a release. Architectures lists the
// guest architectures (x86_64, aarch64) it applies to; empty means all.
type LaneGate struct {
	Reason        string
	Architectures []string
}

// LabLane is a vmlab qualification lane with per-release recipes.
type LabLane string

const (
	LaneResources  LabLane = "resources"
	LaneUpdates    LabLane = "updates"
	LaneAirgap     LabLane = "airgap"
	LaneUnattended LabLane = "unattended"
	LaneServices   LabLane = "services"
	LaneServer     LabLane = "server"
	LaneAdvisories LabLane = "advisories"
	// LaneAcceptance is the stock-image console acceptance lane and
	// LaneEncryptedAcceptance its vendor-installer encrypted variant.
	LaneAcceptance          LabLane = "acceptance"
	LaneEncryptedAcceptance LabLane = "encrypted-acceptance"
	LaneEnrollFromConsole   LabLane = "enroll-from-console"
	// The provision lanes feed the console's copied provisioning snippet for
	// one installer format, verbatim, into a real first boot or installation.
	LaneProvisionCloudInit   LabLane = "provision-cloud-init"
	LaneProvisionAutoinstall LabLane = "provision-autoinstall"
	LaneProvisionKickstart   LabLane = "provision-kickstart"
	LaneProvisionAutoYaST    LabLane = "provision-autoyast"
)

// LabLanes lists every lane whose recipes are tracked per release; a lane
// outside this list needs no per-release recipe.
var LabLanes = []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneServer, LaneAdvisories, LaneAcceptance, LaneEncryptedAcceptance, LaneEnrollFromConsole,
	LaneProvisionCloudInit, LaneProvisionAutoinstall, LaneProvisionKickstart, LaneProvisionAutoYaST}

// ProvisionLane is the lab lane qualifying a provisioning format.
func ProvisionLane(p Provisioning) (LabLane, bool) {
	switch p {
	case ProvisionCloudInit:
		return LaneProvisionCloudInit, true
	case ProvisionAutoinstall:
		return LaneProvisionAutoinstall, true
	case ProvisionKickstart:
		return LaneProvisionKickstart, true
	case ProvisionAutoYaST:
		return LaneProvisionAutoYaST, true
	default:
		return "", false
	}
}

// LaneProvisioning is the provisioning format a provision lane qualifies.
func LaneProvisioning(l LabLane) (Provisioning, bool) {
	format := Provisioning(strings.TrimPrefix(string(l), "provision-"))
	if lane, ok := ProvisionLane(format); !ok || lane != l {
		return "", false
	}
	return format, true
}

// ProvisionGate is why the release cannot run provision lane l: its vendor
// does not install through that format (Release.Provisioning omits it).
// It is "" for an offered format and for every other lane.
func (r *Release) ProvisionGate(l LabLane) string {
	format, ok := LaneProvisioning(l)
	if !ok || slices.Contains(r.Provisioning, format) {
		return ""
	}
	return fmt.Sprintf("%s does not provision via %s", r.Name, format)
}

// LabLane returns nil when the release has a maintained recipe for the lane.
func (r *Release) LabLane(l LabLane) error {
	if slices.Contains(r.Lab.Lanes, l) {
		return nil
	}
	return fmt.Errorf("platform: no maintained vm %s lane for %s", l, r.Name)
}

// OwnedBootUnavailableFor is why the owned UKI recovery fixture cannot run for
// the guest architecture (either spelling), or "" when it can.
func (l Lab) OwnedBootUnavailableFor(architecture string) string {
	if l.OwnedBootUnavailable != "" {
		return l.OwnedBootUnavailable
	}
	return l.OwnedBootUnavailableOn[kernelArchitecture(architecture)]
}

// SecureBootUnavailableFor is why the installed release cannot boot under
// enforced Secure Boot on the guest architecture (either spelling), or "".
func (l Lab) SecureBootUnavailableFor(architecture string) string {
	if l.SecureBootUnavailable != "" {
		return l.SecureBootUnavailable
	}
	return l.SecureBootUnavailableOn[kernelArchitecture(architecture)]
}

// MeasuredGRUBUnavailableFor is why the release's stock GRUB cannot carry
// measured recovery on the guest architecture (either spelling), or "".
func (l Lab) MeasuredGRUBUnavailableFor(architecture string) string {
	return l.MeasuredGRUBUnavailableOn[kernelArchitecture(architecture)]
}

// LabLaneOn is LabLane for one guest architecture; it accepts the Debian
// (amd64, arm64) and kernel (x86_64, aarch64) architecture spellings.
func (r *Release) LabLaneOn(l LabLane, architecture string) error {
	architecture = kernelArchitecture(architecture)
	if reason := r.LaneGateOn(l, architecture); reason != "" {
		return fmt.Errorf("platform: vm %s lane gated for %s on %s: %s", l, r.Name, architecture, reason)
	}
	if err := r.LabLane(l); err != nil {
		return err
	}
	allowed, restricted := r.Lab.LaneArchitectures[l]
	if !restricted {
		allowed = r.Architectures
	}
	if slices.Contains(allowed, architecture) {
		return nil
	}
	return fmt.Errorf("platform: no maintained vm %s lane for %s on %s", l, r.Name, architecture)
}

// LaneGateOn returns the registry's reason the lane cannot qualify the release
// on the architecture (either spelling), or "" when it is not gated there.
func (r *Release) LaneGateOn(l LabLane, architecture string) string {
	gate, ok := r.Lab.LaneGates[l]
	if !ok || (len(gate.Architectures) != 0 && !slices.Contains(gate.Architectures, kernelArchitecture(architecture))) {
		return ""
	}
	return gate.Reason
}

func kernelArchitecture(architecture string) string {
	switch architecture {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return architecture
}

// DNF reports whether the backend is a DNF generation.
func (b Backend) DNF() bool { return b == BackendDNF4 || b == BackendDNF5 }

// Installer is a vendor installer whose unattended recipe the lab remasters
// into the authenticated vendor ISO.
type Installer string

const (
	InstallerNone   Installer = ""
	Subiquity       Installer = "subiquity"        // autoinstall user-data over NoCloud
	Anaconda        Installer = "anaconda"         // kickstart
	DebianInstaller Installer = "debian-installer" // preseed
	AutoYaST        Installer = "autoyast"         // AutoYaST profile through linuxrc
	// Distinst is Pop!_OS's libdistinst through its vendor CLI, run in the
	// live system by systemd's kernel-command-line service.
	Distinst Installer = "distinst"
	// Ubiquity is the casper live installer (Linux Mint) driven by a debconf
	// preseed through its noninteractive frontend.
	Ubiquity Installer = "ubiquity"
	// OmarchyCidata is the Omarchy ISO's own unattended mode: a second drive
	// labeled cidata carries the configurator's archinstall files. Nothing is
	// remastered, so it has no InstallerMedia.
	OmarchyCidata Installer = "omarchy-cidata"
	ArchISO       Installer = "archiso" // vendor live ISO with a local installation script
)

// InstallerMedia is the vendor ISO layout an installer recipe is remastered
// into. The recipe lives in the ISO's /lindm-seed directory.
type InstallerMedia struct {
	// GRUB is the vendor boot configuration on the ISO (a BLS entry when
	// SystemdBoot). EFIImage mirrors it inside the El Torito EFI FAT image.
	GRUB        string
	EFIImage    bool
	SystemdBoot bool
	// Seed is the recipe file name and Args the kernel arguments that make the
	// installer read it.
	Seed, Args string
	// Entry is the GRUB default entry: the vendor's text installer.
	Entry string
	// Separator appends "---" so the installer arguments stay off the
	// installed kernel command line.
	Separator bool
	// RedeclareEFI: xorriso cannot replay the vendor boot catalog, so the
	// unchanged EFI image is re-declared as the only UEFI El Torito entry.
	RedeclareEFI bool
	// LiveSeparator: the vendor live entries end kernel arguments with "--";
	// it is dropped so the installer and console arguments appended after it
	// are parsed by the kernel rather than passed to init.
	LiveSeparator bool
}

var installerMedia = map[Installer]InstallerMedia{
	Subiquity: {GRUB: "/boot/grub/grub.cfg", Seed: "user-data", Args: `autoinstall noprompt ds=nocloud\;s=/cdrom/lindm-seed/`, Entry: "0", Separator: true},
	Anaconda:  {GRUB: "/EFI/BOOT/grub.cfg", EFIImage: true, Seed: "ks.cfg", Args: "inst.ks=cdrom:/lindm-seed/ks.cfg inst.text", Entry: "0"},
	// The first Debian entry boots the graphical initrd; the vendor's text
	// installer is selected by title.
	DebianInstaller: {GRUB: "/boot/grub/grub.cfg", Seed: "preseed.cfg", Args: "auto=true priority=critical preseed/file=/cdrom/lindm-seed/preseed.cfg DEBIAN_FRONTEND=text net.ifnames=0 biosdevname=0", Entry: "'Install'", Separator: true},
	// linuxrc reads the profile from the DVD itself and configures DHCP for
	// the snapshot-bound online repository; the installer self-update would
	// fetch content outside both pins. openSUSE's ARM DVD catalogs its EFI
	// image with platform 0 behind a hybrid MBR xorriso cannot replay.
	AutoYaST: {GRUB: "/EFI/BOOT/grub.cfg", EFIImage: true, Seed: "autoinst.xml", Args: "autoyast=cd:/lindm-seed/autoinst.xml textmode=1 self_update=0 net.ifnames=0 ifcfg=eth0=dhcp", Entry: "'Installation'", RedeclareEFI: true},
	// Pop has no unattended installer mode. systemd-run-generator boots the
	// casper live system into kernel-command-line.service instead of
	// graphical.target, so neither the greeter nor pop-installer starts; GRUB
	// re-quotes the spaced argument as one kernel parameter.
	Distinst: {GRUB: "/boot/grub/grub.cfg", Seed: "install.sh", Args: `"systemd.run=/bin/sh -eu /cdrom/lindm-seed/install.sh" systemd.run_success_action=poweroff systemd.run_failure_action=poweroff`, Entry: "0", Separator: true},
	// casper loads the debconf seed and start-ubiquity-dm runs the
	// noninteractive (automatic, X-less) frontend instead of the live session;
	// noprompt skips casper's remove-the-medium wait at the final reboot.
	Ubiquity: {GRUB: "/boot/grub/grub.cfg", Seed: "preseed.cfg", Args: "noninteractive noprompt file=/cdrom/lindm-seed/preseed.cfg", Entry: "0", LiveSeparator: true},
	ArchISO:  {GRUB: "/loader/entries/01-archiso-linux.conf", EFIImage: true, SystemdBoot: true, Seed: "install.sh", Args: "script=/run/archiso/bootmnt/lindm-seed/install.sh"},
}

// Media returns the installer's remastering layout; ok is false for
// InstallerNone and unknown installers.
func (i Installer) Media() (InstallerMedia, bool) {
	m, ok := installerMedia[i]
	return m, ok
}

// LabTPM is the dracut recipe that lets the installed initramfs unlock LUKS
// with a TPM2 token.
type LabTPM struct {
	// Modules are the dracut modules; dracut 108 and later split
	// systemd-cryptsetup out of crypt.
	Modules []string
	// Packages are what the installed root adds for them; a trailing "-"
	// removes a package (apt).
	Packages []string
	// Items are extra initramfs files and Drivers explicit kernel drivers, for
	// a dracut without a tpm2-tss module; %s is the Debian multiarch triplet.
	Items, Drivers []string
	// Unobservable lists architectures whose installed kernel cannot bind the
	// TPM QEMU attaches there; their goldens are a separate TPM-absent tuple.
	Unobservable []string
	// Unsupported states why the release has no TPM2-unlocking boot path at
	// all; the lab then records an observed passphrase prompt after a real
	// TPM2 bind instead of an unattended boot.
	Unsupported string
}

// LabSession is the autologin GNOME or KDE session of the encrypted golden.
type LabSession struct {
	// Desktops maps a lab desktop ("gnome", "kde") to the packages that install
	// it (DNF groups under Anaconda).
	Desktops map[string][]string
	// ArchitectureDesktops replaces a Desktops entry on one guest architecture
	// (x86_64, aarch64) whose vendor media lack that environment.
	ArchitectureDesktops map[string]map[string][]string
	// GDMConfig is the GDM daemon file that enables autologin, and Name the
	// lab user's AccountsService session. The GDM service is the release's
	// Desktop.DisplayManager.
	GDMConfig, Name string
	// GDMSysconfig, when set, is the sysconfig file whose
	// DISPLAYMANAGER_AUTOLOGIN openSUSE's GDM (gdm-sysconfig-settings.patch)
	// answers AutomaticLoginEnable and AutomaticLogin from ahead of GDMConfig;
	// the lab names the autologin user there too.
	GDMSysconfig string
	// Terminal is the argv prefix that opens a terminal running a command.
	Terminal []string
	// UpgradePrompt is the update-manager file whose release-upgrade Prompt the
	// lab sets to never, so its dialog cannot cover the session.
	UpgradePrompt string
	// FirstLoginMarkers are paths relative to the lab user's .config whose
	// existence suppresses release-specific welcome units before autologin.
	FirstLoginMarkers []string
	// Capture are the assistance capture-stack packages recorded as evidence.
	Capture []string
}

// DesktopPackages returns the packages that install the lab desktop on the
// guest architecture.
func (s LabSession) DesktopPackages(desktop, architecture string) []string {
	if packages, ok := s.ArchitectureDesktops[kernelArchitecture(architecture)][desktop]; ok {
		return packages
	}
	return s.Desktops[desktop]
}

// LabGuest are the native guest facts of the device-action lanes.
type LabGuest struct {
	// Initrd is the installed initramfs path; %s is the kernel release.
	Initrd string
	// Kernel overrides the conventional /boot/vmlinuz-%s path. Like Initrd,
	// it may be a fixed path or contain %s for the observed kernel release.
	Kernel string
	// KernelConfig names the installed configuration; %s is the observed
	// kernel release. A .gz suffix means gzip-compressed configuration.
	KernelConfig string
	// KernelConfigModule is loaded only in the disposable lab guest before
	// reading a kernel-provided configuration (for example IKCONFIG_PROC).
	KernelConfigModule string
	// CryptsetupConsole: the initramfs reports a rejected passphrase only in
	// the journal, so the lab routes systemd-cryptsetup diagnostics to the
	// console to observe it.
	CryptsetupConsole bool
	// Actions are the device-action prerequisites and OwnedBoot those of the
	// owned systemd-boot recovery fixture. MeasuredBoot are the recovery
	// closure inputs of the measured-BLS fixture, which keeps the vendor
	// shim+GRUB chain; empty means no maintained measured-recovery recipe.
	Actions, OwnedBoot, MeasuredBoot []string
	// OwnedBootHostonly: the stock initramfs is a generic (no-hostonly) image
	// too large for the owned ordinary UKI (RHEL's KVM image ships ~240 MB,
	// beyond its 200 MiB ESP), so the fixture embeds a dracut --hostonly
	// rebuild for the running kernel instead; the installed one is unchanged.
	OwnedBootHostonly bool
	// FromInstaller: the golden installs Actions and Lab.ResourcePackages from
	// the authenticated installer media's own signed repository (Omarchy's ISO
	// offline repository), and lanes only verify their presence. The release
	// has no immutable online repository snapshot to refresh against.
	FromInstaller bool
}
