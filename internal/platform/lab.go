package platform

import (
	"fmt"
	"slices"
)

// Lab records the virtual-machine lab recipes maintained for a release. A lane
// absent from Lanes has no maintained fixture builder or oracle there.
type Lab struct {
	Lanes []LabLane
	// LaneArchitectures restricts a lane to the listed guest architectures
	// (x86_64, aarch64) on which it was natively qualified. A lane absent here
	// runs on every Release.Architectures entry.
	LaneArchitectures map[LabLane][]string
	// Entitlement: the guest's vendor repositories need a subscription token.
	Entitlement bool
	// Installer is the vendor installer the lab's encrypted and installed-image
	// recipes remaster; InstallerNone when the lab installs from cloud images.
	Installer Installer
	// Kickstart is the Anaconda kickstart syntax version, e.g. "F44".
	// Repository and RepositoryKey are the immutable signed release tree and
	// its key file that the installed root adds packages from; %s is the
	// architecture.
	Kickstart, Repository, RepositoryKey string
	// TPM is the encrypted installer's TPM2-unlocking initramfs recipe.
	TPM LabTPM
	// Session is the encrypted golden's graphical lab session.
	Session LabSession
	// Guest names the native guest facts of the device-action lanes.
	Guest LabGuest
	// FirstBootAccount: the installer hands the lab account to cloud-init,
	// which creates it on first boot, so installer late commands cannot own
	// files to it (Ubuntu 22.04's subiquity); the login key arrives through
	// the installer's own SSH identity instead.
	FirstBootAccount bool
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
	// LaneAcceptance is the stock-image console acceptance lane and
	// LaneEncryptedAcceptance its vendor-installer encrypted variant.
	LaneAcceptance          LabLane = "acceptance"
	LaneEncryptedAcceptance LabLane = "encrypted-acceptance"
	LaneEnrollFromConsole   LabLane = "enroll-from-console"
)

// LabLanes lists every lane whose recipes are tracked per release; a lane
// outside this list needs no per-release recipe.
var LabLanes = []LabLane{LaneResources, LaneUpdates, LaneAirgap, LaneUnattended, LaneServices, LaneServer, LaneAcceptance, LaneEncryptedAcceptance, LaneEnrollFromConsole}

// LabLane returns nil when the release has a maintained recipe for the lane.
func (r *Release) LabLane(l LabLane) error {
	if slices.Contains(r.Lab.Lanes, l) {
		return nil
	}
	return fmt.Errorf("platform: no maintained vm %s lane for %s", l, r.Name)
}

// LabLaneOn is LabLane for one guest architecture; it accepts the Debian
// (amd64, arm64) and kernel (x86_64, aarch64) architecture spellings.
func (r *Release) LabLaneOn(l LabLane, architecture string) error {
	if err := r.LabLane(l); err != nil {
		return err
	}
	switch architecture {
	case "amd64":
		architecture = "x86_64"
	case "arm64":
		architecture = "aarch64"
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
)

// InstallerMedia is the vendor ISO layout an installer recipe is remastered
// into. The recipe lives in the ISO's /lindm-seed directory.
type InstallerMedia struct {
	// GRUB is the vendor grub.cfg on the ISO. EFIImage: the El Torito EFI FAT
	// image carries the same file, which must be patched too.
	GRUB     string
	EFIImage bool
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
	// GDMConfig is the GDM daemon file that enables autologin, and Name the
	// lab user's AccountsService session. The GDM service is the release's
	// Desktop.DisplayManager.
	GDMConfig, Name string
	// Terminal is the argv prefix that opens a terminal running a command.
	Terminal []string
	// UpgradePrompt is the update-manager file whose release-upgrade Prompt the
	// lab sets to never, so its dialog cannot cover the session.
	UpgradePrompt string
	// Capture are the assistance capture-stack packages recorded as evidence.
	Capture []string
}

// LabGuest are the native guest facts of the device-action lanes.
type LabGuest struct {
	// Initrd is the installed initramfs path; %s is the kernel release.
	Initrd string
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
}
