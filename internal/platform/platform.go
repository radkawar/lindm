// Package platform is the single declarative registry of the Linux releases
// lindm recognizes. Each row records the os-release identity it matches, its
// support tier, native tooling facts, provider quirks and explicit capability
// gates. Agent providers, server capability gating and the lab ask this package
// for capabilities and native facts; they never compare distribution IDs.
//
// Identification is exact: ID plus a VERSION_ID rule (and VARIANT_ID where a
// product has mutable and image-based variants). ID_LIKE, names and resemblance
// are never selectors. A derivative row names its base row explicitly; native
// tooling facts come from the base, while gates and evidence stay the
// derivative's own. An unlisted ID or version resolves to a release whose every
// capability is gated with a reason, never to a guessed neighbour.
//
// The registry does not certify anything: a capability that is not gated is
// implemented for that release, and qualification remains per-cell evidence
// recorded by the lab matrix ledger.
package platform

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Tier is the owner-set support tier of a release.
type Tier uint8

const (
	// TierOutside marks a release lindm recognizes but the owner has not placed
	// in a support tier (legacy server branches, enterprise SUSE, Leap).
	TierOutside Tier = iota
	Tier1
	Tier2
	// TierFuture is design-only: no mutable provider ever qualifies it.
	TierFuture
)

func (t Tier) String() string {
	switch t {
	case Tier1:
		return "1"
	case Tier2:
		return "2"
	case TierFuture:
		return "Future"
	default:
		return "Outside"
	}
}

// Family is the native packaging lineage of a release.
type Family string

const (
	FamilyDebian Family = "debian"
	FamilyRedHat Family = "redhat"
	FamilyArch   Family = "arch"
	FamilySUSE   Family = "suse"
	FamilyNix    Family = "nix"
)

// Backend is the native package backend a release's providers drive.
type Backend string

const (
	BackendNone   Backend = ""
	BackendAPT    Backend = "apt"
	BackendDNF4   Backend = "dnf4"
	BackendDNF5   Backend = "dnf5"
	BackendPacman Backend = "pacman"
	BackendZypper Backend = "zypper"
)

// PackageDB is the native installed-package database behind a backend.
type PackageDB string

const (
	PackageDBNone   PackageDB = ""
	PackageDBDpkg   PackageDB = "dpkg"
	PackageDBRPM    PackageDB = "rpm"
	PackageDBPacman PackageDB = "pacman"
)

// PackageDB returns the installed-package database the backend maintains.
func (b Backend) PackageDB() PackageDB {
	switch b {
	case BackendAPT:
		return PackageDBDpkg
	case BackendDNF4, BackendDNF5, BackendZypper:
		return PackageDBRPM
	case BackendPacman:
		return PackageDBPacman
	default:
		return PackageDBNone
	}
}

// PackageFormat is the native package file format lindm publishes for a backend:
// "deb", "rpm" or "arch" (pacman .pkg.tar.zst), empty when none.
func (b Backend) PackageFormat() string { return b.PackageDB().PackageFormat() }

// PackageFormat is the native package file format lindm publishes for a
// package database: "deb", "rpm" or "arch" (pacman .pkg.tar.zst), empty when none.
func (d PackageDB) PackageFormat() string {
	switch d {
	case PackageDBDpkg:
		return "deb"
	case PackageDBRPM:
		return "rpm"
	case PackageDBPacman:
		return "arch"
	default:
		return ""
	}
}

// PackageTooling describes the native package tooling.
type PackageTooling struct {
	Backend Backend
	// Minimum is the oldest backend version the providers accept.
	Minimum string
	// ALPM identifies the supported native ABI used by the retained-transaction
	// adapter. These are repository-artifact facts, not native qualification.
	ALPM ALPMABI
	// ResourceDependencies are mandatory runtime packages for advertised
	// native package resource execution, in the backend's package namespace.
	ResourceDependencies []string
}

type ALPMABI struct {
	Path    string
	SONAME  string
	Version string
}

// ResourceDependencies returns the union needed by one backend's packages.
// Derivatives use their explicit base's native tooling facts.
func (b Backend) ResourceDependencies() []string {
	var dependencies []string
	for _, release := range registry {
		tooling := release.Native().Packages
		if tooling.Backend == b {
			for _, dependency := range tooling.ResourceDependencies {
				if !slices.Contains(dependencies, dependency) {
					dependencies = append(dependencies, dependency)
				}
			}
		}
	}
	return dependencies
}

// PAMManager owns a release's PAM stack.
type PAMManager string

const (
	PAMManagerNone          PAMManager = ""
	PAMManagerPamAuthUpdate PAMManager = "pam-auth-update"
	PAMManagerAuthselect    PAMManager = "authselect"
	PAMManagerNative        PAMManager = "native-pam"
	PAMManagerPamConfig     PAMManager = "pam-config"
)

// PasswordPins are qualified libpwquality, PAM module and manager releases.
// Rolling managers require the full native package release; other managers use
// upstream versions. Pins apply only to the exact observed VERSION_ID.
type PasswordPins struct {
	Version string // exact VERSION_ID the pins were measured on
	Quality string
	PAM     string
	Manager string
}

// Quirks are native behaviours providers must honour for a release.
type Quirks struct {
	// AccountChroot: shadow tools must chroot (--root) into the account root
	// because --prefix takes the SELinux label of the prefixed path (EL 9
	// shadow-utils 4.9, EL 10 4.15) and EL 9's chage has no --prefix.
	AccountChroot bool
	// AccountVendorConfig: shadow reads login.defs from the vendor /usr/etc
	// (libeconf builds) and --prefix reads it only
	// below the prefix, so a prefix account root also binds the host /usr/etc
	// read-only. Without it Tumbleweed's useradd used its built-in defaults
	// (UID_MAX 6000) instead of the host policy.
	AccountVendorConfig bool
	// SystemdFloor is the oldest systemd whose unit-file/timer D-Bus interface
	// and systemd-analyze verify options the definition provider uses.
	SystemdFloor int
	PAMManager   PAMManager
	Password     []PasswordPins
	// NoPasswordMinAge: shadow 4.20 removed the minimum password age (sp_min,
	// chage/passwd --mindays and login.defs PASS_MIN_DAYS), and its tools fail
	// while PASS_MIN_DAYS is set, so password policy refuses min_age_days.
	// Every release shipping shadow >= 4.20 sets it.
	NoPasswordMinAge bool
	// RecoveryGRUB is how measured original-device recovery adds a one-shot
	// entry to the vendor shim+GRUB chain. Read from the release's own row,
	// never a derivative's base: a derivative may ship another loader.
	RecoveryGRUB GRUBChain
	// SSHBannerUnit admits only the typed pre-authentication banner provider.
	// Read the release's own row, not Native(): qualification is not inherited.
	SSHBannerUnit string
	// RecoveryOwnerKey requires an owner-enrolled Secure Boot key for UKI
	// recovery. This is a loader policy of the release itself, not its base.
	RecoveryOwnerKey bool
	// TPM2UnsealRetry is how the shipped systemd-tpm2 token survives a PCR
	// extension during its unseal.
	TPM2UnsealRetry TPM2UnsealRetry
}

// TPM2UnsealRetry is how a release's systemd-tpm2 unseal recovers when any
// PCR is extended between its TPM2_PolicyPCR and TPM2_Unseal: the TPM's global
// pcrUpdateCounter changes and Unseal fails with TPM_RC_PCR_CHANGED. Under
// Secure Boot the kernel's IMA architecture policy measures every module load
// into PCR 10, so initrd module loading races the boot-time unlock.
type TPM2UnsealRetry uint8

const (
	// TPM2UnsealRetryInSession: systemd restarts the policy session itself
	// (the systemd-stable 252 loop; upstream 255.5 and 256 and later).
	TPM2UnsealRetryInSession TPM2UnsealRetry = iota
	// TPM2UnsealRetryNextToken: systemd's retry reuses the parameter-encryption
	// session that tpm2-tss 4 leaves without TPMA_SESSION_DECRYPT after the
	// failed Unseal (systemd 254 to 255.4 and their backports; fixed upstream
	// in 1923e213165d), so the token fails with -EINVAL ("Missing encryption
	// session"). libcryptsetup maps that to -ENOENT and opens the next token,
	// so further references to the same sealed keyslot are the only retries.
	TPM2UnsealRetryNextToken
)

// TPM2NextTokenReferences is how many LUKS2 tokens reference the one sealed
// keyslot of a managed TPM2 bind on a TPM2UnsealRetryNextToken release. Its
// systemd-cryptsetup opens the tokens twice per boot (every token, then the
// systemd-tpm2 ones), so four references give eight independent unseals of
// the identical sealed object and PCR policy, each with fresh sessions.
const TPM2NextTokenReferences = 4

// GRUBEntries is the vendor GRUB menu source a one-shot entry is added to.
type GRUBEntries string

const (
	// GRUBEntriesNone: no maintained measured-recovery method.
	GRUBEntriesNone GRUBEntries = ""
	// GRUBBLS: blscfg reads <boot>/loader/entries; next_entry names the
	// entry file stem.
	GRUBBLS GRUBEntries = "bls"
	// GRUBBLSLoaderEntryOneShot: BLS entries and kernel paths are relative
	// to the loader ESP, and the Boot Loader Interface EFI variable selects
	// the entry once. This is not blscfg's grubenv next_entry protocol.
	GRUBBLSLoaderEntryOneShot GRUBEntries = "bls-loader-entry-oneshot"
	// GRUBCustomConfig: grub.d's 41_custom sources <boot>/<ConfigDirectory>/
	// custom.cfg at boot without regenerating grub.cfg; next_entry names the
	// menuentry --id.
	GRUBCustomConfig GRUBEntries = "custom.cfg"
)

// GRUBChain is the stock shim+GRUB facts measured recovery relies on.
type GRUBChain struct {
	Entries GRUBEntries
	// BootDirectory is the mounted vendor boot filesystem used for staging.
	BootDirectory string
	// Editenv is the absolute path of the distribution's grub-editenv, which
	// writes next_entry where the signed GRUB reads it (a grubenv file or the
	// btrfs bootloader env_block).
	Editenv string
	// ConfigDirectory is GRUB's directory below /boot, e.g. "grub2".
	ConfigDirectory string
}

// Desktop is the qualified graphical edition of a release.
type Desktop struct {
	Name           string // edition, e.g. "GNOME"
	Version        string // qualified desktop version, e.g. "46"
	DisplayManager string // e.g. "gdm3"
	Lock           string // screen lock backend, e.g. "gnome-shell (logind Lock)"
	// SessionLockUnsupported, when set, is the natively proven reason a logind
	// session lock has no effect on the desktop's locker. The Lock capability
	// (account lock, session lock request) stays supported; the server refuses
	// a lock action that would only lock sessions.
	SessionLockUnsupported string
}

// Feed is a vendor advisory source adapter.
type Feed string

const (
	FeedOSV           Feed = "osv"
	FeedDebianTracker Feed = "debian-tracker"
	FeedRPMUpdateinfo Feed = "rpm-updateinfo"
	FeedRedHatCSAF    Feed = "redhat-csaf"
	FeedSUSECSAF      Feed = "suse-csaf"
	FeedSUSEOVAL      Feed = "suse-oval"
	FeedArchASA       Feed = "arch-asa"
)

// AdvisoryExport is the complete online export of one vendor source.
type AdvisoryExport struct {
	URL string
	// ArchitectureURLs selects the repository for the canonical machine
	// architecture when a vendor does not publish one cross-architecture export.
	ArchitectureURLs map[string]string
	Format           string
	MaxAgeSeconds    uint64
	MaxArchiveBytes  uint64
	PlatformStream   string
}

// Advisory names the vendor advisory sources the server applies to a release.
type Advisory struct {
	// Feeds are the accepted vendor sources, the primary one first.
	Feeds []Feed
	// Exports records maintained online acquisition facts for lab provisioning.
	// A missing entry is unsupported, not permission to guess a vendor URL.
	Exports map[Feed]AdvisoryExport
	// Ecosystem is the vendor's product identity: the OSV ecosystem, the
	// updateinfo product name or the CSAF product CPE, in which a trailing
	// "spN" stands for the configured SLES service pack.
	Ecosystem string
	// OVALPlatform and OVALReleasePackage bind OVAL metadata and its native
	// installed-product prerequisite; neither is inferred from display names.
	OVALPlatform       string
	OVALReleasePackage string
	// PURLNamespace and PURLDistro are the package-URL namespace and distro
	// qualifier the vendor feed uses for this release.
	PURLNamespace string
	PURLDistro    string
	// CodenameRelease accepts the codename as the feed release (legacy
	// "noble" sources).
	CodenameRelease bool
	// PlatformStreams: the vendor feed is per servicing stream (Red Hat
	// standard/EUS/E4S). A standard major feed covers every minor; hosts need
	// corroborated stream evidence and native module identity.
	PlatformStreams bool
	// Partial says why even a complete vendor export cannot establish a clean
	// result; empty when a complete export is authoritative.
	Partial string
	// ArchiveOrigin, ArchiveSuites and ArchiveSigners identify the release's
	// own signed APT archive (with Codename): the Release Origin, the suites
	// its feed assesses for security support, and the uppercase primary-key
	// fingerprints that sign them. A derivative's packages are covered by this
	// release's feed only when every APT index listing them matches.
	ArchiveOrigin  string
	ArchiveSuites  []string
	ArchiveSigners []string
	// VendorOrigins are a derivative vendor's own Release Origins. When set,
	// the derivative is evaluated against its base's feed for verified
	// base-archive packages only and is always partial (Partial says why).
	VendorOrigins []string
}

// BaseCoverage returns the base release whose feed applies to this
// derivative's verified base-archive packages, or nil when the release is not
// such a derivative. The derivative itself never names a feed.
func (r *Release) BaseCoverage() *Release {
	if r.base == nil || len(r.Advisory.VendorOrigins) == 0 || r.Gate(Advisories) != nil {
		return nil
	}
	if b := r.base; b.Advisory.ArchiveOrigin != "" && len(b.Advisory.ArchiveSuites) > 0 && len(b.Advisory.ArchiveSigners) > 0 && b.Gate(Advisories) == nil {
		return b
	}
	return nil
}

// ModuleBlocklistTooling names qualified initramfs tooling for a typed blocklist.
// Empty tooling is an explicit unsupported platform, not a distro-family fallback.
type ModuleBlocklistTooling struct {
	Modprobe            string
	InitramfsPattern    string
	Rebuild             string
	RebuildArgs         []string
	RebuildWithFileArgs []string // Optional fixed inclusion of the owned stanza.
	WritePaths          []string
	StateDirectory      string // Native tool state; absent state needs its parent for that invocation.
}

// VendorRepository is one vendor package archive a signed capability policy
// may approve (PACKAGES). Every fact is verified registry material compiled
// into the agent; a policy never carries URLs, suites, keys or fingerprints.
type VendorRepository struct {
	// RepositoryID is the stable repository identity profiles bind
	// (apt/<uuid>, rpm/<uuid>).
	RepositoryID string
	// DB selects the source form: dpkg (APT) or rpm.
	DB PackageDB
	// ArchiveURIs is the HTTPS APT archive per kernel architecture (x86_64,
	// aarch64). Suites lists the primary suite first; one repository identity
	// covers every suite with the same components and signing key.
	ArchiveURIs map[string]string
	Suites      []string
	Components  []string
	// NativeRepositories are RPM repositories, the primary first, verified
	// with the same key: HTTPS base URLs per kernel architecture when the
	// vendor signs repomd.xml, otherwise an HTTPS metalink per architecture.
	NativeRepositories []VendorNativeRepository
	// KeyFile is the vendor-packaged public key on the host: a regular file,
	// never a distribution symlink. KeyArtifactID names it in ArtifactRef.
	KeyFile       string
	KeyArtifactID string
	// KeySHA256 lists the accepted lowercase hex digests of KeyFile's exact
	// bytes; any other content is unrecognized.
	KeySHA256 []string
	// RPMFingerprint is the uppercase primary-key fingerprint KeyFile holds.
	RPMFingerprint string
	// MetadataUnsigned: the vendor publishes no repository metadata signature
	// (no repomd.xml.asc). Its RPM metadata is then authenticated only through
	// HTTPS metalinks served by MetalinkHost, whose repomd.xml digests librepo
	// checks; package signatures stay mandatory.
	MetadataUnsigned bool
	MetalinkHost     string
	// VariantMarkers are host files that only an architecture variant these
	// URLs do not serve installs (AlmaLinux 10's x86_64_v2 build ships
	// /etc/rpm/macros.x86_64_v2 but reports uname x86_64). Any present, or
	// unobservable, marker leaves the archive platform_not_qualified.
	VariantMarkers []string
}

// VendorNativeRepository is one RPM repository of a vendor archive. BaseURLs
// are used only with signed metadata (MetadataUnsigned false); Metalinks only
// for a pinned MetalinkHost.
type VendorNativeRepository struct {
	ID        string
	BaseURLs  map[string][]string
	Metalinks map[string]string
}

// AccountDefaults are the vendor's regular local account ranges and home
// root a signed capability policy may approve (LOCAL_ACCOUNTS).
type AccountDefaults struct {
	// HomeRootID is the stable approved home root identity profiles name in
	// HomePolicy.approved_root_id.
	HomeRootID     string
	HomeRoot       string
	MinUID, MaxUID uint32
	MinGID, MaxGID uint32
}

// UnsignedMetadataAllowed reports whether repository metadata without a
// signature may be trusted through these metalinks: at least one, each an
// HTTPS URL on a metalink host this release pins for a vendor archive without
// metadata signatures. Derivatives pin their own rows only.
func (r *Release) UnsignedMetadataAllowed(metalinks []string) bool {
	if len(metalinks) == 0 {
		return false
	}
	for _, metalink := range metalinks {
		u, err := url.Parse(metalink)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
			return false
		}
		if !slices.ContainsFunc(r.VendorRepositories, func(v VendorRepository) bool {
			return v.MetadataUnsigned && v.MetalinkHost != "" && v.MetalinkHost == u.Host
		}) {
			return false
		}
	}
	return true
}

// RollingUpdateTooling describes the whole-system snapshot update model.
// Snapshot dates are signed policy inputs, never moving registry defaults.
type RollingUpdateTooling struct {
	ArchiveURL        string
	Repositories      []string
	SnapshotCPEPrefix string
}

// RebootSignal is a native reboot-required marker the release's own package
// hooks maintain: Writers, shipped by Package, create Marker when an
// installed update needs a reboot. It is the OS-update reboot oracle when
// the optional oracle tool (needrestart on APT) is not installed.
type RebootSignal struct {
	Marker  string
	Package string
	Writers []string
}

// Provisioning is a vendor unattended-installation input whose console
// snippet installs lindm-agent from the customer's lindmd repository and
// enrolls the device with a provisioning token.
type Provisioning string

const (
	// ProvisionCloudInit is first-boot cloud-config on a cloud image.
	ProvisionCloudInit Provisioning = "cloud-init"
	// ProvisionKickstart is an Anaconda %post section run in the target chroot.
	ProvisionKickstart Provisioning = "kickstart"
	// ProvisionAutoinstall is subiquity autoinstall user-data, which the
	// installed system's cloud-init applies on first boot.
	ProvisionAutoinstall Provisioning = "autoinstall"
	// ProvisionAutoYaST is an AutoYaST chroot-script run in the target.
	ProvisionAutoYaST Provisioning = "autoyast"
	// ProvisionNixOS is a NixOS module; see the nixos row's Lifecycle gate.
	ProvisionNixOS Provisioning = "nixos"
)

// Release is one registry row.
type Release struct {
	Key  string // stable key, e.g. "ubuntu-24.04"; lab matrix and docs key
	Name string // display name, e.g. "Ubuntu 24.04 LTS"
	// Distribution groups releases in documentation, e.g. "Ubuntu".
	Distribution string
	ID           string // os-release ID
	Version      Version
	Codename     string   // os-release VERSION_CODENAME
	IDLike       []string // documented ID_LIKE; informational, never a selector
	// Variants are the accepted VARIANT_ID values; nil accepts any.
	Variants []string
	// Base is the Key of the release whose native tooling a derivative ships.
	Base string
	// UpgradeTo is the Key of the release the vendor's supported in-place
	// release upgrade reaches; empty when no upgrade path is modelled.
	UpgradeTo string
	Tier      Tier
	// Page is the docs/platforms page describing the release.
	Page          string
	Family        Family
	Architectures []string
	Packages      PackageTooling
	RollingUpdate *RollingUpdateTooling
	// RebootSignal is nil when the release maintains no reboot-required
	// marker; the OS-update runner then needs its oracle tool.
	RebootSignal    *RebootSignal
	Systemd         int
	FDE             string
	Desktop         Desktop
	Firewall        string
	Advisory        Advisory
	Quirks          Quirks
	Lab             Lab
	ModuleBlocklist ModuleBlocklistTooling
	// VendorRepositories, StandardFileRoots and Accounts are the release's
	// facts behind remotely granted provider capabilities. Absent facts leave
	// the capability unavailable (platform_not_qualified), never guessed.
	VendorRepositories []VendorRepository
	// StandardFileRoots are vendor drop-in directories (FILES).
	StandardFileRoots []string
	Accounts          AccountDefaults
	// RequalificationDays scopes a rolling snapshot's evidence window. Zero
	// means this release does not use the periodic rolling qualification lane.
	// Native tooling derivatives inherit their base's cadence.
	RequalificationDays int
	// Supports lists the implemented capabilities; every other capability is
	// gated, with the reason in Gates or a default reason.
	Supports []Capability
	Gates    map[Capability]string
	// ArchitectureGates gates a supported capability on one guest
	// architecture (x86_64, aarch64) whose native stack refuses it.
	ArchitectureGates map[string]map[Capability]string
	// Provisioning lists the vendor's unattended installer formats the console
	// offers for this release; installation readiness still follows Lifecycle.
	Provisioning []Provisioning

	base *Release
}

// Native returns the release whose native tooling and quirks apply: the base
// for a derivative, the release itself otherwise.
func (r *Release) Native() *Release {
	if r.base != nil {
		return r.base
	}
	return r
}

// Known reports whether the release is a registry row.
func (r *Release) Known() bool { return r.Key != "" }

// DisplayName names a registered release as administrators read it, keeping
// the reported point release when the registry entry covers a major version
// ("RHEL 9" reported as 9.4 is "RHEL 9.4"). Empty for unregistered releases.
func (r *Release) DisplayName(versionID string) string {
	if !r.Known() {
		return ""
	}
	if versionID == "" || strings.Contains(r.Name, versionID) {
		return r.Name
	}
	return r.Distribution + " " + versionID
}

// Supported reports whether the capability is implemented for the release.
func (r *Release) Supported(c Capability) bool { return slices.Contains(r.Supports, c) }

// TPM2BindSystemdFloor is the oldest systemd whose systemd-cryptenroll reads
// the owner unlock secret from a descriptor (--unlock-key-file, 252) — the
// action provider never passes secrets through argv or the environment — and
// whose libcryptsetup TPM2 token plugin (250) verifies the enrolled token.
const TPM2BindSystemdFloor = 252

// TPM2BindSupported reports whether the release's shipped systemd can perform
// the managed TPM2 binding. A release without a recorded systemd version is
// left to the root provider's native probe.
func (r *Release) TPM2BindSupported() bool {
	systemd := r.Native().Systemd
	return systemd == 0 || systemd >= TPM2BindSystemdFloor
}

// TPM2TokenReferences is how many LUKS2 tokens the managed TPM2 bind writes
// for its one sealed keyslot: one where systemd retries a PCR change itself,
// TPM2NextTokenReferences where only libcryptsetup's next token does.
func (r *Release) TPM2TokenReferences() int {
	if r.Native().Quirks.TPM2UnsealRetry == TPM2UnsealRetryNextToken {
		return TPM2NextTokenReferences
	}
	return 1
}

// Gate returns nil when the capability is implemented for the release, and
// otherwise a *GateError carrying the explicit reason.
func (r *Release) Gate(c Capability) error {
	if reason := r.GateReason(c); reason != "" {
		return &GateError{Release: r.Name, Capability: c, Reason: reason}
	}
	return nil
}

// GateReason returns the explicit reason a capability is gated, or "" when
// it is implemented.
func (r *Release) GateReason(c Capability) string {
	if r.Supported(c) {
		return ""
	}
	if reason := r.Gates[c]; reason != "" {
		return reason
	}
	return "not implemented for " + r.Name
}

// GateReasonOn is GateReason for one guest architecture; it accepts the
// Debian (amd64, arm64) and kernel (x86_64, aarch64) spellings.
func (r *Release) GateReasonOn(c Capability, architecture string) string {
	if reason := r.GateReason(c); reason != "" {
		return reason
	}
	return r.ArchitectureGates[kernelArchitecture(architecture)][c]
}

// PasswordPins returns the password-provider pins measured on the observed
// VERSION_ID of this release (or of its base for a derivative).
func (r *Release) PasswordPins(versionID string) (PasswordPins, bool) {
	if r.base != nil {
		versionID = r.base.Version.Value
	}
	for _, pins := range r.Native().Quirks.Password {
		if pins.Version == versionID {
			return pins, true
		}
	}
	return PasswordPins{}, false
}

// GateError reports a gated capability.
type GateError struct {
	Release    string
	Capability Capability
	Reason     string
}

func (e *GateError) Error() string {
	return fmt.Sprintf("platform: %s gated on %s: %s", e.Capability, e.Release, e.Reason)
}

// VersionRule says how a row matches os-release VERSION_ID.
type VersionRule uint8

const (
	// VersionExact requires VERSION_ID to equal Value.
	VersionExact VersionRule = iota
	// VersionMajor accepts Value or any Value.N minor.
	VersionMajor
	// VersionAbsent requires VERSION_ID to be absent (Arch's rolling model).
	VersionAbsent
	// VersionSnapshot requires a YYYYMMDD snapshot VERSION_ID (Tumbleweed).
	VersionSnapshot
	// VersionAny accepts any VERSION_ID, including none.
	VersionAny
)

// Version is a VERSION_ID rule. Value is also the lab manifest version for
// rolling rows ("rolling" for Arch, empty for snapshots, which use the
// manifest's snapshot date).
type Version struct {
	Rule  VersionRule
	Value string
}

// Exact, Major, Absent, Snapshot and Any build version rules.
func Exact(v string) Version { return Version{Rule: VersionExact, Value: v} }
func Major(v string) Version { return Version{Rule: VersionMajor, Value: v} }
func Absent() Version        { return Version{Rule: VersionAbsent, Value: "rolling"} }
func Snapshot() Version      { return Version{Rule: VersionSnapshot} }
func Any() Version           { return Version{Rule: VersionAny} }

func (v Version) matches(versionID string) bool {
	switch v.Rule {
	case VersionExact:
		return versionID == v.Value
	case VersionMajor:
		return versionID == v.Value || strings.HasPrefix(versionID, v.Value+".") && !strings.Contains(versionID[len(v.Value)+1:], ".")
	case VersionAbsent:
		return versionID == ""
	case VersionSnapshot:
		return snapshot(versionID)
	default:
		return true
	}
}

// rolling reports a rule without fixed releases (absent or snapshot VERSION_ID).
func (v Version) rolling() bool { return v.Rule == VersionAbsent || v.Rule == VersionSnapshot }

// String renders the rule for documentation.
func (v Version) String() string {
	switch v.Rule {
	case VersionExact:
		return v.Value
	case VersionMajor:
		return v.Value + ".x"
	case VersionAbsent:
		return "absent (rolling)"
	case VersionSnapshot:
		return "YYYYMMDD snapshot"
	default:
		return "any"
	}
}

func snapshot(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// OSRelease is the subset of os-release(5) that identifies a release.
type OSRelease struct {
	ID        string
	VersionID string
	VariantID string
}

// Identify returns the registry row matching the observed os-release identity,
// or an unknown release whose every capability is gated.
func Identify(o OSRelease) *Release {
	for _, r := range registry {
		if r.ID == o.ID && r.Version.matches(o.VersionID) && (r.Variants == nil || slices.Contains(r.Variants, o.VariantID)) {
			return r
		}
	}
	return unknown(o.ID, o.VersionID)
}

// Product is the native identity carried in resource evidence; it has no
// VARIANT_ID, so callers that must exclude image-based variants re-read
// os-release and use Identify.
type Product interface {
	GetOsId() string
	GetVersion() string
}

// Of identifies an observed resource platform product.
func Of(p Product) *Release {
	return Identify(OSRelease{ID: p.GetOsId(), VersionID: p.GetVersion()})
}

// SameRelease reports whether two VERSION_IDs of one os-release ID name the
// same release: equal values, or values the registry assigns to one versioned
// row (a major row accepts its minors, so "9.4" and "9.6" are both RHEL 9; a
// snapshot row accepts every snapshot). Rows accepting any VERSION_ID, and
// values outside the registry, match only exactly.
func SameRelease(id, a, b string) bool {
	if a == b {
		return true
	}
	ra, rb := Identify(OSRelease{ID: id, VersionID: a}), Identify(OSRelease{ID: id, VersionID: b})
	return ra.Known() && ra == rb && ra.Version.Rule != VersionAny
}

// SameArchitecture reports whether two machine architectures are equal in
// either spelling: kernel (x86_64, aarch64) or Debian (amd64, arm64).
func SameArchitecture(a, b string) bool {
	return kernelArchitecture(a) == kernelArchitecture(b)
}

// ForManifest identifies a lab image manifest's distribution and version.
// Rolling rows use their manifest convention ("rolling" for Arch, the
// snapshot date for Tumbleweed).
func ForManifest(distribution, version string) *Release {
	for _, r := range registry {
		if r.ID != distribution || r.Variants != nil && !slices.Contains(r.Variants, "") {
			continue
		}
		if r.Version.Rule == VersionAbsent && version == r.Version.Value || r.Version.Rule != VersionAbsent && r.Version.matches(version) {
			return r
		}
	}
	return unknown(distribution, version)
}

// ForFeed identifies an advisory feed source's distro and release. Feeds name
// rolling rows "rolling" and may name a CodenameRelease row by its codename;
// otherwise the row's VERSION_ID rule applies (a major row also accepts one
// exact minor, which the source keeps as its scope).
func ForFeed(distro, release string) *Release {
	for _, r := range registry {
		if r.ID != distro || r.Variants != nil && !slices.Contains(r.Variants, "") {
			continue
		}
		if rolling := r.Version.rolling(); rolling && release == feedRolling || !rolling && r.Version.matches(r.FeedRelease(release)) {
			return r
		}
	}
	return unknown(distro, release)
}

const feedRolling = "rolling"

// FeedRelease returns the feed spelling of a VERSION_ID observed on or
// configured for this release: "rolling" for a rolling row's absent or
// snapshot VERSION_ID, the version for an accepted codename, otherwise the
// VERSION_ID unchanged.
func (r *Release) FeedRelease(versionID string) string {
	switch {
	case r.Version.rolling() && r.Version.matches(versionID):
		return feedRolling
	case r.Advisory.CodenameRelease && versionID == r.Codename:
		return r.Version.Value
	}
	return versionID
}

// Lookup returns the row with the given key.
func Lookup(key string) (*Release, bool) {
	for _, r := range registry {
		if r.Key == key {
			return r, true
		}
	}
	return nil, false
}

// Releases returns every registry row in registry order. Callers must not
// modify the rows.
func Releases() []*Release { return slices.Clone(registry) }

// KnownID reports whether s is an os-release ID of any registry row.
func KnownID(s string) bool {
	return slices.ContainsFunc(registry, func(r *Release) bool { return r.ID == s })
}

func unknown(id, version string) *Release {
	name := fmt.Sprintf("unregistered release ID=%q VERSION_ID=%q", id, version)
	gates := make(map[Capability]string, len(Capabilities))
	for _, c := range Capabilities {
		gates[c] = "release is not in the platform registry"
	}
	return &Release{Name: name, ID: id, Version: Exact(version), Gates: gates}
}
