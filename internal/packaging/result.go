//go:build linux

package packaging

// Format selects a native package.
type Format string

const (
	FormatDEB Format = "deb"
	FormatRPM Format = "rpm"
)

// Custody separates development package-signing keys from production custody.
// Production keys are never generated here.
type Custody string

const (
	CustodyDevelopment Custody = "development"
	CustodyProduction  Custody = "production"
)

// SigningKey is an explicit GnuPG home used only for package and repository
// signatures. It is not an agent execution, TLS, or TUF key.
// Operations sharing Home must run sequentially: concurrent use returns
// ErrSignerBusy without interrupting the operation already using its agent.
type SigningKey struct {
	Home        string
	Fingerprint string
	Custody     Custody
	// PassphraseFile is required for production custody. Development keys may
	// leave it empty; signing then uses an empty passphrase file created in
	// the private work directory. The file contents are never logged.
	PassphraseFile string
	// RejectFingerprints are execution, TLS, and TUF fingerprints.
	RejectFingerprints []string
	// RejectPathPrefixes are additional homes that must not sign packages.
	RejectPathPrefixes []string
}

// BuildRequest builds one upstream version. The VM upgrade proof calls Build
// twice, with the same signer, and checks UpgradeOrdered.
type BuildRequest struct {
	AgentBinary string
	Version     string
	// OutputDir must be a private 0700 directory owned by the current UID.
	OutputDir string
	// Formats empty means both DEB and RPM. RPM requires Signer.
	Formats []Format
	Signer  SigningKey
	// SourceDateEpoch zero selects DefaultSourceDateEpoch, never the wall clock.
	SourceDateEpoch int64
}

// Architecture is derived from the ELF header, not from the caller's claim.
type Architecture struct {
	ELF    string `json:"elf"`
	GOARCH string `json:"goarch"`
	Debian string `json:"debian"`
	RPM    string `json:"rpm"`
}

// Artifact is one built package. Signed is true only for an RPM whose
// signature verified in a private rpmdb. A DEB is not signed here.
type Artifact struct {
	Format            Format       `json:"format"`
	Path              string       `json:"path"`
	SHA256            string       `json:"sha256"`
	Size              int64        `json:"size"`
	Architecture      Architecture `json:"architecture"`
	Version           string       `json:"version"`
	PayloadSHA256     string       `json:"payload_sha256"`
	Signed            bool         `json:"signed"`
	SignerFingerprint string       `json:"signer_fingerprint,omitempty"`
}

// ToolVersion records a native tool actually invoked or probed.
type ToolVersion struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

// BuildResult is evidence from one build. CreaterepoC is "not-installed" when
// the RPM repository tool is absent; that is not a successful repository build.
type BuildResult struct {
	Artifacts                 []Artifact    `json:"artifacts"`
	BinarySHA256              string        `json:"binary_sha256"`
	Architecture              Architecture  `json:"architecture"`
	Version                   string        `json:"version"`
	GoVersion                 string        `json:"go_version,omitempty"`
	Tools                     []ToolVersion `json:"tools"`
	UnitSyntaxOK              bool          `json:"unit_syntax_ok"`
	ExecutablePresenceChecked bool          `json:"executable_presence_checked"`
	CreaterepoC               string        `json:"createrepo_c"`
	SignerFingerprint         string        `json:"signer_fingerprint,omitempty"`
	Custody                   Custody       `json:"custody,omitempty"`
	PublicKey                 string        `json:"public_key,omitempty"`
}

// APTRequest publishes already built DEBs. The signer signs InRelease, not
// each .deb.
type APTRequest struct {
	OutputDir       string
	DEBs            []string
	Signer          SigningKey
	SourceDateEpoch int64
}

// APTRepository is an isolated archive. Install it with APTSources, not dpkg -i.
type APTRepository struct {
	Root                 string        `json:"root"`
	Distribution         string        `json:"distribution"`
	Component            string        `json:"component"`
	InRelease            string        `json:"inrelease"`
	Release              string        `json:"release"`
	Packages             string        `json:"packages"`
	PublicKey            string        `json:"public_key"`
	PublicKeyArmor       string        `json:"public_key_armor"`
	Fingerprint          string        `json:"fingerprint"`
	Custody              Custody       `json:"custody"`
	InReleaseVerified    bool          `json:"inrelease_verified"`
	PackagesHashVerified bool          `json:"packages_hash_verified"`
	Tools                []ToolVersion `json:"tools"`
}

// RPMRequest publishes signed RPMs. It fails before writing if createrepo_c
// is missing.
type RPMRequest struct {
	OutputDir       string
	RPMs            []string
	Signer          SigningKey
	SourceDateEpoch int64
}

// RPMRepository points at repodata created by createrepo_c. RepoMetadataSigned
// is true only when repomd.xml.asc was created and verified.
type RPMRepository struct {
	Root               string        `json:"root"`
	Repomd             string        `json:"repomd"`
	PublicKey          string        `json:"public_key"`
	PublicKeyArmor     string        `json:"public_key_armor"`
	Fingerprint        string        `json:"fingerprint"`
	Custody            Custody       `json:"custody"`
	GPGCheck           bool          `json:"gpgcheck"`
	LocalPkgGPGCheck   bool          `json:"localpkg_gpgcheck"`
	RepoMetadataSigned bool          `json:"repo_metadata_signed"`
	Tools              []ToolVersion `json:"tools"`
}
