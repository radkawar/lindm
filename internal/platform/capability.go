package platform

// Capability is one gated product capability. Capability names are also the
// documentation column keys.
type Capability string

const (
	Inventory        Capability = "inventory"
	Lifecycle        Capability = "lifecycle"
	Dispatch         Capability = "dispatch"
	Packages         Capability = "packages"
	Accounts         Capability = "accounts"
	Sysctl           Capability = "sysctl"
	Definitions      Capability = "definitions"
	Password         Capability = "password"
	Firewall         Capability = "firewall"
	Encryption       Capability = "encryption"
	Wipe             Capability = "wipe"
	ReportLoss       Capability = "report-loss"
	Lock             Capability = "lock"
	RecoverySanitize Capability = "recovery-sanitize"
	SelfUpdate       Capability = "self-update"
	Assistance       Capability = "assistance"
	Advisories       Capability = "advisories"
	OSUpdate         Capability = "os-update"
	ReleaseUpgrade   Capability = "release-upgrade"
)

// Capabilities lists every capability in documentation order.
var Capabilities = []Capability{
	Inventory, Lifecycle, Dispatch, Packages, Accounts, Sysctl, Definitions, Password, Firewall,
	Encryption, Wipe, ReportLoss, Lock, RecoverySanitize, SelfUpdate, Assistance, Advisories,
	OSUpdate, ReleaseUpgrade,
}

// ResourceCapabilities are the configuration-resource provider capabilities.
var ResourceCapabilities = []Capability{Packages, Accounts, Sysctl, Definitions, Password, Firewall}
