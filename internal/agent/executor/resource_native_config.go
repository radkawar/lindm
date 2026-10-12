//go:build linux

package executor

import (
	agentv1 "lindm/gen/lindm/agent/v1"
)

// NativeResourceProviders is the effective provider policy: root-owned local
// configuration merged with the verified capability policy's registry-derived
// providers. It is never decoded from a resource profile or an RPC.
type NativeResourceProviders struct {
	Files          *agentv1.NativeFileProviderConfig
	Accounts       *agentv1.NativeAccountProviderConfig
	Sysctl         *agentv1.NativeSysctlProviderConfig
	Firewall       *agentv1.NativeFirewallProviderConfig
	Password       *agentv1.NativePasswordProviderConfig
	OSUpdate       *agentv1.NativeOSUpdateProviderConfig
	ProtectedPaths []string
}
