//go:build linux

package executor

import (
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// NativeResourceProviders contains only locally provisioned policy. It is never
// decoded from a resource profile or accepted over the executor RPC boundary.
type NativeResourceProviders struct {
	Files          *agentv1.NativeFileProviderConfig
	Accounts       *agentv1.NativeAccountProviderConfig
	Sysctl         *agentv1.NativeSysctlProviderConfig
	Firewall       *agentv1.NativeFirewallProviderConfig
	Password       *agentv1.NativePasswordProviderConfig
	ProtectedPaths []string
}

func WithNativeResourceProviders(local NativeResourceProviders) Option {
	return func(s *Service) {
		s.nativeResources = NativeResourceProviders{
			Files: proto.CloneOf(local.Files), Accounts: proto.CloneOf(local.Accounts), Sysctl: proto.CloneOf(local.Sysctl),
			Firewall: proto.CloneOf(local.Firewall), Password: proto.CloneOf(local.Password), ProtectedPaths: append([]string(nil), local.ProtectedPaths...),
		}
	}
}
