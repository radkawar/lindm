//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/definitionprovider"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/platform"
)

// nativeKind is the root helper's closed contract for one resource kind. Every
// kind applies through resourceprovider.NativeApply semantics and returns its
// after-image; effect grants derive only from the validated typed request.
// observe is set only for kinds whose facts the resident executor cannot read
// inside its own sandbox; the executor observes the others itself.
type nativeKind struct {
	// prepare provisions private scratch state before the effect unit starts.
	prepare func(directory string, request *agentv1.NativeResourceTransactionRequest) error
	// effect adds the kind's grants to the effect unit's base sandbox.
	effect func(s *effectSandbox, directory string, request *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState) error
	apply  func(ctx context.Context, document *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
	// observation adjusts the read-only observation unit; observe fills result.
	observation func(ctx context.Context, properties []unitProperty, request *agentv1.NativeResourceObservationRequest) ([]unitProperty, error)
	observe     func(ctx context.Context, document *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceObservationRequest, result *agentv1.NativeHelperResult) error
	// evidence marks a read-only kind whose observation is compliance
	// evidence rather than an ownership after-image.
	evidence bool
}

// effectSandbox is the transient unit's grant set for one native effect.
type effectSandbox struct {
	paths          []string
	caps           uint64
	privateNetwork bool
	kernelTunables bool
	protectHome    string
	families       []string
	accountRoot    string
	memoryMax      uint64
	runtimeMax     time.Duration
}

func (s *effectSandbox) fileCaps() {
	for _, capability := range []uint{unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FOWNER, unix.CAP_FSETID, unix.CAP_LEASE} {
		s.caps |= uint64(1) << capability
	}
}

// applyOnly adapts a provider's uniform native apply to the registry.
func applyOnly(apply resourceprovider.NativeApply) func(context.Context, *config.Document, resourceprovider.NativeEnv, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
	return func(ctx context.Context, _ *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		return apply(ctx, env, request, gate)
	}
}

var account = nativeKind{
	prepare: func(directory string, request *agentv1.NativeResourceTransactionRequest) error {
		return prepareAccountRoot(directory, platform.Of(request.GetPlan().GetBackend().GetProduct()).Native().Quirks.AccountChroot)
	},
	effect: func(s *effectSandbox, directory string, _ *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState) error {
		s.accountRoot = filepath.Join(directory, accountprovider.NativeRootDirectory)
		s.paths = append(s.paths, filepath.Join(s.accountRoot, "etc"))
		s.fileCaps()
		s.protectHome = "read-only"
		s.caps |= uint64(1) << unix.CAP_SYS_CHROOT
		s.privateNetwork = false
		s.families = append(s.families, "AF_INET", "AF_INET6")
		if user := desired.GetLocalUser(); user != nil && user.GetHome().GetCreation() == resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT {
			s.paths = append(s.paths, filepath.Dir(user.GetHomeDirectory()))
		}
		return nil
	},
	apply: applyOnly(accountprovider.ApplyNative),
	observation: func(_ context.Context, properties []unitProperty, _ *agentv1.NativeResourceObservationRequest) ([]unitProperty, error) {
		properties = setProperty(properties, "ProtectHome", "read-only")
		properties = setProperty(properties, "PrivateNetwork", false)
		return setProperty(properties, "RestrictAddressFamilies", addressFamilies("AF_UNIX", "AF_INET", "AF_INET6")), nil
	},
	observe: func(ctx context.Context, _ *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceObservationRequest, result *agentv1.NativeHelperResult) (err error) {
		result.After, err = accountprovider.ObserveNative(ctx, env, request.GetDesired())
		return err
	},
}

// nativeKinds is the only kind dispatch in the root helper.
var nativeKinds = resourceprovider.NewRegistry(map[resourcev1.ResourceKind]nativeKind{
	resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE: {
		effect: func(s *effectSandbox, _ string, _ *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState) error {
			s.paths = append(s.paths, filepath.Dir(desired.GetManagedFile().GetPath()))
			s.fileCaps()
			return nil
		},
		apply: applyOnly(fileprovider.ApplyNative),
	},
	resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP: account,
	resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:  account,
	resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL: {
		effect: func(s *effectSandbox, _ string, request *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState) error {
			key := desired.GetSysctl().GetKey()
			if strings.HasPrefix(key, "net.") {
				s.privateNetwork = false
			}
			if sysctlprovider.NeedsRuntimeWrite(request) {
				// ProtectKernelTunables=no leaves /proc/sys writable; a bind mount of
				// the procfs file itself is refused by SELinux on Fedora.
				s.kernelTunables = false
				if strings.HasPrefix(key, "net.") {
					s.caps |= uint64(1) << unix.CAP_NET_ADMIN
				} else {
					s.caps |= uint64(1) << unix.CAP_SYS_ADMIN
				}
			}
			if sysctlprovider.NeedsPersistenceWrite(request) {
				s.paths = append(s.paths, filepath.Dir(sysctlprovider.StanzaPath(key)))
			}
			s.fileCaps()
			return nil
		},
		apply: applyOnly(sysctlprovider.ApplyNative),
	},
	resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION: {
		effect: func(s *effectSandbox, _ string, request *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState) error {
			path, err := definitionprovider.DefinitionPath(desired)
			if err != nil {
				return err
			}
			parent := filepath.Dir(path)
			// Creating a missing drop-in directory, or releasing one this ledger
			// created, writes the unit root itself.
			createdParent := request.GetPlan().GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && request.GetOwnership().GetBaseline().GetDefinitionFile().GetParentMissing()
			if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) || createdParent {
				parent = filepath.Dir(parent)
			} else if err != nil {
				return err
			}
			s.paths = append(s.paths, parent)
			s.fileCaps()
			return nil
		},
		apply: applyOnly(definitionprovider.ApplyNative),
	},
	resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY: {
		effect: func(s *effectSandbox, _ string, request *agentv1.NativeResourceTransactionRequest, _ *resourcev1.ResourceDesiredState) error {
			// Atomic login.defs replacement needs its parent. Native authselect also
			// rewrites /etc/nsswitch.conf and its PAM/dconf symlinks, not a file bind.
			s.paths = append(s.paths, "/etc")
			s.fileCaps()
			switch platform.Of(request.GetPlan().GetBackend().GetProduct()).Native().Quirks.PAMManager {
			case platform.PAMManagerPamAuthUpdate:
				s.paths = append(s.paths, "/usr/share/pam-configs", "/var/lib/pam", "/var/cache/debconf")
			case platform.PAMManagerAuthselect:
				s.paths = append(s.paths, "/var/lib/authselect")
			default:
				return errors.New("native_password_platform_not_supported")
			}
			return nil
		},
		apply: applyOnly(passwordprovider.ApplyNative),
	},
	resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE: {
		effect: func(s *effectSandbox, _ string, _ *agentv1.NativeResourceTransactionRequest, _ *resourcev1.ResourceDesiredState) error {
			s.paths = append(s.paths, firewallprovider.StateDirectory, "/var/lib/lindm/connectivity-guard")
			s.fileCaps()
			s.caps |= uint64(1)<<unix.CAP_NET_ADMIN | uint64(1)<<unix.CAP_NET_RAW
			s.privateNetwork = false
			s.families = append(s.families, "AF_INET", "AF_INET6", "AF_NETLINK")
			s.memoryMax = 128 << 20
			s.runtimeMax = time.Minute
			return nil
		},
		apply: func(ctx context.Context, document *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (_ *agentv1.ResourceOwnershipSnapshot, resultErr error) {
			guard, closeGuard, err := newFirewallGuard(ctx, document, request)
			if err != nil {
				return nil, err
			}
			defer func() { resultErr = errors.Join(resultErr, closeGuard()) }()
			return firewallprovider.ApplyNative(ctx, env, request, guard, gate)
		},
		observation: func(_ context.Context, properties []unitProperty, request *agentv1.NativeResourceObservationRequest) ([]unitProperty, error) {
			properties = setProperty(properties, "PrivateNetwork", false)
			if request.GetFirewallVerification() != nil {
				properties = setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_NET_ADMIN|uint64(1)<<unix.CAP_NET_RAW|uint64(1)<<unix.CAP_DAC_READ_SEARCH)
				return setProperty(properties, "RestrictAddressFamilies", addressFamilies("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK")), nil
			}
			properties = setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_NET_ADMIN|uint64(1)<<unix.CAP_DAC_READ_SEARCH)
			return setProperty(properties, "RestrictAddressFamilies", addressFamilies("AF_UNIX", "AF_NETLINK")), nil
		},
		observe: func(ctx context.Context, document *config.Document, env resourceprovider.NativeEnv, request *agentv1.NativeResourceObservationRequest, result *agentv1.NativeHelperResult) (err error) {
			template := &resourcev1.ResourceObservation{Ref: proto.CloneOf(request.GetDesired().GetRef()), Metadata: &resourcev1.ObservationMetadata{ExecutorIncarnation: env.ExecutorIncarnation, Backend: proto.CloneOf(request.GetBackend())}}
			result.After, err = firewallprovider.ReadNative(ctx, env.Config.GetFirewallProvider(), template)
			if err != nil || request.GetFirewallVerification() == nil {
				return err
			}
			verifier, closeVerifier, err := newFirewallVerifier(ctx, document, request)
			if err != nil {
				return err
			}
			result.FirewallAllow, result.FirewallDeny, result.FirewallEvidence, err = verifier.ProbeVerification(ctx, request.GetDesired().GetFirewallZone(), request.GetFirewallVerification())
			return errors.Join(err, closeVerifier())
		},
	},
	resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE: {
		// Read-only compliance: no native effect exists, so effect and apply
		// stay unset and LaunchResource refuses the kind.
		evidence: true,
		observation: func(ctx context.Context, properties []unitProperty, _ *agentv1.NativeResourceObservationRequest) ([]unitProperty, error) {
			devices, err := actionprovider.RootEncryptionReadDevices(ctx)
			if err != nil || len(devices) == 0 {
				return properties, err
			}
			type devicePermission struct {
				Path        string
				Permissions string
			}
			allow := make([]devicePermission, 0, len(devices))
			for _, path := range devices {
				mode := "r"
				if path == "/dev/mapper/control" || path == "/dev/tpmrm0" {
					mode = "rw"
				}
				allow = append(allow, devicePermission{path, mode})
			}
			properties = setProperty(properties, "PrivateDevices", false)
			properties = setProperty(properties, "DevicePolicy", "closed")
			properties = setProperty(properties, "DeviceAllow", allow)
			return setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_DAC_READ_SEARCH), nil
		},
		observe: func(ctx context.Context, _ *config.Document, _ resourceprovider.NativeEnv, _ *agentv1.NativeResourceObservationRequest, result *agentv1.NativeHelperResult) error {
			evidence, err := actionprovider.ObserveRootEncryption(ctx)
			if err != nil {
				return err
			}
			result.Encryption = &agentv1.NativeRootEncryptionEvidence{LuksRoot: evidence.LUKSRoot, Target: proto.CloneOf(evidence.Target), NativeSha256: bytes.Clone(evidence.NativeSHA256), MetadataSha256: bytes.Clone(evidence.MetadataSHA256), TpmBound: evidence.TPMBound, Reason: evidence.Reason}
			for _, recovery := range evidence.Recovery {
				result.Encryption.Recovery = append(result.Encryption.Recovery, &agentv1.NativeRootRecoveryEvidence{ActionId: recovery.ActionID, Keyslot: recovery.Keyslot, KeySha256: bytes.Clone(recovery.KeySHA256)})
			}
			return nil
		},
	},
})

var errKindNotSupported = errors.New("native_resource_kind_not_supported")

// effectKind returns the registered kind that has a native effect.
func effectKind(kind resourcev1.ResourceKind) (nativeKind, error) {
	entry, err := nativeKinds.Lookup(kind)
	if err != nil || entry.apply == nil {
		return nativeKind{}, errKindNotSupported
	}
	return entry, nil
}

// observedKind returns the registered kind that has a native observation.
func observedKind(kind resourcev1.ResourceKind) (nativeKind, error) {
	entry, err := nativeKinds.Lookup(kind)
	if err != nil || entry.observe == nil {
		return nativeKind{}, errors.New("native_observation_kind_not_supported")
	}
	return entry, nil
}

func addressFamilies(families ...string) any {
	return struct {
		AllowList bool
		Families  []string
	}{true, families}
}
