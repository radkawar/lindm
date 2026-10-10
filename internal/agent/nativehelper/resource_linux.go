//go:build linux

package nativehelper

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/definitionprovider"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/statefs"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/resource"
)

func resourceDirectory(stateDirectory, category, id string, create bool) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", errors.New("native_resource_identity")
	}
	root, err := statefs.OpenDirectory(stateDirectory)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(root) }()
	if create {
		if err := unix.Mkdirat(root, category, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return "", err
		}
	}
	parent := filepath.Join(stateDirectory, category)
	parentFD, err := statefs.OpenDirectory(parent)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if create {
		if err := unix.Mkdirat(parentFD, id, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return "", err
		}
		if err := unix.Fsync(parentFD); err != nil {
			return "", err
		}
	}
	directory := filepath.Join(parent, id)
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return "", err
	}
	return directory, unix.Close(fd)
}

// LaunchResource uses the same one-use native-preflight handshake as package
// transactions. Paths and capabilities come only from this closed kind switch.
func LaunchResource(ctx context.Context, stateDirectory string, input *agentv1.NativeResourceTransactionRequest, authorize func(context.Context) (*agentv1.NativeEffectPermit, error)) (*agentv1.ResourceOwnershipSnapshot, error) {
	request := proto.CloneOf(input)
	if request == nil {
		return nil, errors.New("native_resource_request_required")
	}
	request.Nonce = make([]byte, 32)
	if _, err := rand.Read(request.Nonce); err != nil {
		return nil, err
	}
	encoded, err := encodeRecord(request)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	if err := resource.ValidatePlan(request.GetPlan()); err != nil {
		return nil, err
	}
	directory, err := resourceDirectory(stateDirectory, "resource-transactions", request.GetActionId(), true)
	if err != nil {
		return nil, err
	}
	if kind := request.GetPlan().GetRef().GetKind(); kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER || kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP {
		if err := prepareAccountRoot(directory); err != nil {
			return nil, err
		}
	}
	properties, err := resourceProperties(directory, request)
	if err != nil {
		return nil, err
	}
	result := new(agentv1.NativeHelperResult)
	if err := launchEffect(ctx, directory, "lindm-resource-"+request.GetActionId()+".service", encoded, request.GetNonce(), properties, authorize, result); err != nil {
		return nil, err
	}
	// Providers that report an after-image require it themselves; account effects
	// are always independently observed by the executor instead.
	return result.GetAfter(), nil
}

// RunResource loads only the root-owned request for a fixed action identifier.
// Neither arbitrary write paths nor native command strings cross this boundary.
func RunResource(ctx context.Context, document *config.Document, actionID string) error {
	if os.Geteuid() != 0 || document == nil {
		return errors.New("native_resource_root_configuration_required")
	}
	ctx, cancel := context.WithTimeout(ctx, transactionTimeout)
	defer cancel()
	directory, err := resourceDirectory(document.StateDirectory, "resource-transactions", actionID, false)
	if err != nil {
		return err
	}
	request := new(agentv1.NativeResourceTransactionRequest)
	encoded, err := readRecord(directory, "apply-request.pb", request)
	if err != nil {
		return err
	}
	defer clear(encoded)
	custody, err := helperCustody(directory)
	if err != nil {
		return err
	}
	defer custody.Close()
	if request.GetActionId() != actionID {
		return errors.New("native_resource_action_mismatch")
	}
	if err := resource.ValidatePlan(request.GetPlan()); err != nil {
		return err
	}
	if err := writeProtected(directory, "apply-invocation.pb", encoded); err != nil {
		return err
	}
	return serveEffect(ctx, directory, encoded, request.GetNonce(), func(ctx context.Context, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		platform := request.GetPlan().GetBackend().GetProduct()
		incarnation := request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation()
		switch request.GetPlan().GetRef().GetKind() {
		case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
			return fileprovider.ExecuteNative(ctx, fileprovider.NativeConfig{Native: document.Proto.GetFileProvider(), Platform: platform, ExecutorIncarnation: incarnation, ProtectedPaths: document.ProtectedPaths}, request, gate)
		case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
			return nil, accountprovider.ExecuteNative(ctx, accountprovider.NativeConfig{Native: document.Proto.GetAccountProvider(), Platform: platform, ExecutorIncarnation: incarnation, AccountRoot: filepath.Join(directory, "account-root"), NativeDigest: custody.Digest}, request, gate)
		case resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:
			return sysctlprovider.ExecuteNative(ctx, sysctlprovider.NativeConfig{Native: document.Proto.GetSysctlProvider(), Platform: platform, ExecutorIncarnation: incarnation}, request, gate)
		case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:
			return definitionprovider.ExecuteNative(ctx, definitionprovider.NativeConfig{Platform: platform, ExecutorIncarnation: incarnation, ScratchDirectory: directory}, request, gate)
		case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
			return passwordprovider.ExecuteNative(ctx, document.Proto.GetPasswordProvider(), request, gate)
		case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
			return applyFirewall(ctx, document, request, gate)
		default:
			return nil, errors.New("native_resource_kind_not_supported")
		}
	})
}

func applyFirewall(ctx context.Context, document *config.Document, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (_ *agentv1.ResourceOwnershipSnapshot, resultErr error) {
	guard, closeGuard, err := newFirewallGuard(ctx, document, request)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeGuard()) }()
	if err := firewallprovider.ApplyNative(ctx, document.Proto.GetFirewallProvider(), request, guard, gate); err != nil {
		return nil, err
	}
	return firewallprovider.ReadNative(ctx, document.Proto.GetFirewallProvider(), request.GetBefore().GetObservation())
}

func setProperty(properties []unitProperty, name string, value any) []unitProperty {
	for i := range properties {
		if properties[i].Name == name {
			properties[i].Value = dbus.MakeVariant(value)
			return properties
		}
	}
	return append(properties, unitProperty{Name: name, Value: dbus.MakeVariant(value)})
}

func resourceProperties(directory string, request *agentv1.NativeResourceTransactionRequest) ([]unitProperty, error) {
	desired := resource.PlanDesired(request.GetPlan())
	if desired == nil {
		return nil, errors.New("native_resource_desired_missing")
	}
	paths := []string{directory}
	caps := uint64(1) << unix.CAP_DAC_READ_SEARCH
	privateNetwork := true
	kernelTunables := true
	protectHome := "yes"
	families := []string{"AF_UNIX"}
	var accountRoot string
	addFileCaps := func() {
		for _, capability := range []uint{unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FOWNER, unix.CAP_FSETID, unix.CAP_LEASE} {
			caps |= uint64(1) << capability
		}
	}
	switch desired.GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		paths = append(paths, filepath.Dir(desired.GetManagedFile().GetPath()))
		addFileCaps()
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		accountRoot = filepath.Join(directory, "account-root")
		paths = append(paths, filepath.Join(accountRoot, "etc"))
		addFileCaps()
		protectHome = "read-only"
		caps |= uint64(1) << unix.CAP_SYS_CHROOT
		privateNetwork = false
		families = append(families, "AF_INET", "AF_INET6")
		if user := desired.GetLocalUser(); user != nil && user.GetHome().GetCreation() == resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT {
			paths = append(paths, filepath.Dir(user.GetHomeDirectory()))
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:
		key := desired.GetSysctl().GetKey()
		if strings.HasPrefix(key, "net.") {
			privateNetwork = false
		}
		if sysctlprovider.NeedsRuntimeWrite(request) {
			// ProtectKernelTunables=no leaves /proc/sys writable; a bind mount of
			// the procfs file itself is refused by SELinux on Fedora.
			kernelTunables = false
			if strings.HasPrefix(key, "net.") {
				caps |= uint64(1) << unix.CAP_NET_ADMIN
				privateNetwork = false
			} else {
				caps |= uint64(1) << unix.CAP_SYS_ADMIN
			}
		}
		if sysctlprovider.NeedsPersistenceWrite(request) {
			paths = append(paths, filepath.Dir(sysctlprovider.StanzaPath(key)))
		}
		addFileCaps()
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:
		path, err := definitionprovider.DefinitionPath(desired)
		if err != nil {
			return nil, err
		}
		parent := filepath.Dir(path)
		// Creating a missing drop-in directory, or releasing one this ledger
		// created, writes the unit root itself.
		createdParent := request.GetPlan().GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && request.GetOwnership().GetBaseline().GetDefinitionFile().GetParentMissing()
		if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) || createdParent {
			parent = filepath.Dir(parent)
		} else if err != nil {
			return nil, err
		}
		paths = append(paths, parent)
		addFileCaps()
	case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
		// Atomic login.defs replacement needs its parent. Native authselect also
		// rewrites /etc/nsswitch.conf and its PAM/dconf symlinks, not a file bind.
		paths = append(paths, "/etc")
		addFileCaps()
		switch request.GetPlan().GetBackend().GetProduct().GetOsId() {
		case "ubuntu":
			paths = append(paths, "/usr/share/pam-configs", "/var/lib/pam", "/var/cache/debconf")
		case "fedora":
			paths = append(paths, "/var/lib/authselect")
		default:
			return nil, errors.New("native_password_platform_not_supported")
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		paths = append(paths, firewallprovider.StateDirectory, "/var/lib/lindm/connectivity-guard")
		addFileCaps()
		caps |= uint64(1)<<unix.CAP_NET_ADMIN | uint64(1)<<unix.CAP_NET_RAW
		privateNetwork = false
		families = append(families, "AF_INET", "AF_INET6", "AF_NETLINK")
	default:
		return nil, errors.New("native_resource_kind_not_supported")
	}
	properties := transientProperties(directory, request.GetActionId(), "apply")
	properties = setProperty(properties, "Description", "Lindm bounded native resource transaction")
	properties = setProperty(properties, "ExecStart", []unitExec{{Path: helperExecutable, Arguments: []string{helperExecutable, "resource-transaction", "-transaction", request.GetActionId()}}})
	properties = setProperty(properties, "ReadWritePaths", paths)
	properties = setProperty(properties, "CapabilityBoundingSet", caps)
	properties = setProperty(properties, "PrivateNetwork", privateNetwork)
	properties = setProperty(properties, "ProtectHome", protectHome)
	properties = setProperty(properties, "ProtectKernelTunables", kernelTunables)
	properties = setProperty(properties, "RestrictAddressFamilies", struct {
		AllowList bool
		Families  []string
	}{true, families})
	properties = setProperty(properties, "RestrictSUIDSGID", true)
	properties = setProperty(properties, "NoNewPrivileges", true)
	if accountRoot != "" {
		properties = setProperty(properties, "BindPaths", []struct {
			Source        string
			Destination   string
			IgnoreMissing bool
			Flags         uint64
		}{{"/etc", filepath.Join(accountRoot, "etc"), false, 0}})
	}
	properties = setProperty(properties, "MemoryMax", uint64(512<<20))
	properties = setProperty(properties, "TasksMax", uint64(64))
	if desired.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE {
		properties = setProperty(properties, "MemoryMax", uint64(128<<20))
		properties = setProperty(properties, "RuntimeMaxUSec", uint64(time.Minute/time.Microsecond))
	}
	return properties, nil
}

func prepareAccountRoot(directory string) error {
	parent, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, "account-root", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	root, err := statefs.OpenDirectory(filepath.Join(directory, "account-root"))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(root) }()
	if err := unix.Mkdirat(root, "etc", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	// Native useradd may create a mailbox under <prefix>/var/{mail,spool/mail}
	// when the distribution default asks for one; keep that in private scratch.
	for _, path := range []string{"var", "var/spool", "var/spool/mail", "var/mail"} {
		if err := unix.Mkdirat(root, path, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	target, err := statefs.OpenDirectory(filepath.Join(directory, "account-root", "etc"))
	if err != nil {
		return err
	}
	return errors.Join(unix.Close(target), unix.Fsync(root), unix.Fsync(parent))
}
