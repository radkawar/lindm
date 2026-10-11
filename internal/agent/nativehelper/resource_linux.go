//go:build linux

package nativehelper

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/agent/statefs"
	"lindm/internal/platform"
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
// transactions. Paths and capabilities come only from the closed kind registry.
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
	kind, err := effectKind(request.GetPlan().GetRef().GetKind())
	if err != nil {
		return nil, err
	}
	directory, err := resourceDirectory(stateDirectory, "resource-transactions", request.GetActionId(), true)
	if err != nil {
		return nil, err
	}
	if kind.prepare != nil {
		if err := kind.prepare(directory, request); err != nil {
			return nil, err
		}
	}
	properties, err := resourceProperties(kind, directory, request)
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
	kind, err := effectKind(request.GetPlan().GetRef().GetKind())
	if err != nil {
		return err
	}
	env := resourceprovider.NativeEnv{
		Config: document.Proto, ProtectedPaths: document.ProtectedPaths, Directory: directory, Digest: custody.Digest,
		Platform: request.GetPlan().GetBackend().GetProduct(), ExecutorIncarnation: request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation(),
	}
	return serveEffect(ctx, directory, encoded, request.GetNonce(), func(ctx context.Context, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		return kind.apply(ctx, document, env, request, gate)
	})
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

func resourceProperties(kind nativeKind, directory string, request *agentv1.NativeResourceTransactionRequest) ([]unitProperty, error) {
	desired := resource.PlanDesired(request.GetPlan())
	if desired == nil {
		return nil, errors.New("native_resource_desired_missing")
	}
	sandbox := effectSandbox{
		paths: []string{directory}, caps: uint64(1) << unix.CAP_DAC_READ_SEARCH, privateNetwork: true, kernelTunables: true,
		protectHome: "yes", families: []string{"AF_UNIX"}, memoryMax: 512 << 20,
	}
	if err := kind.effect(&sandbox, directory, request, desired); err != nil {
		return nil, err
	}
	properties := transientProperties(directory, request.GetActionId(), "apply")
	properties = setProperty(properties, "Description", "Lindm bounded native resource transaction")
	properties = setProperty(properties, "ExecStart", []unitExec{{Path: helperExecutable, Arguments: []string{helperExecutable, "resource-transaction", "-transaction", request.GetActionId()}}})
	properties = setProperty(properties, "ReadWritePaths", sandbox.paths)
	properties = setProperty(properties, "CapabilityBoundingSet", sandbox.caps)
	properties = setProperty(properties, "PrivateNetwork", sandbox.privateNetwork)
	properties = setProperty(properties, "ProtectHome", sandbox.protectHome)
	properties = setProperty(properties, "ProtectKernelTunables", sandbox.kernelTunables)
	properties = setProperty(properties, "RestrictAddressFamilies", addressFamilies(sandbox.families...))
	properties = setProperty(properties, "RestrictSUIDSGID", true)
	properties = setProperty(properties, "NoNewPrivileges", true)
	if sandbox.accountRoot != "" {
		chroot := platform.Of(request.GetPlan().GetBackend().GetProduct()).Native().Quirks.AccountChroot
		properties = setProperty(properties, "BindPaths", accountRootBinds(sandbox.accountRoot, chroot))
		if chroot {
			// The bound procfs lacks the unit's own ProtectKernelTunables and
			// ProtectKernelLogs overmounts; repeat them inside the account root.
			readOnly := make([]string, 0, len(protectedProcEntries))
			for _, entry := range protectedProcEntries {
				readOnly = append(readOnly, "-"+filepath.Join(sandbox.accountRoot, "proc", entry))
			}
			properties = setProperty(properties, "ReadOnlyPaths", readOnly)
			properties = setProperty(properties, "InaccessiblePaths", []string{"-" + filepath.Join(sandbox.accountRoot, "proc", "kmsg")})
			// The tools' own login-shell check resolves the host shells there.
			properties = setProperty(properties, "BindReadOnlyPaths", []bindPath{{"/usr", filepath.Join(sandbox.accountRoot, "usr"), false, 0}})
		}
	}
	properties = setProperty(properties, "MemoryMax", sandbox.memoryMax)
	properties = setProperty(properties, "TasksMax", uint64(64))
	if sandbox.runtimeMax != 0 {
		properties = setProperty(properties, "RuntimeMaxUSec", uint64(sandbox.runtimeMax/time.Microsecond))
	}
	return properties, nil
}

// protectedProcEntries are the procfs paths systemd's ProtectKernelTunables
// makes read-only.
var protectedProcEntries = []string{"acpi", "apm", "asound", "bus", "fs", "irq", "kallsyms", "kcore", "latency_stats", "mtrr", "scsi", "sys", "sysrq-trigger", "timer_list"}

type bindPath struct {
	Source        string
	Destination   string
	IgnoreMissing bool
	Flags         uint64
}

// accountRootBinds exposes the host /etc to the account helper; a chroot
// product (platform Quirks.AccountChroot) also needs the host procfs
// for SELinux file-creation contexts and selinuxfs for chage's access check.
// Neither is recursive, so no other mount below them is exposed.
func accountRootBinds(accountRoot string, chroot bool) []bindPath {
	binds := []bindPath{{"/etc", filepath.Join(accountRoot, "etc"), false, 0}}
	if chroot {
		binds = append(binds, bindPath{"/proc", filepath.Join(accountRoot, "proc"), false, 0}, bindPath{"/sys/fs/selinux", filepath.Join(accountRoot, "sys", "fs", "selinux"), false, 0})
	}
	return binds
}

func prepareAccountRoot(directory string, chroot bool) error {
	parent, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, accountprovider.NativeRootDirectory, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	root, err := statefs.OpenDirectory(filepath.Join(directory, accountprovider.NativeRootDirectory))
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
	if chroot {
		// Mount points for the host procfs, selinuxfs and /usr binds, and EL's
		// merged /bin link.
		for _, path := range []string{"proc", "sys", "sys/fs", "sys/fs/selinux", "usr"} {
			if err := unix.Mkdirat(root, path, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
				return err
			}
		}
		if err := unix.Symlinkat("usr/bin", root, "bin"); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	target, err := statefs.OpenDirectory(filepath.Join(directory, accountprovider.NativeRootDirectory, "etc"))
	if err != nil {
		return err
	}
	return errors.Join(unix.Close(target), unix.Fsync(root), unix.Fsync(parent))
}
