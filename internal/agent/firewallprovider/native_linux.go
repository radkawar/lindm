//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

const StateDirectory = "/var/lib/lindm/firewall"
const RestoreUnitPath = "/usr/lib/systemd/system/lindm-firewall-restore.service"
const RestoreEnablePath = "/etc/systemd/system/network-pre.target.wants/lindm-firewall-restore.service"
const RestoreUnit = `[Unit]
Description=Lindm owned firewall typed state restoration
DefaultDependencies=no
After=local-fs.target systemd-tmpfiles-setup.service lindm-connectivity-guard.service
Requires=lindm-connectivity-guard.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/lindm/lindm-agent firewall-restore
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_LEASE
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=/var/lib/lindm/firewall
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=no
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
LimitCORE=0
MemoryMax=128M
TasksMax=64
TimeoutStartSec=60
RemainAfterExit=yes

[Install]
WantedBy=network-pre.target
`

func StatePath(zone string) string { return filepath.Join(StateDirectory, zone+".pb") }
func smallRead(path string, limit int) (data []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err = io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err == nil && len(data) > limit {
		err = ErrUnsupported
	}
	return data, err
}

// namespaceIdentity proves the helper runs in PID 1's network namespace.
// /proc/1/ns/net is ptrace-gated: a capability-bounded root helper cannot open
// or stat it (EACCES) without CAP_SYS_PTRACE, which would expose the executor's
// keys. Per-namespace /proc/<pid>/net entries are not ptrace-gated and are the
// same kernel entry exactly when both tasks share a network namespace.
func namespaceIdentity() ([]byte, error) {
	var self, selfEntry, hostEntry unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &self); err != nil {
		return nil, err
	}
	if err := unix.Stat("/proc/self/net/dev", &selfEntry); err != nil {
		return nil, err
	}
	if err := unix.Stat("/proc/1/net/dev", &hostEntry); err != nil {
		return nil, err
	}
	if selfEntry.Dev != hostEntry.Dev || selfEntry.Ino != hostEntry.Ino {
		return nil, fmt.Errorf("%w: helper is not in the host network namespace", ErrUnsupported)
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("lindm.firewall.netns.v1\x00%d\x00%d", self.Dev, self.Ino)))
	return digest[:], nil
}
func checkInterfaces(config *agentv1.NativeFirewallProviderConfig) error {
	for _, binding := range config.GetAllowedInterfaces() {
		name := binding.GetIfname()
		if name == "" {
			return fmt.Errorf("%w: exact interface name required", ErrUnsupported)
		}
		base := filepath.Join("/sys/class/net", name)
		if binding.GetPermanentMac() != "" {
			kind, err := smallRead(filepath.Join(base, "addr_assign_type"), 16)
			if err != nil {
				return err
			}
			address, err := smallRead(filepath.Join(base, "address"), 64)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(kind)) != "0" || strings.TrimSpace(string(address)) != binding.GetPermanentMac() {
				return fmt.Errorf("%w: permanent interface address changed", ErrConflict)
			}
		} else {
			device, err := filepath.EvalSymlinks(filepath.Join(base, "device"))
			if err != nil {
				return err
			}
			if device != binding.GetHardwareId() {
				return fmt.Errorf("%w: interface hardware path changed", ErrConflict)
			}
		}
	}
	return nil
}
func rootPath(path string, regular bool) error {
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	current := "/"
	for index, part := range parts {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			return err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			return ErrConflict
		}
		kind := st.Mode & unix.S_IFMT
		if index < len(parts)-1 || !regular {
			if kind != unix.S_IFDIR {
				return ErrConflict
			}
		} else if kind != unix.S_IFREG || st.Nlink != 1 {
			return ErrConflict
		}
	}
	return nil
}
func persistenceReady(template *resourcev1.ResourceObservation) bool {
	if err := rootPath(StateDirectory, false); err != nil {
		return false
	}
	unit, err := nativefile.Capture(RestoreUnitPath, template)
	if err != nil || !bytes.Equal(unit.GetManagedFileContent(), []byte(RestoreUnit)) || unit.GetObservation().GetManagedFile().GetFile().GetUid() != 0 || unit.GetObservation().GetManagedFile().GetFile().GetMode()&0022 != 0 {
		return false
	}
	if err := rootPath("/usr/libexec/lindm/lindm-agent", true); err != nil {
		return false
	}
	if err := rootPath(filepath.Dir(RestoreEnablePath), false); err != nil {
		return false
	}
	var st unix.Stat_t
	if err := unix.Lstat(RestoreEnablePath, &st); err != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return false
	}
	target, err := os.Readlink(RestoreEnablePath)
	return err == nil && target == RestoreUnitPath
}

// ReadNative runs only inside the fixed CAP_NET_ADMIN host-network helper. It
// returns a private snapshot; callers expose only its closed observation arm.
func ReadNative(ctx context.Context, config *agentv1.NativeFirewallProviderConfig, template *resourcev1.ResourceObservation) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if os.Geteuid() != 0 || template.GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE {
		return nil, ErrUnsupported
	}
	if err := validateMessage(config); err != nil {
		return nil, err
	}
	if err := checkInterfaces(config); err != nil {
		return nil, err
	}
	if err := resource.ValidateRef(template.GetRef()); err != nil {
		return nil, err
	}
	namespace, err := namespaceIdentity()
	if err != nil {
		return nil, err
	}
	boot, err := smallRead("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return nil, err
	}
	connection, err := openNetlink(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, connection.close()) }()
	zone := template.GetRef().GetCanonicalKey()
	snapshot, foreign, err := connection.observe(tableName(zone))
	if err != nil {
		return nil, err
	}
	snapshot.NetworkNamespaceSha256 = namespace
	o := proto.CloneOf(template)
	if o.Metadata == nil {
		o.Metadata = &resourcev1.ObservationMetadata{}
	}
	o.Metadata.BootId = strings.TrimSpace(string(boot))
	o.Metadata.ObservedAt = timestamppb.Now()
	o.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_OK
	file, err := nativefile.Capture(StatePath(zone), o)
	if err != nil {
		return nil, err
	}
	snapshot.PersistenceFile = proto.CloneOf(file.GetObservation().GetManagedFile())
	snapshot.PersistenceContent = bytes.Clone(file.GetManagedFileContent())
	snapshot.PersistenceXattrs = file.GetManagedFileXattrs()
	if !snapshot.GetPersistenceFile().GetExists() {
		creation := fileTarget(file, []byte{})
		if err := nativefile.CreationMetadata(ctx, creation); err != nil {
			return nil, err
		}
		snapshot.CreationXattrs = creation.GetManagedFileXattrs()
	}
	if snapshot.GetPersistenceFile().GetExists() {
		state := &agentv1.FirewallPersistentState{}
		if err := proto.Unmarshal(snapshot.GetPersistenceContent(), state); err != nil {
			return nil, ErrConflict
		}
		if err := validateMessage(state); err != nil {
			return nil, err
		}
		snapshot.Persistent = state
		configDigest, err := messageDigest(config)
		if err != nil {
			return nil, err
		}
		if state.GetDesired().GetZoneId() != zone || state.GetPhase() != agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED || !bytes.Equal(state.GetConfigurationSha256(), configDigest) {
			snapshot.Conflict = true
		}
		expected, err := compile(state, config)
		if err != nil {
			return nil, err
		}
		if !nativeEqual(snapshot, expected.snapshot()) {
			snapshot.Conflict = true
		}
		if snapshot.GetPersistenceFile().GetFile().GetUid() != 0 || snapshot.GetPersistenceFile().GetFile().GetGid() != 0 || snapshot.GetPersistenceFile().GetFile().GetMode() != 0600 {
			snapshot.Conflict = true
		}
	} else if len(snapshot.GetUserdata()) != 0 {
		snapshot.Conflict = true
	}
	kernel, err := nativeDigest(snapshot)
	if err != nil {
		return nil, err
	}
	persistent := sha256.Sum256(snapshot.GetPersistenceContent())
	observed := &resourcev1.FirewallZoneObservation{NativeOwner: "lindm-dedicated-nftables", NativeVersion: o.GetMetadata().GetBackend().GetNativeVersion(), ZoneId: zone, Table: snapshot.GetTable(), Exists: len(snapshot.GetUserdata()) != 0, KernelRulesSha256: kernel, PersistentSha256: persistent[:], NativeIdentitySha256: kernel, OwnershipUserdata: bytes.Clone(snapshot.GetUserdata()), NetworkNamespaceSha256: namespace, DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, Conflict: snapshot.GetConflict(), PersistentReady: persistenceReady(o), ForeignTables: foreign}
	if state := snapshot.GetPersistent(); state != nil {
		d := state.GetDesired()
		observed.PersistentRules = d.GetRules()
		observed.DefaultIngress = d.GetDefaultIngress()
		observed.DefaultEgress = d.GetDefaultEgress()
		if !snapshot.GetConflict() {
			observed.ActiveRules = d.GetRules()
			observed.BoundInterfaces = d.GetInterfaces()
		}
	}
	o.Observed = &resourcev1.ResourceObservation_FirewallZone{FirewallZone: observed}
	revision, err := messageDigest(observed)
	if err != nil {
		return nil, err
	}
	o.Metadata.NativeRevision = revision
	if err := resource.ValidateObservation(o); err != nil {
		return nil, err
	}
	return &agentv1.ResourceOwnershipSnapshot{Observation: o, Firewall: snapshot}, nil
}
func persistenceImage(s *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipSnapshot {
	result := &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(s.GetObservation()), ManagedFileContent: bytes.Clone(s.GetFirewall().GetPersistenceContent()), ManagedFileXattrs: s.GetFirewall().GetPersistenceXattrs()}
	result.Observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(s.GetFirewall().GetPersistenceFile())}
	return result
}
func fileTarget(before *agentv1.ResourceOwnershipSnapshot, content []byte) *agentv1.ResourceOwnershipSnapshot {
	result := proto.CloneOf(before)
	o := result.Observation.GetManagedFile()
	o.Exists = content != nil
	result.ManagedFileContent = bytes.Clone(content)
	if content == nil {
		o.File = nil
		result.ManagedFileXattrs = nil
		o.SecurityMetadataSha256 = nativefile.XattrDigest(nil)
	} else {
		digest := sha256.Sum256(content)
		o.File = &resourcev1.FileIdentity{Path: o.GetPath(), Sha256: digest[:], Mode: 0600}
		o.SecurityMetadataSha256 = nativefile.XattrDigest(result.GetManagedFileXattrs())
	}
	return result
}
