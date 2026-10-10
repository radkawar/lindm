//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// RootEncryptionEvidence contains public native facts, not an escrow assertion.
// Recovery fingerprints must be joined to authenticated durable server receipts.
// No token payload, sealed object, key or raw metadata escapes this adapter.
type RootEncryptionEvidence struct {
	LUKSRoot       bool
	Target         *agentv1.StorageTarget
	NativeSHA256   []byte
	MetadataSHA256 []byte
	Recovery       []RootRecoveryEvidence
	TPMBound       bool
	Reason         string
}
type RootRecoveryEvidence struct {
	ActionID  string
	Keyslot   uint32
	KeySHA256 []byte
}

type complianceGraph struct {
	facts         []string
	cryptUUID     string
	backing       string
	backingDisk   string
	mappingDevice string
	leaves        int
	protected     int
}

// rootEncryptionGraph follows kernel dependencies, including LVM above dm-crypt.
// Every leaf must be covered; a single encrypted leg of a mixed root is not enough.
func rootEncryptionGraph(root string, read func(string) ([]byte, error), children func(string) ([]os.DirEntry, error)) (*complianceGraph, error) {
	g := &complianceGraph{}
	visiting := make(map[string]bool)
	nodes := 0
	var visit func(string, bool, int) error
	visit = func(device string, encrypted bool, depth int) error {
		nodes++
		if !canonicalBlockDeviceNumber(device) || strings.HasPrefix(device, "0:") || nodes > 128 || depth > 32 || visiting[device] {
			return ErrUnsupported
		}
		visiting[device] = true
		defer delete(visiting, device)
		base := "/sys/dev/block/" + device
		raw, err := read(base + "/dm/uuid")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		id := strings.TrimSpace(string(raw))
		g.facts = append(g.facts, device+"="+id)
		entries, err := children(base + "/slaves")
		if err != nil && (!errors.Is(err, os.ErrNotExist) || id != "") {
			return err
		}
		crypt := strings.HasPrefix(id, "CRYPT-")
		if crypt {
			if !strings.HasPrefix(id, "CRYPT-LUKS2-") || len(id) < 45 || id[44] != '-' || len(entries) != 1 || g.cryptUUID != "" {
				return ErrUnsupported
			}
			compact := id[12:44]
			if _, err := hex.DecodeString(compact); err != nil {
				return ErrUnsupported
			}
			g.cryptUUID = compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:]
			g.mappingDevice = device
			encrypted = true
		}
		if len(entries) == 0 {
			g.leaves++
			if encrypted {
				g.protected++
			}
		}
		for _, entry := range entries {
			raw, err := read(base + "/slaves/" + entry.Name() + "/dev")
			if err != nil {
				return err
			}
			next := strings.TrimSpace(string(raw))
			g.facts = append(g.facts, device+">"+next)
			if crypt {
				g.backing = next
			}
			if err := visit(next, encrypted, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(root, false, 0); err != nil {
		return nil, err
	}
	if g.leaves == 0 || g.cryptUUID != "" && g.leaves != g.protected {
		return nil, ErrUnsupported
	}
	slices.Sort(g.facts)
	return g, nil
}

// ObserveRootEncryption performs only bounded native reads. TPM success requires
// cryptsetup's systemd-tpm2 token plugin to unlock-test the exact active slot on
// the current TPM/PCR state. No mapper is created and no key is printed.
func ObserveRootEncryption(ctx context.Context) (*RootEncryptionEvidence, error) {
	p := &Provider{run: runNative}
	return p.observeRootEncryption(ctx)
}
func (p *Provider) observeRootEncryption(ctx context.Context) (_ *RootEncryptionEvidence, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat("/", &st); err != nil {
		return nil, err
	}
	graph, err := rootEncryptionGraph(fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)), readSysfsIdentityFile, os.ReadDir)
	if err != nil {
		return nil, err
	}
	graphHash := sha256.Sum256([]byte(strings.Join(graph.facts, "\n")))
	result := &RootEncryptionEvidence{NativeSHA256: graphHash[:], Reason: "root_not_luks2"}
	if graph.cryptUUID == "" {
		return result, nil
	}
	tableHash, err := p.complianceCryptTable(ctx, graph)
	if err != nil {
		return nil, err
	}
	raw, err := p.run(ctx, nativeRequest{command: lsblk, args: []string{"--json", "--tree", "--bytes", "--output", "PATH,TYPE,SIZE,WWN,SERIAL,UUID,PTTYPE,PTUUID,ROTA,MOUNTPOINTS,FSTYPE,MAJ:MIN"}})
	if err != nil {
		return nil, err
	}
	var topology struct {
		Devices []blockNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(raw, &topology); err != nil {
		return nil, err
	}
	target, err := complianceTarget(topology.Devices, graph, nativeBlockIdentity)
	if err != nil {
		return nil, err
	}
	// Reuse exact durable identity and pinned descriptor checks, without granting
	// any action capability or requiring a destructive/action allowlist entry.
	p.config = &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: target}}}
	handle, err := p.openTarget(ctx, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: target, Pcrs: []uint32{7}}}}, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, handle.file.Close()) }()
	if handle.node.Device != graph.backing {
		return nil, ErrConflict
	}
	var custody unix.Stat_t
	if err := unix.Fstat(int(handle.file.Fd()), &custody); err != nil {
		return nil, err
	}
	if custody.Uid != 0 {
		return nil, ErrConflict
	}
	uuid, err := p.crypt(ctx, handle.file, []string{"luksUUID", descriptor(0)})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(uuid)) != target.GetLuksUuid() {
		return nil, ErrConflict
	}
	metadata, hash, err := p.metadata(ctx, handle.file)
	if err != nil {
		return nil, err
	}
	result.LUKSRoot = true
	result.Target = target
	result.Reason = ""
	result.MetadataSHA256 = hash
	for _, token := range metadata.Tokens {
		if token.Type != "lindm-recovery" || len(token.Keyslots) != 1 || token.ActionID == "" {
			continue
		}
		key, err := hex.DecodeString(token.KeySHA256)
		if err != nil || len(key) != sha256.Size {
			continue
		}
		slot, err := slotNumber(token.Keyslots[0])
		if err != nil {
			continue
		}
		result.Recovery = append(result.Recovery, RootRecoveryEvidence{ActionID: token.ActionID, Keyslot: slot, KeySHA256: key})
	}
	ids := make([]string, 0, len(metadata.Tokens))
	for id := range metadata.Tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		token := metadata.Tokens[id]
		if !complianceTPMToken(token) {
			continue
		}
		var tpm unix.Stat_t
		if err := unix.Stat("/dev/tpmrm0", &tpm); err != nil || tpm.Mode&unix.S_IFMT != unix.S_IFCHR {
			continue
		}
		if p.testComplianceTPMToken(ctx, handle.file, id, token) {
			result.TPMBound = true
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, afterHash, err := p.metadata(ctx, handle.file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hash, afterHash) {
		return nil, ErrConflict
	}
	finalUUID, err := p.crypt(ctx, handle.file, []string{"luksUUID", descriptor(0)})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(finalUUID)) != target.GetLuksUuid() {
		return nil, ErrConflict
	}
	var afterRoot unix.Stat_t
	if err := unix.Stat("/", &afterRoot); err != nil {
		return nil, err
	}
	if afterRoot.Dev != st.Dev {
		return nil, ErrConflict
	}
	afterGraph, err := rootEncryptionGraph(fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)), readSysfsIdentityFile, os.ReadDir)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(graph.facts, afterGraph.facts) {
		return nil, ErrConflict
	}
	afterTable, err := p.complianceCryptTable(ctx, afterGraph)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tableHash, afterTable) {
		return nil, ErrConflict
	}
	identity, err := (proto.MarshalOptions{Deterministic: true}).Marshal(target)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	digest.Write(graphHash[:])
	digest.Write(hash)
	digest.Write(identity)
	digest.Write(tableHash)
	if result.TPMBound {
		digest.Write([]byte{1})
	} else {
		digest.Write([]byte{0})
	}
	result.NativeSHA256 = digest.Sum(nil)
	slices.SortFunc(result.Recovery, func(a, b RootRecoveryEvidence) int { return strings.Compare(a.ActionID, b.ActionID) })
	return result, nil
}
func (p *Provider) testComplianceTPMToken(ctx context.Context, file *os.File, id string, token luksToken) bool {
	if !complianceTPMToken(token) {
		return false
	}
	if _, err := slotNumber(id); err != nil {
		return false
	}
	_, err := p.crypt(ctx, file, []string{"open", "--type", "luks2", "--test-passphrase", "--token-only", "--token-id", id, "--key-slot", token.Keyslots[0], descriptor(0)})
	return err == nil
}
func complianceTPMToken(token luksToken) bool {
	if token.Type != "systemd-tpm2" || len(token.Keyslots) != 1 || len(token.PCRs) == 0 || len(token.PCRs) > 24 {
		return false
	}
	var seen [24]bool
	for _, pcr := range token.PCRs {
		if pcr >= 24 || seen[pcr] {
			return false
		}
		seen[pcr] = true
	}
	_, err := strconv.ParseUint(token.Keyslots[0], 10, 5)
	return err == nil
}
func complianceTarget(nodes []blockNode, g *complianceGraph, native func(string) sysfsBlockIdentity) (*agentv1.StorageTarget, error) {
	var result *agentv1.StorageTarget
	var visit func([]blockNode, *blockNode) error
	visit = func(nodes []blockNode, disk *blockNode) error {
		for i := range nodes {
			n := &nodes[i]
			parent := disk
			if n.Type == "disk" {
				if resolveBlockIdentity(n, native(n.Device)) != "" {
					return ErrConflict
				}
				parent = n
			}
			if n.Device == g.backing {
				if result != nil || parent == nil || n.Filesystem != "crypto_LUKS" || n.UUID != g.cryptUUID || parent.Serial == "" || n.Size == 0 || filepath.Dir(n.Path) != "/dev" {
					return ErrUnsupported
				}
				result = &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: n.UUID, Wwn: parent.WWN, Serial: parent.Serial, SizeBytes: n.Size}
				if parent.WWN == "" {
					if n.Type != "part" || parent.PartitionTable != "gpt" || parent.DiskGUID == "" || parent.Size < n.Size || !absentNativeWWN(native(parent.Device)) {
						return ErrUnsupported
					}
					result.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS
					result.GptDiskGuid = parent.DiskGUID
					result.DiskSizeBytes = parent.Size
				}
			}
			if err := visit(n.Children, parent); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(nodes, nil); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrUnsupported
	}
	selected, _, diagnostic := resolveTargetIdentity(nodes, result, false, native)
	if diagnostic.MatchCount != 1 || selected.Device != g.backing {
		return nil, ErrConflict
	}
	return result, nil
}

// Query the complete selected table, not --target crypt filtering: filtering
// could conceal a linear/plaintext segment alongside one crypt segment. Default
// dmsetup output masks keys. Neither table text nor key references are published.
func (p *Provider) complianceCryptTable(ctx context.Context, g *complianceGraph) ([]byte, error) {
	major, minor, ok := strings.Cut(g.mappingDevice, ":")
	if !ok {
		return nil, ErrConflict
	}
	raw, err := p.run(ctx, nativeRequest{command: dmsetup, args: []string{"table", "--major", major, "--minor", minor}})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	size, err := readSysfsIdentityFile("/sys/dev/block/" + g.mappingDevice + "/size")
	if err != nil {
		return nil, err
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(size)), 10, 64)
	if err != nil || sectors == 0 {
		return nil, ErrConflict
	}
	if !complianceCryptTableMatches(raw, g.backing, sectors) {
		return nil, ErrConflict
	}
	hash := sha256.Sum256(raw)
	return hash[:], nil
}
func complianceCryptTableMatches(raw []byte, backing string, sectors uint64) bool {
	line := strings.TrimSpace(string(raw))
	if len(line) == 0 || strings.ContainsAny(line, "\n\r") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.HasSuffix(fields[0], ":") {
		fields = fields[1:]
	}
	if len(fields) < 8 || fields[0] != "0" || fields[2] != "crypt" || strings.Contains(fields[3], "null") || fields[6] != backing {
		return false
	}
	length, err := strconv.ParseUint(fields[1], 10, 64)
	return err == nil && length == sectors
}

// RootEncryptionReadDevices derives the transient read helper's exact host device
// allowlist using only stat("/") and bounded kernel sysfs facts. It performs no
// /dev opens, ioctls or native commands in the resident executor's sandbox.
// The helper must independently re-observe root topology and pin native identity;
// this list is confinement, not evidence of encryption or authority for effects.
func RootEncryptionReadDevices(ctx context.Context) ([]string, error) {
	if ctx == nil {
		return nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var root unix.Stat_t
	if err := unix.Stat("/", &root); err != nil {
		return nil, err
	}
	graph, err := rootEncryptionGraph(fmt.Sprintf("%d:%d", unix.Major(root.Dev), unix.Minor(root.Dev)), readSysfsIdentityFile, os.ReadDir)
	if err != nil {
		return nil, err
	}
	if graph.cryptUUID != "" {
		graph.backingDisk, err = complianceParentDisk(graph.backing, readSysfsIdentityFile, filepath.EvalSymlinks)
		if err != nil {
			return nil, err
		}
	}
	devices, err := complianceReadDevices(graph, readSysfsIdentityFile)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return devices, err
}

func complianceReadDevices(graph *complianceGraph, read func(string) ([]byte, error)) ([]string, error) {
	if graph.cryptUUID == "" {
		return nil, nil
	}
	if !canonicalBlockDeviceNumber(graph.backing) {
		return nil, ErrConflict
	}
	raw, err := read("/sys/dev/block/" + graph.backing + "/uevent")
	if err != nil {
		return nil, err
	}
	name, device, err := complianceDeviceUevent(raw)
	if err != nil {
		return nil, err
	}
	if device != graph.backing || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrConflict
	}
	devices := []string{"/dev/" + name, "/dev/mapper/control"}
	if graph.backingDisk != "" {
		if !canonicalBlockDeviceNumber(graph.backingDisk) || graph.backingDisk == graph.backing {
			return nil, ErrConflict
		}
		diskRaw, err := read("/sys/dev/block/" + graph.backingDisk + "/uevent")
		if err != nil {
			return nil, err
		}
		diskName, diskDevice, err := complianceDeviceUevent(diskRaw)
		if err != nil {
			return nil, err
		}
		if diskDevice != graph.backingDisk || diskName == name || filepath.Base(diskName) != diskName || diskName == "." || diskName == ".." {
			return nil, ErrConflict
		}
		devices = append(devices, "/dev/"+diskName)
	}
	raw, err = read("/sys/class/tpmrm/tpmrm0/uevent")
	if errors.Is(err, os.ErrNotExist) {
		return devices, nil
	}
	if err != nil {
		return nil, err
	}
	name, _, err = complianceDeviceUevent(raw)
	if err != nil {
		return nil, err
	}
	if name != "tpmrm0" {
		return nil, ErrConflict
	}
	return append(devices, "/dev/tpmrm0"), nil
}

func complianceDeviceUevent(raw []byte) (string, string, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return "", "", ErrUnsupported
	}
	fields := make(map[string]string, 3)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", "", ErrConflict
		}
		if key != "DEVNAME" && key != "MAJOR" && key != "MINOR" {
			continue
		}
		if _, seen := fields[key]; seen {
			return "", "", ErrConflict
		}
		fields[key] = value
	}
	name := fields["DEVNAME"]
	device := fields["MAJOR"] + ":" + fields["MINOR"]
	if name == "" || !canonicalBlockDeviceNumber(device) {
		return "", "", ErrConflict
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return "", "", ErrConflict
		}
	}
	return name, device, nil
}

func complianceParentDisk(device string, read func(string) ([]byte, error), resolve func(string) (string, error)) (string, error) {
	if !canonicalBlockDeviceNumber(device) {
		return "", ErrConflict
	}
	base := "/sys/dev/block/" + device
	partition, err := read(base + "/partition")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	number, err := strconv.ParseUint(strings.TrimSpace(string(partition)), 10, 32)
	if err != nil || number == 0 {
		return "", ErrConflict
	}
	canonical, err := resolve(base)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(canonical, "/sys/devices/") || filepath.Clean(canonical) != canonical {
		return "", ErrConflict
	}
	raw, err := read(filepath.Dir(canonical) + "/dev")
	if err != nil {
		return "", err
	}
	parent := strings.TrimSpace(string(raw))
	if !canonicalBlockDeviceNumber(parent) || parent == device {
		return "", ErrConflict
	}
	if _, err := read("/sys/dev/block/" + parent + "/partition"); !errors.Is(err, os.ErrNotExist) {
		return "", ErrConflict
	}
	return parent, nil
}
