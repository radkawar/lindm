//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"reflect"
	"strings"

	"github.com/google/uuid"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

type nativeBlock struct {
	Name          string        `json:"name"`
	KernelName    string        `json:"kname"`
	Type          string        `json:"type"`
	Size          json.Number   `json:"size"`
	FSType        *string       `json:"fstype"`
	FSTypePresent bool          `json:"-"`
	FSVersion     *string       `json:"fsver"`
	UUID          *string       `json:"uuid"`
	PartUUID      *string       `json:"partuuid"`
	PartType      *string       `json:"parttype"`
	PTType        *string       `json:"pttype"`
	PTUUID        *string       `json:"ptuuid"`
	Transport     *string       `json:"tran"`
	Model         *string       `json:"model"`
	Serial        *string       `json:"serial"`
	WWN           *string       `json:"wwn"`
	Revision      *string       `json:"rev"`
	Mountpoint    *string       `json:"mountpoint"`
	Mountpoints   []*string     `json:"mountpoints"`
	Parent        *string       `json:"pkname"`
	Children      []nativeBlock `json:"children"`
}

func (n *nativeBlock) UnmarshalJSON(data []byte) error {
	type blockFields nativeBlock
	fields := struct {
		*blockFields
		FSType json.RawMessage `json:"fstype"`
	}{blockFields: (*blockFields)(n)}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	n.FSTypePresent = fields.FSType != nil
	if !n.FSTypePresent {
		return nil
	}
	return json.Unmarshal(fields.FSType, &n.FSType)
}

type storageGraph struct {
	order   []string
	nodes   map[string]nativeBlock
	parents map[string]map[string]bool
}

func nullableText(value *string) *inventoryv1.ObservedString {
	if value == nil {
		return observed("", nil)
	}
	return observed(*value, nil)
}

func storageName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 256 && !strings.ContainsAny(name, "/\x00\r\n")
}

func readStorageGraph(reader io.Reader) (*storageGraph, inventoryv1.CollectionStatus) {
	var native struct {
		Devices []nativeBlock `json:"blockdevices"`
	}
	if status := decodeNative(reader, &native); status != success {
		return nil, status
	}
	if native.Devices == nil {
		return nil, invalid
	}
	g := &storageGraph{nodes: make(map[string]nativeBlock), parents: make(map[string]map[string]bool)}
	occurrences := 0
	var visit func([]nativeBlock, string) inventoryv1.CollectionStatus
	visit = func(nodes []nativeBlock, parent string) inventoryv1.CollectionStatus {
		for _, n := range nodes {
			occurrences++
			if occurrences > 1024 {
				return capacity
			}
			if !storageName(n.Name) || (n.KernelName != "" && !storageName(n.KernelName)) || observed(n.Type, nil).Status != success {
				return invalid
			}
			if _, err := decimal(n.Size.String()); err != nil {
				return invalid
			}
			children, declaredParent := n.Children, n.Parent
			n.Children, n.Parent = nil, nil
			if previous, exists := g.nodes[n.Name]; exists {
				if !reflect.DeepEqual(previous, n) {
					return invalid
				}
			} else {
				if len(g.order) == 256 {
					return capacity
				}
				g.order = append(g.order, n.Name)
				g.nodes[n.Name] = n
				g.parents[n.Name] = make(map[string]bool)
			}
			if parent != "" {
				if declaredParent != nil && *declaredParent != "" && *declaredParent != parent && *declaredParent != g.nodes[parent].KernelName {
					return invalid
				}
				g.parents[n.Name][parent] = true
			} else if declaredParent != nil && *declaredParent != "" {
				if !storageName(*declaredParent) {
					return invalid
				}
				g.parents[n.Name][*declaredParent] = true
			}
			if status := visit(children, n.Name); status != success {
				return status
			}
		}
		return success
	}
	if status := visit(native.Devices, ""); status != success {
		return nil, status
	}
	// PKNAME is a kernel name on some util-linux releases, while NAME may be
	// a device-mapper alias. Resolve only names actually present in this snapshot.
	aliases := make(map[string]string, len(g.nodes))
	for name, n := range g.nodes {
		if n.KernelName == "" {
			continue
		}
		if prior, ok := aliases[n.KernelName]; ok && prior != name {
			return nil, invalid
		}
		aliases[n.KernelName] = name
	}
	for _, parents := range g.parents {
		for parent := range parents {
			if _, ok := g.nodes[parent]; ok {
				continue
			}
			if name, ok := aliases[parent]; ok {
				delete(parents, parent)
				parents[name] = true
			}
		}
	}
	return g, success
}

func (g *storageGraph) ancestors(name string, active, visited map[string]bool) (bool, bool) {
	if active[name] {
		return false, false
	}
	if visited[name] {
		return true, true
	}
	if _, ok := g.nodes[name]; !ok {
		return true, false
	}
	active[name], visited[name] = true, true
	complete := true
	for parent := range g.parents[name] {
		acyclic, known := g.ancestors(parent, active, visited)
		if !acyclic {
			return false, false
		}
		complete = complete && known
	}
	delete(active, name)
	return true, complete
}

func (g *storageGraph) observation() *inventoryv1.StorageDetails {
	result := &inventoryv1.StorageDetails{Status: success}
	rootAncestors := make(map[string]bool)
	rootKnown, topologyComplete := false, true
	ancestors := make(map[string]map[string]bool, len(g.nodes))
	complete := make(map[string]bool, len(g.nodes))
	for _, name := range g.order {
		seen := make(map[string]bool)
		acyclic, known := g.ancestors(name, make(map[string]bool), seen)
		if !acyclic {
			return &inventoryv1.StorageDetails{Status: invalid}
		}
		ancestors[name], complete[name] = seen, known
		topologyComplete = topologyComplete && known
		n := g.nodes[name]
		mounts := n.Mountpoints
		if n.Mountpoint != nil {
			mounts = append(append([]*string(nil), mounts...), n.Mountpoint)
		}
		for _, mount := range mounts {
			if mount != nil && *mount == "/" {
				rootKnown = true
				for ancestor := range seen {
					rootAncestors[ancestor] = true
				}
			}
		}
	}
	for _, name := range g.order {
		n := g.nodes[name]
		size, _ := decimal(n.Size.String()) // Validated before constructing any rows.
		identity := &inventoryv1.StorageIdentity{
			Transport: nullableText(n.Transport), Model: nullableText(n.Model), Serial: nullableText(n.Serial),
			Firmware: nullableText(n.Revision), Wwn: nullableText(n.WWN), Eui: observed("", nil),
			PartitionUuid: nullableText(n.PartUUID), PartitionType: nullableText(n.PartType), FilesystemUuid: nullableText(n.UUID),
			LuksUuid: observed("", nil), LuksVersion: observed("", nil),
			LuksKeyslotCount: number(0, fs.ErrNotExist), LuksTokenCount: number(0, fs.ErrNotExist), LuksTokenTypes: observed("", nil),
			BackingDisk: observed("", nil), RootBacking: boolean(false, fs.ErrNotExist), Nvme: &inventoryv1.ObservedNVMeScope{Status: unavailable},
			GptDiskGuid: observed("", nil),
		}
		if n.Type == "disk" && n.PTType != nil && *n.PTType == "gpt" {
			identity.GptDiskGuid = nullableText(n.PTUUID)
			if identity.GptDiskGuid.Status == success {
				if guid, err := uuid.Parse(identity.GptDiskGuid.Value); err != nil || guid == uuid.Nil {
					identity.GptDiskGuid = observed("", errInvalid)
				}
			}
		}
		if rootKnown && topologyComplete {
			identity.RootBacking = boolean(rootAncestors[name], nil)
		}
		var disk string
		for ancestor := range ancestors[name] {
			if g.nodes[ancestor].Type != "disk" {
				continue
			}
			if disk != "" {
				disk = ""
				break
			}
			disk = ancestor
		}
		if complete[name] {
			identity.BackingDisk = observed(disk, nil)
		}
		encryption := observed("", nil)
		// Explicit native null is no known signature. An omitted source field
		// is not evidence of unencrypted storage.
		if n.FSTypePresent {
			encryption = observed("none", nil)
		}
		for ancestor := range ancestors[name] {
			if ancestor != name && g.nodes[ancestor].Type == "crypt" {
				encryption = observed("inherited-dm-crypt", nil)
			}
		}
		if !complete[name] {
			encryption = observed("", nil)
		}
		if n.Type == "crypt" {
			encryption = observed("dm-crypt", nil)
		}
		if n.FSType != nil && *n.FSType == "crypto_LUKS" {
			encryption = observed("luks", nil)
			identity.LuksUuid, identity.LuksVersion = nullableText(n.UUID), nullableText(n.FSVersion)
			identity.FilesystemUuid = observed("", nil)
		}
		parent := observed("", nil)
		if len(g.parents[name]) == 1 {
			for p := range g.parents[name] {
				parent = observed(p, nil)
			}
		}
		mountpoint := nullableText(n.Mountpoint)
		for _, mount := range n.Mountpoints {
			if mount != nil && *mount != "" && (mountpoint.Status != success || *mount == "/") {
				mountpoint = nullableText(mount)
			}
		}
		result.Devices = append(result.Devices, &inventoryv1.BlockDevice{Name: name, Type: observed(n.Type, nil), Parent: parent, SizeBytes: number(size, nil), Filesystem: nullableText(n.FSType), Mountpoint: mountpoint, Encryption: encryption, Identity: identity})
	}
	inheritStorageIdentity(result)
	return result
}

// Match the action provider: inherit only missing disk identifiers, never size.
func inheritStorageIdentity(result *inventoryv1.StorageDetails) {
	byName := make(map[string]*inventoryv1.BlockDevice, len(result.Devices))
	for _, device := range result.Devices {
		byName[device.Name] = device
	}
	for _, device := range result.Devices {
		id := device.Identity
		disk := byName[id.BackingDisk.Value]
		if disk == nil || disk == device {
			continue
		}
		for _, field := range []struct {
			dst **inventoryv1.ObservedString
			src *inventoryv1.ObservedString
		}{
			{&id.Serial, disk.Identity.Serial}, {&id.Wwn, disk.Identity.Wwn},
			{&id.Transport, disk.Identity.Transport}, {&id.Model, disk.Identity.Model},
			{&id.Firmware, disk.Identity.Firmware}, {&id.Eui, disk.Identity.Eui},
			{&id.GptDiskGuid, disk.Identity.GptDiskGuid},
		} {
			if (*field.dst).Status == unavailable {
				*field.dst = field.src
			}
		}
	}
}

func parseStorage(reader io.Reader) *inventoryv1.StorageDetails {
	graph, status := readStorageGraph(reader)
	if status != success {
		return &inventoryv1.StorageDetails{Status: status}
	}
	return graph.observation()
}

func collectStorage(ctx context.Context, s detailSources) *inventoryv1.StorageDetails {
	var graph *storageGraph
	status := s.run(ctx, backend{name: "lsblk", path: "/usr/bin/lsblk", args: []string{"--json", "--bytes", "--tree", "--output", "NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,UUID,PARTUUID,PARTTYPE,PTTYPE,PTUUID,TRAN,MODEL,SERIAL,WWN,REV,MOUNTPOINTS,PKNAME"}}, func(reader io.Reader) inventoryv1.CollectionStatus {
		var parsedStatus inventoryv1.CollectionStatus
		graph, parsedStatus = readStorageGraph(reader)
		return parsedStatus
	})
	if status != success {
		return &inventoryv1.StorageDetails{Status: status}
	}
	result := graph.observation()
	if result.Status != success {
		return result
	}
	for _, device := range result.Devices {
		n := graph.nodes[device.Name]
		kernelName := n.KernelName
		if kernelName == "" {
			kernelName = n.Name
		}
		if device.Type.Value == "disk" && s.readFile != nil {
			collectDiskFallback(ctx, s, kernelName, device.Identity)
		}
		if device.Filesystem.Value == "crypto_LUKS" {
			collectLUKS(ctx, s, kernelName, device.Identity)
		}
	}
	inheritStorageIdentity(result)
	for _, device := range result.Devices {
		if device.Type.Value == "disk" && device.Identity.Transport.Value == "nvme" {
			name := graph.nodes[device.Name].KernelName
			if name == "" {
				name = device.Name
			}
			device.Identity.Nvme = collectNVMeScope(ctx, s, name, device)
		}
	}
	return result
}
