//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func storageTruthIdentity(fields map[string]string) *inventoryv1.StorageIdentity {
	id := &inventoryv1.StorageIdentity{
		Transport: truthString(strings.TrimSpace(fields["TRAN"])), Model: truthString(strings.TrimSpace(fields["MODEL"])),
		Serial: truthString(strings.TrimSpace(fields["SERIAL"])), Firmware: truthString(strings.TrimSpace(fields["REV"])), Wwn: truthString(fields["WWN"]), Eui: truthString(""),
		PartitionUuid: truthString(fields["PARTUUID"]), PartitionType: truthString(fields["PARTTYPE"]), FilesystemUuid: truthString(fields["UUID"]),
		LuksUuid: truthString(""), LuksVersion: truthString(""), LuksTokenTypes: truthString(""),
		LuksKeyslotCount: &inventoryv1.ObservedUint64{Status: truthUnavailable}, LuksTokenCount: &inventoryv1.ObservedUint64{Status: truthUnavailable},
		BackingDisk: truthString(""), RootBacking: &inventoryv1.ObservedBool{Status: truthUnavailable}, Nvme: &inventoryv1.ObservedNVMeScope{Status: truthUnavailable},
		GptDiskGuid: truthString(""),
	}
	if fields["TYPE"] == "disk" && fields["PTTYPE"] == "gpt" {
		id.GptDiskGuid = truthString(fields["PTUUID"])
		if id.GptDiskGuid.Status == truthSuccess {
			if guid, err := uuid.Parse(id.GptDiskGuid.Value); err != nil || guid == uuid.Nil {
				id.GptDiskGuid = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT}
			}
		}
	}
	if fields["FSTYPE"] == "crypto_LUKS" {
		id.LuksUuid, id.LuksVersion, id.FilesystemUuid = truthString(fields["UUID"]), truthString(fields["FSVER"]), truthString("")
	}
	return id
}

// Independent oracle uses lsblk's pairs presentation, sysfs and native tools,
// never the agent parser or the action provider's identity implementation.
func (o vmInventoryOracle) storageIdentities(storage *inventoryv1.StorageDetails, pairs []byte) error {
	byName := make(map[string]*inventoryv1.BlockDevice, len(storage.Devices))
	kernel := make(map[string]string, len(storage.Devices))
	for _, device := range storage.Devices {
		byName[device.Name] = device
	}
	lines, err := truthLines(pairs)
	if err != nil {
		return err
	}
	for _, line := range lines {
		fields, err := parseTruthPairs(line)
		if err != nil {
			return err
		}
		kernel[fields["NAME"]] = fields["KNAME"]
	}
	root := make(map[string]bool)
	rootKnown := false
	for _, device := range storage.Devices {
		if device.Mountpoint.Value != "/" {
			continue
		}
		rootKnown = true
		for current, count := device, 0; current != nil; count++ {
			if count >= len(storage.Devices) {
				return errors.New("cyclic storage identity oracle")
			}
			root[current.Name] = true
			current = byName[current.Parent.Value]
		}
	}
	for _, device := range storage.Devices {
		id := device.Identity
		if rootKnown {
			id.RootBacking = truthBool(root[device.Name])
		}
		if device.Type.Value == "disk" {
			id.BackingDisk = truthString(device.Name)
			if err := o.storageDiskIdentity(kernel[device.Name], id); err != nil {
				return err
			}
		}
		if device.Filesystem.Value == "crypto_LUKS" {
			if err := o.storageLUKSIdentity(kernel[device.Name], id); err != nil {
				return err
			}
		}
	}
	for _, device := range storage.Devices {
		if device.Type.Value == "disk" {
			continue
		}
		for current, count := byName[device.Parent.Value], 0; current != nil; count++ {
			if count >= len(storage.Devices) {
				return errors.New("cyclic storage identity oracle")
			}
			if current.Type.Value == "disk" {
				id, disk := device.Identity, current.Identity
				id.BackingDisk = truthString(current.Name)
				for _, pair := range []struct {
					dst **inventoryv1.ObservedString
					src *inventoryv1.ObservedString
				}{
					{&id.Transport, disk.Transport}, {&id.Model, disk.Model}, {&id.Serial, disk.Serial}, {&id.Wwn, disk.Wwn}, {&id.Firmware, disk.Firmware}, {&id.Eui, disk.Eui},
					{&id.GptDiskGuid, disk.GptDiskGuid},
				} {
					if (*pair.dst).Status == truthUnavailable {
						*pair.dst = pair.src
					}
				}
				break
			}
			current = byName[current.Parent.Value]
		}
	}
	return nil
}

func (o vmInventoryOracle) storageDiskIdentity(name string, id *inventoryv1.StorageIdentity) error {
	if name == "" || strings.ContainsAny(name, "/\x00\r\n") {
		return errors.New("invalid storage kernel name oracle")
	}
	base := "/sys/class/block/" + name + "/"
	for _, field := range []struct {
		dst   **inventoryv1.ObservedString
		paths []string
	}{
		{&id.Firmware, []string{"device/firmware_rev", "device/rev"}}, {&id.Eui, []string{"eui"}}, {&id.Transport, []string{"device/transport"}},
	} {
		if (*field.dst).Status != truthUnavailable {
			continue
		}
		for _, path := range field.paths {
			value, err := o.file(base + path)
			if err != nil {
				return err
			}
			if value.Status != truthUnavailable {
				*field.dst = value
				break
			}
		}
	}
	if id.Transport.Status == truthUnavailable {
		uevent, err := o.file(base + "device/uevent")
		if err != nil {
			return err
		}
		if uevent.Status == truthSuccess && strings.Contains("\n"+uevent.Value+"\n", "\nDRIVER=virtio_blk\n") {
			id.Transport = truthString("virtio")
		}
	}
	if id.Transport.Status == truthUnavailable || id.Firmware.Status == truthUnavailable {
		data, status, err := o.optional("udevadm", "udevadm info --query=property --path="+nativeQuote(strings.TrimSuffix(base, "/")))
		if err != nil {
			return err
		}
		values := make(map[string]string)
		for line := range strings.SplitSeq(string(data), "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				values[key] = value
			}
		}
		for _, field := range []struct {
			dst **inventoryv1.ObservedString
			key string
		}{{&id.Transport, "ID_BUS"}, {&id.Firmware, "ID_REVISION"}} {
			if (*field.dst).Status != truthUnavailable {
				continue
			}
			if status == truthSuccess {
				*field.dst = truthString(values[field.key])
			} else {
				*field.dst = &inventoryv1.ObservedString{Status: status}
			}
		}
	}
	if id.Transport.Value == "nvme" {
		scope, err := o.storageNVMeIdentity(name, id)
		if err != nil {
			return err
		}
		id.Nvme = scope
	}
	return nil
}

func (o vmInventoryOracle) storageLUKSIdentity(name string, id *inventoryv1.StorageIdentity) error {
	if name == "" || strings.ContainsAny(name, "/\x00\r\n") {
		return errors.New("invalid LUKS kernel name oracle")
	}
	readable, err := o.storageBlockReadable(name)
	if err != nil {
		return err
	}
	var data []byte
	status := truthDenied
	if readable {
		data, status, err = o.optional("cryptsetup", "sudo -n cryptsetup luksDump "+nativeQuote("/dev/"+name))
		if err != nil {
			return err
		}
	}
	if status != truthSuccess {
		truthLUKSUnobserved(id, status)
		return nil
	}
	var slots, tokens uint64
	var types []string
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "UUID:") && strings.TrimSpace(strings.TrimPrefix(line, "UUID:")) != id.LuksUuid.Value {
			return errors.New("LUKS UUID oracle changed")
		}
		if strings.HasPrefix(line, "Version:") {
			id.LuksVersion = truthString(strings.TrimSpace(strings.TrimPrefix(line, "Version:")))
		}
		switch line {
		case "Keyslots:":
			section = "slots"
			continue
		case "Tokens:":
			section = "tokens"
			continue
		}
		if strings.HasPrefix(line, "Key Slot ") && strings.HasSuffix(line, ": ENABLED") {
			slots++
		}
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			section = ""
			continue
		}
		if !strings.HasPrefix(line, "  ") || len(line) < 3 || line[2] < '0' || line[2] > '9' {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			return errors.New("malformed LUKS public summary oracle")
		}
		if section == "slots" {
			slots++
		}
		if section == "tokens" {
			tokens++
			types = append(types, strings.TrimSpace(value))
		}
	}
	id.LuksKeyslotCount = truthUint(slots)
	if id.LuksVersion.Value == "2" {
		sort.Strings(types)
		id.LuksTokenCount = truthUint(tokens)
		id.LuksTokenTypes = truthString(strings.Join(types, ","))
	}
	return nil
}

// truthLUKSUnobserved records a failed header read on the header fields and on
// any LUKS UUID/version lsblk did not supply (legacy lsblk has no FSVER).
func truthLUKSUnobserved(id *inventoryv1.StorageIdentity, status inventoryv1.CollectionStatus) {
	id.LuksKeyslotCount = &inventoryv1.ObservedUint64{Status: status}
	id.LuksTokenCount = &inventoryv1.ObservedUint64{Status: status}
	id.LuksTokenTypes = &inventoryv1.ObservedString{Status: status}
	for _, field := range []*inventoryv1.ObservedString{id.LuksUuid, id.LuksVersion} {
		if field.Status == truthUnavailable {
			field.Status = status
		}
	}
}

// Storage identity oracles match the inspected agent's root privilege; an
// unprivileged probe would only observe its own permission failure.
func (o vmInventoryOracle) storageBlockReadable(name string) (bool, error) {
	data, err := o.command("if sudo -n test -r " + nativeQuote("/dev/"+name) + "; then printf yes; else printf no; fi")
	return string(data) == "yes", err
}

func (o vmInventoryOracle) storageNVMeIdentity(name string, id *inventoryv1.StorageIdentity) (*inventoryv1.ObservedNVMeScope, error) {
	result := &inventoryv1.ObservedNVMeScope{Status: truthUnavailable}
	readable, err := o.storageBlockReadable(name)
	if err != nil {
		return nil, err
	}
	if !readable {
		result.Status = truthDenied
		return result, nil
	}
	device := nativeQuote("/dev/" + name)
	data, status, err := o.optional("nvme", "sudo -n nvme id-ctrl --output-format=json "+device)
	if err != nil {
		return nil, err
	}
	if status != truthSuccess {
		result.Status = status
		return result, nil
	}
	var controller struct {
		VID      uint32 `json:"vid"`
		SSVID    uint32 `json:"ssvid"`
		Serial   string `json:"sn"`
		Model    string `json:"mn"`
		Firmware string `json:"fr"`
	}
	if err := json.Unmarshal(data, &controller); err != nil {
		return nil, errors.New("invalid NVMe controller oracle")
	}
	data, err = o.command("sudo -n nvme id-ns --output-format=json " + device)
	if err != nil {
		return nil, err
	}
	var namespace struct {
		Size    uint64 `json:"nsze"`
		Format  uint32 `json:"flbas"`
		NGUID   string `json:"nguid"`
		EUI     string `json:"eui64"`
		Formats []struct {
			Shift uint32 `json:"ds"`
		} `json:"lbafs"`
	}
	if err := json.Unmarshal(data, &namespace); err != nil {
		return nil, errors.New("invalid NVMe namespace oracle")
	}
	nsid, err := o.file("/sys/class/block/" + name + "/nsid")
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(nsid.Value, 10, 32)
	if err != nil || n == 0 || namespace.Format >= uint32(len(namespace.Formats)) {
		return nil, errors.New("invalid NVMe namespace identity oracle")
	}
	shift := namespace.Formats[namespace.Format].Shift
	if shift < 9 || shift > 12 || namespace.Size > ^uint64(0)>>shift {
		return nil, errors.New("unsupported NVMe geometry oracle")
	}
	basis := agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID
	serial, model := strings.TrimSpace(controller.Serial), strings.TrimSpace(controller.Model)
	fallback := fmt.Sprintf("nvme.%04x-%x-%x-%08x", controller.VID, serial, model, n)
	wwns := []string{"eui." + namespace.EUI, "eui." + namespace.NGUID}
	sort.Strings(wwns)
	if id.Wwn.Value == fallback || (id.Wwn.Value == "" && strings.Trim(namespace.EUI+namespace.NGUID, "0") == "") {
		basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
	} else if id.Wwn.Value != wwns[0] && id.Wwn.Value != wwns[1] {
		return nil, errors.New("NVMe namespace NID oracle mismatch")
	}
	result.Status = truthSuccess
	result.Scope = &agentv1.NVMeSanitizeScope{NamespaceId: uint32(n), Identity: &agentv1.NVMeSanitizeIdentity{Basis: basis, VendorId: controller.VID, SubsystemVendorId: controller.SSVID, ControllerSerial: serial, ControllerModel: model, ControllerFirmware: strings.TrimSpace(controller.Firmware), NamespaceSizeBytes: namespace.Size << shift, LbaFormat: namespace.Format, LbaDataSizeShift: shift}}
	return result, nil
}
