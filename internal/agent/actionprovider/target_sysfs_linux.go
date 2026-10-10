//go:build linux

package actionprovider

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

type sysfsIdentityValue struct {
	Value string `json:"value"`
	Error string `json:"error,omitempty"`
}

type sysfsBlockIdentity struct {
	WWID       sysfsIdentityValue `json:"wwid"`
	DeviceWWID sysfsIdentityValue `json:"device_wwid"`
	Serial     sysfsIdentityValue `json:"device_serial"`
	VPDSerial  sysfsIdentityValue `json:"vpd_pg80_serial"`
}

func nativeBlockIdentity(device string) sysfsBlockIdentity {
	return readSysfsBlockIdentity(device, readSysfsIdentityFile)
}

// lsblk's WWN column comes from the udev database, which does not exist in the
// recovery initramfs. Linux exposes the same NVMe WWID directly and the SCSI
// NAA/EUI bytes with a different, explicit prefix. Do not invent an identity
// from a device pathname, a serial alone, or the approved tuple.
func resolveBlockIdentity(node *blockNode, identity sysfsBlockIdentity) string {
	wwn := identity.WWID.Value
	if deviceWWN := scsiWWN(identity.DeviceWWID.Value); deviceWWN != "" {
		if wwn != "" && wwn != deviceWWN {
			return "native_wwn_conflict"
		}
		wwn = deviceWWN
	}
	serial := identity.Serial.Value
	if identity.VPDSerial.Value != "" {
		if serial != "" && serial != identity.VPDSerial.Value {
			return "native_serial_conflict"
		}
		serial = identity.VPDSerial.Value
	}
	if wwn != "" && node.WWN != "" && wwn != node.WWN {
		return "lsblk_native_wwn_conflict"
	}
	if identity.WWID.Value != "" && identity.Serial.Value != "" {
		// Without udev, lsblk prints the padded NVMe sysfs serial verbatim.
		// Canonicalize only the fixed-width trailing ASCII spaces, exactly as
		// nvmeASCII does, and only against independently read native evidence.
		node.Serial = strings.TrimRight(node.Serial, " ")
	}
	if serial != "" && node.Serial != "" && serial != node.Serial {
		return "lsblk_native_serial_conflict"
	}
	if node.WWN == "" {
		node.WWN = wwn
	}
	if node.Serial == "" {
		node.Serial = serial
	}
	node.nativeWWN = node.nativeWWN || wwn != ""
	node.nativeSerial = node.nativeSerial || serial != ""
	return ""
}

func sameNativeBlockIdentity(node blockNode, evidence sysfsBlockIdentity) bool {
	observed := node
	if node.nativeWWN {
		observed.WWN = ""
	}
	if node.nativeSerial {
		observed.Serial = ""
	}
	return resolveBlockIdentity(&observed, evidence) == "" && observed.WWN == node.WWN && observed.Serial == node.Serial
}

func scsiWWN(wwid string) string {
	hex, ok := strings.CutPrefix(wwid, "naa.")
	if !ok {
		hex, ok = strings.CutPrefix(wwid, "eui.")
	}
	if !ok || len(hex) != 16 && len(hex) != 32 {
		return ""
	}
	for _, b := range []byte(hex) {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return ""
		}
	}
	return "0x" + hex
}

// Sysfs is indexed by a kernel device number, never by a remotely supplied path
// or a boot-local disk/controller name. This reader performs no device commands.
func readSysfsBlockIdentity(device string, readFile func(string) ([]byte, error)) sysfsBlockIdentity {
	read := func(attribute string, binarySerial bool) sysfsIdentityValue {
		if !canonicalBlockDeviceNumber(device) {
			return sysfsIdentityValue{Error: "invalid_device_number"}
		}
		data, err := readFile("/sys/dev/block/" + device + "/" + attribute)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return sysfsIdentityValue{Error: "absent"}
			}
			return sysfsIdentityValue{Error: "unavailable"}
		}
		if len(data) > 4096 {
			return sysfsIdentityValue{Error: "oversized"}
		}
		if binarySerial {
			if len(data) < 4 || data[0] != 0 || data[1] != 0x80 || int(binary.BigEndian.Uint16(data[2:4])) != len(data)-4 {
				return sysfsIdentityValue{Error: "invalid_vpd_pg80"}
			}
			data = data[4:]
		}
		value := string(data)
		if !binarySerial {
			value = strings.TrimSuffix(value, "\n")
		}
		value = strings.TrimRight(value, " ")
		for _, b := range []byte(value) {
			if b < 0x20 || b > 0x7e {
				return sysfsIdentityValue{Error: "invalid_text"}
			}
		}
		if value == "" {
			return sysfsIdentityValue{Error: "empty"}
		}
		return sysfsIdentityValue{Value: value}
	}
	return sysfsBlockIdentity{
		WWID:       read("wwid", false),
		DeviceWWID: read("device/wwid", false),
		Serial:     read("device/serial", false),
		VPDSerial:  read("device/vpd_pg80", true),
	}
}

func canonicalBlockDeviceNumber(device string) bool {
	major, minor, ok := strings.Cut(device, ":")
	if !ok {
		return false
	}
	for _, part := range []string{major, minor} {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part {
			return false
		}
	}
	return true
}

func readSysfsIdentityFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	return data, errors.Join(err, file.Close())
}

func (identity sysfsBlockIdentity) diagnostic() *sysfsBlockIdentity {
	identity.WWID.Value = diagnosticIdentityText(identity.WWID.Value)
	identity.DeviceWWID.Value = diagnosticIdentityText(identity.DeviceWWID.Value)
	identity.Serial.Value = diagnosticIdentityText(identity.Serial.Value)
	identity.VPDSerial.Value = diagnosticIdentityText(identity.VPDSerial.Value)
	return &identity
}
