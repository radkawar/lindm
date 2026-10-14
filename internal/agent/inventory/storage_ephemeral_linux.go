// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// dmMapName is a device-mapper name the collector looks up in crypttab;
// anything else is never proven.
var dmMapName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,126}$`)

// luksHeaderOffsets are the LUKS1/LUKS2 primary header (0) and the LUKS2
// secondary header positions cryptsetup probes (16 KiB to 4 MiB).
var luksHeaderOffsets = []int64{0, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000}

// collectEphemeralKey proves that a dm-crypt mapping is a plain mapping keyed
// from the kernel RNG on every activation, as distinst's random-key swap is:
// the kernel's device-mapper UUID is libcryptsetup's CRYPT-PLAIN-<name>, the
// mapping's only kernel slave is its observed parent, crypttab's single entry
// for it names /dev/urandom or /dev/random as its key in plain mode with no
// null cipher, and the backing device carries no LUKS header. A mapping the
// kernel labels CRYPT-LUKS is reported false; any failed or contradictory
// proof step leaves its status, so the mapping is never treated as ephemeral.
//
// Every step is a sysfs, /etc or block-device read: the root inventory helper
// runs with an empty capability bounding set and only block devices allowed,
// so device-mapper ioctls (dmsetup) are unavailable to it by design.
func collectEphemeralKey(ctx context.Context, s detailSources, kernelName string, graph *storageGraph, device *inventoryv1.BlockDevice) {
	id := device.Identity
	fail := func(err error) { id.EphemeralKey = boolean(false, err) }
	if s.readFile == nil || s.readDir == nil || s.openBlock == nil || !storageName(kernelName) {
		fail(fs.ErrNotExist)
		return
	}
	base := "/sys/class/block/" + kernelName + "/"
	nameData, err := s.readFile(base + "dm/name")
	if err != nil {
		fail(err)
		return
	}
	name := strings.TrimSpace(string(nameData))
	if !dmMapName.MatchString(name) {
		fail(errInvalid)
		return
	}
	dmUUID, err := s.readFile(base + "dm/uuid")
	if err != nil {
		fail(err)
		return
	}
	switch value := strings.TrimSpace(string(dmUUID)); {
	case strings.HasPrefix(value, "CRYPT-LUKS"):
		id.EphemeralKey = boolean(false, nil)
		return
	case value != "CRYPT-PLAIN-"+name:
		fail(fs.ErrNotExist)
		return
	}
	if err := ctx.Err(); err != nil {
		fail(err)
		return
	}
	parent, known := graph.nodes[device.GetParent().GetValue()]
	if device.GetParent().GetStatus() != success || !known {
		fail(fs.ErrNotExist)
		return
	}
	backing := parent.KernelName
	if backing == "" {
		backing = parent.Name
	}
	if !storageName(backing) {
		fail(errInvalid)
		return
	}
	slaves, err := s.readDir(base + "slaves")
	if err != nil {
		fail(err)
		return
	}
	if len(slaves) != 1 || slaves[0].Name() != backing {
		fail(errInvalid)
		return
	}
	crypttab, err := s.readFile("/etc/crypttab")
	if err != nil {
		fail(err)
		return
	}
	if !randomKeyCrypttab(crypttab, name) {
		fail(fs.ErrNotExist)
		return
	}
	file, err := s.openBlock("/dev/" + backing)
	if err != nil {
		fail(err)
		return
	}
	header, err := luksHeaderPresent(file)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	switch {
	case err != nil:
		fail(err)
	case header:
		// A plain mapping over a LUKS header contradicts the kernel's label.
		fail(errInvalid)
	default:
		id.EphemeralKey = boolean(true, nil)
	}
}

// randomKeyCrypttab reports whether the single crypttab entry for name keys it
// from the kernel RNG in plain mode (no luks, tcrypt or bitlk option) and does
// not configure a null cipher.
func randomKeyCrypttab(data []byte, name string) bool {
	matches, random := 0, false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || fields[0] != name {
			continue
		}
		matches++
		random = len(fields) >= 3 && (fields[2] == "/dev/urandom" || fields[2] == "/dev/random")
		if len(fields) >= 4 {
			for option := range strings.SplitSeq(fields[3], ",") {
				key, value, _ := strings.Cut(option, "=")
				if key == "luks" || key == "tcrypt" || key == "bitlk" || (key == "cipher" && strings.Contains(value, "null")) {
					random = false
				}
			}
		}
	}
	return scanner.Err() == nil && matches == 1 && random
}

// luksHeaderPresent probes the LUKS1/LUKS2 magic at every standard header
// offset of a pinned read-only block descriptor.
func luksHeaderPresent(file io.ReaderAt) (bool, error) {
	magic := make([]byte, 6)
	for _, offset := range luksHeaderOffsets {
		n, err := file.ReadAt(magic, offset)
		if errors.Is(err, io.EOF) && n < len(magic) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if bytes.Equal(magic, []byte("LUKS\xba\xbe")) || bytes.Equal(magic, []byte("SKUL\xba\xbe")) {
			return true, nil
		}
	}
	return false, nil
}
