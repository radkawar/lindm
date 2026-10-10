//go:build linux

package inventory

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/actionprovider"
)

// CollectStorage observes public native identities through read-only interfaces.
// The root executor uses this bounded projection for inventory; it grants no
// authority to execute an action and never publishes key material.
func CollectStorage(ctx context.Context) *inventoryv1.StorageDetails {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	result := collectStorage(ctx, detailSources{
		readFile: readDetailFile, run: runNative, openBlock: openStorageBlock,
		nvmeScope: actionprovider.ReadNVMeSanitizeScope,
	})
	if status := detailCategoryStatus(result); status != success {
		return &inventoryv1.StorageDetails{Status: status}
	}
	if err := protovalidate.Validate(result); err != nil {
		return &inventoryv1.StorageDetails{Status: invalid}
	}
	return result
}

func openStorageBlock(path string) (_ *os.File, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && (info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0) {
		err = errInvalid
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func collectNVMeScope(ctx context.Context, s detailSources, name string, device *inventoryv1.BlockDevice) (result *inventoryv1.ObservedNVMeScope) {
	result = &inventoryv1.ObservedNVMeScope{Status: unavailable}
	if err := ctx.Err(); err != nil {
		result.Status = statusFor(err)
		return result
	}
	if s.openBlock == nil || s.nvmeScope == nil {
		return result
	}
	file, err := s.openBlock("/dev/" + name)
	if err != nil {
		result.Status = statusFor(err)
		return result
	}
	defer func() {
		if err := file.Close(); err != nil {
			result.Status, result.Scope = statusFor(err), nil
		}
	}()
	id := device.Identity
	if id.Serial.Status != success {
		result.Status = id.Serial.Status
		return result
	}
	if device.SizeBytes.Status != success {
		result.Status = device.SizeBytes.Status
		return result
	}
	if id.Wwn.Status != success && id.Wwn.Status != unavailable {
		result.Status = id.Wwn.Status
		return result
	}
	scope, err := s.nvmeScope(ctx, file, &agentv1.StorageTarget{Wwn: id.Wwn.Value, Serial: id.Serial.Value, SizeBytes: device.SizeBytes.Value})
	if errors.Is(err, actionprovider.ErrUnsupported) {
		return result
	}
	if err != nil {
		result.Status = statusFor(err)
		return result
	}
	if scope == nil || scope.ControllerWide || protovalidate.Validate(scope) != nil {
		result.Status = invalid
		return result
	}
	result.Status, result.Scope = success, scope
	return result
}

// Only sysfs public identity attributes and a narrow udev property allowlist
// are retained. Missing fields do not manufacture a media identity.
func collectDiskFallback(ctx context.Context, s detailSources, name string, id *inventoryv1.StorageIdentity) {
	base := "/sys/class/block/" + name + "/"
	fallback := func(dst **inventoryv1.ObservedString, paths ...string) {
		if (*dst).Status != unavailable {
			return
		}
		for _, path := range paths {
			value := s.text(ctx, base+path)
			if value.Status != unavailable {
				*dst = value
				return
			}
		}
	}
	fallback(&id.Firmware, "device/firmware_rev", "device/rev")
	fallback(&id.Eui, "eui")
	if id.Transport.Status == unavailable {
		data, err := s.file(ctx, base+"device/uevent")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			id.Transport = observed("", err)
		} else if err == nil {
			if !nativeText(data) {
				id.Transport = observed("", errInvalid)
			} else {
				for line := range strings.SplitSeq(string(data), "\n") {
					switch line {
					case "DRIVER=virtio_blk":
						id.Transport = observed("virtio", nil)
					case "DRIVER=nvme":
						id.Transport = observed("nvme", nil)
					}
				}
			}
		}
	}
	// Serial/WWN deliberately remain exactly lsblk's spelling: the action
	// provider resolves using that same evidence, not normalized udev aliases.
	if id.Transport.Status != unavailable && id.Firmware.Status != unavailable {
		return
	}
	var properties map[string]string
	status := s.run(ctx, backend{name: "udevadm", path: "/usr/bin/udevadm", args: []string{"info", "--query=property", "--path=" + strings.TrimSuffix(base, "/")}}, func(reader io.Reader) inventoryv1.CollectionStatus {
		var status inventoryv1.CollectionStatus
		properties, status = parseUdevProperties(reader)
		return status
	})
	for _, field := range []struct {
		dst **inventoryv1.ObservedString
		key string
	}{{&id.Transport, "ID_BUS"}, {&id.Firmware, "ID_REVISION"}} {
		if (*field.dst).Status != unavailable {
			continue
		}
		if status == success {
			*field.dst = observed(properties[field.key], nil)
		} else {
			*field.dst = &inventoryv1.ObservedString{Status: status}
		}
	}
}

type luksSummary struct {
	uuid     string
	version  string
	keyslots uint64
	tokens   uint64
	types    []string
}

// The human-readable summary supplies UUID/version (absent from LUKS2 JSON)
// and LUKS1 slot states. LUKS2 counts/types are cross-checked with JSON metadata.
// No header bytes, digests, salts or token attributes survive this projection.
func parseLUKSSummary(reader io.Reader) (*luksSummary, inventoryv1.CollectionStatus) {
	limited := &io.LimitedReader{R: reader, N: maxDetailFile + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	summary := &luksSummary{}
	section := ""
	seenSlots, seenTokens := make(map[uint64]bool), make(map[uint64]bool)
	seenKeySection, seenTokenSection := false, false
	for scanner.Scan() {
		line := scanner.Text()
		if !nativeText(scanner.Bytes()) {
			return nil, invalid
		}
		if strings.HasPrefix(line, "Version:") {
			if summary.version != "" {
				return nil, invalid
			}
			summary.version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "UUID:") {
			if summary.uuid != "" {
				return nil, invalid
			}
			summary.uuid = strings.TrimSpace(strings.TrimPrefix(line, "UUID:"))
		} else if strings.HasPrefix(line, "Key Slot ") {
			key, state, ok := strings.Cut(strings.TrimPrefix(line, "Key Slot "), ":")
			slot, err := decimal(key)
			if !ok || err != nil || slot > 7 || seenSlots[slot] {
				return nil, invalid
			}
			seenSlots[slot] = true
			switch strings.TrimSpace(state) {
			case "ENABLED":
				summary.keyslots++
			case "DISABLED":
			default:
				return nil, invalid
			}
		} else if line == "Keyslots:" {
			if seenKeySection {
				return nil, invalid
			}
			seenKeySection, section = true, "keyslots"
		} else if line == "Tokens:" {
			if seenTokenSection {
				return nil, invalid
			}
			seenTokenSection, section = true, "tokens"
		} else if line != "" && line[0] != ' ' && line[0] != '\t' {
			section = ""
		} else if (section == "keyslots" || section == "tokens") && strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '\t' {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			index, err := decimal(key)
			if !ok || err != nil || index > 31 {
				return nil, invalid
			}
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\r\n,") {
				return nil, invalid
			}
			if section == "keyslots" {
				if seenSlots[index] || value != "luks2" {
					return nil, invalid
				}
				seenSlots[index] = true
				summary.keyslots++
			} else {
				if seenTokens[index] {
					return nil, invalid
				}
				seenTokens[index] = true
				summary.tokens++
				summary.types = append(summary.types, value)
			}
		}
	}
	if limited.N == 0 {
		return nil, capacity
	}
	if err := scanner.Err(); err != nil {
		return nil, statusFor(err)
	}
	if observed(summary.uuid, nil).Status != success {
		return nil, invalid
	}
	switch summary.version {
	case "1":
		if len(seenSlots) != 8 || seenKeySection || seenTokenSection {
			return nil, invalid
		}
	case "2":
		if !seenKeySection || !seenTokenSection {
			return nil, invalid
		}
	default:
		return nil, unavailable
	}
	return summary, success
}

func collectLUKS(ctx context.Context, s detailSources, name string, id *inventoryv1.StorageIdentity) {
	setFailure := func(status inventoryv1.CollectionStatus) {
		id.LuksKeyslotCount = &inventoryv1.ObservedUint64{Status: status}
		id.LuksTokenCount = &inventoryv1.ObservedUint64{Status: status}
		id.LuksTokenTypes = &inventoryv1.ObservedString{Status: status}
		if id.LuksUuid.Status == unavailable {
			id.LuksUuid.Status = status
		}
		if id.LuksVersion.Status == unavailable {
			id.LuksVersion.Status = status
		}
	}
	if err := ctx.Err(); err != nil {
		setFailure(statusFor(err))
		return
	}
	if s.openBlock == nil {
		setFailure(unavailable)
		return
	}
	file, err := s.openBlock("/dev/" + name)
	if err != nil {
		setFailure(statusFor(err))
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			setFailure(statusFor(err))
		}
	}()
	// The native process reopens the parent's pinned read-only descriptor, not
	// a mutable /dev alias. Never request --dump-master-key.
	path := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
	var summary *luksSummary
	consume := func(reader io.Reader) inventoryv1.CollectionStatus {
		var status inventoryv1.CollectionStatus
		summary, status = parseLUKSSummary(reader)
		return status
	}
	selected := backend{name: "cryptsetup", path: "/usr/sbin/cryptsetup", args: []string{"luksDump", path}}
	status := s.run(ctx, selected, consume)
	if status == unavailable {
		selected.path = "/usr/bin/cryptsetup"
		status = s.run(ctx, selected, consume)
	}
	if status != success {
		setFailure(status)
		return
	}
	if (id.LuksUuid.Status == success && id.LuksUuid.Value != summary.uuid) || (id.LuksVersion.Status == success && id.LuksVersion.Value != summary.version) {
		id.LuksUuid, id.LuksVersion = observed("", errInvalid), observed("", errInvalid)
		setFailure(invalid)
		return
	}
	id.LuksUuid, id.LuksVersion = observed(summary.uuid, nil), observed(summary.version, nil)
	if summary.version == "2" {
		var metadata *luksSummary
		selected.args = []string{"luksDump", "--dump-json-metadata", path}
		status = s.run(ctx, selected, func(reader io.Reader) inventoryv1.CollectionStatus {
			var status inventoryv1.CollectionStatus
			metadata, status = parseLUKSMetadata(reader)
			return status
		})
		if status != success {
			setFailure(status)
			return
		}
		slices.Sort(summary.types)
		if summary.keyslots != metadata.keyslots || summary.tokens != metadata.tokens || !slices.Equal(summary.types, metadata.types) {
			setFailure(invalid)
			return
		}
		summary = metadata
	}
	id.LuksKeyslotCount = number(summary.keyslots, nil)
	if summary.version == "1" {
		// LUKS1 has no token metadata feature; absence is not a measured zero.
		id.LuksTokenCount, id.LuksTokenTypes = number(0, fs.ErrNotExist), observed("", nil)
		return
	}
	id.LuksTokenCount = number(summary.tokens, nil)
	id.LuksTokenTypes = observed(strings.Join(summary.types, ","), nil)
}
