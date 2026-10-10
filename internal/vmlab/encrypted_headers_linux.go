package vmlab

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EncryptedHeader is an appliance observation, independent of guest software.
// Device uses a stable appliance disk label, not a host block-device pathname.
type EncryptedHeader struct {
	Disk   string          `json:"disk,omitempty"`
	Device string          `json:"device"`
	UUID   string          `json:"uuid"`
	JSON   json.RawMessage `json:"json"`
}

// guestfish has no native JSON luksDump API. debug sh runs cryptsetup in its
// appliance, without mounting a guest filesystem or running guest binaries.
// Labels constrain discovery to this one attached disk, excluding appliance root.
const encryptedHeaderScript = `set -eu
command -v cryptsetup >/dev/null
[ -b /dev/disk/guestfs/encrypted ]
for device in /dev/disk/guestfs/encrypted /dev/disk/guestfs/encrypted[0-9]*; do
  [ -b "$device" ] || continue
  if cryptsetup isLuks "$device"; then
    cryptsetup isLuks --type luks2 "$device"
    uuid=$(cryptsetup luksUUID "$device")
    echo
    echo LINDM-LUKS2
    echo "$device"
    echo "$uuid"
    cryptsetup luksDump --dump-json-metadata "$device"
  else
    status=$?
    [ "$status" -eq 1 ] || exit "$status"
  fi
done`

// readEncryptedHeaders requires a stopped VM for a coherent before/after oracle.
// It never attaches NBD, invokes host cryptsetup, mounts anything, or opens a host
// block device. libguestfs opens only a checked regular qcow2 chain read-only.
func readEncryptedHeaders(ctx context.Context, overlayPath, workDir string) (_ []EncryptedHeader, err error) {
	if err := encryptedPrivateDir(workDir); err != nil {
		return nil, err
	}
	overlay, err := openRegular(overlayPath)
	if err != nil {
		return nil, fmt.Errorf("open encrypted overlay: %w", err)
	}
	defer func() { err = errors.Join(err, overlay.Close()) }()
	if err := encryptedQCOWChain(overlay, overlayPath, 0); err != nil {
		return nil, err
	}
	// Address the already checked descriptor via the supervising process: QEMU
	// does not necessarily inherit guestfish's extra descriptors.
	path := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), overlay.Fd())
	data, err := encryptedHostOutput(ctx, workDir, 3*time.Minute, "guestfish", "--ro", "--", "add-drive-opts", path, "readonly:true", "format:qcow2", "label:encrypted", ":", "run", ":", "debug", "sh", encryptedHeaderScript)
	if err != nil {
		return nil, fmt.Errorf("read LUKS2 headers (guestfish appliance with cryptsetup required): %w", err)
	}
	return parseEncryptedHeaders(data)
}

// QEMU follows qcow2 backing filenames itself. Check those before giving it the
// image so a crafted backing reference cannot expose a host device or network URI.
// External-data-file qcow2 images are deliberately unsupported for this lab.
func encryptedQCOWBacking(file *os.File) (string, error) {
	var header [104]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return "", fmt.Errorf("read qcow2 header: %w", err)
	}
	version := binary.BigEndian.Uint32(header[4:8])
	if string(header[:4]) != "QFI\xfb" || (version != 2 && version != 3) {
		return "", errors.New("encrypted disk and backing files must use qcow2 format")
	}
	if version == 3 && binary.BigEndian.Uint64(header[72:80])&(1<<2) != 0 {
		return "", errors.New("qcow2 external data files are not permitted")
	}
	offset := binary.BigEndian.Uint64(header[8:16])
	size := binary.BigEndian.Uint32(header[16:20])
	if size == 0 && offset == 0 {
		return "", nil
	}
	if size == 0 || size > 4096 || offset < 72 || offset > 1<<20 {
		return "", errors.New("invalid qcow2 backing filename bounds")
	}
	name := make([]byte, size)
	if _, err := file.ReadAt(name, int64(offset)); err != nil {
		return "", fmt.Errorf("read qcow2 backing filename: %w", err)
	}
	if bytes.ContainsAny(name, ":\x00\r\n") {
		return "", errors.New("qcow2 backing filename must be a local regular file")
	}
	backingPath := string(name)
	if !filepath.IsAbs(backingPath) {
		return "", errors.New("qcow2 backing filename must be absolute for descriptor-pinned inspection")
	}
	return backingPath, nil
}

func encryptedQCOWChain(file *os.File, path string, depth int) (err error) {
	if depth >= 8 {
		return errors.New("encrypted overlay backing chain exceeds limit")
	}
	backingPath, err := encryptedQCOWBacking(file)
	if err != nil || backingPath == "" {
		return err
	}
	backing, err := openRegular(backingPath)
	if err != nil {
		return fmt.Errorf("open qcow2 backing file: %w", err)
	}
	defer func() { err = errors.Join(err, backing.Close()) }()
	return encryptedQCOWChain(backing, backingPath, depth+1)
}

func parseEncryptedHeaders(data []byte) ([]EncryptedHeader, error) {
	if len(data) > 4<<20 {
		return nil, errors.New("encrypted header output exceeds limit")
	}
	parts := bytes.Split(data, []byte("\nLINDM-LUKS2\n"))
	if len(bytes.TrimSpace(parts[0])) != 0 || len(parts) > 129 {
		return nil, errors.New("invalid encrypted header framing")
	}
	headers := make([]EncryptedHeader, 0, len(parts)-1)
	devices, uuids := make(map[string]bool), make(map[string]bool)
	for _, part := range parts[1:] {
		fields := bytes.SplitN(part, []byte{'\n'}, 3)
		if len(fields) != 3 {
			return nil, errors.New("invalid encrypted header framing")
		}
		device, uuid := string(fields[0]), string(fields[1])
		suffix, ok := strings.CutPrefix(device, "/dev/disk/guestfs/encrypted")
		partition, err := strconv.ParseUint(suffix, 10, 16)
		validDevice := ok && (suffix == "" || (err == nil && partition != 0 && strconv.FormatUint(partition, 10) == suffix))
		if !validDevice || !encryptedLUKSUUID(uuid) || devices[device] || uuids[uuid] {
			return nil, errors.New("invalid or duplicate encrypted device identity")
		}
		if _, err := encryptedHeaderJSON(fields[2]); err != nil {
			return nil, err
		}
		devices[device], uuids[uuid] = true, true
		headers = append(headers, EncryptedHeader{Device: device, UUID: uuid, JSON: bytes.TrimSpace(fields[2])})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].Device < headers[j].Device })
	return headers, nil
}

func encryptedLUKSUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encryptedHeadersEqual matches UUIDs and all metadata, including keyslots,
// tokens, digests and segments. Device names differ between guest and appliance;
// JSON object order/whitespace and numeric spelling do not matter, but arrays do.
// Invalid or ambiguous metadata is an error rather than equal.
func encryptedHeadersEqual(a, b []EncryptedHeader) (bool, error) {
	left, err := encryptedHeaderSet(a)
	if err != nil {
		return false, err
	}
	right, err := encryptedHeaderSet(b)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(left, right), nil
}

func encryptedHeaderSet(headers []EncryptedHeader) (map[string]any, error) {
	result := make(map[string]any, len(headers))
	for _, header := range headers {
		if header.Device == "" || !encryptedLUKSUUID(header.UUID) {
			return nil, errors.New("invalid encrypted header identity")
		}
		if _, exists := result[header.UUID]; exists {
			return nil, errors.New("duplicate encrypted header UUID")
		}
		value, err := encryptedHeaderJSON(header.JSON)
		if err != nil {
			return nil, err
		}
		result[header.UUID] = value
	}
	return result, nil
}

func encryptedHeaderJSON(data []byte) (any, error) {
	if len(data) > 4<<20 {
		return nil, errors.New("LUKS2 JSON exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := encryptedJSONValue(decoder, 0)
	if err != nil {
		return nil, errors.New("invalid or ambiguous LUKS2 JSON metadata")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing LUKS2 JSON metadata")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("LUKS2 metadata must be an object")
	}
	for _, name := range []string{"keyslots", "tokens", "segments", "digests", "config"} {
		if _, ok := object[name].(map[string]any); !ok {
			return nil, errors.New("LUKS2 metadata is missing a required object")
		}
	}
	return value, nil
}

func encryptedJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON depth exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid JSON object key")
				}
				if _, exists := object[name]; exists {
					return nil, errors.New("duplicate JSON object key")
				}
				object[name], err = encryptedJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, errors.New("invalid JSON object terminator")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				item, err := encryptedJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, errors.New("invalid JSON array terminator")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		text := string(value)
		if len(text) > 128 {
			return nil, errors.New("JSON number exceeds limit")
		}
		if i := strings.IndexAny(text, "eE"); i >= 0 {
			exponent, err := strconv.Atoi(text[i+1:])
			if err != nil || exponent < -4096 || exponent > 4096 {
				return nil, errors.New("JSON exponent exceeds limit")
			}
		}
		number, ok := new(big.Rat).SetString(text)
		if !ok {
			return nil, errors.New("invalid JSON number")
		}
		// A distinct type prevents the number 1 matching the string "1".
		return encryptedJSONNumber(number.RatString()), nil
	default:
		return value, nil
	}
}

type encryptedJSONNumber string
