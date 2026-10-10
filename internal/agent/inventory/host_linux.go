//go:build linux

package inventory

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const maxHostFile = 64 << 10

var errCapacity = errors.New("collection capacity exceeded")
var errInvalid = errors.New("invalid native evidence")

// Host files are small regular procfs/sysfs/configuration files. O_NONBLOCK
// prevents an unexpected FIFO from blocking before the regular-file check.
func readHostFile(path string) (_ []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHostFile+1))
	if len(data) > maxHostFile {
		return nil, errCapacity
	}
	return data, err
}

func statusFor(err error) inventoryv1.CollectionStatus {
	switch {
	case err == nil:
		return success
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT
	case errors.Is(err, fs.ErrPermission):
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	case errors.Is(err, fs.ErrNotExist):
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	case errors.Is(err, errCapacity):
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED
	default:
		return inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
	}
}

func observed(value string, err error) *inventoryv1.ObservedString {
	if err != nil {
		return &inventoryv1.ObservedString{Status: statusFor(err)}
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return &inventoryv1.ObservedString{Status: unavailable}
	}
	if len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return &inventoryv1.ObservedString{Status: invalid}
	}
	return &inventoryv1.ObservedString{Status: success, Value: value}
}

func observedFile(ctx context.Context, readFile func(string) ([]byte, error), path string) *inventoryv1.ObservedString {
	if err := ctx.Err(); err != nil {
		return observed("", err)
	}
	data, err := readFile(path)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return observed(string(data), err)
}

var osKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var osID = regexp.MustCompile(`^[a-z0-9._-]+$`)

// parseOSRelease implements os-release's shell-style assignments, not a shell:
// single/double quotes and backslash escapes are recognized; expansion and
// concatenation of quoted strings are never performed. Last duplicate wins,
// as required by os-release(5). Comments occupy their own lines.
func parseOSRelease(data []byte) (map[string]string, error) {
	if len(data) > maxHostFile {
		return nil, errCapacity
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return nil, errInvalid
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !osKey.MatchString(key) {
			return nil, errInvalid
		}
		value, err := unquoteOSValue(raw)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	return values, nil
}

func unquoteOSValue(raw string) (string, error) {
	var quote byte
	if len(raw) > 0 && (raw[0] == '\'' || raw[0] == '"') {
		quote = raw[0]
		if len(raw) < 2 || raw[len(raw)-1] != quote {
			return "", errInvalid
		}
		raw = raw[1 : len(raw)-1]
	}
	var value strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\\' && quote != '\'' {
			i++
			if i == len(raw) {
				return "", errInvalid
			}
			if quote == '"' && !strings.ContainsRune("$`\"\\", rune(raw[i])) {
				value.WriteByte('\\')
			}
			value.WriteByte(raw[i])
			continue
		}
		if c < 32 || c == 127 || c == quote || (quote == 0 && strings.ContainsRune(" \t'\"$`;|&()<>", rune(c))) || (quote == '"' && (c == '$' || c == '`')) {
			return "", errInvalid
		}
		value.WriteByte(c)
	}
	return value.String(), nil
}

func loadOSRelease(ctx context.Context, readFile func(string) ([]byte, error)) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := readFile("/etc/os-release")
	// Only absence selects the vendor fallback; never hide denied/invalid local
	// configuration behind a more convenient vendor identity.
	if errors.Is(err, fs.ErrNotExist) {
		data, err = readFile("/usr/lib/os-release")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return parseOSRelease(data)
}

func collectHost(ctx context.Context, readFile func(string) ([]byte, error), rootObservation bool) (*inventoryv1.HostObservation, map[string]string) {
	host := &inventoryv1.HostObservation{StartedAt: timestamppb.Now()}
	release, releaseErr := loadOSRelease(ctx, readFile)
	host.OsId = observed(release["ID"], releaseErr)
	if host.OsId.Status == success && !osID.MatchString(host.OsId.Value) {
		host.OsId = observed("", errInvalid)
	}
	host.OsVersion = observed(release["VERSION_ID"], releaseErr)
	host.BootId = observedFile(ctx, readFile, "/proc/sys/kernel/random/boot_id")
	if host.BootId.Status == success {
		id, err := uuid.Parse(host.BootId.Value)
		if err != nil || id == uuid.Nil || id.String() != host.BootId.Value {
			host.BootId = observed("", errInvalid)
		}
	}
	name, err := os.Hostname()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	host.Hostname = observed(name, err)
	var uts syscall.Utsname
	err = syscall.Uname(&uts)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	host.Architecture = observed(utsString(uts.Machine[:]), err)
	host.KernelRelease = observed(utsString(uts.Release[:]), err)
	host.HardwareVendor = observedFile(ctx, readFile, "/sys/class/dmi/id/sys_vendor")
	host.HardwareModel = observedFile(ctx, readFile, "/sys/class/dmi/id/product_name")
	if rootObservation {
		host.HardwareSerial = &inventoryv1.ObservedString{Status: unavailable}
	} else {
		host.HardwareSerial = observedFile(ctx, readFile, "/sys/class/dmi/id/product_serial")
	}
	host.FinishedAt = timestamppb.Now()
	return host, release
}

func utsString[T ~int8 | ~uint8](data []T) string {
	buf := make([]byte, 0, len(data))
	for _, b := range data {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}
