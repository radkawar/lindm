//go:build linux

package inventory

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const maxDetailFile = 4 << 20

// detailSources is a function seam, not a second provider: production uses the
// same bounded native runner as package inventory. Reads never access shadow,
// home directories, process environments, or session identities.
type detailSources struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]fs.DirEntry, error)
	stat     func(string) (fs.FileInfo, error)
	run      nativeRunner
	sessions func(context.Context) *inventoryv1.SessionCounts
}

func readDetailFile(path string) (_ []byte, err error) {
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
	data, err := io.ReadAll(io.LimitReader(f, maxDetailFile+1))
	if len(data) > maxDetailFile {
		return nil, errCapacity
	}
	return data, err
}

func readDetailDir(path string) (_ []fs.DirEntry, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	entries, err := f.ReadDir(257)
	if len(entries) > 256 {
		return nil, errCapacity
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return entries, err
}

func number(value uint64, err error) *inventoryv1.ObservedUint64 {
	if err != nil {
		return &inventoryv1.ObservedUint64{Status: statusFor(err)}
	}
	return &inventoryv1.ObservedUint64{Status: success, Value: value}
}

func boolean(value bool, err error) *inventoryv1.ObservedBool {
	if err != nil {
		return &inventoryv1.ObservedBool{Status: statusFor(err)}
	}
	return &inventoryv1.ObservedBool{Status: success, Value: value}
}

func decimal(value string) (uint64, error) {
	if value == "" {
		return 0, errInvalid
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errInvalid
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errInvalid
	}
	return n, nil
}

func (s detailSources) file(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := s.readFile(path)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) > maxDetailFile {
		return nil, errCapacity
	}
	return data, err
}

func (s detailSources) text(ctx context.Context, path string) *inventoryv1.ObservedString {
	data, err := s.file(ctx, path)
	return observed(string(data), err)
}

func (s detailSources) uint(ctx context.Context, path string) *inventoryv1.ObservedUint64 {
	data, err := s.file(ctx, path)
	if err != nil {
		return number(0, err)
	}
	value, err := decimal(strings.TrimSpace(string(data)))
	return number(value, err)
}

func collectDetails(ctx context.Context, s detailSources) *inventoryv1.NativeDetails {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cpu, cpuErr := s.file(ctx, "/proc/cpuinfo")
	memory, memoryErr := s.file(ctx, "/proc/meminfo")
	users, usersErr := s.file(ctx, "/etc/passwd")
	modules, modulesErr := s.file(ctx, "/proc/modules")
	uptime, uptimeErr := s.file(ctx, "/proc/uptime")
	stat, statErr := s.file(ctx, "/proc/stat")
	result := &inventoryv1.NativeDetails{
		Cpu: collectCPU(ctx, s, cpu, cpuErr), Memory: parseMemory(memory, memoryErr),
		Storage: collectStorage(ctx, s.run), Network: collectNetwork(ctx, s.run),
		Firmware: collectFirmware(ctx, s), Tpm: collectTPM(ctx, s), Power: collectPower(ctx, s),
		Sessions: s.sessions(ctx), LocalUsers: parseLocalUsers(users, usersErr),
		KernelModuleCount: parseModuleCount(modules, modulesErr),
		UptimeSeconds:     parseUptime(uptime, uptimeErr), BootTimeUnixSeconds: parseBootTime(stat, statErr),
		Backends: collectBackends(ctx, s), Flatpak: collectApplications(ctx, s.run, "flatpak"), Snap: collectApplications(ctx, s.run, "snap"),
		Platform: collectPlatform(ctx, s),
	}
	boundDetails(result)
	return result
}

// Reserve at most 64 KiB per repeated category. This keeps the complete host
// evidence below the control-plane envelope without publishing truncated lists.
func boundDetails(result *inventoryv1.NativeDetails) {
	check := func(message proto.Message) inventoryv1.CollectionStatus {
		const maxCategory = 64 << 10
		if proto.Size(message) > maxCategory {
			return capacity
		}
		data, err := (protojson.MarshalOptions{Multiline: true}).Marshal(message)
		if err != nil {
			return invalid
		}
		if len(data) > maxCategory {
			return capacity
		}
		return success
	}
	if status := check(result.Storage); status != success {
		result.Storage = &inventoryv1.StorageDetails{Status: status}
	}
	if status := check(result.Network); status != success {
		result.Network = &inventoryv1.NetworkDetails{Status: status}
	}
	if status := check(result.Power.Batteries); status != success {
		result.Power.Batteries = &inventoryv1.BatteryDetails{Status: status}
	}
	if status := check(result.LocalUsers); status != success {
		result.LocalUsers = &inventoryv1.LocalUsers{Status: status}
	}
	if status := check(result.Flatpak); status != success {
		result.Flatpak = &inventoryv1.ApplicationDetails{Status: status}
	}
	if status := check(result.Snap); status != success {
		result.Snap = &inventoryv1.ApplicationDetails{Status: status}
	}
	if result.Platform != nil {
		if status := check(result.Platform.Repositories); status != success {
			result.Platform.Repositories = &inventoryv1.RepositoryObservation{Status: status}
		}
	}
}

func nativeText(data []byte) bool {
	return utf8.Valid(data) && !strings.ContainsRune(string(data), '\x00')
}

func parseLocalUsers(data []byte, err error) *inventoryv1.LocalUsers {
	result := &inventoryv1.LocalUsers{Status: statusFor(err)}
	if err != nil {
		return result
	}
	if !nativeText(data) || (len(data) > 0 && data[len(data)-1] != '\n') {
		result.Status = invalid
		return result
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			if len(data) == 0 {
				break
			}
			result.Status = invalid
			break
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" || len(fields[0]) > 256 || len(fields[6]) > 4096 {
			result.Status = invalid
			break
		}
		uid, err := decimal(fields[2])
		if err != nil || uid > 1<<32-1 {
			result.Status = invalid
			break
		}
		if len(result.Users) == 4096 {
			result.Status = capacity
			break
		}
		// Password, GECOS, home and group fields are deliberately not retained.
		result.Users = append(result.Users, &inventoryv1.LocalUser{Uid: uid, Name: fields[0], Shell: fields[6]})
	}
	if result.Status != success {
		result.Users = nil
	}
	return result
}

func parseModuleCount(data []byte, err error) *inventoryv1.ObservedUint64 {
	if err != nil {
		return number(0, err)
	}
	if !nativeText(data) {
		return number(0, errInvalid)
	}
	var count uint64
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			if len(data) == 0 {
				break
			}
			return number(0, errInvalid)
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return number(0, errInvalid)
		}
		if _, err := decimal(fields[1]); err != nil {
			return number(0, err)
		}
		if _, err := decimal(fields[2]); err != nil {
			return number(0, err)
		}
		if fields[4] != "Live" && fields[4] != "Loading" && fields[4] != "Unloading" {
			return number(0, errInvalid)
		}
		count++
	}
	return number(count, nil)
}

func parseUptime(data []byte, err error) *inventoryv1.ObservedUint64 {
	if err != nil {
		return number(0, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return number(0, errInvalid)
	}
	var seconds uint64
	for i, field := range fields {
		whole, fraction, ok := strings.Cut(field, ".")
		if !ok || len(fraction) != 2 {
			return number(0, errInvalid)
		}
		n, err := decimal(whole)
		if err != nil {
			return number(0, err)
		}
		if _, err := decimal(fraction); err != nil {
			return number(0, err)
		}
		if i == 0 {
			seconds = n
		}
	}
	return number(seconds, nil)
}

func parseBootTime(data []byte, err error) *inventoryv1.ObservedUint64 {
	if err != nil {
		return number(0, err)
	}
	var value uint64
	found := false
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "btime" {
			continue
		}
		if found || len(fields) != 2 {
			return number(0, errInvalid)
		}
		value, err = decimal(fields[1])
		found = true
		if err != nil || value == 0 || value > uint64(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix()) {
			return number(0, errInvalid)
		}
	}
	if !found {
		return number(0, fs.ErrNotExist)
	}
	return number(value, nil)
}
