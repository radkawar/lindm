//go:build linux

package capabilitypolicy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

// RecordName is the executor-owned record inside the protected state directory.
const RecordName = "capability-policy.binpb"

// maxRecordBytes bounds the record: a 64 KiB envelope plus the decoded policy
// it carries and the record framing.
const maxRecordBytes = 256 << 10

// ErrRecord reports an unreadable, unsafe or invalid capability policy record.
var ErrRecord = errors.New("capability_policy_record_invalid")

var recordValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(&agentv1.CapabilityPolicyRecord{}), protovalidate.WithDisableLazy())
})

// RecordPath is the record's path in the executor state directory.
func RecordPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, RecordName)
}

// LoadRecord reads the accepted capability policy record. An absent record
// returns nil, nil. The state directory must pass the executor's private
// directory custody (current-UID 0700, non-replaceable ancestry) and the
// record must be a current-UID 0600 regular file with one link. Signatures
// are not re-verified here: only the executor writes the record, after
// verification.
func LoadRecord(stateDirectory string) (_ *agentv1.CapabilityPolicyRecord, resultErr error) {
	directoryFD, err := statefs.OpenDirectory(stateDirectory)
	if err != nil {
		return nil, fmt.Errorf("open capability policy state directory: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(directoryFD)) }()
	present, err := statefs.CheckFile(directoryFD, RecordName)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecord, err)
	}
	if !present {
		return nil, nil
	}
	fd, err := unix.Openat(directoryFD, RecordName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open capability policy record: %w", err)
	}
	file := os.NewFile(uintptr(fd), RecordName)
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("stat capability policy record: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size > maxRecordBytes {
		return nil, fmt.Errorf("%w: unsafe record file", ErrRecord)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read capability policy record: %w", err)
	}
	if len(data) > maxRecordBytes {
		return nil, fmt.Errorf("%w: record exceeds capacity", ErrRecord)
	}
	record := new(agentv1.CapabilityPolicyRecord)
	if err := proto.Unmarshal(data, record); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecord, err)
	}
	if err := validateRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

// StoreRecord atomically replaces the record: a private temporary file in the
// checked state directory, fsync, rename over the record, then directory
// fsync. Only the executor calls it.
func StoreRecord(stateDirectory string, record *agentv1.CapabilityPolicyRecord) (resultErr error) {
	if err := validateRecord(record); err != nil {
		return err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode capability policy record: %w", err)
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("%w: record exceeds capacity", ErrRecord)
	}
	directoryFD, err := statefs.OpenDirectory(stateDirectory)
	if err != nil {
		return fmt.Errorf("open capability policy state directory: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), "capability-policy-directory")
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	if _, err := statefs.CheckFile(directoryFD, RecordName); err != nil {
		return fmt.Errorf("%w: %w", ErrRecord, err)
	}
	file, err := os.CreateTemp("/proc/self/fd/"+strconv.Itoa(directoryFD), ".capability-policy-")
	if err != nil {
		return fmt.Errorf("create capability policy record: %w", err)
	}
	name := filepath.Base(file.Name())
	defer func() {
		_ = file.Close()
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write capability policy record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync capability policy record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close capability policy record: %w", err)
	}
	if err := unix.Renameat(directoryFD, name, directoryFD, RecordName); err != nil {
		return fmt.Errorf("replace capability policy record: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync capability policy state directory: %w", err)
	}
	return nil
}

func validateRecord(record *agentv1.CapabilityPolicyRecord) error {
	validator, err := recordValidator()
	if err != nil {
		return fmt.Errorf("compile capability policy record rules: %w", err)
	}
	if record == nil || protodata.ValidateClosed(record.ProtoReflect()) != nil {
		return fmt.Errorf("%w: unknown or missing fields", ErrRecord)
	}
	if err := validator.Validate(record); err != nil {
		return fmt.Errorf("%w: %w", ErrRecord, err)
	}
	return nil
}
