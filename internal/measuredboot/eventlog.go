package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	maxEvents       = 4096
	maxEventData    = 65536
	maxSpecIDAlgs   = 16
	maxPCR          = 23
	evNoAction      = 0x3
	algSHA256       = 0x000b
	specIDSignature = "Spec ID Event03\x00"
)

// knownDigestSizes are the TCG algorithm registry digest sizes accepted in a
// Spec ID event. Unknown algorithms are rejected rather than skipped.
var knownDigestSizes = map[uint16]uint16{
	0x0004: 20, // SHA-1
	0x000b: 32, // SHA-256
	0x000c: 48, // SHA-384
	0x000d: 64, // SHA-512
	0x0012: 32, // SM3-256
	0x0027: 32, // SHA3-256
	0x0028: 48, // SHA3-384
	0x0029: 64, // SHA3-512
}

var (
	errEventLogTooLarge    = errors.New("measuredboot: event_log_too_large")
	errEventLogTruncated   = errors.New("measuredboot: event_log_truncated")
	errEventLogSpecID      = errors.New("measuredboot: event_log_spec_id_invalid")
	errEventLogNoSHA256    = errors.New("measuredboot: event_log_sha256_bank_missing")
	errEventLogDigest      = errors.New("measuredboot: event_log_digest_invalid")
	errEventLogTooMany     = errors.New("measuredboot: event_log_too_many_events")
	errEventLogEventSize   = errors.New("measuredboot: event_log_event_too_large")
	errReplayPCR           = errors.New("measuredboot: replay_pcr_unsupported")
	errReplaySHA256Missing = errors.New("measuredboot: replay_sha256_missing")
)

// Event is one TCG PC Client event. SHA256 is nil when the event carries no
// SHA-256 digest (including the SHA-1-format Spec ID header event). SHA256 and
// Data alias the slice passed to ParseEventLog.
type Event struct {
	PCR    uint32
	Type   uint32
	SHA256 []byte
	Data   []byte
}

type logReader struct {
	data []byte
	off  int
}

func (r *logReader) take(n int) ([]byte, error) {
	if n < 0 || len(r.data)-r.off < n {
		return nil, errEventLogTruncated
	}
	value := r.data[r.off : r.off+n : r.off+n]
	r.off += n
	return value, nil
}

func (r *logReader) uint16() (uint16, error) {
	value, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(value), nil
}

func (r *logReader) uint32() (uint32, error) {
	value, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}

func (r *logReader) eventData() ([]byte, error) {
	size, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if size > maxEventData {
		return nil, errEventLogEventSize
	}
	return r.take(int(size))
}

// ParseEventLog parses a crypto-agile TCG PC Client event log: the SHA-1-format
// Spec ID header event followed by TCG_PCR_EVENT2 records. It rejects SHA-1-only
// logs, logs without a SHA-256 bank, truncation, trailing bytes and digests of
// algorithms the header does not declare. Every event, including EV_NO_ACTION,
// is returned in log order.
func ParseEventLog(data []byte) ([]Event, error) {
	if len(data) > MaxEventLogBytes {
		return nil, errEventLogTooLarge
	}
	r := logReader{data: data}
	pcr, err := r.uint32()
	if err != nil {
		return nil, err
	}
	eventType, err := r.uint32()
	if err != nil {
		return nil, err
	}
	sha1, err := r.take(20)
	if err != nil {
		return nil, err
	}
	if pcr != 0 || eventType != evNoAction || !bytes.Equal(sha1, make([]byte, 20)) {
		return nil, errEventLogSpecID
	}
	header, err := r.eventData()
	if err != nil {
		return nil, err
	}
	sizes, err := parseSpecID(header)
	if err != nil {
		return nil, err
	}
	events := []Event{{PCR: pcr, Type: eventType, Data: header}}
	for r.off < len(r.data) {
		if len(events) == maxEvents {
			return nil, errEventLogTooMany
		}
		event, err := parseEvent2(&r, sizes)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func parseSpecID(header []byte) (map[uint16]uint16, error) {
	r := logReader{data: header}
	signature, err := r.take(len(specIDSignature))
	if err != nil || string(signature) != specIDSignature {
		return nil, errEventLogSpecID
	}
	// platformClass(4), specVersionMinor(1), specVersionMajor(1),
	// specErrata(1), uintnSize(1).
	fixed, err := r.take(8)
	if err != nil {
		return nil, errEventLogSpecID
	}
	if fixed[5] != 2 || (fixed[7] != 1 && fixed[7] != 2) {
		return nil, errEventLogSpecID
	}
	count, err := r.uint32()
	if err != nil || count == 0 || count > maxSpecIDAlgs {
		return nil, errEventLogSpecID
	}
	sizes := make(map[uint16]uint16, count)
	for range count {
		alg, err := r.uint16()
		if err != nil {
			return nil, errEventLogSpecID
		}
		size, err := r.uint16()
		if err != nil {
			return nil, errEventLogSpecID
		}
		known, ok := knownDigestSizes[alg]
		if _, duplicate := sizes[alg]; !ok || known != size || duplicate {
			return nil, errEventLogDigest
		}
		sizes[alg] = size
	}
	vendorSize, err := r.take(1)
	if err != nil {
		return nil, errEventLogSpecID
	}
	if _, err := r.take(int(vendorSize[0])); err != nil || r.off != len(header) {
		return nil, errEventLogSpecID
	}
	if _, ok := sizes[algSHA256]; !ok {
		return nil, errEventLogNoSHA256
	}
	return sizes, nil
}

func parseEvent2(r *logReader, sizes map[uint16]uint16) (Event, error) {
	var event Event
	var err error
	if event.PCR, err = r.uint32(); err != nil {
		return Event{}, err
	}
	if event.Type, err = r.uint32(); err != nil {
		return Event{}, err
	}
	count, err := r.uint32()
	if err != nil {
		return Event{}, err
	}
	if count == 0 || count > uint32(len(sizes)) {
		return Event{}, errEventLogDigest
	}
	var seen [maxSpecIDAlgs]uint16
	for i := range count {
		alg, err := r.uint16()
		if err != nil {
			return Event{}, err
		}
		size, ok := sizes[alg]
		if !ok {
			return Event{}, errEventLogDigest
		}
		for _, previous := range seen[:i] {
			if previous == alg {
				return Event{}, errEventLogDigest
			}
		}
		seen[i] = alg
		digest, err := r.take(int(size))
		if err != nil {
			return Event{}, err
		}
		if alg == algSHA256 {
			event.SHA256 = digest
		}
	}
	if event.Data, err = r.eventData(); err != nil {
		return Event{}, err
	}
	return event, nil
}

// Replay extends the SHA-256 digests of events into each selected PCR from
// the all-zero reset value. EV_NO_ACTION events are never extended. PCR 0 is
// unsupported because its reset value depends on the StartupLocality event.
func Replay(events []Event, pcrs []int) (map[int][32]byte, error) {
	if len(pcrs) == 0 {
		return nil, errReplayPCR
	}
	var selected [maxPCR + 1]bool
	for _, pcr := range pcrs {
		if pcr < 1 || pcr > maxPCR || selected[pcr] {
			return nil, errReplayPCR
		}
		selected[pcr] = true
	}
	var values [maxPCR + 1][32]byte
	var buffer [64]byte
	for _, event := range events {
		if event.Type == evNoAction || event.PCR > maxPCR || !selected[event.PCR] {
			continue
		}
		if len(event.SHA256) != sha256.Size {
			return nil, errReplaySHA256Missing
		}
		copy(buffer[:32], values[event.PCR][:])
		copy(buffer[32:], event.SHA256)
		values[event.PCR] = sha256.Sum256(buffer[:])
	}
	result := make(map[int][32]byte, len(pcrs))
	for _, pcr := range pcrs {
		result[pcr] = values[pcr]
	}
	return result, nil
}
