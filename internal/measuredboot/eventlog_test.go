package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseEventLogFixture(t *testing.T) {
	data := fixtureLog(t)
	events, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(events) != fixtureEventCount {
		t.Fatalf("events = %d, want %d", len(events), fixtureEventCount)
	}
	header := events[0]
	if header.PCR != 0 || header.Type != evNoAction || header.SHA256 != nil || !bytes.HasPrefix(header.Data, []byte(specIDSignature)) {
		t.Fatalf("header = %+v", header)
	}
	for i, event := range events[1:] {
		if len(event.SHA256) != sha256.Size {
			t.Fatalf("event %d has no SHA-256 digest", i+1)
		}
	}
	kernel := events[fixtureKernelIndex]
	if kernel.PCR != grubFilePCR || kernel.Type != evIPL || !bytes.Equal(kernel.SHA256, mustHex(t, fixtureKernelSHA256)) {
		t.Fatalf("kernel event = %+v", kernel)
	}
	if encoded := encodeEventLog(t, events); !bytes.Equal(encoded, data) {
		t.Fatal("re-encoded fixture differs from the original log")
	}
}

func TestParseEventLogRejects(t *testing.T) {
	data := fixtureLog(t)
	events := fixtureEvents(t)
	sha1Only := binary.LittleEndian.AppendUint32(nil, 0)
	sha1Only = binary.LittleEndian.AppendUint32(sha1Only, 0x8) // EV_S_CRTM_VERSION
	sha1Only = append(sha1Only, bytes.Repeat([]byte{1}, 20)...)
	sha1Only = binary.LittleEndian.AppendUint32(sha1Only, 2)
	sha1Only = append(sha1Only, 0, 0)

	sha1Header := bytes.Clone(events[0].Data)
	binary.LittleEndian.PutUint16(sha1Header[28:], 0x0004)
	binary.LittleEndian.PutUint16(sha1Header[30:], 20)
	sha1Bank := encodeEventLog(t, []Event{{PCR: 0, Type: evNoAction, Data: sha1Header}})

	wrongSize := bytes.Clone(events[0].Data)
	binary.LittleEndian.PutUint16(wrongSize[30:], 20)

	unknownDigest := bytes.Clone(data)
	firstEvent := 32 + len(events[0].Data)
	binary.LittleEndian.PutUint16(unknownDigest[firstEvent+12:], 0x0004)

	oversizedEvent := encodeEventLog(t, events[:2])
	binary.LittleEndian.PutUint32(oversizedEvent[len(oversizedEvent)-len(events[1].Data)-4:], maxEventData+1)
	oversizedEvent = append(oversizedEvent, make([]byte, maxEventData+1)...)

	tiny := Event{PCR: 10, Type: evIPL, SHA256: make([]byte, 32)}
	tooMany := make([]Event, 0, maxEvents+1)
	tooMany = append(tooMany, events[0])
	for range maxEvents {
		tooMany = append(tooMany, tiny)
	}

	for name, test := range map[string]struct {
		data []byte
		want error
	}{
		"empty":            {nil, errEventLogTruncated},
		"truncated":        {data[:len(data)-1], errEventLogTruncated},
		"truncated header": {data[:40], errEventLogTruncated},
		"trailing byte":    {append(bytes.Clone(data), 0), errEventLogTruncated},
		"oversized":        {make([]byte, MaxEventLogBytes+1), errEventLogTooLarge},
		"sha1 only":        {sha1Only, errEventLogSpecID},
		"no sha256 bank":   {sha1Bank, errEventLogNoSHA256},
		"wrong digest size": {
			encodeEventLog(t, []Event{{PCR: 0, Type: evNoAction, Data: wrongSize}}), errEventLogDigest,
		},
		"undeclared digest": {unknownDigest, errEventLogDigest},
		"oversized event":   {oversizedEvent, errEventLogEventSize},
		"too many events":   {encodeEventLog(t, tooMany), errEventLogTooMany},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEventLog(test.data); !errors.Is(err, test.want) {
				t.Fatalf("ParseEventLog error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := ParseEventLog(encodeEventLog(t, tooMany[:maxEvents])); err != nil {
		t.Fatalf("ParseEventLog at the event bound: %v", err)
	}
}

func TestReplay(t *testing.T) {
	digest := func(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
	extend := func(pcr [32]byte, digest []byte) [32]byte {
		return sha256.Sum256(append(pcr[:], digest...))
	}
	events := []Event{
		{PCR: 8, Type: evIPL, SHA256: digest(1)},
		{PCR: 8, Type: evNoAction, SHA256: digest(9)},
		{PCR: 9, Type: evIPL, SHA256: digest(2)},
		{PCR: 8, Type: evIPL, SHA256: digest(3)},
		{PCR: 0, Type: evIPL},
	}
	values, err := Replay(events, []int{8, 9, 4})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	wantPCR8 := extend(extend([32]byte{}, digest(1)), digest(3))
	if values[8] != wantPCR8 || values[9] != extend([32]byte{}, digest(2)) || values[4] != [32]byte{} || len(values) != 3 {
		t.Fatalf("Replay = %x", values)
	}
	for name, pcrs := range map[string][]int{"none": nil, "pcr0": {0, 8}, "duplicate": {8, 8}, "out of range": {24}} {
		if _, err := Replay(events, pcrs); !errors.Is(err, errReplayPCR) {
			t.Fatalf("%s: Replay error = %v", name, err)
		}
	}
	missing := append(events, Event{PCR: 9, Type: evIPL})
	if _, err := Replay(missing, []int{9}); !errors.Is(err, errReplaySHA256Missing) {
		t.Fatalf("Replay without SHA-256 error = %v", err)
	}
}
