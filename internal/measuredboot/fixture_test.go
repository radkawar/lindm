package measuredboot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// The fixture is the stock-boot TCG event log of a Fedora 44 swtpm/OVMF Secure
// Boot VM (GRUB 2.12-56.fc44, shim 16.1).
const (
	fixturePath          = "testdata/fedora44-stock.eventlog"
	fixtureEventCount    = 107
	fixtureLinuxIndex    = 99
	fixtureKernelIndex   = 100
	fixtureCmdlineIndex  = 102
	fixtureInitrdCommand = 103
	fixtureInitrdIndex   = 104
	fixtureSecureBoot    = 4
	fixtureKernelPath    = "/boot/vmlinuz-6.19.10-300.fc44.x86_64"
	fixtureInitrdPath    = "/boot/initramfs-6.19.10-300.fc44.x86_64.img"
	fixtureKernelOptions = "no_timer_check console=tty1 console=ttyS0,115200n8 systemd.firstboot=off root=UUID=15c26993-ac30-424a-9c4b-faec4434d234 rootflags=subvol=root"
	fixtureKernelSHA256  = "4b37e4e542a62c580c751787848be6c99e6f908f6712c8c6da85516b8d541de2"
	fixtureInitrdSHA256  = "47a48ed0bb4354a632172af72aff825635f649d5e372acd399630024c833c1ee"
)

func fixtureLog(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtureEvents(t *testing.T) []Event {
	t.Helper()
	events, err := ParseEventLog(fixtureLog(t))
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	return events
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// encodeEventLog writes events[0] as the SHA-1-format Spec ID header and the
// rest as TCG_PCR_EVENT2 records carrying only a SHA-256 digest.
func encodeEventLog(t *testing.T, events []Event) []byte {
	t.Helper()
	var out []byte
	out = binary.LittleEndian.AppendUint32(out, events[0].PCR)
	out = binary.LittleEndian.AppendUint32(out, events[0].Type)
	out = append(out, make([]byte, 20)...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(events[0].Data)))
	out = append(out, events[0].Data...)
	for _, event := range events[1:] {
		if len(event.SHA256) != sha256.Size {
			t.Fatalf("event without SHA-256 digest: %+v", event)
		}
		out = binary.LittleEndian.AppendUint32(out, event.PCR)
		out = binary.LittleEndian.AppendUint32(out, event.Type)
		out = binary.LittleEndian.AppendUint32(out, 1)
		out = binary.LittleEndian.AppendUint16(out, algSHA256)
		out = append(out, event.SHA256...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(event.Data)))
		out = append(out, event.Data...)
	}
	return out
}

// grubCommand returns a PCR 8 GRUB string event measured as GRUB measures it:
// the digest covers the text after the "grub_cmd: " or "kernel_cmdline: "
// prefix, and the data is NUL-terminated.
func grubCommand(t *testing.T, text string) Event {
	t.Helper()
	body, found := strings.CutPrefix(text, grubCommandPrefix)
	if !found {
		body, found = strings.CutPrefix(text, grubKernelCmdlinePrefix)
	}
	if !found {
		t.Fatalf("not a GRUB string event: %q", text)
	}
	digest := sha256.Sum256([]byte(body))
	return Event{PCR: grubCommandPCR, Type: evIPL, SHA256: digest[:], Data: []byte(text + "\x00")}
}

// grubFile returns a PCR 9 GRUB file event for path with the given contents.
func grubFile(path string, contents []byte) Event {
	digest := sha256.Sum256(contents)
	return Event{PCR: grubFilePCR, Type: evIPL, SHA256: digest[:], Data: []byte(path + "\x00")}
}

// replaceEvents returns a copy of events with events[from:to] replaced.
func replaceEvents(events []Event, from, to int, replacement ...Event) []Event {
	return slices.Concat(events[:from:from], replacement, events[to:])
}

type softwareAK struct {
	key    *ecdsa.PrivateKey
	public []byte
}

// newSoftwareAK stands in for the TPM attestation key: the template with a
// software P-256 point.
func newSoftwareAK(t *testing.T, mutate func(*tpm2.TPMTPublic)) softwareAK {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	public := AttestationKeyTemplate()
	public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: encoded[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: encoded[33:]},
	})
	if mutate != nil {
		mutate(&public)
	}
	return softwareAK{key: key, public: tpm2.Marshal(public)}
}

func selection(pcrs ...int) tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, pcr := range pcrs {
		bitmap[pcr/8] |= 1 << (pcr % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap}}}
}

// quoteFor builds and signs a TPMS_ATTEST quote over the replay of log for
// pcrs, as a TPM would with the attestation key.
func (ak softwareAK) quoteFor(t *testing.T, qualifyingData, log []byte, pcrs ...int) Evidence {
	t.Helper()
	events, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	values, err := Replay(events, pcrs)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	h := sha256.New()
	for _, pcr := range pcrs {
		value := values[pcr]
		h.Write(value[:])
	}
	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: append([]byte{0, 0x0b}, make([]byte, 32)...)},
		ExtraData:       tpm2.TPM2BData{Buffer: qualifyingData},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1000, ResetCount: 1, RestartCount: 0, Safe: true},
		FirmwareVersion: 0x2023,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: selection(pcrs...),
			PCRDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	}
	quote := tpm2.Marshal(attest)
	return Evidence{Quote: quote, Signature: ak.sign(t, quote), EventLog: log}
}

func (ak softwareAK) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, ak.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
		}),
	})
}

func fixtureExpected(t *testing.T, ak softwareAK, qualifyingData []byte) Expected {
	t.Helper()
	return Expected{
		AttestationKeyPublic: ak.public,
		QualifyingData:       qualifyingData,
		KernelSHA256:         mustHex(t, fixtureKernelSHA256),
		InitrdSHA256:         mustHex(t, fixtureInitrdSHA256),
		KernelPath:           fixtureKernelPath,
		InitrdPath:           fixtureInitrdPath,
		KernelOptions:        fixtureKernelOptions,
	}
}
