package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// This is a source-derived recovery-boot fixture; the captured ordinary
// Tumbleweed log is tested below. GRUB 2.14
// blsuki.c bls_create_entry emits linux followed by initrd; tpm.c measures
// commands/cmdline in PCR 8 and files in PCR 9. The source is the openSUSE
// Factory grub2 source revision 50cc75c719472639997e054ccf17fc06. Native logs
// must qualify the actual signed loader and both architecture tuples separately.
func TestVerifyLoaderInterfaceBLSRecoverySequence(t *testing.T) {
	const kernelPath = "/0123456789abcdef0123456789abcdef/7.2.9-1-default/linux"
	initrdPath := "/lindm-recovery-" + testAction + ".initrd"
	kernel, initrd := []byte("source-model vendor kernel"), []byte("source-model approved recovery initramfs")
	kernelDigest, initrdDigest := sha256.Sum256(kernel), sha256.Sum256(initrd)
	for _, console := range []string{"ttyS0,115200n8", "ttyAMA0,115200"} {
		t.Run(console, func(t *testing.T) {
			options, err := KernelOptions(testAction, console)
			if err != nil {
				t.Fatal(err)
			}
			// Reuse only the unrelated firmware prefix of the captured generic
			// fixture. Every BLS event below is explicitly synthetic.
			events := fixtureEvents(t)[:fixtureLinuxIndex:fixtureLinuxIndex]
			start := len(events)
			events = append(events,
				grubCommand(t, "grub_cmd: linux "+kernelPath+" "+options),
				grubFile(kernelPath, kernel),
				grubCommand(t, "kernel_cmdline: "+kernelPath+" "+options),
				grubCommand(t, "grub_cmd: initrd "+initrdPath),
				grubFile(initrdPath, initrd),
			)
			ak := newSoftwareAK(t, nil)
			fresh := QualifyingData([]byte("signed BOOTED receipt"), []byte("fresh signed challenge"))
			expected := Expected{AttestationKeyPublic: ak.public, QualifyingData: fresh, KernelSHA256: kernelDigest[:], InitrdSHA256: initrdDigest[:], KernelPath: kernelPath, InitrdPath: initrdPath, KernelOptions: options}
			log := encodeEventLog(t, events)
			if len(log) > MaxEventLogBytes {
				t.Fatal("fixture exceeds bounded parser contract")
			}
			valid := ak.quoteFor(t, fresh, log, QuotePCRs[:]...)
			if err := Verify(expected, valid); err != nil {
				t.Fatalf("strict BLS sequence refused: %v", err)
			}
			for name, changed := range map[string][]Event{
				"omitted kernel":         replaceEvents(events, start+1, start+2),
				"omitted cmdline":        replaceEvents(events, start+2, start+3),
				"foreign device":         replaceEvents(events, start+4, start+5, grubFile("(hd9,gpt1)"+initrdPath, initrd)),
				"extra initrd":           append(events[:len(events):len(events)], grubCommand(t, "grub_cmd: initrd /foreign"), grubFile("/foreign", initrd)),
				"changed loaded options": replaceEvents(events, start+2, start+3, grubCommand(t, "kernel_cmdline: "+kernelPath+" "+options+" init=/bin/sh")),
				"changed initramfs":      replaceEvents(events, start+4, start+5, grubFile(initrdPath, []byte("unapproved"))),
			} {
				t.Run(name, func(t *testing.T) {
					// Even a fresh, valid signature over a self-consistent replay
					// cannot make an altered sequence or artifact authorized.
					proof := ak.quoteFor(t, fresh, encodeEventLog(t, changed), QuotePCRs[:]...)
					if err := Verify(expected, proof); !errors.Is(err, ErrRejected) {
						t.Fatalf("altered BLS recovery admitted: %v", err)
					}
				})
			}
			badSignature := valid
			badSignature.Signature = bytes.Clone(valid.Signature)
			badSignature.Signature[len(badSignature.Signature)-1] ^= 1
			for name, proof := range map[string]Evidence{
				"signature":     badSignature,
				"stale quote":   ak.quoteFor(t, QualifyingData([]byte("signed BOOTED receipt"), []byte("stale challenge")), log, QuotePCRs[:]...),
				"other receipt": ak.quoteFor(t, QualifyingData([]byte("other BOOTED receipt"), []byte("fresh signed challenge")), log, QuotePCRs[:]...),
			} {
				t.Run(name, func(t *testing.T) {
					if err := Verify(expected, proof); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "quote_") {
						t.Fatalf("unbound quote admitted: %v", err)
					}
				})
			}
		})
	}
}

// Captured ordinary boots of the snapshot-pinned Tumbleweed goldens (signed
// shim, GRUB2-BLS 2.14 with LoaderInfo "GRUB2 2.14", kernel 7.2.9-1-default on
// the ESP) from the passing recovery-sanitize records: aarch64 20261007
// (e5f34964…fe0fd) and x86_64 20261009 (c8c9130f…97f71). sdbootutil names the
// nested ESP image linux-<digest>; kernel digests equal each record's
// recovery_vendor_kernel_sha256.
func TestFinalGRUBBootAcceptsNativeTumbleweedLoaderInterfaceLogs(t *testing.T) {
	for _, test := range []struct {
		fixture, kernelPath, initrdPath, kernelSHA256, console string
	}{
		{
			"testdata/tumbleweed-20261007-arm64-stock.eventlog",
			"/opensuse-tumbleweed/7.2.9-1-default/linux-0090333a44575441ead65e686edb1e6740ef4921",
			"/opensuse-tumbleweed/7.2.9-1-default/initrd-076539f31fbe8f2b53023a47d07a46d22848426d",
			"2b6e007ab48f54af31606b392bc2e1ef19bab2a3a87bc27a71e94e1bb8a8ae6a",
			"console=ttyAMA0,115200",
		},
		{
			"testdata/tumbleweed-20261009-amd64-stock.eventlog",
			"/opensuse-tumbleweed/7.2.9-1-default/linux-d7edbad05bc5365293a0df4a59d6442e786b33b0",
			"/opensuse-tumbleweed/7.2.9-1-default/initrd-9a1ec4db05a3f089217de1edb8b49df863e83abb",
			"31d6dc18a607c74ccc077c2a6c6ac262d3e72c318eb2abfdd3c2679fac4f304f",
			"console=ttyS0,115200n8",
		},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			data, err := os.ReadFile(test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			events, err := ParseEventLog(data)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := FinalGRUBBoot(events)
			if err != nil || loaded.KernelPath != test.kernelPath || loaded.InitrdPath != test.initrdPath || hex.EncodeToString(loaded.KernelSHA256) != test.kernelSHA256 {
				t.Fatalf("Tumbleweed FinalGRUBBoot = %+v, %v", loaded, err)
			}
			if !strings.Contains(loaded.KernelOptions, test.console) {
				t.Fatalf("captured options lost the vendor console: %q", loaded.KernelOptions)
			}
		})
	}
}
