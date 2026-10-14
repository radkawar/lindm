// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

const testActionID = "835f64ea-cd3e-4d5d-91c1-be872c70a0b5"

func loaderEntryBytes(entry string, terminated bool) []byte {
	data := []byte{0x06, 0, 0, 0}
	units := utf16.Encode([]rune(entry))
	if terminated {
		units = append(units, 0)
	}
	for _, unit := range units {
		data = binary.LittleEndian.AppendUint16(data, unit)
	}
	return data
}

func TestInitParamsRenderAndStrictParse(t *testing.T) {
	for _, params := range []initParams{
		{Mode: initModeUKI, ESPUUID: "ABCD-1234"},
		{Mode: initModeUKI, ESPUUID: "abcd-12ef", StateUUID: "12345678-1234-1234-1234-123456789abc"},
		{Mode: initModeMeasuredGRUB, StateUUID: "12345678-1234-1234-1234-123456789abc"},
	} {
		parsed, err := parseInitParams([]byte(params.render()))
		if err != nil || parsed != params {
			t.Fatalf("%+v did not round-trip: %+v, %v", params, parsed, err)
		}
	}
	if got := initParamsFor(BuildRequest{ESPUUID: "ABCD-1234", StateUUID: "12345678-1234-1234-1234-123456789abc"}); got != (initParams{Mode: initModeUKI, ESPUUID: "ABCD-1234", StateUUID: "12345678-1234-1234-1234-123456789abc"}) {
		t.Fatalf("build request mapped to %+v", got)
	}
	const state = "state_uuid 12345678-1234-1234-1234-123456789abc\n"
	for name, text := range map[string]string{
		"empty":                "",
		"header only":          initParamsHeader + "\n",
		"wrong header":         "lindm-recovery-init-v2\nboot_mode uki\nesp_uuid ABCD-1234\n",
		"no final newline":     initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234",
		"carriage return":      initParamsHeader + "\r\nboot_mode uki\r\nesp_uuid ABCD-1234\r\n",
		"unknown mode":         initParamsHeader + "\nboot_mode shell\nesp_uuid ABCD-1234\n",
		"uki without esp":      initParamsHeader + "\nboot_mode uki\n" + state,
		"invalid esp":          initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD1234\n",
		"uppercase state":      initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234\nstate_uuid 12345678-1234-1234-1234-123456789ABC\n",
		"reordered":            initParamsHeader + "\nboot_mode uki\n" + state + "esp_uuid ABCD-1234\n",
		"extra line":           initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234\n" + state + "extra 1\n",
		"duplicate esp":        initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234\nesp_uuid ABCD-1234\n",
		"blank line":           initParamsHeader + "\n\nboot_mode uki\nesp_uuid ABCD-1234\n",
		"grub without state":   initParamsHeader + "\nboot_mode measured_grub\n",
		"grub with esp":        initParamsHeader + "\nboot_mode measured_grub\nesp_uuid ABCD-1234\n" + state,
		"double space":         initParamsHeader + "\nboot_mode  uki\nesp_uuid ABCD-1234\n",
		"oversized":            initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234\n" + strings.Repeat("#", maxInitParamsBytes),
		"shell substitution":   initParamsHeader + "\nboot_mode uki\nesp_uuid $(poweroff)\n",
		"trailing field space": initParamsHeader + "\nboot_mode uki\nesp_uuid ABCD-1234 \n",
	} {
		if parsed, err := parseInitParams([]byte(text)); err == nil {
			t.Fatalf("%s accepted as %+v", name, parsed)
		}
	}
}

// The previous shell init accepted exactly lindm-recovery-<36 chars>.efi whose
// action, after removing dashes, was 32 lowercase hex digits at the canonical
// dash positions. The Go parser keeps those cases and additionally requires a
// well-formed UTF-16LE efivarfs value.
func TestSelectedRecoveryEntryValidation(t *testing.T) {
	entry := "lindm-recovery-" + testActionID + ".efi"
	for _, terminated := range []bool{true, false} {
		gotEntry, gotAction, err := selectedRecoveryEntry(loaderEntryBytes(entry, terminated))
		if err != nil || gotEntry != entry || gotAction != testActionID {
			t.Fatalf("terminated=%v rejected: %q %q %v", terminated, gotEntry, gotAction, err)
		}
	}
	reject := map[string][]byte{
		"empty":               {},
		"attributes only":     {6, 0, 0, 0},
		"terminator only":     loaderEntryBytes("", true),
		"uppercase hex":       loaderEntryBytes("lindm-recovery-"+strings.ToUpper(testActionID)+".efi", true),
		"wrong prefix":        loaderEntryBytes("lindm-recoverx-"+testActionID+".efi", true),
		"ordinary uki":        loaderEntryBytes("ubuntu-6.8.0-45-generic.efi", true),
		"conf entry":          loaderEntryBytes("lindm-recovery-"+testActionID+".conf", true),
		"missing suffix":      loaderEntryBytes("lindm-recovery-"+testActionID, true),
		"misplaced dash":      loaderEntryBytes("lindm-recovery-835f64e-acd3e-4d5d-91c1-be872c70a0b5.efi", true),
		"dash instead of hex": loaderEntryBytes("lindm-recovery-835f64e--cd3e-4d5d-91c1-be872c70a0b5.efi", true),
		"short action":        loaderEntryBytes("lindm-recovery-835f64ea-cd3e-4d5d-91c1-be872c70a0b.efi", true),
		"long action":         loaderEntryBytes("lindm-recovery-835f64ea-cd3e-4d5d-91c1-be872c70a0b55.efi", true),
		"non-hex":             loaderEntryBytes("lindm-recovery-835f64ea-cd3e-4d5d-91c1-be872c70a0bg.efi", true),
		"path traversal":      loaderEntryBytes("lindm-recovery-../../../../etc/shadow-0000000000000.efi", true),
		"slash":               loaderEntryBytes("lindm-recovery-835f64ea/cd3e-4d5d-91c1-be872c70a0b5.efi", true),
		"trailing space":      loaderEntryBytes("lindm-recovery-"+testActionID+".efi ", true),
		"leading space":       loaderEntryBytes(" lindm-recovery-"+testActionID+".efi", true),
		"non-ascii":           loaderEntryBytes("lindm-recovery-"+testActionID[:35]+"é.efi", true),
		"odd length":          loaderEntryBytes(entry, true)[:4+2*len(entry)+1],
		"garbage after nul":   append(loaderEntryBytes(entry, true), 'x', 0),
		"embedded nul":        loaderEntryBytes("lindm-recovery-"+testActionID+"\x00.efi", true),
		"packed bytes":        append([]byte{6, 0, 0, 0}, []byte(entry)...),
		"oversized":           loaderEntryBytes(entry+strings.Repeat("x", maxLoaderEntryBytes), true),
	}
	for name, data := range reject {
		if _, _, err := selectedRecoveryEntry(data); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestParseModuleLoadIsOrderedAndBounded(t *testing.T) {
	names, err := parseModuleLoad([]byte("virtio_pci\nnls_cp437\ncrc-t10dif\nsd_mod\n"))
	if err != nil || strings.Join(names, ",") != "virtio_pci,nls_cp437,crc-t10dif,sd_mod" {
		t.Fatalf("ordered module list lost: %q %v", names, err)
	}
	if names, err := parseModuleLoad(nil); err != nil || len(names) != 0 {
		t.Fatalf("empty list rejected: %q %v", names, err)
	}
	var many strings.Builder
	for i := range maxModuleLoadEntries + 1 {
		fmt.Fprintf(&many, "m%d\n", i)
	}
	for name, text := range map[string]string{
		"unterminated":    "virtio_pci",
		"blank line":      "virtio_pci\n\nnvme\n",
		"duplicate":       "nvme\nnvme\n",
		"path":            "../../evil\n",
		"absolute":        "/lib/modules/x/nvme.ko\n",
		"suffix":          "nvme.ko\n",
		"space":           "nvme param=1\n",
		"carriage return": "nvme\r\n",
		"too long name":   strings.Repeat("a", maxModuleNameBytes+1) + "\n",
		"too many":        many.String(),
		"oversized":       strings.Repeat("a\n", maxModuleLoadBytes),
	} {
		if names, err := parseModuleLoad([]byte(text)); err == nil {
			t.Fatalf("%s accepted: %q", name, names)
		}
	}
}
