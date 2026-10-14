// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// These deterministic synthetic native-format inputs cover parser boundaries;
// they are not captured distribution fixtures or native qualification evidence.
func TestSyntheticLUKSMetadataPublicProjection(t *testing.T) {
	summary, status := parseLUKSMetadata(strings.NewReader(syntheticLUKS2JSON))
	if status != success || summary.version != "2" || summary.uuid != "" || summary.keyslots != 2 || summary.tokens != 1 || strings.Join(summary.types, ",") != "systemd-tpm2" {
		t.Fatalf("public summary: %+v %v", summary, status)
	}
	for _, secret := range []string{"forbidden", "salt", "digest", "blob"} {
		if strings.Contains(fmt.Sprintf("%+v", summary), secret) {
			t.Fatal("retained sensitive metadata")
		}
	}
	projection := `{"tokens":{"4":{"type":"systemd-tpm2","keyslots":["2"]},"0":{"type":"systemd-fido2"}},"keyslots":{"2":{"type":"luks2"}}}`
	summary, status = parseLUKSMetadata(strings.NewReader(projection))
	if status != success || summary.keyslots != 1 || summary.tokens != 2 || strings.Join(summary.types, ",") != "systemd-fido2,systemd-tpm2" {
		t.Fatalf("public capture shape/order: %+v %v", summary, status)
	}
	summary, status = parseLUKSMetadata(strings.NewReader(`{"keyslots":{},"tokens":{}}`))
	if status != success || summary.keyslots != 0 || summary.tokens != 0 {
		t.Fatalf("empty native maps: %+v %v", summary, status)
	}
}

func TestSyntheticLUKSMetadataRejectsAmbiguityAndBounds(t *testing.T) {
	for _, data := range []string{
		``, `null`, `[]`, `{}`, `{"keyslots":{}}`,
		`{"keyslots":null,"tokens":{}}`,
		`{"keyslots":{},"tokens":[]}`,
		`{"keyslots":{},"keyslots":{},"tokens":{}}`,
		`{"keyslots":{},"tokens":{},"tokens":{}}`,
		`{"keyslots":{"0":{"type":"luks2"},"0":{"type":"luks2"}},"tokens":{}}`,
		`{"keyslots":{"0":{"type":"luks2"},"00":{"type":"luks2"}},"tokens":{}}`,
		`{"keyslots":{},"tokens":{"0":{"type":"x"},"0":{"type":"y"}}}`,
		`{"keyslots":{"32":{"type":"luks2"}},"tokens":{}}`,
		`{"keyslots":{},"tokens":{"32":{"type":"x"}}}`,
		`{"keyslots":{"-1":{"type":"luks2"}},"tokens":{}}`,
		`{"keyslots":{"0":{"type":"unknown"}},"tokens":{}}`,
		`{"keyslots":{"0":{}},"tokens":{}}`,
		`{"keyslots":{},"tokens":{"0":{"type":"x","type":"y"}}}`,
		`{"keyslots":{},"tokens":{"0":{"type":null}}}`,
		`{"keyslots":{},"tokens":{"0":{"type":""}}}`,
		`{"keyslots":{},"tokens":{"0":{"type":"x,y"}}}`,
		`{"keyslots":{},"tokens":{"0":{"type":"x\u0000"}}}`,
		`{"keyslots":{},"tokens":{"0":{"type":"` + strings.Repeat("x", 257) + `"}}}`,
		`{"keyslots":{},"tokens":{}} {}`,
		`{"keyslots":{},"tokens":{},"payload":[1,}`,
		`{"keyslots":{},"tokens":{},"payload":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `}`,
	} {
		if summary, status := parseLUKSMetadata(strings.NewReader(data)); status != invalid || summary != nil {
			t.Fatalf("malformed metadata accepted: %+v %v", summary, status)
		}
	}
	var entries []string
	for i := range 32 {
		entries = append(entries, fmt.Sprintf(`"%d":{"type":"luks2"}`, i))
	}
	if summary, status := parseLUKSMetadata(strings.NewReader(`{"keyslots":{` + strings.Join(entries, ",") + `},"tokens":{}}`)); status != success || summary.keyslots != 32 {
		t.Fatalf("native slot limit: %+v %v", summary, status)
	}
	for _, data := range []string{strings.Repeat(" ", maxDetailFile+1), syntheticLUKS2JSON + strings.Repeat(" ", maxDetailFile), `{"payload":"` + strings.Repeat("x", maxDetailFile) + `"}`} {
		if summary, status := parseLUKSMetadata(strings.NewReader(data)); status != capacity || summary != nil {
			t.Fatalf("unbounded metadata: %+v %v", summary, status)
		}
	}
}

func TestSyntheticLUKSCollectionCrossChecksNativeReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-descriptor")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, text, metadata string
		wantCalls            int
		wantStatus           inventoryv1.CollectionStatus
	}{
		{"match", syntheticLUKS2, syntheticLUKS2JSON, 2, success},
		{"uuid changed", strings.Replace(syntheticLUKS2, "32cfd1cf", "42cfd1cf", 1), syntheticLUKS2JSON, 1, invalid},
		{"version changed", syntheticLUKS2, syntheticLUKS2JSON, 1, invalid},
		{"slots changed", syntheticLUKS2, strings.Replace(syntheticLUKS2JSON, `,"2":{"type":"luks2"}`, "", 1), 2, invalid},
		{"tokens changed", syntheticLUKS2, `{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{}}`, 2, invalid},
		{"type changed", syntheticLUKS2, strings.Replace(syntheticLUKS2JSON, "systemd-tpm2", "systemd-fido2", 1), 2, invalid},
		{"json malformed", syntheticLUKS2, `{`, 2, invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := parseStorage(strings.NewReader(syntheticStorage)).Devices[1].Identity
			if tc.name == "version changed" {
				id.LuksVersion.Value = "1"
			}
			calls, pinned := 0, ""
			s := detailSources{
				openBlock: func(string) (*os.File, error) { return os.Open(path) },
				run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
					calls++
					if calls == 1 {
						pinned = selected.args[len(selected.args)-1]
						return consume(strings.NewReader(tc.text))
					}
					if selected.args[len(selected.args)-1] != pinned {
						t.Fatal("metadata reopened another target")
					}
					return consume(strings.NewReader(tc.metadata))
				},
			}
			collectLUKS(t.Context(), s, "sda1", id)
			if calls != tc.wantCalls || id.LuksKeyslotCount.Status != tc.wantStatus || id.LuksTokenCount.Status != tc.wantStatus {
				t.Fatalf("cross-check: calls=%d identity=%v", calls, id)
			}
			if tc.wantStatus != success && (id.LuksKeyslotCount.Value != 0 || id.LuksTokenCount.Value != 0 || id.LuksTokenTypes.Value != "") {
				t.Fatal("partial summary published after disagreement")
			}
		})
	}
}

func TestSyntheticUdevPropertyProjection(t *testing.T) {
	properties, status := parseUdevProperties(strings.NewReader("DEVNAME=/dev/sda\nID_BUS=ata\nID_REVISION=1.0\nID_SERIAL=not-an-authority-fallback\nSECRET=not-retained\n"))
	if status != success || len(properties) != 2 || properties["ID_BUS"] != "ata" || properties["ID_REVISION"] != "1.0" {
		t.Fatalf("public udev fields: %v %v", properties, status)
	}
	for _, data := range []string{"ID_BUS=ata\nID_BUS=scsi\n", "ID_REVISION=1\nID_REVISION=2\n", "broken\n", "ID_BUS=ata\x00\n"} {
		if properties, status := parseUdevProperties(strings.NewReader(data)); status != invalid || properties != nil {
			t.Fatalf("ambiguous properties: %v %v", properties, status)
		}
	}
	if properties, status := parseUdevProperties(strings.NewReader(strings.Repeat("x", maxDetailFile+1))); status != capacity || properties != nil {
		t.Fatalf("unbounded properties: %v %v", properties, status)
	}
}

func TestSyntheticLUKS1CollectionDoesNotInventTokenEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-luks1-descriptor")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	id := parseStorage(strings.NewReader(syntheticStorage)).Devices[1].Identity
	id.LuksVersion.Value = "1"
	text := "Version: 1\nUUID: " + id.LuksUuid.Value + "\n"
	for i := range 8 {
		state := "DISABLED"
		if i == 0 {
			state = "ENABLED"
		}
		text += fmt.Sprintf("Key Slot %d: %s\n", i, state)
	}
	calls := 0
	s := detailSources{
		openBlock: func(string) (*os.File, error) { return os.Open(path) },
		run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			calls++
			if len(selected.args) != 2 || selected.args[0] != "luksDump" {
				t.Fatalf("LUKS1 requested JSON: %+v", selected)
			}
			return consume(strings.NewReader(text))
		},
	}
	collectLUKS(t.Context(), s, "sda1", id)
	if calls != 1 || id.LuksVersion.Value != "1" || id.LuksKeyslotCount.Status != success || id.LuksKeyslotCount.Value != 1 || id.LuksTokenCount.Status != unavailable || id.LuksTokenTypes.Status != unavailable {
		t.Fatalf("LUKS1 capability evidence: calls=%d identity=%v", calls, id)
	}
}
