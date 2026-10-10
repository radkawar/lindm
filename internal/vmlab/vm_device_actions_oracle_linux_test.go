//go:build linux

package vmlab

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestActionRecoveryTextPreservesLiteralHex(t *testing.T) {
	key := strings.Repeat("ab", 32)
	got, err := actionRecoveryText([]byte(key))
	if err != nil || got != key || len(got) != 64 {
		t.Fatalf("literal recovery credential changed: length=%d err=%v", len(got), err)
	}
	for _, invalid := range []string{strings.Repeat("AB", 32), key + "\n", key[:32], strings.Repeat("g", 64)} {
		if _, err := actionRecoveryText([]byte(invalid)); err == nil {
			t.Fatal("accepted noncanonical recovery credential")
		}
	}
}

func TestActionNativeTargetsInheritExactParentIdentity(t *testing.T) {
	data := []byte(`{"blockdevices":[{"path":"/dev/sda","type":"disk","size":1073741824,"wwn":"0x5000000000000001","serial":"lindm-lab-0","children":[{"path":"/dev/sda3","type":"part","size":1000000000,"uuid":"11111111-1111-4111-8111-111111111111","fstype":"crypto_LUKS"}]},{"path":"/dev/sdb","type":"disk","size":1073741824,"wwn":"0x5000000000000002","serial":"lindm-lab-1"}]}`)
	targets, err := actionNativeTargets(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].Identity.GetSerial() != "lindm-lab-0" || targets[0].Identity.GetWwn() != "0x5000000000000001" || targets[0].Identity.GetSizeBytes() != 1000000000 || targets[0].Identity.GetLuksUuid() == "" || targets[1].Identity.GetLuksUuid() != "" {
		t.Fatalf("wrong native identity selection: %+v", targets)
	}
	if _, err := actionNativeTargets([]byte(`{"blockdevices":[{"path":"/dev/vda","type":"disk","size":1000,"serial":"no-wwn"}]}`)); err == nil {
		t.Fatal("accepted incomplete media identity")
	}
}

func TestActionHeaderSlotsRequireExactUniqueUUID(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	header := EncryptedHeader{UUID: uuid, JSON: json.RawMessage(`{"keyslots":{"0":{},"3":{}}}`)}
	slots, err := actionHeaderSlots([]EncryptedHeader{header}, uuid)
	if err != nil || len(slots) != 2 || !slices.Contains(slots, 0) || !slices.Contains(slots, 3) {
		t.Fatalf("keyslot oracle: %v %v", slots, err)
	}
	if _, err := actionHeaderSlots(nil, uuid); err == nil {
		t.Fatal("missing header was accepted")
	}
	if _, err := actionHeaderSlots([]EncryptedHeader{header, header}, uuid); err == nil {
		t.Fatal("duplicate UUID was accepted")
	}
	header.JSON = json.RawMessage(`{"keyslots":{"32":{}}}`)
	if _, err := actionHeaderSlots([]EncryptedHeader{header}, uuid); err == nil {
		t.Fatal("invalid keyslot was accepted")
	}
}

func TestLiveEraseResultsRequireEveryFrozenTargetAndNativeProof(t *testing.T) {
	targets := []*agentv1.StorageTarget{{Wwn: "root", Serial: "root", SizeBytes: 4096, LuksUuid: "root-uuid"}, {Wwn: "data", Serial: "data", SizeBytes: 8192, LuksUuid: "data-uuid"}}
	root := &agentv1.CryptoEraseTargetResult{Target: targets[0], HeaderBytes: 4096, NativeLuksErase: true, RawZeroVerified: true, MetadataAbsent: true}
	data := &agentv1.CryptoEraseTargetResult{Target: targets[1], HeaderBytes: 4096, NativeLuksErase: true, RawZeroVerified: true, MetadataAbsent: true}
	if err := validateLiveEraseResults(targets, []*agentv1.CryptoEraseTargetResult{data, root}); err != nil {
		t.Fatal(err)
	}
	for name, results := range map[string][]*agentv1.CryptoEraseTargetResult{"missing": {root}, "duplicate": {root, root}, "unexpected": {root, {Target: &agentv1.StorageTarget{Wwn: "different"}}}} {
		t.Run(name, func(t *testing.T) {
			if err := validateLiveEraseResults(targets, results); err == nil {
				t.Fatal("accepted incomplete aggregate result")
			}
		})
	}
	for _, missing := range []string{"native", "zero", "metadata", "extent"} {
		t.Run(missing, func(t *testing.T) {
			invalid := proto.CloneOf(data)
			switch missing {
			case "native":
				invalid.NativeLuksErase = false
			case "zero":
				invalid.RawZeroVerified = false
			case "metadata":
				invalid.MetadataAbsent = false
			case "extent":
				invalid.HeaderBytes = 0
			}
			if err := validateLiveEraseResults(targets, []*agentv1.CryptoEraseTargetResult{root, invalid}); err == nil {
				t.Fatal("accepted missing native proof")
			}
		})
	}
}
