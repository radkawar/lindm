//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// actionBlockNode is native lsblk evidence, not a second action configuration
// schema. Parent media identity is carried to a LUKS partition explicitly.
type actionBlockNode struct {
	Path       string            `json:"path"`
	Type       string            `json:"type"`
	Size       uint64            `json:"size"`
	WWN        string            `json:"wwn"`
	Serial     string            `json:"serial"`
	UUID       string            `json:"uuid"`
	Filesystem string            `json:"fstype"`
	Children   []actionBlockNode `json:"children"`
}

type actionNativeTarget struct {
	Identity *agentv1.StorageTarget `json:"identity"`
	Path     string                 `json:"path"`
	Type     string                 `json:"type"`
}

func actionNativeTargets(data []byte) ([]actionNativeTarget, error) {
	var topology struct {
		Devices []actionBlockNode `json:"blockdevices"`
	}
	if len(data) > 1<<20 {
		return nil, errors.New("action storage topology exceeds bound")
	}
	if err := json.Unmarshal(data, &topology); err != nil {
		return nil, fmt.Errorf("decode action storage topology: %w", err)
	}
	var targets []actionNativeTarget
	var visit func([]actionBlockNode, string, string) error
	visit = func(nodes []actionBlockNode, wwn, serial string) error {
		for _, node := range nodes {
			parentWWN, parentSerial := wwn, serial
			if node.WWN != "" {
				parentWWN = node.WWN
			}
			if node.Serial != "" {
				parentSerial = node.Serial
			}
			if (node.Filesystem == "crypto_LUKS" || (node.Type == "disk" && node.Filesystem == "" && len(node.Children) == 0)) && parentWWN != "" && parentSerial != "" {
				if node.Size == 0 || !strings.HasPrefix(node.Path, "/dev/") || strings.ContainsAny(node.Path, "\n\r\x00") {
					return errors.New("invalid native block identity")
				}
				identity := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: parentWWN, Serial: parentSerial, SizeBytes: node.Size}
				if node.Filesystem == "crypto_LUKS" {
					if !vmValidID(node.UUID) {
						return errors.New("invalid native LUKS UUID")
					}
					identity.LuksUuid = node.UUID
				}
				targets = append(targets, actionNativeTarget{Identity: identity, Path: node.Path, Type: node.Type})
			}
			if err := visit(node.Children, parentWWN, parentSerial); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(topology.Devices, "", ""); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no complete native action target identity")
	}
	return targets, nil
}

// Device node numbers are boot-local, not part of approved media identity.
func actionWholeDiskPath(data []byte, expected *agentv1.StorageTarget) (string, error) {
	if len(data) > 1<<20 || expected.GetIdentityBasis() != agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL || expected.GetLuksUuid() != "" || expected.GetWwn() == "" || expected.GetSerial() == "" || expected.GetSizeBytes() == 0 {
		return "", errors.New("incomplete whole-disk identity or oversized topology")
	}
	var topology struct {
		Devices []actionBlockNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &topology); err != nil {
		return "", err
	}
	var matched string
	for _, node := range topology.Devices {
		if node.Type != "disk" || node.WWN != expected.GetWwn() || node.Serial != expected.GetSerial() || node.Size != expected.GetSizeBytes() {
			continue
		}
		if matched != "" || !strings.HasPrefix(node.Path, "/dev/") || strings.ContainsAny(node.Path, "\n\r\x00") {
			return "", errors.New("ambiguous or invalid current whole-disk path")
		}
		matched = node.Path
	}
	if matched == "" {
		return "", errors.New("approved whole-disk identity is absent after reboot")
	}
	return matched, nil
}

func observeActionTargets(ctx context.Context, vm *EncryptedVM) ([]actionNativeTarget, error) {
	data, err := vm.Run(ctx, "sudo -n lsblk --json --tree --bytes --output PATH,TYPE,SIZE,WWN,SERIAL,UUID,FSTYPE", nil)
	if err != nil {
		return nil, err
	}
	return actionNativeTargets(data)
}

// actionRecoveryText returns the literal printable recovery credential. Decoding
// hexadecimal here would test different bytes than the user receives at reveal.
func actionRecoveryText(key []byte) (string, error) {
	if len(key) != 64 {
		return "", errors.New("recovery credential is not 64 lowercase hexadecimal characters")
	}
	for _, c := range key {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("recovery credential is not canonical lowercase hexadecimal")
		}
	}
	return string(key), nil
}

// actionHeaderSlots observes independently collected, powered-off metadata.
// No recovery plaintext, ciphertext, salt, or keyslot KDF data is returned.
func actionHeaderSlots(headers []EncryptedHeader, luksUUID string) ([]uint32, error) {
	var matched *EncryptedHeader
	for i := range headers {
		if headers[i].UUID != luksUUID {
			continue
		}
		if matched != nil {
			return nil, errors.New("ambiguous out-of-band LUKS UUID")
		}
		matched = &headers[i]
	}
	if matched == nil {
		return nil, errors.New("out-of-band LUKS header missing")
	}
	var metadata struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
	}
	if err := json.Unmarshal(matched.JSON, &metadata); err != nil {
		return nil, err
	}
	slots := make([]uint32, 0, len(metadata.Keyslots))
	for slot := range metadata.Keyslots {
		value, err := strconv.ParseUint(slot, 10, 5)
		if err != nil || strconv.FormatUint(value, 10) != slot {
			return nil, errors.New("invalid out-of-band LUKS keyslot")
		}
		slots = append(slots, uint32(value))
	}
	slices.Sort(slots)
	return slots, nil
}

type actionBootEvidence struct {
	Credential string        `json:"credential_kind"`
	Boot       UnlockOutcome `json:"boot"`
	ObservedAt time.Time     `json:"observed_at"`
}

func actionRecoveryBoot(ctx context.Context, vm *EncryptedVM, key []byte, previousBoot, kind string) (*actionBootEvidence, error) {
	text, err := actionRecoveryText(key)
	if err != nil {
		return nil, err
	}
	boot, err := vm.ColdBoot(ctx, text)
	if err != nil {
		return nil, err
	}
	if !boot.Accepted || !boot.PromptSeen || boot.BootID == previousBoot {
		return nil, errors.New("recovery key did not independently unlock a new cold boot")
	}
	return &actionBootEvidence{Credential: kind, Boot: boot, ObservedAt: time.Now().UTC()}, nil
}
