// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestRecoveryHelpersFollowQualifiedOperations(t *testing.T) {
	for _, test := range []struct {
		name     string
		target   *agentv1.QualifiedActionTarget
		liveRoot bool
		want     []string
	}{
		{
			name:   "SATA overwrite",
			target: &agentv1.QualifiedActionTarget{AllowOverwrite: true},
			want:   []string{"usr/bin/lsblk"},
		},
		{
			name:   "NVMe format",
			target: &agentv1.QualifiedActionTarget{NativeSanitizeMethods: []agentv1.SanitizeMethod{agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA}},
			want:   []string{"usr/bin/lsblk"},
		},
		{
			name:   "LUKS observation",
			target: &agentv1.QualifiedActionTarget{Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: "12345678-1234-1234-1234-123456789abc", Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}},
			want:   []string{"usr/bin/lsblk", "usr/sbin/cryptsetup"},
		},
		{
			name:   "offline crypto erase",
			target: &agentv1.QualifiedActionTarget{AllowCryptoErase: true},
			want:   []string{"usr/bin/lsblk", "usr/sbin/cryptsetup"},
		},
		{
			name:     "live root mapping observation",
			target:   &agentv1.QualifiedActionTarget{AllowCryptoErase: true},
			liveRoot: true,
			want:     []string{"usr/bin/lsblk", "usr/sbin/cryptsetup", "usr/sbin/dmsetup"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &agentv1.RecoveryRuntimeConfig{Provider: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{test.target, test.target}, AllowLiveRootCryptoErase: test.liveRoot}}
			required := RequiredNativeHelpers(config)
			if !slices.Equal(required, test.want) {
				t.Fatalf("required helpers = %v, want %v", required, test.want)
			}
			files := make([]Ingredient, len(required))
			for i, name := range required {
				files[i] = Ingredient{Destination: name, Executable: true}
			}
			if err := requireNativeHelpers(files, required); err != nil {
				t.Fatalf("exact helper set rejected: %v", err)
			}
			for i, name := range required {
				files[i].Executable = false
				if err := requireNativeHelpers(files, required); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("missing executable %s not refused: %v", name, err)
				}
				files[i].Executable = true
			}
		})
	}
}

func TestBuildClosureRequiresConfiguredMethodBeforeELFValidation(t *testing.T) {
	runtime := &agentv1.RecoveryRuntimeConfig{BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, Provider: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{AllowCryptoErase: true}}}}
	data, err := protojson.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	config := fixtureIngredient(t, t.TempDir(), "recovery.json", data)
	// These are ingredient declarations, not fake native executables. The build
	// must reject the absent method helper before inspecting any ELF payload.
	files := []Ingredient{{Destination: "usr/bin/lsblk", Executable: true}}
	if err := validateBuildClosure(config, files, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI); err == nil || !strings.Contains(err.Error(), "required_native_helper_missing: usr/sbin/cryptsetup") {
		t.Fatalf("crypto erase qualification accepted without its native helper: %v", err)
	}
	if err := validateBuildClosure(config, files, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB); err == nil || !strings.Contains(err.Error(), "runtime_boot_mode_mismatch") {
		t.Fatalf("UKI runtime configuration accepted in a measured build: %v", err)
	}
}

func TestBuildClosureRejectsUnknownRuntimeFields(t *testing.T) {
	config := fixtureIngredient(t, t.TempDir(), "recovery.json", []byte(`{"unknownMethod":true}`))
	if err := validateBuildClosure(config, nil, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI); err == nil || !strings.Contains(err.Error(), "decode_runtime_config") {
		t.Fatalf("unknown runtime field accepted: %v", err)
	}
}

func TestELFClosureRequiresExecutableInterpreter(t *testing.T) {
	// Minimal valid ELF files isolate interpreter admission from host libc and
	// external tool availability. No fixture binary is executed.
	ingredient := func(name, interpreter string) Ingredient {
		t.Helper()
		header := elf.Header64{
			Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
			Type:  uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1, Ehsize: 64,
		}
		if interpreter != "" {
			header.Phoff, header.Phentsize, header.Phnum = 64, 56, 1
		}
		var payload bytes.Buffer
		if err := binary.Write(&payload, binary.LittleEndian, header); err != nil {
			t.Fatal(err)
		}
		if interpreter != "" {
			segment := elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 120, Filesz: uint64(len(interpreter) + 1), Align: 1}
			if err := binary.Write(&payload, binary.LittleEndian, segment); err != nil {
				t.Fatal(err)
			}
			payload.WriteString(interpreter + "\x00")
		}
		return fixtureIngredient(t, t.TempDir(), name, payload.Bytes())
	}
	helper := ingredient("helper", "/lib64/ld-test.so")
	loader := ingredient("loader", "")
	files := []Ingredient{
		{Source: helper.Source, Destination: "usr/bin/lsblk", Executable: true},
		{Source: loader.Source, Destination: "lib64/ld-test.so"},
	}
	if err := validateClosure(files); err == nil || !strings.Contains(err.Error(), "non_executable_elf_interpreter: /lib64/ld-test.so") {
		t.Fatalf("non-executable loader admitted: %v", err)
	}
	files[1].Executable = true
	if err := validateClosure(files); err != nil {
		t.Fatalf("complete executable interpreter rejected: %v", err)
	}
}
