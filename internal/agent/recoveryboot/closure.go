// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// RequiredNativeHelpers returns initramfs-relative paths for the configured
// recovery operations. This selects dependencies, not execution authority.
// Direct overwrite/discard and native NVMe admin commands use Go I/O/ioctl,
// and image Authenticode verification is in-process.
func RequiredNativeHelpers(config *agentv1.RecoveryRuntimeConfig) []string {
	required := []string{"usr/bin/lsblk"}
	provider := config.GetProvider()
	var luks bool
	for _, target := range provider.GetTargets() {
		luks = luks || target.GetTarget().GetLuksUuid() != "" || target.GetAllowCryptoErase()
	}
	if luks {
		required = append(required, "usr/sbin/cryptsetup")
	}
	if provider.GetAllowLiveRootCryptoErase() {
		required = append(required, "usr/sbin/dmsetup")
	}
	return required
}

func validateBuildClosure(config Ingredient, files []Ingredient, mode agentv1.RecoveryBootMode) error {
	input, err := os.Open(config.Source)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err = errors.Join(err, input.Close()); err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("recoveryboot: runtime_config_too_large")
	}
	runtime := new(agentv1.RecoveryRuntimeConfig)
	if err := protojson.Unmarshal(data, runtime); err != nil {
		return fmt.Errorf("recoveryboot: decode_runtime_config: %w", err)
	}
	if runtime.GetBootMode() != mode {
		return errors.New("recoveryboot: runtime_boot_mode_mismatch")
	}
	if err := requireNativeHelpers(files, RequiredNativeHelpers(runtime)); err != nil {
		return err
	}
	return validateClosure(files)
}

func requireNativeHelpers(files []Ingredient, required []string) error {
	for _, name := range required {
		found := false
		for _, file := range files {
			if file.Destination == name && file.Executable {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("recoveryboot: required_native_helper_missing: %s", name)
		}
	}
	return nil
}

// validateClosure does not run ldd or any ingredient binary. ELF interpreters and
// DT_NEEDED libraries must resolve inside the explicitly approved file closure.
// dlopen modules remain explicit release ingredients, not discovered host files.
func validateClosure(files []Ingredient) error {
	if err := requireNativeHelpers(files, RequiredNativeHelpers(nil)); err != nil {
		return err
	}
	byPath := make(map[string]Ingredient, len(files))
	for _, file := range files {
		byPath[file.Destination] = file
	}
	for _, file := range files {
		binary, err := elf.Open(file.Source)
		if err != nil {
			if file.Executable {
				return fmt.Errorf("recoveryboot: native_helper_not_elf: %s", file.Destination)
			}
			continue
		}
		libraries, libraryErr := binary.ImportedLibraries()
		if libraryErr != nil {
			return errors.Join(libraryErr, binary.Close())
		}
		for _, segment := range binary.Progs {
			if segment.Type != elf.PT_INTERP {
				continue
			}
			interpreter, err := io.ReadAll(io.LimitReader(segment.Open(), 4097))
			if err != nil {
				return errors.Join(err, binary.Close())
			}
			name := strings.TrimSuffix(string(interpreter), "\x00")
			if len(interpreter) > 4096 || !strings.HasPrefix(name, "/") {
				return errors.Join(errors.New("recoveryboot: invalid_elf_interpreter"), binary.Close())
			}
			loader, ok := byPath[strings.TrimPrefix(name, "/")]
			if !ok {
				return errors.Join(fmt.Errorf("recoveryboot: missing_elf_interpreter: %s", name), binary.Close())
			}
			if !loader.Executable {
				return errors.Join(fmt.Errorf("recoveryboot: non_executable_elf_interpreter: %s", name), binary.Close())
			}
		}
		for _, library := range libraries {
			found := false
			for candidate := range byPath {
				// Standard loader directories only; no host ld.so.cache dependency.
				dir := path.Dir(candidate)
				if path.Base(candidate) == library && (dir == "lib" || dir == "lib64" || dir == "usr/lib" || dir == "usr/lib64" || strings.HasPrefix(dir, "lib/") || strings.HasPrefix(dir, "usr/lib/")) {
					found = true
					break
				}
			}
			if !found {
				return errors.Join(fmt.Errorf("recoveryboot: missing_elf_library: %s", library), binary.Close())
			}
		}
		if err := binary.Close(); err != nil {
			return err
		}
	}
	return nil
}
