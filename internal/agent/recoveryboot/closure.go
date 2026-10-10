package recoveryboot

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// validateClosure does not run ldd or any ingredient binary. ELF interpreters and
// DT_NEEDED libraries must resolve inside the explicitly approved file closure.
// dlopen modules remain explicit release ingredients, not discovered host files.
func validateClosure(files []Ingredient) error {
	byPath := make(map[string]Ingredient, len(files))
	for _, file := range files {
		byPath[file.Destination] = file
	}
	for _, required := range []string{"usr/bin/sbverify", "usr/bin/lsblk", "usr/sbin/cryptsetup", "usr/sbin/dmsetup", "usr/sbin/nvme"} {
		file, ok := byPath[required]
		if !ok || !file.Executable {
			return fmt.Errorf("recoveryboot: required_native_helper_missing: %s", required)
		}
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
			if _, ok := byPath[strings.TrimPrefix(name, "/")]; !ok {
				return errors.Join(fmt.Errorf("recoveryboot: missing_elf_interpreter: %s", name), binary.Close())
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
