// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func persistentVMTestState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	golden, dir := filepath.Join(root, "golden-test"), filepath.Join(root, "desktop")
	for _, path := range []string{golden, filepath.Join(golden, "tpm"), dir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"disk.qcow2", "nvram.fd", "firmware-code.fd", "tpm/state"} {
		if err := os.WriteFile(filepath.Join(golden, name), []byte("original "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := encryptedStateDigests(golden)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(&encryptedGoldenState{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(golden, "state.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lindm-persistent-vm"), []byte(persistentVMMarker), 0600); err != nil {
		t.Fatal(err)
	}
	state := &persistentVMState{Version: 1, Golden: golden, GoldenSHA256: files["disk.qcow2"]}
	if err := writePersistentJSON(dir, "vm.json", state); err != nil {
		t.Fatal(err)
	}
	key, _, err := encryptedKey()
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := encryptedKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"owner-secret": []byte("private-owner-secret"), "ssh-key": key, "ssh-host-key": host, "disk.qcow2": []byte("overlay")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pin := persistentGoldenPin(golden, dir)
	if err := os.MkdirAll(filepath.Dir(pin), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pin, []byte(dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, golden
}

func TestPersistentVMCloseRetainsIdentityAndDestroyUnpins(t *testing.T) {
	dir, golden := persistentVMTestState(t)
	vm, err := ResumePersistentVM(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if vm.InitialUnlockSecret() != "private-owner-secret" {
		t.Fatal("owner unlock secret changed")
	}
	if err := vm.SavePersistentDevice(&PersistentDevice{DeviceID: "same-device", DesktopPassword: "private-desktop"}); err != nil {
		t.Fatal(err)
	}
	if err := vm.SavePersistentDevice(&PersistentDevice{DeviceID: "different-device"}); err == nil {
		t.Fatal("replaced enrolled identity")
	}
	if _, err := ResumePersistentVM(context.Background(), dir); err == nil {
		t.Fatal("opened an in-use VM")
	}
	if err := DestroyPersistentVM(dir); err == nil {
		t.Fatal("destroyed in-use VM")
	}
	if err := vm.Close(); err != nil {
		t.Fatal(err)
	}
	vm, err = ResumePersistentVM(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	device, err := vm.PersistentDevice()
	if err != nil || device.DeviceID != "same-device" || device.DesktopPassword != "private-desktop" {
		t.Fatalf("lost saved identity: %v", err)
	}
	if err := vm.Close(); err != nil {
		t.Fatal(err)
	}
	if err := DestroyPersistentVM(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, persistentGoldenPin(golden, dir)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned path retained: %s: %v", path, err)
		}
	}
	if _, err := os.Stat(golden); err != nil {
		t.Fatal("destroy removed backing golden", err)
	}
	if err := DestroyPersistentVM(dir); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentVMRefusesMissingOrChangedGolden(t *testing.T) {
	for _, change := range []string{"missing", "changed", "republished", "unreferenced"} {
		t.Run(change, func(t *testing.T) {
			dir, golden := persistentVMTestState(t)
			switch change {
			case "missing":
				if err := os.RemoveAll(golden); err != nil {
					t.Fatal(err)
				}
			case "unreferenced":
				if err := os.Remove(persistentGoldenPin(golden, dir)); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(golden, "disk.qcow2"), []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				if change == "republished" {
					files, err := encryptedStateDigests(golden)
					if err != nil {
						t.Fatal(err)
					}
					if err := writePersistentJSON(golden, "state.json", &encryptedGoldenState{Files: files}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if vm, err := ResumePersistentVM(context.Background(), dir); err == nil {
				_ = vm.Close()
				t.Fatal("accepted missing or changed backing golden")
			}
		})
	}
}

func TestPersistentVMRefusesUnownedAndPublicState(t *testing.T) {
	dir, _ := persistentVMTestState(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if err := DestroyPersistentVM(alias); err == nil {
		t.Fatal("destroy accepted symlink")
	}
	if err := os.Chmod(filepath.Join(dir, "owner-secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if vm, err := ResumePersistentVM(context.Background(), dir); err == nil {
		_ = vm.Close()
		t.Fatal("accepted publicly readable owner secret")
	}
	if err := os.Remove(filepath.Join(dir, ".lindm-persistent-vm")); err != nil {
		t.Fatal(err)
	}
	if err := DestroyPersistentVM(dir); err == nil {
		t.Fatal("removed unmarked directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "disk.qcow2")); err != nil {
		t.Fatal("refusal removed disk", err)
	}
}

func TestPersistentGoldenReferencePath(t *testing.T) {
	golden := filepath.Join(t.TempDir(), "golden-pinned")
	a := persistentGoldenPin(golden, "/private/demos/a/desktop")
	b := persistentGoldenPin(golden, "/private/demos/b/desktop")
	if a == b || !strings.Contains(a, "/.references/golden-pinned/") {
		t.Fatal("references do not distinguish machine owners")
	}
}
