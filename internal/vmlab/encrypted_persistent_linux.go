//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

const persistentVMMarker = "lindm persistent encrypted VM v1\n"

// PersistentDevice records the enrolled identity, never a replacement enrollment.
type PersistentDevice struct {
	DeviceID        string `json:"device_id"`
	DesktopPassword string `json:"desktop_password,omitempty"`
	TPMActionID     string `json:"tpm_action_id,omitempty"`
	// DesktopPrepared records completed one-time lab desktop provisioning.
	DesktopPrepared bool `json:"desktop_prepared,omitempty"`
}

type persistentVMState struct {
	Version      int                        `json:"version"`
	ImageID      string                     `json:"image_id"`
	ImageSHA256  string                     `json:"image_sha256"`
	Golden       string                     `json:"golden"`
	GoldenSHA256 string                     `json:"golden_sha256"`
	Hardware     VMHardwareOptions          `json:"hardware"`
	Firmware     *EncryptedFirmwareEvidence `json:"firmware"`
	CacheDir     string                     `json:"cache_dir"`
}

// ProvisionPersistentVM creates a powered-off machine in a new private directory.
// Its cache reference survives Stop and Close; only DestroyPersistentVM removes it.
func ProvisionPersistentVM(ctx context.Context, manifest *labv1.ImageManifest, options EncryptedVMOptions, dir string) (_ *EncryptedVM, err error) {
	hardware, err := encryptedMachineHardware(manifest, options)
	if err != nil {
		return nil, err
	}
	hardware.Desktop = hardware.Desktop || options.Desktop != ""
	golden, err := encryptedGolden(ctx, manifest, options)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	lock, err := lockPersistentVM(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	var pin string
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(dir))
			if pin != "" {
				err = errors.Join(err, os.Remove(pin))
			}
		}
	}()
	if err = os.WriteFile(filepath.Join(dir, ".lindm-persistent-vm"), []byte(persistentVMMarker), 0600); err != nil {
		return nil, err
	}
	v := &EncryptedVM{dir: dir, initialSecret: golden.Secret, firmware: golden.Firmware, cacheDir: options.CacheDir, hardware: hardware, persistentLock: lock}
	// References live outside the entry: a missing pinned golden must never be
	// silently rebuilt beneath an existing qcow2 backing chain.
	pin = persistentGoldenPin(golden.Dir, dir)
	if err = os.MkdirAll(filepath.Dir(pin), 0700); err != nil {
		return nil, err
	}
	if err = os.WriteFile(pin, []byte(dir+"\n"), 0600); err != nil {
		return nil, err
	}
	digest, err := encryptedFileDigest(filepath.Join(golden.Dir, "disk.qcow2"))
	if err != nil {
		return nil, err
	}
	state := persistentVMState{Version: 1, ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), Golden: golden.Dir, GoldenSHA256: digest, Hardware: hardware, Firmware: golden.Firmware, CacheDir: options.CacheDir}
	if err = writePersistentJSON(dir, "vm.json", &state); err != nil {
		return nil, err
	}
	if err = copyEncryptedState(golden.Dir, dir); err != nil {
		return nil, err
	}
	if _, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "-F", "qcow2", "-b", filepath.Join(golden.Dir, "disk.qcow2"), "disk.qcow2"); err != nil {
		return nil, err
	}
	if err = os.Chmod(filepath.Join(dir, "disk.qcow2"), 0600); err != nil {
		return nil, err
	}
	for i := range hardware.ExtraDisks {
		name := fmt.Sprintf("extra-%d.qcow2", i)
		if _, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", name, "1G"); err != nil {
			return nil, err
		}
		if err = os.Chmod(filepath.Join(dir, name), 0600); err != nil {
			return nil, err
		}
	}
	for name, data := range map[string][]byte{"owner-secret": []byte(golden.Secret), "ssh-key": golden.LoginKey, "ssh-host-key": golden.HostKey} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, err
		}
	}
	v.config, err = encryptedSSHConfig(golden.LoginKey, golden.HostKey)
	return v, err
}

// ResumePersistentVM opens a stopped machine without changing its identity. Boot
// remains explicit: ColdBoot with InitialUnlockSecret is the current owner-unlock
// seam; a product TPM-binding action may replace that boot policy later.
func ResumePersistentVM(ctx context.Context, dir string) (_ *EncryptedVM, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	lock, err := lockPersistentVM(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	if err = checkPersistentVMDirectory(dir); err != nil {
		return nil, err
	}
	state, err := readPersistentVMState(dir)
	if err != nil {
		return nil, err
	}
	if err = verifyPersistentGolden(dir, state); err != nil {
		return nil, err
	}
	secret, err := readPersistentPrivate(dir, "owner-secret")
	if err != nil {
		return nil, err
	}
	login, err := readPersistentPrivate(dir, "ssh-key")
	if err != nil {
		return nil, err
	}
	host, err := readPersistentPrivate(dir, "ssh-host-key")
	if err != nil {
		return nil, err
	}
	config, err := encryptedSSHConfig(login, host)
	if err != nil {
		return nil, err
	}
	return &EncryptedVM{dir: dir, initialSecret: string(secret), firmware: state.Firmware, config: config, cacheDir: state.CacheDir, hardware: state.Hardware, persistentLock: lock}, nil
}

func checkPersistentVMDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("persistent VM requires a private 0700 directory, not a symlink")
	}
	marker, err := readPersistentPrivate(dir, ".lindm-persistent-vm")
	if err != nil {
		return err
	}
	if string(marker) != persistentVMMarker {
		return errors.New("not a lindm persistent VM directory")
	}
	return nil
}

func lockPersistentVM(dir string) (*os.File, error) {
	file, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(errors.New("persistent VM is already in use"), err, file.Close())
	}
	return file, nil
}

func readPersistentPrivate(dir, name string) ([]byte, error) {
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("persistent VM state must be a private regular file")
	}
	return readRegular(filepath.Join(dir, name), 1<<20)
}

func readPersistentVMState(dir string) (*persistentVMState, error) {
	data, err := readPersistentPrivate(dir, "vm.json")
	if err != nil {
		return nil, err
	}
	var state persistentVMState
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 || !filepath.IsAbs(state.Golden) || !strings.HasPrefix(filepath.Base(state.Golden), "golden-") || len(state.GoldenSHA256) != 64 {
		return nil, errors.New("invalid persistent VM state")
	}
	return &state, nil
}

func persistentGoldenPin(golden, dir string) string {
	digest := sha256.Sum256([]byte(dir))
	return filepath.Join(filepath.Dir(golden), ".references", filepath.Base(golden), hex.EncodeToString(digest[:]))
}

func verifyPersistentGolden(dir string, state *persistentVMState) error {
	pin, err := readPersistentPrivate(filepath.Dir(persistentGoldenPin(state.Golden, dir)), filepath.Base(persistentGoldenPin(state.Golden, dir)))
	if err != nil {
		return fmt.Errorf("read persistent golden reference: %w", err)
	}
	if string(pin) != dir+"\n" {
		return errors.New("persistent golden reference changed")
	}
	golden, err := loadEncryptedGolden(state.Golden)
	if err != nil {
		return fmt.Errorf("persistent backing golden missing or changed: %w", err)
	}
	if golden.Files["disk.qcow2"] != state.GoldenSHA256 {
		return errors.New("persistent backing golden digest changed")
	}
	return nil
}

func writePersistentJSON(dir, name string, value any) (err error) {
	file, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(file.Name()))
		}
	}()
	encodeErr := json.NewEncoder(file).Encode(value)
	if err = errors.Join(encodeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

// PersistentDevice returns the saved enrollment; absent means first enrollment.
func (v *EncryptedVM) PersistentDevice() (*PersistentDevice, error) {
	data, err := readPersistentPrivate(v.dir, "device.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var device PersistentDevice
	if err := json.Unmarshal(data, &device); err != nil {
		return nil, err
	}
	if device.DeviceID == "" {
		return nil, errors.New("persistent device record has no identity")
	}
	return &device, nil
}

// SavePersistentDevice atomically records enrollment and private desktop access.
func (v *EncryptedVM) SavePersistentDevice(device *PersistentDevice) error {
	if v.persistentLock == nil || device == nil || device.DeviceID == "" {
		return errors.New("saving a persistent device requires an owned VM and enrolled identity")
	}
	old, err := v.PersistentDevice()
	if err != nil {
		return err
	}
	if old != nil && old.DeviceID != device.DeviceID {
		return errors.New("persistent device identity cannot be replaced")
	}
	return writePersistentJSON(v.dir, "device.json", device)
}

// Stop requests ACPI shutdown for at most 45 seconds, then cuts power and joins
// only this machine's QEMU/swtpm. It never removes persistent machine state.
func (v *EncryptedVM) Stop(ctx context.Context) error {
	if v.guest != nil {
		shutdown, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := v.guest.qmpCommand(shutdown, map[string]any{"execute": "system_powerdown", "id": "powerdown"}); err == nil {
			select {
			case <-v.guest.done:
			case <-shutdown.Done():
			}
		}
	}
	return v.Kill()
}

// DestroyPersistentVM refuses unowned or running directories and removes only
// the named stopped machine plus its exact golden reference. Missing is success.
func DestroyPersistentVM(dir string) (err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	lock, err := lockPersistentVM(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err = checkPersistentVMDirectory(dir); errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(dir); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return err
	} else if err != nil {
		return err
	}
	state, err := readPersistentVMState(dir)
	if err != nil {
		return err
	}
	if err = os.RemoveAll(dir); err != nil {
		return err
	}
	if err = os.Remove(persistentGoldenPin(state.Golden, dir)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
