package recoveryboot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// rootDirectory requires a directory reached by a no-follow walk through
// root-owned, non-group/world-writable components.
func rootDirectory(name string) error {
	f, _, err := custody.OpenRoot(name, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	return f.Close()
}

// ProvisionKey creates exactly one new one-action key, never loads or overwrites
// a device key. The caller must register its public key with the signed handoff.
func ProvisionKey(name string) (ed25519.PrivateKey, error) {
	if err := custody.PrivateDirectory(filepath.Dir(name)); err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		clear(key)
		return nil, err
	}
	defer clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	if err := writeExclusive(name, encoded, 0600); err != nil {
		clear(key)
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(name)); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

// LoadKey cannot create state on reboot. Ordinary device keys are rejected by
// the handoff public-key binding in Stage and the recovery runtime.
func LoadKey(name string) (_ ed25519.PrivateKey, err error) {
	if err := custody.PrivateDirectory(filepath.Dir(name)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, f.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size > 4096 {
		return nil, errors.New("recoveryboot: unsafe_action_key")
	}
	data := make([]byte, st.Size)
	defer clear(data)
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("recoveryboot: invalid_action_key")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("recoveryboot: ed25519_action_key_required")
	}
	return key, nil
}

func syncDirectory(name string) (err error) {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}

func offTargetState(name string, targets []string) error {
	if err := custody.PrivateDirectory(name); err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("recoveryboot: frozen_targets_required")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(name, &fs); err != nil {
		return err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return errors.New("recoveryboot: qualified_ext4_state_required")
	}
	var state unix.Stat_t
	if err := unix.Stat(name, &state); err != nil {
		return err
	}
	stateDisks, err := backingDisks(uint64(state.Dev))
	if err != nil {
		return err
	}
	for _, target := range targets {
		var st unix.Stat_t
		if err := unix.Stat(target, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFBLK {
			return errors.New("recoveryboot: block_target_required")
		}
		disks, err := backingDisks(uint64(st.Rdev))
		if err != nil {
			return err
		}
		for disk := range disks {
			if stateDisks[disk] {
				return errors.New("recoveryboot: state_on_wipe_target")
			}
		}
	}
	return nil
}

func backingDisks(device uint64) (map[string]bool, error) {
	root, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(device), unix.Minor(device)))
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	var visit func(string, int) error
	visit = func(node string, depth int) error {
		if depth > 16 {
			return errors.New("recoveryboot: block_ancestry_depth")
		}
		if _, err := os.Stat(filepath.Join(node, "partition")); err == nil {
			return visit(filepath.Dir(node), depth+1)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		children, err := os.ReadDir(filepath.Join(node, "slaves"))
		if err != nil {
			return err
		}
		if len(children) == 0 {
			dev, err := os.ReadFile(filepath.Join(node, "dev"))
			if err != nil {
				return err
			}
			// Loop/file-backed and memory disks do not establish off-target custody.
			major, _, _ := strings.Cut(strings.TrimSpace(string(dev)), ":")
			n, err := strconv.Atoi(major)
			if err != nil || n == 7 || n == 1 {
				return errors.New("recoveryboot: unsupported_state_backing")
			}
			result[strings.TrimSpace(string(dev))] = true
			// NVMe sanitize can affect sibling namespaces. Treat the entire
			// controller as shared backing, never only a namespace's dev_t.
			if strings.HasPrefix(filepath.Base(node), "nvme") {
				result["nvme-controller:"+filepath.Dir(node)] = true
			}
		}
		for _, child := range children {
			resolved, err := filepath.EvalSymlinks(filepath.Join(node, "slaves", child.Name()))
			if err != nil {
				return err
			}
			if err := visit(resolved, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(root, 0); err != nil {
		return nil, err
	}
	return result, nil
}

// WriteCapsule persists a bounded nonsecret TPM-authenticated snapshot. The
// recoverycustody store, not this filesystem helper, owns its NV authentication.
func WriteCapsule(stateDirectory, actionID string, snapshot []byte) (string, []byte, error) {
	if !uuidText(actionID) || len(snapshot) == 0 || len(snapshot) > 4<<20 {
		return "", nil, errors.New("recoveryboot: invalid_capsule")
	}
	if err := custody.PrivateDirectory(stateDirectory); err != nil {
		return "", nil, err
	}
	name := filepath.Join(stateDirectory, "lindm-recovery-"+actionID+".capsule")
	if err := writeExclusive(name, snapshot, 0600); err != nil {
		return "", nil, err
	}
	if err := syncDirectory(stateDirectory); err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(snapshot)
	return name, digest[:], nil
}
