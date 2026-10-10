//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The key signs only this run's owned firmware-db boot artifacts. It is never
// installed in the host firmware, copied into the guest, or included in evidence.
type actionBootSigner struct {
	dir, key, certificate string
	certificateSHA256     []byte
}

func newActionBootSigner(workDir string) (_ *actionBootSigner, err error) {
	dir, err := os.MkdirTemp(workDir, "lindm-native-owned-boot-")
	if err != nil {
		return nil, err
	}
	signer := &actionBootSigner{dir: dir, key: filepath.Join(dir, "signing.key"), certificate: filepath.Join(dir, "signing.pem")}
	defer func() {
		if err != nil {
			err = errors.Join(err, signer.Close())
		}
	}()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "lindm disposable native recovery " + uuid.NewString()}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(privateDER)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privatePEM)
	if err := os.WriteFile(signer.key, privatePEM, 0600); err != nil {
		return nil, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(signer.certificate, publicPEM, 0600); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(publicPEM)
	signer.certificateSHA256 = append([]byte(nil), digest[:]...)
	return signer, nil
}

func (s *actionBootSigner) Close() error { return os.RemoveAll(s.dir) }

func (s *actionBootSigner) sign(ctx context.Context, input, output string) error {
	if _, err := hostCommand(ctx, s.dir, "sbsign", nil, "--key", s.key, "--cert", s.certificate, "--output", output, input); err != nil {
		return err
	}
	_, err := hostCommand(ctx, s.dir, "sbverify", nil, "--cert", s.certificate, output)
	return err
}

type actionBoundedFileWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *actionBoundedFileWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("native boot artifact exceeds transfer bound")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}

// Transfers public package bytes over the existing pinned SSH transport without
// buffering a distro initramfs/UKI in memory or creating another VM implementation.
func downloadActionBootFile(ctx context.Context, vm *guestVM, source, destination string, limit int64) (digest []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if vm.client == nil {
		return nil, errors.New("native artifact transfer requires pinned SSH")
	}
	stop := context.AfterFunc(ctx, func() { _ = vm.client.Close() })
	defer stop()
	session, err := vm.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	session.Stdout = &actionBoundedFileWriter{writer: io.MultiWriter(file, hash), remaining: limit}
	session.Stderr = io.Discard
	if err := session.Run("sudo -n cat -- " + nativeQuote(source)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func uploadActionBootFile(ctx context.Context, vm *guestVM, source, destination string) (err error) {
	file, err := openRegular(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	command := "umask 077; set -C; cat > " + nativeQuote(destination) + "; printf '%s  %s\\n' " + nativeQuote(hex.EncodeToString(hash.Sum(nil))) + " " + nativeQuote(destination) + " | sha256sum --check --status"
	_, err = vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), file, 4096, 3*time.Minute)
	return err
}

type actionOwnedBootEvidence struct {
	OriginalBootID    string             `json:"original_boot_id"`
	ConvertedBootID   string             `json:"converted_boot_id"`
	KernelRelease     string             `json:"kernel_release"`
	SignerPEMSHA256   string             `json:"signer_pem_sha256"`
	SystemdBootSHA256 string             `json:"signed_systemd_boot_sha256"`
	OrdinaryUKISHA256 string             `json:"signed_ordinary_uki_sha256"`
	LoaderStatus      string             `json:"loader_status"`
	LoaderInfo        string             `json:"running_loader_info"`
	SecureBoot        bool               `json:"secure_boot"`
	SetupMode         bool               `json:"setup_mode"`
	StateUUID         string             `json:"off_target_state_uuid"`
	OriginalTarget    actionNativeTarget `json:"original_unencrypted_target"`
	StateTarget       actionNativeTarget `json:"off_target_state_target"`
}

func actionOwnedCloudTargets(ctx context.Context, vm *guestVM) (*actionNativeTarget, *actionNativeTarget, error) {
	data, err := vm.run(ctx, "lsblk --json --tree --bytes --output PATH,TYPE,SIZE,WWN,SERIAL,UUID,FSTYPE", nil, 1<<20, 15*time.Second)
	if err != nil {
		return nil, nil, err
	}
	var topology struct {
		Devices []actionBlockNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &topology); err != nil {
		return nil, nil, err
	}
	var root, state *actionNativeTarget
	for _, node := range topology.Devices {
		if node.Serial != "lindm-lab-0" && node.Serial != "lindm-lab-1" {
			continue
		}
		if node.Type != "disk" || node.WWN == "" || node.Size == 0 || !strings.HasPrefix(node.Path, "/dev/") {
			return nil, nil, errors.New("owned cloud disk has incomplete native identity")
		}
		target := &actionNativeTarget{Identity: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: node.WWN, Serial: node.Serial, SizeBytes: node.Size}, Path: node.Path, Type: node.Type}
		if node.Serial == "lindm-lab-0" {
			if root != nil || len(node.Children) == 0 || node.Filesystem == "crypto_LUKS" {
				return nil, nil, errors.New("ambiguous original unencrypted cloud root")
			}
			for _, partition := range node.Children {
				if partition.Filesystem == "crypto_LUKS" {
					return nil, nil, errors.New("original recovery target is encrypted")
				}
			}
			root = target
		} else {
			if state != nil || len(node.Children) != 0 || node.Filesystem != "" {
				return nil, nil, errors.New("off-target state disk is not a fresh owned extra disk")
			}
			state = target
		}
	}
	if root == nil || state == nil {
		return nil, nil, errors.New("owned original root and independent state media are required")
	}
	return root, state, nil
}

// Conversion touches only this disposable guest's ESP, fstab and private NVRAM.
// The baseline vendor golden and host boot configuration remain unchanged.
func provisionActionOwnedBoot(ctx context.Context, vm *guestVM, distribution string, signer *actionBootSigner) (_ *actionOwnedBootEvidence, err error) {
	evidence := &actionOwnedBootEvidence{SignerPEMSHA256: hex.EncodeToString(signer.certificateSHA256)}
	root, state, err := actionOwnedCloudTargets(ctx, vm)
	if err != nil {
		return evidence, err
	}
	evidence.OriginalTarget, evidence.StateTarget = *root, *state
	install := ""
	switch distribution {
	case "ubuntu":
		install = "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y systemd-boot systemd-boot-efi systemd-ukify sbsigntool busybox-static cryptsetup-bin dmsetup nvme-cli e2fsprogs kmod zstd"
	case "fedora":
		install = "dnf -y install systemd-boot-unsigned systemd-ukify sbsigntools busybox cryptsetup device-mapper nvme-cli e2fsprogs kmod zstd"
	default:
		return evidence, errors.New("owned boot fixture requires a maintained Ubuntu/Fedora package recipe")
	}
	installed, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(install), nil, 1<<20, 15*time.Minute)
	if err != nil {
		return evidence, err
	}
	if installed.ExitCode != 0 {
		return evidence, fmt.Errorf("install owned boot prerequisites: guest exit %d: %s", installed.ExitCode, installed.Stderr)
	}
	initial, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id; uname -r", nil, 4096, 10*time.Second)
	if err != nil {
		return evidence, err
	}
	fields := strings.Fields(string(initial))
	if len(fields) != 2 || !vmValidID(fields[0]) || strings.ContainsAny(fields[1], "/\\\x00") {
		return evidence, errors.New("invalid original guest boot identity")
	}
	evidence.OriginalBootID, evidence.KernelRelease = fields[0], fields[1]
	loader, stub, fallback := "systemd-bootx64.efi", "linuxx64.efi.stub", "BOOTX64.EFI"
	if vm.hardware.Architecture == "aarch64" {
		loader, stub, fallback = "systemd-bootaa64.efi", "linuxaa64.efi.stub", "BOOTAA64.EFI"
	}
	initrd := "/boot/initrd.img-" + evidence.KernelRelease
	if distribution == "fedora" {
		initrd = "/boot/initramfs-" + evidence.KernelRelease + ".img"
	}
	prepare := "install -d -m 0700 /run/lindm-native-owned-boot; test -d /boot/efi/EFI; mount -o remount,umask=0077 /boot/efi; ukify build --linux=" + nativeQuote("/boot/vmlinuz-"+evidence.KernelRelease) + " --initrd=" + nativeQuote(initrd) + " --stub=" + nativeQuote("/usr/lib/systemd/boot/efi/"+stub) + " --cmdline=@/proc/cmdline --output=/run/lindm-native-owned-boot/ordinary-unsigned.efi"
	prepared, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(prepare), nil, 8192, 3*time.Minute)
	if err != nil {
		return evidence, err
	}
	if prepared.ExitCode != 0 {
		return evidence, fmt.Errorf("build owned ordinary UKI: guest exit %d: %s", prepared.ExitCode, prepared.Stderr)
	}
	for _, item := range []struct{ source, name string }{{"/usr/lib/systemd/boot/efi/" + loader, "loader"}, {"/run/lindm-native-owned-boot/ordinary-unsigned.efi", "ordinary"}} {
		unsigned := filepath.Join(signer.dir, item.name+"-unsigned.efi")
		signed := filepath.Join(signer.dir, item.name+"-signed.efi")
		if _, err := downloadActionBootFile(ctx, vm, item.source, unsigned, 512<<20); err != nil {
			return evidence, err
		}
		if err := signer.sign(ctx, unsigned, signed); err != nil {
			return evidence, err
		}
		digest, err := dispatchFileDigest(signed)
		if err != nil {
			return evidence, err
		}
		if item.name == "loader" {
			evidence.SystemdBootSHA256 = digest
		} else {
			evidence.OrdinaryUKISHA256 = digest
		}
		if err := uploadActionBootFile(ctx, vm, signed, "/run/lindm-native-owned-boot/"+item.name+"-signed.efi"); err != nil {
			return evidence, err
		}
	}
	stateUUID := uuid.NewString()
	evidence.StateUUID = stateUUID
	configure := "mkfs.ext4 -F -U " + nativeQuote(stateUUID) + " " + nativeQuote(state.Path) + "; install -d -m0700 /var/lib/lindm-recovery; mount -t ext4 -o nosuid,nodev,noexec " + nativeQuote(state.Path) + " /var/lib/lindm-recovery; chmod 0700 /var/lib/lindm-recovery; printf '%s\\n' " + nativeQuote("UUID="+stateUUID+" /var/lib/lindm-recovery ext4 defaults,nosuid,nodev,noexec 0 2") + " >> /etc/fstab; bootctl --esp-path=/boot/efi install; install -m0600 /run/lindm-native-owned-boot/loader-signed.efi /boot/efi/EFI/systemd/" + loader + "; install -m0600 /run/lindm-native-owned-boot/loader-signed.efi /boot/efi/EFI/BOOT/" + fallback + "; install -d -m0700 /boot/efi/EFI/Linux; install -m0600 /run/lindm-native-owned-boot/ordinary-signed.efi /boot/efi/EFI/Linux/lindm-native-original.efi; printf 'default lindm-native-original.efi\\ntimeout 0\\n' > /boot/efi/loader/loader.conf; sync"
	configured, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(configure), nil, 8192, 3*time.Minute)
	if err != nil {
		return evidence, err
	}
	if configured.ExitCode != 0 {
		return evidence, fmt.Errorf("install owned signed boot: guest exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	if err := rebootLifecycleGuest(ctx, vm, evidence.OriginalBootID); err != nil {
		return evidence, err
	}
	observed, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id; sudo -n bootctl --esp-path=/boot/efi status --no-pager", nil, 32<<10, 15*time.Second)
	if err != nil {
		return evidence, err
	}
	lines := strings.SplitN(string(observed), "\n", 2)
	if len(lines) != 2 || !vmValidID(lines[0]) || lines[0] == evidence.OriginalBootID {
		return evidence, errors.New("owned signed systemd-boot was not observed on a new guest boot")
	}
	evidence.ConvertedBootID, evidence.LoaderStatus = lines[0], lines[1]
	evidence.LoaderInfo, err = observeActionOwnedFirmware(ctx, vm)
	if err != nil {
		return evidence, err
	}
	evidence.SecureBoot, evidence.SetupMode = true, false
	if _, err := vm.run(ctx, "sudo -n mount -o remount,umask=0077 /boot/efi", nil, 4096, 15*time.Second); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func writeActionBootPublicFile(directory, name string, data []byte) (string, []byte, error) {
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", nil, err
	}
	_, writeErr := io.Copy(file, bytes.NewReader(data))
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return "", nil, fmt.Errorf("write native boot public input: %w", err)
	}
	digest := sha256.Sum256(data)
	return path, digest[:], nil
}

func observeActionOwnedFirmware(ctx context.Context, vm *guestVM) (string, error) {
	const variables = "/sys/firmware/efi/efivars/"
	for _, flag := range []struct {
		name  string
		value byte
	}{{"SecureBoot", 1}, {"SetupMode", 0}} {
		raw, err := vm.run(ctx, "sudo -n cat "+nativeQuote(variables+flag.name+"-8be4df61-93ca-11d2-aa0d-00e098032b8c"), nil, 32, 10*time.Second)
		if err != nil {
			return "", err
		}
		if len(raw) != 5 || raw[4] != flag.value {
			return "", errors.New("owned firmware did not enforce Secure Boot user mode")
		}
	}
	raw, err := vm.run(ctx, "sudo -n cat "+nativeQuote(variables+"LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"), nil, 4096, 10*time.Second)
	if err != nil {
		return "", err
	}
	if len(raw) < 6 || len(raw)%2 != 0 {
		return "", errors.New("invalid actual EFI loader identity")
	}
	wide := make([]uint16, (len(raw)-4)/2)
	for i := range wide {
		wide[i] = binary.LittleEndian.Uint16(raw[4+2*i:])
	}
	loader := strings.TrimRight(string(utf16.Decode(wide)), "\x00")
	if !strings.HasPrefix(loader, "systemd-boot ") {
		return "", errors.New("ordinary guest did not actually boot systemd-boot")
	}
	return loader, nil
}
