//go:build linux

package vmlab

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
	"lindm/internal/labexec"
	"lindm/internal/packaging"
)

// Inputs come from the installed signed distro and lindm packages in this guest,
// not similarly named host binaries. Build independently closes/pins every ELF
// dependency before signing the actual UKI with the fixture's enrolled db signer.
// A nil signer builds the unsigned measured-GRUB initramfs for the vendor
// kernel; the kernel as GRUB measures it is retained at
// actionVendorKernel(workDir) for its offline release descriptor.
// A nonempty ukify is the lab host's private pinned copy (remote hosts without
// systemd-ukify); it runs as the lab user, outside the product's /usr custody.
func buildActionRecoveryArtifact(ctx context.Context, vm *guestVM, workDir string, signer *actionBootSigner, boot *actionOwnedBootEvidence, runtime *agentv1.RecoveryRuntimeConfig, root, bootstrap, serverCA []byte, ukify string) (*recoveryboot.Artifact, error) {
	measured := signer == nil
	request := recoveryboot.BuildRequest{OutputDirectory: filepath.Join(workDir, "recovery-build"), StateUUID: boot.StateUUID, SourceDateEpoch: time.Now().Unix(), BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}
	if ukify != "" {
		if !filepath.IsAbs(ukify) || filepath.Clean(ukify) != ukify || filepath.Base(ukify) != "ukify" {
			return nil, errors.New("recovery ukify must be an absolute clean path to ukify")
		}
		request.Ukify = func(ctx context.Context, env, args []string) error {
			return labexec.Run(ctx, labexec.Command{Path: ukify, Args: args, Env: append([]string{"PATH=/usr/bin:/bin", "LANG=C"}, env...), Timeout: 90 * time.Second})
		}
	}
	if !measured {
		_, serialConsole, err := encryptedInstallerArchitecture(vm.hardware.Architecture)
		if err != nil {
			return nil, err
		}
		request.SigningKey, request.Certificate, request.SerialConsole = signer.key, recoveryboot.Ingredient{Source: signer.certificate, SHA256: signer.certificateSHA256}, serialConsole
		request.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
	}
	// The initramfs is compressed before UKI signing. Its decompressor and FAT
	// charset modules must come from the same installed kernel as the image.
	kernelConfig, err := vm.run(ctx, "cat "+nativeQuote("/boot/config-"+boot.KernelRelease), nil, 1<<20, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("read recovery kernel configuration: %w", err)
	}
	if !strings.Contains("\n"+string(kernelConfig)+"\n", "\nCONFIG_RD_GZIP=y\n") {
		return nil, errors.New("qualified recovery kernel requires built-in gzip initramfs decompression")
	}
	// provisionActionOwnedBoot rebooted into the signed ordinary UKI; /run's
	// earlier staging directory cannot survive that boot boundary.
	if err := lifecycleCommand(ctx, vm, "create recovery module staging after owned boot", "mkdir -m 0700 /run/lindm-native-owned-boot"); err != nil {
		return nil, err
	}
	if !measured {
		espUUID, err := vm.run(ctx, "sudo -n findmnt --noheadings --output UUID --target /boot/efi", nil, 1024, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("observe qualified recovery ESP identity: %w", err)
		}
		request.ESPUUID = strings.TrimSpace(string(espUUID))
	}
	counter := 0
	collected := make(map[string]bool)
	collect := func(source, destination string, executable bool) (recoveryboot.Ingredient, error) {
		counter++
		path := filepath.Join(workDir, fmt.Sprintf("ingredient-%04d", counter))
		digest, err := downloadActionBootFile(ctx, vm, source, path, 256<<20)
		if err != nil {
			return recoveryboot.Ingredient{}, fmt.Errorf("collect recovery ingredient %s: %w", source, err)
		}
		return recoveryboot.Ingredient{Source: path, Destination: destination, SHA256: digest, Executable: executable}, nil
	}
	addPublic := func(name, destination string, data []byte) error {
		source, digest, err := writeActionBootPublicFile(workDir, name, data)
		if err != nil {
			return err
		}
		request.Files = append(request.Files, recoveryboot.Ingredient{Source: source, Destination: destination, SHA256: digest})
		return nil
	}
	kernelSource := actionVendorKernel(workDir)
	if measured {
		kernelSource += ".file"
	}
	kernelPath := boot.KernelPath
	if kernelPath == "" {
		kernelPath = "/boot/vmlinuz-" + boot.KernelRelease
	}
	kernel, err := downloadActionBootFile(ctx, vm, kernelPath, kernelSource, 256<<20)
	if err != nil {
		return nil, fmt.Errorf("collect recovery vendor kernel: %w", err)
	}
	if measured {
		if kernel, err = measuredVendorKernel(kernelSource, actionVendorKernel(workDir)); err != nil {
			return nil, fmt.Errorf("measured form of recovery vendor kernel: %w", err)
		}
	}
	request.Kernel = recoveryboot.Ingredient{Source: actionVendorKernel(workDir), SHA256: kernel}
	if !measured {
		stub := "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
		if vm.hardware.Architecture == "aarch64" {
			stub = "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub"
		}
		request.Stub, err = collect(stub, "", false)
		if err != nil {
			return nil, err
		}
	}
	request.Agent, err = collect(packaging.BinaryPath, "", true)
	if err != nil {
		return nil, err
	}
	encoded, err := protojson.Marshal(runtime)
	if err != nil {
		return nil, err
	}
	configPath, configDigest, err := writeActionBootPublicFile(workDir, "recovery-config.json", encoded)
	if err != nil {
		return nil, err
	}
	request.Config = recoveryboot.Ingredient{Source: configPath, SHA256: configDigest}
	if err := addPublic("execution-root.json", "etc/lindm/execution-root.json", root); err != nil {
		return nil, err
	}
	if err := addPublic("bootstrap-envelope.pb", "etc/lindm/bootstrap-envelope.pb", bootstrap); err != nil {
		return nil, err
	}
	if err := addPublic("server-ca.pem", "etc/lindm/server-ca.pem", serverCA); err != nil {
		return nil, err
	}
	// QEMU's user-network host address reaches this run's ephemeral loopback
	// listener. The certificate still authenticates localhost; no TLS override.
	if err := addPublic("hosts", "etc/hosts", []byte("10.0.2.2 localhost\n")); err != nil {
		return nil, err
	}
	if err := addPublic("nsswitch.conf", "etc/nsswitch.conf", []byte("hosts: files dns\n")); err != nil {
		return nil, err
	}
	for _, destination := range recoveryboot.RequiredNativeHelpers(runtime) {
		helper := "/" + destination
		in, err := collect(helper, strings.TrimPrefix(helper, "/"), true)
		if err != nil {
			return nil, err
		}
		request.Files = append(request.Files, in)
		collected[helper] = true
		image, err := elf.Open(in.Source)
		if err != nil {
			return nil, err
		}
		var interpreterPath string
		for _, segment := range image.Progs {
			if segment.Type != elf.PT_INTERP {
				continue
			}
			interpreter, readErr := io.ReadAll(io.LimitReader(segment.Open(), 4097))
			if readErr != nil {
				return nil, errors.Join(readErr, image.Close())
			}
			interpreterPath = strings.TrimSuffix(string(interpreter), "\x00")
		}
		if err := image.Close(); err != nil {
			return nil, err
		}
		libraries, err := vm.run(ctx, "LC_ALL=C ldd "+nativeQuote(helper), nil, 64<<10, 15*time.Second)
		if err != nil {
			return nil, fmt.Errorf("resolve recovery libraries for %s: %w", helper, err)
		}
		if strings.Contains(string(libraries), "not found") {
			return nil, errors.New("signed guest package has an unresolved native library")
		}
		for _, field := range strings.Fields(string(libraries)) {
			if !strings.HasPrefix(field, "/") || collected[field] {
				continue
			}
			if filepath.Clean(field) != field {
				return nil, errors.New("noncanonical native library path")
			}
			library, err := collect(field, strings.TrimPrefix(field, "/"), field == interpreterPath)
			if err != nil {
				return nil, err
			}
			request.Files = append(request.Files, library)
			collected[field] = true
		}
	}
	// Keep only the distro-signed modules needed by this exact emulated tuple.
	// modprobe's ordered insmod closure is decompressed without altering module
	// bytes/signatures; recovery init loads modules.load in this order with
	// finit_module(2), so no host zstd/depmod/modprobe enters the initramfs.
	modules := []string{"virtio_pci", "virtio_net", "efivarfs"}
	if !measured {
		// Only the UKI path mounts the ESP inside recovery.
		modules = append(modules, "vfat")
	}
	if runtime.GetCustody() == agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET {
		modules = append(modules, "ext4")
	}
	// FAT requests these NLS modules dynamically, outside modprobe's static
	// dependency graph. Preserve the distro kernel's actual mount defaults.
	for _, line := range strings.Split(string(kernelConfig), "\n") {
		if measured {
			break
		}
		if value, ok := strings.CutPrefix(line, "CONFIG_FAT_DEFAULT_CODEPAGE="); ok {
			modules = append(modules, "nls_cp"+value)
		}
		if value, ok := strings.CutPrefix(line, "CONFIG_FAT_DEFAULT_IOCHARSET="); ok {
			modules = append(modules, "nls_"+strings.Trim(value, `"`))
		}
	}
	switch vm.hardware.StorageBus {
	case "nvme":
		modules = append(modules, "nvme")
	case "sata":
		modules = append(modules, "ahci", "sd_mod")
	default:
		return nil, errors.New("original recovery controller fixture requires NVMe or SATA")
	}
	if runtime.GetCustody() == agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		if !vm.hardware.TPM {
			return nil, errors.New("qualified recovery TPM custody requires a TPM")
		}
		modules = append(modules, "tpm_tis")
	} else if measured && vm.hardware.TPM {
		// A TPM-less measured artifact exists only for the capability refusal
		// lane; the device's readiness gate refuses it before any staging.
		modules = append(modules, "tpm_tis", "tpm_crb")
	}
	var load strings.Builder
	seenModules := make(map[string]bool)
	for _, module := range modules {
		output, err := vm.run(ctx, "sudo -n modprobe --show-depends "+nativeQuote(module), nil, 64<<10, 15*time.Second)
		if err != nil {
			return nil, fmt.Errorf("resolve recovery module %s: %w", module, err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] == "builtin" {
				continue
			}
			if len(fields) != 2 || fields[0] != "insmod" || !strings.HasPrefix(fields[1], "/") {
				return nil, errors.New("native kernel module closure requires an unmodified insmod dependency")
			}
			source := fields[1]
			base := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(source), ".zst"), ".xz")
			if !strings.HasSuffix(base, ".ko") || seenModules[base] {
				continue
			}
			seenModules[base] = true
			if strings.HasSuffix(source, ".zst") || strings.HasSuffix(source, ".xz") {
				tool := "zstd -dc -- "
				if strings.HasSuffix(source, ".xz") {
					tool = "xz -dc -- "
				}
				plain := "/run/lindm-native-owned-boot/" + base
				result, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote("umask 077; set -C; "+tool+nativeQuote(source)+" > "+nativeQuote(plain)), nil, 4096, 30*time.Second)
				if err != nil {
					return nil, fmt.Errorf("decompress recovery module %s: %w", source, err)
				}
				if result.ExitCode != 0 {
					return nil, fmt.Errorf("decompress recovery module %s exited %d: %s", source, result.ExitCode, result.Stderr)
				}
				source = plain
			}
			moduleFile, err := collect(source, "lib/modules/"+boot.KernelRelease+"/"+base, false)
			if err != nil {
				return nil, err
			}
			request.Files = append(request.Files, moduleFile)
			load.WriteString(strings.TrimSuffix(base, ".ko") + "\n")
		}
	}
	if err := addPublic("modules.load", "etc/lindm/modules.load", []byte(load.String())); err != nil {
		return nil, err
	}
	return recoveryboot.Build(ctx, request)
}

func actionVendorKernel(workDir string) string { return filepath.Join(workDir, "vendor-kernel") }

// measuredVendorKernel writes the kernel image GRUB measures: the file itself,
// or a gzip-compressed kernel's decompressed image. The returned digest is
// checked against the agent's own measured-form digest of the original file.
func measuredVendorKernel(file, target string) (_ []byte, err error) {
	want, err := recoveryboot.MeasuredKernelSHA256(file)
	if err != nil {
		return nil, err
	}
	input, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	reader := bufio.NewReader(input)
	var source io.Reader = reader
	if magic, peekErr := reader.Peek(2); peekErr == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, compressed.Close()) }()
		compressed.Multistream(false)
		source = compressed
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(output, hash), source)
	if err = errors.Join(err, output.Close()); err != nil {
		return nil, err
	}
	if got := hash.Sum(nil); !bytes.Equal(got, want) {
		return nil, errors.New("decompressed vendor kernel digest differs from its measured form")
	}
	return want, nil
}
