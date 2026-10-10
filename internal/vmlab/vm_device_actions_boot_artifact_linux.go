//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
	"lindm/internal/packaging"
)

// Inputs come from the installed signed distro and lindm packages in this guest,
// not similarly named host binaries. Build independently closes/pins every ELF
// dependency before signing the actual UKI with the fixture's enrolled db signer.
func buildActionRecoveryArtifact(ctx context.Context, vm *guestVM, signer *actionBootSigner, boot *actionOwnedBootEvidence, runtime *agentv1.RecoveryRuntimeConfig, root, bootstrap, serverCA []byte) (*recoveryboot.Artifact, error) {
	request := recoveryboot.BuildRequest{OutputDirectory: filepath.Join(signer.dir, "recovery-build"), SigningKey: signer.key, Certificate: recoveryboot.Ingredient{Source: signer.certificate, SHA256: signer.certificateSHA256}, StateUUID: boot.StateUUID, SourceDateEpoch: time.Now().Unix()}
	// provisionActionOwnedBoot rebooted into the signed ordinary UKI; /run's
	// earlier staging directory cannot survive that boot boundary.
	if err := lifecycleCommand(ctx, vm, "create recovery module staging after owned boot", "mkdir -m 0700 /run/lindm-native-owned-boot"); err != nil {
		return nil, err
	}
	espUUID, err := vm.run(ctx, "sudo -n findmnt --noheadings --output UUID --target /boot/efi", nil, 1024, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("observe qualified recovery ESP identity: %w", err)
	}
	request.ESPUUID = strings.TrimSpace(string(espUUID))
	counter := 0
	collected := make(map[string]bool)
	collect := func(source, destination string, executable bool) (recoveryboot.Ingredient, error) {
		counter++
		path := filepath.Join(signer.dir, fmt.Sprintf("ingredient-%04d", counter))
		digest, err := downloadActionBootFile(ctx, vm, source, path, 256<<20)
		if err != nil {
			return recoveryboot.Ingredient{}, fmt.Errorf("collect recovery ingredient %s: %w", source, err)
		}
		return recoveryboot.Ingredient{Source: path, Destination: destination, SHA256: digest, Executable: executable}, nil
	}
	addPublic := func(name, destination string, data []byte) error {
		source, digest, err := writeActionBootPublicFile(signer.dir, name, data)
		if err != nil {
			return err
		}
		request.Files = append(request.Files, recoveryboot.Ingredient{Source: source, Destination: destination, SHA256: digest})
		return nil
	}
	request.Kernel, err = collect("/boot/vmlinuz-"+boot.KernelRelease, "", false)
	if err != nil {
		return nil, err
	}
	stub := "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
	if vm.hardware.Architecture == "aarch64" {
		stub = "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub"
	}
	request.Stub, err = collect(stub, "", false)
	if err != nil {
		return nil, err
	}
	request.Busybox, err = collect("/usr/bin/busybox", "", true)
	if err != nil {
		return nil, err
	}
	request.Agent, err = collect(packaging.BinaryPath, "", true)
	if err != nil {
		return nil, err
	}
	encoded, err := protojson.Marshal(runtime)
	if err != nil {
		return nil, err
	}
	configPath, configDigest, err := writeActionBootPublicFile(signer.dir, "recovery-config.json", encoded)
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
	for _, helper := range []string{"/usr/bin/sbverify", "/usr/bin/lsblk", "/usr/sbin/cryptsetup", "/usr/sbin/dmsetup", "/usr/sbin/nvme"} {
		in, err := collect(helper, strings.TrimPrefix(helper, "/"), true)
		if err != nil {
			return nil, err
		}
		request.Files = append(request.Files, in)
		collected[helper] = true
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
			library, err := collect(field, strings.TrimPrefix(field, "/"), false)
			if err != nil {
				return nil, err
			}
			request.Files = append(request.Files, library)
			collected[field] = true
		}
	}
	// Keep only the distro-signed modules needed by this exact emulated tuple.
	// modprobe's ordered insmod closure is decompressed without altering module
	// bytes/signatures; BusyBox does not need host zstd/depmod in the initramfs.
	modules := []string{"virtio_pci", "virtio_net", "ext4", "vfat", "efivarfs"}
	switch vm.hardware.StorageBus {
	case "nvme":
		modules = append(modules, "nvme")
	case "sata":
		modules = append(modules, "ahci", "sd_mod")
	default:
		return nil, errors.New("original recovery controller fixture requires NVMe or SATA")
	}
	if vm.hardware.TPM {
		modules = append(modules, "tpm_tis")
	}
	var load, dependencies strings.Builder
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
			dependencies.WriteString(base + ":\n")
		}
	}
	if err := addPublic("modules.load", "etc/lindm/modules.load", []byte(load.String())); err != nil {
		return nil, err
	}
	if err := addPublic("modules.dep", "lib/modules/"+boot.KernelRelease+"/modules.dep", []byte(dependencies.String())); err != nil {
		return nil, err
	}
	return recoveryboot.Build(ctx, request)
}
