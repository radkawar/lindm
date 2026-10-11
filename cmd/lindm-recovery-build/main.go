// lindm-recovery-build builds a signed recovery UKI, or a measured-BLS recovery
// initramfs for the vendor kernel, from explicitly approved release
// ingredients. It never stages boot files or touches firmware/TPM state.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
)

type fileFlags []string

func (f *fileFlags) String() string         { return strings.Join(*f, ",") }
func (f *fileFlags) Set(value string) error { *f = append(*f, value); return nil }

func ingredient(value string) (recoveryboot.Ingredient, error) {
	digest, name, ok := strings.Cut(value, ":")
	if !ok || name == "" {
		return recoveryboot.Ingredient{}, errors.New("ingredient must be SHA256:PATH")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 {
		return recoveryboot.Ingredient{}, errors.New("ingredient needs exact SHA256")
	}
	return recoveryboot.Ingredient{Source: name, SHA256: decoded}, nil
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("lindm-recovery-build", flag.ContinueOnError)
	output := flags.String("output", "", "new private build directory (must not exist)")
	kernel := flags.String("kernel", "", "approved SHA256:PATH Linux kernel")
	stub := flags.String("stub", "", "approved SHA256:PATH systemd EFI stub")
	agent := flags.String("agent", "", "approved SHA256:PATH static lindm-agent, archived as the image's PID 1 /init")
	config := flags.String("config", "", "approved SHA256:PATH public RecoveryRuntimeConfig")
	cert := flags.String("certificate", "", "approved SHA256:PATH PEM signing certificate")
	key := flags.String("signing-key", "", "private PEM signing key (0600)")
	uuid := flags.String("state-uuid", "", "off-target ext4 UUID mounted by recovery init")
	espUUID := flags.String("esp-uuid", "", "required qualified FAT ESP volume UUID (ABCD-1234)")
	epoch := flags.Int64("source-date-epoch", 0, "reproducible initramfs/kernel image build timestamp")
	serialConsole := flags.String("serial-console", "", "optional signed diagnostic UART: ttyS0,115200n8 or ttyAMA0,115200")
	bootMode := flags.String("boot-mode", "uki", "uki (signed UKI) or measured-grub (unsigned initramfs for the vendor kernel; no stub, certificate or key)")
	var files, executables fileFlags
	flags.Var(&files, "file", "repeat DESTINATION=SHA256:PATH for approved library, module, CA or public trust material")
	flags.Var(&executables, "executable", "repeat DESTINATION=SHA256:PATH for approved native recovery helper")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	request := recoveryboot.BuildRequest{OutputDirectory: *output, SigningKey: *key, StateUUID: *uuid, ESPUUID: *espUUID, SourceDateEpoch: *epoch, SerialConsole: *serialConsole}
	inputs := []struct {
		value  string
		target *recoveryboot.Ingredient
	}{{*kernel, &request.Kernel}, {*agent, &request.Agent}, {*config, &request.Config}}
	switch *bootMode {
	case "uki":
		request.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
		inputs = append(inputs, struct {
			value  string
			target *recoveryboot.Ingredient
		}{*stub, &request.Stub}, struct {
			value  string
			target *recoveryboot.Ingredient
		}{*cert, &request.Certificate})
	case "measured-grub":
		request.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB
		if *stub != "" || *cert != "" || *key != "" || *espUUID != "" || *serialConsole != "" {
			return errors.New("measured-grub takes no stub, certificate, signing key, ESP UUID or serial console")
		}
	default:
		return errors.New("boot-mode must be uki or measured-grub")
	}
	for _, input := range inputs {
		parsed, err := ingredient(input.value)
		if err != nil {
			return err
		}
		*input.target = parsed
	}
	for _, group := range []struct {
		values     fileFlags
		executable bool
	}{{files, false}, {executables, true}} {
		for _, value := range group.values {
			destination, source, ok := strings.Cut(value, "=")
			if !ok {
				return errors.New("file needs DESTINATION=SHA256:PATH")
			}
			parsed, err := ingredient(source)
			if err != nil {
				return err
			}
			parsed.Destination, parsed.Executable = destination, group.executable
			request.Files = append(request.Files, parsed)
		}
	}
	artifact, err := recoveryboot.Build(ctx, request)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "image %s\nsha256 %x\nsize %d\ncertificate_sha256 %x\npcr11_sha256 %x\nkernel_sha256 %x\nclosure %s\ncomponent_sizes %s\n", artifact.Path, artifact.SHA256, artifact.Size, artifact.CertificateSHA256, artifact.PCR11SHA256, artifact.KernelSHA256, artifact.ClosurePath, artifact.SizeEvidencePath)
	return err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
