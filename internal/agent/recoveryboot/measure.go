// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"context"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
)

// PredictPCR11 extracts the exact final UKI sections, including ukify-generated
// uname/SBAT sections, and asks systemd-measure to calculate the SHA256 bank before
// boot-phase extensions. Our minimal init does not run systemd-pcrphase. This
// operation requires no TPM and never queries host PCRs or creates a TPM object.
func PredictPCR11(ctx context.Context, image, outputDirectory string) (_ []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := os.Mkdir(outputDirectory, 0700); err != nil {
		return nil, err
	}
	binary, err := pe.Open(image)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, binary.Close()) }()
	args := []string{"calculate", "--bank=sha256", "--phase=:", "--json=short"}
	linux := false
	for _, section := range binary.Sections {
		switch section.Name {
		case ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat", ".pcrpkey", ".profile", ".dtbauto", ".hwids":
		default:
			continue
		}
		name := strings.TrimPrefix(section.Name, ".")
		if name == "linux" {
			linux = true
		}
		file := filepath.Join(outputDirectory, name)
		if err := extractSection(section, file); err != nil {
			return nil, err
		}
		args = append(args, "--"+name+"="+file)
	}
	if !linux {
		return nil, errors.New("recoveryboot: missing_uki_kernel_section")
	}
	output, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: "/usr/lib/systemd/systemd-measure", Args: args,
		Timeout: 90 * time.Second, StdoutLimit: 64 << 10, StderrLimit: 64 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("recoveryboot: measure UKI: %w", err)
	}
	var result map[string][]struct {
		Phase string `json:"phase"`
		PCR   int    `json:"pcr"`
		Hash  string `json:"hash"`
	}
	if err := json.Unmarshal(output.Stdout, &result); err != nil {
		return nil, err
	}
	values := result["sha256"]
	if len(values) != 1 || values[0].PCR != 11 || values[0].Phase != "" {
		return nil, errors.New("recoveryboot: unexpected_pcr11_measurement")
	}
	digest, err := hex.DecodeString(values[0].Hash)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("recoveryboot: invalid_pcr11_digest")
	}
	if err := writeExclusive(filepath.Join(outputDirectory, "pcr11.json"), output.Stdout, 0600); err != nil {
		return nil, err
	}
	return digest, nil
}

func extractSection(section *pe.Section, name string) (err error) {
	if section.VirtualSize > section.Size {
		return errors.New("recoveryboot: invalid_uki_section_size")
	}
	out, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	if _, err := io.CopyN(out, section.Open(), int64(section.VirtualSize)); err != nil {
		return err
	}
	return out.Sync()
}
