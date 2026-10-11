package recoveryboot

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
)

// SizeEvidence describes the exact built image, not an estimated release size or
// an authorization to stage it. Ingredient sizes are uncompressed payload bytes:
// compression shares a dictionary, so individual compressed contributions are
// not additive. Only InitramfsBytes and SignedImageBytes measure compressed output.
// No source paths, signing-key information or runtime configuration contents are
// included. The JSON document is bounded to 1 MiB and retained with the artifact.
type SizeEvidence struct {
	Version               int             `json:"version"`
	Compression           string          `json:"compression"`
	SignedImageBytes      int64           `json:"signed_image_bytes"`
	SignedImageSHA256     string          `json:"signed_image_sha256"`
	Kernel                ComponentSize   `json:"kernel"`
	Stub                  ComponentSize   `json:"stub"`
	InitramfsBytes        int64           `json:"initramfs_bytes"`
	InitramfsPayloadBytes int64           `json:"initramfs_payload_bytes"`
	UKIOverheadBytes      int64           `json:"uki_overhead_bytes"`
	Ingredients           []ComponentSize `json:"ingredients"`
	Sections              []SectionSize   `json:"sections"`
}

type ComponentSize struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type SectionSize struct {
	Name         string `json:"name"`
	PayloadBytes uint32 `json:"payload_bytes"`
	FileBytes    uint32 `json:"file_bytes"`
}

const maxSizeEvidenceBytes = 1 << 20

func componentSize(in Ingredient, name, kind string) (ComponentSize, error) {
	if len(name) > 512 {
		return ComponentSize{}, errors.New("recoveryboot: size_evidence_name_too_long")
	}
	info, err := os.Stat(in.Source)
	if err != nil {
		return ComponentSize{}, err
	}
	return ComponentSize{Name: name, Kind: kind, Bytes: info.Size(), SHA256: hex.EncodeToString(in.SHA256)}, nil
}

func ingredientKind(name string, executable bool) string {
	switch {
	case strings.HasPrefix(name, "lib/modules/") && strings.HasSuffix(name, ".ko"):
		return "kernel_module"
	case strings.HasPrefix(name, "lib/modules/"):
		return "kernel_module_metadata"
	case strings.HasPrefix(name, "lib/firmware/"), strings.HasPrefix(name, "usr/lib/firmware/"):
		return "firmware"
	case strings.HasPrefix(name, "lib/"), strings.HasPrefix(name, "lib64/"), strings.HasPrefix(name, "usr/lib/"), strings.HasPrefix(name, "usr/lib64/"):
		return "library_or_loader"
	case executable:
		return "native_helper"
	default:
		return "configuration"
	}
}

func measureBuildSizes(request BuildRequest, initrd, image string, signedSize int64) (*SizeEvidence, error) {
	if len(request.Files) > 1024 {
		return nil, errors.New("recoveryboot: size_evidence_too_many_ingredients")
	}
	evidence := &SizeEvidence{Version: 2, Compression: "gzip", SignedImageBytes: signedSize}
	var err error
	evidence.Kernel, err = componentSize(request.Kernel, "kernel", "kernel")
	if err != nil {
		return nil, err
	}
	evidence.Stub, err = componentSize(request.Stub, "stub", "efi_stub")
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(initrd)
	if err != nil {
		return nil, err
	}
	evidence.InitramfsBytes = info.Size()
	// This includes the stub, PE headers/sections, alignment and signature. The
	// stub input is reported separately but must not be added a second time.
	evidence.UKIOverheadBytes = signedSize - evidence.Kernel.Bytes - evidence.InitramfsBytes
	if evidence.UKIOverheadBytes < 0 {
		return nil, errors.New("recoveryboot: invalid_image_size_accounting")
	}
	for _, item := range []struct {
		input Ingredient
		name  string
		kind  string
	}{
		{request.Agent, "init", "agent"},
		{request.Config, "etc/lindm/recovery.json", "configuration"},
		{request.Certificate, "etc/lindm/image-signing.pem", "certificate"},
	} {
		component, err := componentSize(item.input, item.name, item.kind)
		if err != nil {
			return nil, err
		}
		evidence.Ingredients = append(evidence.Ingredients, component)
	}
	for _, in := range request.Files {
		component, err := componentSize(in, in.Destination, ingredientKind(in.Destination, in.Executable))
		if err != nil {
			return nil, err
		}
		evidence.Ingredients = append(evidence.Ingredients, component)
	}
	params := initParamsFor(request).render()
	digest := sha256.Sum256([]byte(params))
	evidence.Ingredients = append(evidence.Ingredients, ComponentSize{Name: initParamsPath, Kind: "init_parameters", Bytes: int64(len(params)), SHA256: hex.EncodeToString(digest[:])})
	sort.Slice(evidence.Ingredients, func(i, j int) bool { return evidence.Ingredients[i].Name < evidence.Ingredients[j].Name })
	for _, component := range evidence.Ingredients {
		evidence.InitramfsPayloadBytes += component.Bytes
	}
	binary, err := pe.Open(image)
	if err != nil {
		return nil, err
	}
	if len(binary.Sections) > 128 {
		return nil, errors.Join(errors.New("recoveryboot: size_evidence_too_many_sections"), binary.Close())
	}
	for _, section := range binary.Sections {
		evidence.Sections = append(evidence.Sections, SectionSize{Name: section.Name, PayloadBytes: section.VirtualSize, FileBytes: section.Size})
	}
	if err := binary.Close(); err != nil {
		return nil, err
	}
	return evidence, nil
}

func writeSizeEvidence(name string, evidence *SizeEvidence) error {
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if len(data) >= maxSizeEvidenceBytes {
		return errors.New("recoveryboot: size_evidence_too_large")
	}
	return writeExclusive(name, append(data, '\n'), 0600)
}
