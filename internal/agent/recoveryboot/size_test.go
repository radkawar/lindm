package recoveryboot

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sizeFixturePE(t *testing.T, dir string) string {
	t.Helper()
	// A parseable PE header supplies real section-size metadata without running
	// a native signer/compiler. These bytes are never treated as a boot image.
	dos := make([]byte, 128)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], uint32(len(dos)))
	var image bytes.Buffer
	image.Write(dos)
	image.WriteString("PE\x00\x00")
	if err := binary.Write(&image, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 2}); err != nil {
		t.Fatal(err)
	}
	for _, section := range []pe.SectionHeader32{
		{Name: [8]uint8{'.', 'l', 'i', 'n', 'u', 'x'}, VirtualSize: 4096, SizeOfRawData: 4096},
		{Name: [8]uint8{'.', 'i', 'n', 'i', 't', 'r', 'd'}, VirtualSize: 256, SizeOfRawData: 512},
	} {
		if err := binary.Write(&image, binary.LittleEndian, section); err != nil {
			t.Fatal(err)
		}
	}
	return fixtureIngredient(t, dir, "sections.efi", image.Bytes()).Source
}

func TestBuildSizeEvidenceAccountsForExactIngredientsAndSections(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "private-source-name", []byte("approved payload"))
	module := input
	module.Destination = "lib/modules/qualified/nvme.ko"
	request := BuildRequest{Kernel: input, Stub: input, Agent: input, Config: input, Certificate: input, Files: []Ingredient{module}, ESPUUID: "ABCD-1234"}
	initrd := fixtureIngredient(t, dir, "initrd", []byte("compressed archive"))
	image := sizeFixturePE(t, dir)
	const signedSize = int64(8192)
	evidence, err := measureBuildSizes(request, initrd.Source, image, signedSize)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Compression != "gzip" || evidence.Kernel.Bytes != 16 || evidence.InitramfsBytes != 18 || evidence.SignedImageBytes != signedSize || evidence.UKIOverheadBytes+evidence.Kernel.Bytes+evidence.InitramfsBytes != signedSize {
		t.Fatalf("incorrect component accounting: %+v", evidence)
	}
	if evidence.Kernel.SHA256 != hex.EncodeToString(input.SHA256) || len(evidence.Ingredients) != 5 || evidence.Version != 2 {
		t.Fatalf("missing pinned ingredients: %+v", evidence)
	}
	var payload int64
	for i, component := range evidence.Ingredients {
		payload += component.Bytes
		if i > 0 && evidence.Ingredients[i-1].Name >= component.Name {
			t.Fatal("ingredient evidence is not in canonical destination order")
		}
		if component.Name == module.Destination && component.Kind != "kernel_module" {
			t.Fatal("module contribution was not distinguished")
		}
		if component.Kind == "busybox" || component.Kind == "init_script" || (component.Name == "init") != (component.Kind == "agent") {
			t.Fatalf("PID 1 agent accounting is wrong: %+v", component)
		}
		if (component.Name == initParamsPath) != (component.Kind == "init_parameters") {
			t.Fatalf("init parameter accounting is wrong: %+v", component)
		}
	}
	if payload != evidence.InitramfsPayloadBytes || !reflect.DeepEqual(evidence.Sections, []SectionSize{{Name: ".linux", PayloadBytes: 4096, FileBytes: 4096}, {Name: ".initrd", PayloadBytes: 256, FileBytes: 512}}) {
		t.Fatalf("payload or PE section accounting lost: %+v", evidence)
	}
	path := filepath.Join(dir, "component-sizes.json")
	if err := writeSizeEvidence(path, evidence); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(dir)) || bytes.Contains(data, []byte("private-source-name")) || bytes.Contains(data, []byte("approved payload")) || len(data) > maxSizeEvidenceBytes {
		t.Fatal("public size evidence leaked sources/contents or exceeded its bound")
	}
	var decoded SizeEvidence
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(&decoded, evidence) {
		t.Fatalf("size evidence did not round-trip: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("size evidence permissions: %v, %v", info, err)
	}
	if err := writeSizeEvidence(path, evidence); err == nil {
		t.Fatal("size evidence replaced an existing artifact")
	}
}

func TestSizeEvidenceBoundsAndInvalidAccounting(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "ingredient", []byte("payload"))
	request := BuildRequest{Kernel: input, Stub: input, Files: make([]Ingredient, 1025)}
	if _, err := measureBuildSizes(request, input.Source, input.Source, 100); err == nil || !strings.Contains(err.Error(), "too_many_ingredients") {
		t.Fatalf("unbounded ingredient list accepted: %v", err)
	}
	request.Files = nil
	if _, err := measureBuildSizes(request, input.Source, input.Source, 1); err == nil || !strings.Contains(err.Error(), "invalid_image_size_accounting") {
		t.Fatalf("negative overhead accepted: %v", err)
	}
	if _, err := componentSize(input, strings.Repeat("x", 513), "configuration"); err == nil {
		t.Fatal("unbounded component name accepted")
	}
	oversized := &SizeEvidence{Compression: strings.Repeat("x", maxSizeEvidenceBytes)}
	path := filepath.Join(dir, "too-large.json")
	if err := writeSizeEvidence(path, oversized); err == nil || !strings.Contains(err.Error(), "size_evidence_too_large") {
		t.Fatalf("unbounded evidence accepted: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("oversized evidence created a file")
	}
}

func TestIngredientSizeKindsPreserveMinimalClosureEvidence(t *testing.T) {
	for _, test := range []struct {
		name       string
		executable bool
		kind       string
	}{
		{"lib/modules/qualified/ahci.ko", false, "kernel_module"},
		{"lib/modules/qualified/modules.dep", false, "kernel_module_metadata"},
		{"lib/firmware/required.bin", false, "firmware"},
		{"usr/lib/firmware/required.bin", false, "firmware"},
		{"lib64/ld-linux-x86-64.so.2", true, "library_or_loader"},
		{"usr/lib64/libnvme.so.1", false, "library_or_loader"},
		{"usr/sbin/nvme", true, "native_helper"},
		{"etc/lindm/server-ca.pem", false, "configuration"},
	} {
		if got := ingredientKind(test.name, test.executable); got != test.kind {
			t.Fatalf("%s = %s, want %s", test.name, got, test.kind)
		}
	}
}
