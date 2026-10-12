package demolab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestLoadOrganizationDemo(t *testing.T) {
	spec := demoFixture(t)
	if len(spec.Devices) != 3 {
		t.Fatal("demo must contain three real devices")
	}
	for _, device := range spec.Devices {
		if !filepath.IsAbs(device.ManifestPath) || !filepath.IsAbs(spec.OrganizationPath) {
			t.Fatal("document references must resolve independently of the working directory")
		}
		if !device.Release.Known() || device.Config.GetFirmware().SecureBoot == nil {
			t.Fatal("demo must have registered releases and explicit firmware security mode")
		}
	}
}

func TestLoadRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*labv1.DemoSpec)
		want   string
	}{
		{"duplicate key", func(s *labv1.DemoSpec) { s.Devices[1].Key = s.Devices[0].Key }, "device keys and hostnames must be unique"},
		{"duplicate hostname", func(s *labv1.DemoSpec) { s.Devices[1].Hostname = s.Devices[0].Hostname }, "device keys and hostnames must be unique"},
		{"invalid key", func(s *labv1.DemoSpec) { s.Devices[0].Key = "../escape" }, "key"},
		{"server assistance", func(s *labv1.DemoSpec) { s.Devices[2].Assistance = true }, "assistance is only available"},
		{"unknown group", func(s *labv1.DemoSpec) { s.Devices[0].Group = "00000000-0000-4000-8000-000000000001" }, "static group"},
		{"unknown token", func(s *labv1.DemoSpec) { s.Devices[0].ProvisioningToken = "absent" }, "does not exist"},
		{"wrong token group", func(s *labv1.DemoSpec) { s.Devices[0].ProvisioningToken = "finance" }, "does not assign static group"},
		{"missing manifest", func(s *labv1.DemoSpec) { s.Devices[0].Manifest = "absent.json" }, "manifest"},
		{"missing org", func(s *labv1.DemoSpec) { s.Organization = "absent.json" }, "absent.json"},
		{"missing firmware", func(s *labv1.DemoSpec) { s.Devices[0].Firmware = nil }, "firmware"},
		{"unspecified security", func(s *labv1.DemoSpec) { s.Devices[0].Firmware.SecureBoot = nil }, "secure_boot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := demoFixture(t)
			document := absoluteDocument(spec)
			test.change(document)
			path := writeSpec(t, document)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	for _, input := range []string{"demo", "organization", "manifest"} {
		t.Run(input, func(t *testing.T) {
			document := absoluteDocument(demoFixture(t))
			path := filepath.Join(t.TempDir(), "unknown.json")
			if err := os.WriteFile(path, []byte(`{"unknownSecuritySetting":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			switch input {
			case "organization":
				document.Organization = path
				path = writeSpec(t, document)
			case "manifest":
				document.Devices[0].Manifest = path
				path = writeSpec(t, document)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Load error = %v, want unknown field", err)
			}
		})
	}
}

func TestLoadRelativeReferences(t *testing.T) {
	document := absoluteDocument(demoFixture(t))
	root := t.TempDir()
	org, err := os.ReadFile(document.GetOrganization())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "org.json"), org, 0o600); err != nil {
		t.Fatal(err)
	}
	document.Organization = "org.json"
	data, err := protojson.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "demo.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.OrganizationPath != filepath.Join(root, "org.json") {
		t.Fatalf("organization resolved to %s", spec.OrganizationPath)
	}
}

func absoluteDocument(spec *Spec) *labv1.DemoSpec {
	document := proto.CloneOf(spec.Document)
	document.Organization = spec.OrganizationPath
	for i := range document.GetDevices() {
		document.Devices[i].Manifest = spec.Devices[i].ManifestPath
	}
	return document
}
