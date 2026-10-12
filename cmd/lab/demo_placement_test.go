package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/demolab"
	"lindm/internal/devlab"
	"lindm/internal/vmlab"
)

func TestDemoPlacementAccountsForRetainedGuests(t *testing.T) {
	host := func(name string) *labv1.LabHost {
		return &labv1.LabHost{Name: name, Transport: "local", Runtime: "native", Architectures: []string{"amd64"}, Kvm: true, MaxGuests: 1, MaxVcpus: 2, MaxMemoryMib: 4096, WorkDirectory: "/tmp/" + name}
	}
	device := func(key, host string) demolab.Device {
		config := &labv1.DemoDevice{Key: key}
		if host != "" {
			config.Host = proto.String(host)
		}
		return demolab.Device{Config: config, Manifest: &labv1.ImageManifest{Architecture: "amd64", Sha256: strings.Repeat("a", 64)}}
	}
	cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{host("a"), host("b")}}
	t.Run("spread", func(t *testing.T) {
		state, err := planDemoBindings("org", &demolab.Spec{Devices: []demolab.Device{device("one", ""), device("two", "")}}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if state.Bindings[0].Host.Name == state.Bindings[1].Host.Name {
			t.Fatal("retained devices exceed their selected host capacity")
		}
	})
	t.Run("reserve-pinned", func(t *testing.T) {
		state, err := planDemoBindings("org", &demolab.Spec{Devices: []demolab.Device{device("unpinned", ""), device("pinned", "a")}}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if state.Bindings[0].Host.Name != "b" || state.Bindings[1].Host.Name != "a" {
			t.Fatal("unpinned device consumed the only slot of a later pinned device")
		}
	})
	t.Run("refuse-impossible", func(t *testing.T) {
		if _, err := planDemoBindings("org", &demolab.Spec{Devices: []demolab.Device{device("one", "a"), device("two", "a")}}, cfg); err == nil {
			t.Fatal("admitted impossible pinned placement")
		}
	})
}

func TestDemoReadyInstructionsUsePositionalConsentAction(t *testing.T) {
	var output bytes.Buffer
	access := &vmlab.AssistanceHold{DeviceID: "device-id", RemoteEvidenceDir: "/remote/evidence", RespondBinary: "/remote/lab", EnrollmentSecret: "never-public", DesktopPassword: "never-public"}
	controller := &vmlab.AssistanceController{Handle: &vmlab.AssistanceControlPlane{Authority: &devlab.ControlPlaneHandle{AdminPort: 18444}, ControllerAddress: "192.0.2.1"}}
	controller.Handle.Relay.ListenerPort = 3478
	run := &demoRun{options: demoOptions{name: "org", lab: "lab", evidence: t.TempDir()}, root: t.TempDir(), stdout: &output, controller: controller,
		state:  &labv1.DemoState{Bindings: []*labv1.DemoBinding{{Key: "desktop", Host: &labv1.LabHost{Transport: "ssh", SshAlias: "spark"}, Device: &labv1.DemoDevice{Role: labv1.DemoRole_DEMO_ROLE_DESKTOP}}}},
		access: &demoOwnerAccess{ConsoleOrigin: "https://localhost:18444", Username: "console-owner", Devices: map[string]*vmlab.AssistanceHold{"desktop": access}}}
	if err := run.writeReady(); err != nil {
		t.Fatal(err)
	}
	want := "ssh spark /remote/lab vm assistance-respond -evidence /remote/evidence <" + strings.Join(vmlab.AssistanceRespondActions, "|") + ">"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("missing executable positional responder command: %s", output.String())
	}
	if strings.Contains(output.String(), "-action") || strings.Contains(output.String(), "never-public") {
		t.Fatal("instructions contain invalid flag or private credential")
	}
	data, err := os.ReadFile(filepath.Join(run.options.evidence, "ready.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("never-public")) {
		t.Fatal("ready evidence disclosed a credential")
	}
}
