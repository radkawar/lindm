//go:build linux

package vmlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
)

func TestAssistanceRelayPreservesColocatedAndBindsSplitAddress(t *testing.T) {
	local, err := devlab.ReserveAssistanceRelay("127.0.0.1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if relay := local.GetRelay(); relay.GetListener().GetAddress() != "127.0.0.1" || len(relay.GetUrls()) != 2 || !strings.HasPrefix(relay.GetUrls()[0], "turn:localhost:") {
		t.Fatal("co-located relay changed")
	}
	split, err := devlab.ReserveAssistanceRelay("127.0.0.2", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	relay := split.GetRelay()
	if relay.GetListener().GetAddress() != "127.0.0.2" || relay.GetRelayAddress() != "127.0.0.2" {
		t.Fatal("split relay did not bind the selected address")
	}
	if len(relay.GetUrls()) != 3 || !strings.HasPrefix(relay.GetUrls()[0], "turn:127.0.0.2:") || !strings.HasSuffix(relay.GetUrls()[0], "?transport=udp") || !strings.HasSuffix(relay.GetUrls()[1], "?transport=tcp") || !strings.HasPrefix(relay.GetUrls()[2], "turn:localhost:") {
		t.Fatalf("split relay URLs = %v", relay.GetUrls())
	}
}

func TestAssistanceControlPlaneIsPrivateAndSingleUse(t *testing.T) {
	controller := &AssistanceController{Handle: &AssistanceControlPlane{Authority: &devlab.ControlPlaneHandle{Password: []byte("lane-secret")}, Delegation: json.RawMessage(`{}`), ControllerAddress: "192.0.2.10"}}
	path := filepath.Join(t.TempDir(), "control-plane")
	if err := controller.WriteControlPlane(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("handle permissions: %v, %v", info, err)
	}
	if err := controller.WriteControlPlane(path); err == nil {
		t.Fatal("overwrote existing private handle")
	}
	handle, err := ReadAssistanceControlPlane(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(handle.Authority.Password) != "lane-secret" {
		t.Fatal("lane credential missing")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("consumed handle remains on disk")
	}
	if err := os.WriteFile(path, []byte(`{"authority":{},"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAssistanceControlPlane(path); err == nil {
		t.Fatal("unknown handle field accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rejected handle remains on disk")
	}
}

// A resumed VM deliberately has no newly built package. Reach the real
// control-plane decoding boundary without building a package or booting a VM;
// deriving enrollment architecture from packages.artifact used to panic here.
func TestAssistanceResumeNeedsNoNewPackageForFixture(t *testing.T) {
	paths, err := filepath.Glob("../../lab/images/*encrypted*.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest *labv1.ImageManifest
	desktopName := ""
	for _, path := range paths {
		candidate, err := LoadManifest(path)
		if err != nil {
			t.Fatal(err)
		}
		release := platform.ForManifest(candidate.GetDistribution(), candidate.GetVersion())
		for _, profile := range labDesktops {
			desktop, err := labDesktopFor(profile.name, release)
			if err == nil && assistanceAdmission(release, desktop) == nil {
				manifest, desktopName = candidate, profile.name
				break
			}
		}
		if manifest != nil {
			break
		}
	}
	if manifest == nil {
		t.Fatal("no maintained manifest admits assistance")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []string{"amd64", "x86_64", "arm64", "aarch64"} {
		t.Run(architecture, func(t *testing.T) {
			image := proto.CloneOf(manifest)
			image.Architecture = architecture
			_, evidenceDir := newTestAssistanceEvidence(t)
			_, err := AssistanceVM(t.Context(), image, VMAssistanceOptions{
				LabBinary: binary, EvidenceDir: evidenceDir,
				PersistentDir: t.TempDir(), FixtureDir: filepath.Join(t.TempDir(), "authority"),
				Hold: func(*AssistanceHold) error {
					t.Fatal("resume unexpectedly reached hold")
					return nil
				},
				Encrypted: EncryptedVMOptions{Desktop: desktopName, Hardware: &VMHardwareOptions{Desktop: true, AllowNetwork: true}},
				ControlPlane: &AssistanceControlPlane{
					Delegation: json.RawMessage(`{"invalid_resume_delegation":true}`),
				},
			})
			if err == nil || !strings.Contains(err.Error(), "invalid_resume_delegation") {
				t.Fatalf("resume did not reach control-plane validation without building a package: %v", err)
			}
		})
	}
}
