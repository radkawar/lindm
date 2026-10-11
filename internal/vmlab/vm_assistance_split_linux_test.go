//go:build linux

package vmlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/devlab"
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
